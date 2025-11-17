// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/block_bitmap_test.c - KUnit tests for block bitmap implementation.
 *
 * Copyright (c) 2025 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "block_bitmap.h"

/*
 * Test helper functions
 */
static struct ssdfs_fs_info *test_create_fs_info(void)
{
	struct ssdfs_fs_info *fsi;

	fsi = kzalloc(sizeof(struct ssdfs_fs_info), GFP_KERNEL);
	if (!fsi)
		return NULL;

	fsi->pagesize = PAGE_SIZE;
	fsi->log_pagesize = PAGE_SHIFT;
	return fsi;
}

static void test_free_fs_info(struct ssdfs_fs_info *fsi)
{
	if (fsi)
		kfree(fsi);
}

/*
 * Test helper functions
 */
static struct folio *test_alloc_folio(unsigned int order)
{
	struct folio *folio;

	folio = folio_alloc(GFP_KERNEL, order);
	if (folio)
		folio_get(folio);

	return folio;
}

/*
 * Test cases for ssdfs_block_bmap_create()
 */
static void test_block_bmap_create_valid_params(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_EXPECT_EQ(test, 0, err);

	if (err == 0) {
		KUNIT_EXPECT_TRUE(test, ssdfs_block_bmap_initialized(&bmap));
		KUNIT_EXPECT_EQ(test, 64, ssdfs_block_bmap_get_pages_capacity(&bmap));
		KUNIT_EXPECT_EQ(test, 64, ssdfs_block_bmap_get_allocation_pool(&bmap));
		KUNIT_EXPECT_EQ(test, 64, ssdfs_block_bmap_get_free_pages(&bmap));
		KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_used_pages(&bmap));
		KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_invalid_pages(&bmap));
		ssdfs_block_bmap_destroy(&bmap);
	}

	test_free_fs_info(fsi);
}

static void test_block_bmap_create_null_params(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	/* Test with NULL fs_info */
	err = ssdfs_block_bmap_create(NULL, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_EXPECT_NE(test, 0, err);

	/* Test with NULL block bitmap */
	err = ssdfs_block_bmap_create(fsi, NULL, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_EXPECT_NE(test, 0, err);

	test_free_fs_info(fsi);
}

static void test_block_bmap_create_zero_capacity(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 0, 0,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_EXPECT_NE(test, 0, err);

	test_free_fs_info(fsi);
}

/*
 * Test cases for block state checking
 */
static void test_block_bmap_state_checking(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test state checking for valid block indices */
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 0));
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 32));
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 63));

	/* Test invalid states */
	KUNIT_EXPECT_FALSE(test, is_block_valid(&bmap, 0));
	KUNIT_EXPECT_FALSE(test, is_block_invalid(&bmap, 0));
	KUNIT_EXPECT_FALSE(test, is_block_pre_allocated(&bmap, 0));

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

/*
 * Test cases for block allocation
 */
static void test_block_bmap_allocation(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test allocating a single block */
	len = 1;
	err = ssdfs_block_bmap_allocate(&bmap, 0, &len, &range);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 1, len);
	KUNIT_EXPECT_EQ(test, 0, range.start);
	KUNIT_EXPECT_EQ(test, 1, range.len);

	/* Verify allocation worked */
	KUNIT_EXPECT_TRUE(test, is_block_valid(&bmap, 0));
	KUNIT_EXPECT_EQ(test, 63, ssdfs_block_bmap_get_free_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 1, ssdfs_block_bmap_get_used_pages(&bmap));

	/* Test allocating multiple blocks */
	len = 5;
	err = ssdfs_block_bmap_allocate(&bmap, 1, &len, &range);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 5, len);
	KUNIT_EXPECT_EQ(test, 1, range.start);
	KUNIT_EXPECT_EQ(test, 5, range.len);

	/* Verify multiple allocation */
	KUNIT_EXPECT_EQ(test, 58, ssdfs_block_bmap_get_free_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 6, ssdfs_block_bmap_get_used_pages(&bmap));

	ssdfs_block_bmap_clear_dirty_state(&bmap);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

/*
 * Test cases for block pre-allocation
 */
static void test_block_bmap_pre_allocation(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test pre-allocating blocks */
	len = 3;
	err = ssdfs_block_bmap_pre_allocate(&bmap, 10, &len, &range);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 3, len);
	KUNIT_EXPECT_EQ(test, 10, range.start);
	KUNIT_EXPECT_EQ(test, 3, range.len);

	/* Verify pre-allocation state */
	KUNIT_EXPECT_TRUE(test, is_block_pre_allocated(&bmap, 10));
	KUNIT_EXPECT_TRUE(test, is_block_pre_allocated(&bmap, 11));
	KUNIT_EXPECT_TRUE(test, is_block_pre_allocated(&bmap, 12));
	KUNIT_EXPECT_FALSE(test, is_block_pre_allocated(&bmap, 13));

	ssdfs_block_bmap_clear_dirty_state(&bmap);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

/*
 * Test cases for block invalidation
 */
static void test_block_bmap_invalidation(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* First allocate some blocks */
	len = 4;
	err = ssdfs_block_bmap_allocate(&bmap, 20, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Verify allocation */
	KUNIT_EXPECT_EQ(test, 4, ssdfs_block_bmap_get_used_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_invalid_pages(&bmap));

	/* Now invalidate some blocks */
	range.start = 20;
	range.len = 2;
	err = ssdfs_block_bmap_invalidate(&bmap, &range);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify invalidation */
	KUNIT_EXPECT_TRUE(test, is_block_invalid(&bmap, 20));
	KUNIT_EXPECT_TRUE(test, is_block_invalid(&bmap, 21));
	KUNIT_EXPECT_TRUE(test, is_block_valid(&bmap, 22));
	KUNIT_EXPECT_TRUE(test, is_block_valid(&bmap, 23));

	KUNIT_EXPECT_EQ(test, 2, ssdfs_block_bmap_get_used_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 2, ssdfs_block_bmap_get_invalid_pages(&bmap));

	ssdfs_block_bmap_clear_dirty_state(&bmap);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

/*
 * Test cases for metadata block operations
 */
static void test_block_bmap_metadata_operations(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	u32 freed_items;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test reserving metadata pages */
	err = ssdfs_block_bmap_reserve_metadata_pages(&bmap, 5);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 5, ssdfs_block_bmap_get_metadata_pages(&bmap));

	/* Test freeing metadata pages */
	err = ssdfs_block_bmap_free_metadata_pages(&bmap, 2, &freed_items);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 2, freed_items);
	KUNIT_EXPECT_EQ(test, 3, ssdfs_block_bmap_get_metadata_pages(&bmap));

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

/*
 * Test cases for block state utilities
 */
static void test_block_state_utilities(struct kunit *test)
{
	u8 byte_val;

	/* Test BLK_BMAP_BYTE_CONTAINS_STATE function */
	byte_val = SSDFS_FREE_STATES_BYTE;
	KUNIT_EXPECT_TRUE(test,
			  BLK_BMAP_BYTE_CONTAINS_STATE(&byte_val,
							SSDFS_BLK_FREE));
	KUNIT_EXPECT_FALSE(test,
			   BLK_BMAP_BYTE_CONTAINS_STATE(&byte_val,
							SSDFS_BLK_VALID));

	byte_val = SSDFS_VALID_STATES_BYTE;
	KUNIT_EXPECT_TRUE(test,
			  BLK_BMAP_BYTE_CONTAINS_STATE(&byte_val,
							SSDFS_BLK_VALID));
	KUNIT_EXPECT_FALSE(test,
			   BLK_BMAP_BYTE_CONTAINS_STATE(&byte_val,
							SSDFS_BLK_FREE));

	byte_val = SSDFS_PRE_ALLOC_STATES_BYTE;
	KUNIT_EXPECT_TRUE(test,
			  BLK_BMAP_BYTE_CONTAINS_STATE(&byte_val,
						SSDFS_BLK_PRE_ALLOCATED));
	KUNIT_EXPECT_FALSE(test,
			   BLK_BMAP_BYTE_CONTAINS_STATE(&byte_val,
							SSDFS_BLK_FREE));

	byte_val = SSDFS_INVALID_STATES_BYTE;
	KUNIT_EXPECT_TRUE(test,
			  BLK_BMAP_BYTE_CONTAINS_STATE(&byte_val,
							SSDFS_BLK_INVALID));
	KUNIT_EXPECT_FALSE(test,
			   BLK_BMAP_BYTE_CONTAINS_STATE(&byte_val,
							SSDFS_BLK_FREE));
}

/*
 * Test cases for block bitmap flags
 */
static void test_block_bmap_flags(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test initialization flag */
	KUNIT_EXPECT_TRUE(test, ssdfs_block_bmap_initialized(&bmap));

	/* Test dirty state management */
	KUNIT_EXPECT_FALSE(test, ssdfs_block_bmap_dirtied(&bmap));
	ssdfs_block_bmap_set_dirty_state(&bmap);
	KUNIT_EXPECT_TRUE(test, ssdfs_block_bmap_dirtied(&bmap));
	ssdfs_block_bmap_clear_dirty_state(&bmap);
	KUNIT_EXPECT_FALSE(test, ssdfs_block_bmap_dirtied(&bmap));

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

/*
 * Test cases for garbage collection
 */
static void test_block_bmap_collect_garbage_valid_blocks(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range, collected_range;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* First allocate some blocks to create valid blocks */
	len = 8;
	err = ssdfs_block_bmap_allocate(&bmap, 10, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 8, len);

	/* Also allocate some non-contiguous blocks */
	len = 4;
	err = ssdfs_block_bmap_allocate(&bmap, 20, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test collecting valid blocks */
	err = ssdfs_block_bmap_collect_garbage(&bmap, 10, 15,
					       SSDFS_BLK_VALID,
					       &collected_range);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Should find the first range of valid blocks */
	KUNIT_EXPECT_EQ(test, 10, collected_range.start);
	KUNIT_EXPECT_LE(test, collected_range.len, 15);
	KUNIT_EXPECT_GT(test, collected_range.len, 0);

	ssdfs_block_bmap_clear_dirty_state(&bmap);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_collect_garbage_pre_allocated_blocks(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range, collected_range;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Pre-allocate some blocks */
	len = 6;
	err = ssdfs_block_bmap_pre_allocate(&bmap, 15, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test collecting pre-allocated blocks */
	err = ssdfs_block_bmap_collect_garbage(&bmap, 10, 20,
					       SSDFS_BLK_PRE_ALLOCATED,
					       &collected_range);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Should find the pre-allocated blocks */
	KUNIT_EXPECT_EQ(test, 15, collected_range.start);
	KUNIT_EXPECT_EQ(test, 6, collected_range.len);

	ssdfs_block_bmap_clear_dirty_state(&bmap);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_collect_garbage_no_blocks_found(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range collected_range;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Try to collect valid blocks when all blocks are free */
	err = ssdfs_block_bmap_collect_garbage(&bmap, 0, 64,
					       SSDFS_BLK_VALID,
					       &collected_range);
	KUNIT_EXPECT_EQ(test, -ENODATA, err);

	/* Try to collect pre-allocated blocks when none exist */
	err = ssdfs_block_bmap_collect_garbage(&bmap, 0, 64,
					       SSDFS_BLK_PRE_ALLOCATED,
					       &collected_range);
	KUNIT_EXPECT_EQ(test, -ENODATA, err);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_collect_garbage_invalid_params(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range collected_range;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test with NULL bitmap */
	err = ssdfs_block_bmap_collect_garbage(NULL, 0, 10,
					       SSDFS_BLK_VALID,
					       &collected_range);
	KUNIT_EXPECT_NE(test, 0, err);

	/* Test with NULL range */
	err = ssdfs_block_bmap_collect_garbage(&bmap, 0, 10,
					       SSDFS_BLK_VALID,
					       NULL);
	KUNIT_EXPECT_NE(test, 0, err);

	/* Test with invalid block state */
	err = ssdfs_block_bmap_collect_garbage(&bmap, 0, 10,
					       SSDFS_BLK_INVALID,
					       &collected_range);
	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	/* Test with invalid block state (free) */
	err = ssdfs_block_bmap_collect_garbage(&bmap, 0, 10,
					       SSDFS_BLK_FREE,
					       &collected_range);
	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	/* Test with start beyond capacity */
	err = ssdfs_block_bmap_collect_garbage(&bmap, 70, 10,
					       SSDFS_BLK_VALID,
					       &collected_range);
	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_collect_garbage_boundary_conditions(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range, collected_range;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Allocate blocks at the end of the bitmap */
	len = 4;
	err = ssdfs_block_bmap_allocate(&bmap, 60, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test collecting from near the end */
	err = ssdfs_block_bmap_collect_garbage(&bmap, 60, 10,
					       SSDFS_BLK_VALID,
					       &collected_range);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 60, collected_range.start);
	KUNIT_EXPECT_EQ(test, 4, collected_range.len);

	/* Test with max_len larger than remaining capacity */
	err = ssdfs_block_bmap_collect_garbage(&bmap, 60, 100,
					       SSDFS_BLK_VALID,
					       &collected_range);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 60, collected_range.start);
	KUNIT_EXPECT_LE(test, collected_range.len, 4);

	ssdfs_block_bmap_clear_dirty_state(&bmap);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

/*
 * Test cases for block bitmap cleaning
 */
static void test_block_bmap_clean_same_capacity(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* First dirty the bitmap with some allocations */
	len = 5;
	err = ssdfs_block_bmap_allocate(&bmap, 10, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	len = 3;
	err = ssdfs_block_bmap_pre_allocate(&bmap, 20, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Add some metadata blocks */
	err = ssdfs_block_bmap_reserve_metadata_pages(&bmap, 7);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Verify bitmap is dirty */
	KUNIT_EXPECT_EQ(test, 8, ssdfs_block_bmap_get_used_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 7, ssdfs_block_bmap_get_metadata_pages(&bmap));
	KUNIT_EXPECT_LT(test, ssdfs_block_bmap_get_free_pages(&bmap), 64);

	/* Clean the bitmap with same capacity */
	err = ssdfs_block_bmap_clean(&bmap, 64);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify all blocks are now free */
	KUNIT_EXPECT_EQ(test, 64, ssdfs_block_bmap_get_free_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_used_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_invalid_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_metadata_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 64, ssdfs_block_bmap_get_allocation_pool(&bmap));

	/* Verify all blocks are actually free */
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 0));
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 10));
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 20));
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 63));

	ssdfs_block_bmap_clear_dirty_state(&bmap);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_clean_expanded_capacity(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 32, 32,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Allocate some blocks */
	len = 5;
	err = ssdfs_block_bmap_allocate(&bmap, 5, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Verify initial state */
	KUNIT_EXPECT_EQ(test, 32, ssdfs_block_bmap_get_pages_capacity(&bmap));
	KUNIT_EXPECT_EQ(test, 27, ssdfs_block_bmap_get_free_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 5, ssdfs_block_bmap_get_used_pages(&bmap));

	/* Clean with expanded capacity */
	err = ssdfs_block_bmap_clean(&bmap, 128);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify new capacity and all blocks are free */
	KUNIT_EXPECT_EQ(test, 128, ssdfs_block_bmap_get_pages_capacity(&bmap));
	KUNIT_EXPECT_EQ(test, 128, ssdfs_block_bmap_get_allocation_pool(&bmap));
	KUNIT_EXPECT_EQ(test, 128, ssdfs_block_bmap_get_free_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_used_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_invalid_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_metadata_pages(&bmap));

	/* Verify blocks in the expanded range are free */
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 0));
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 31));
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 64));
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 127));

	ssdfs_block_bmap_clear_dirty_state(&bmap);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_clean_invalid_params(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test with NULL bitmap */
	err = ssdfs_block_bmap_clean(NULL, 64);
	KUNIT_EXPECT_NE(test, 0, err);

	/* Test with shrinking capacity (should fail) */
	err = ssdfs_block_bmap_clean(&bmap, 32);
	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	/* Verify bitmap state hasn't changed */
	KUNIT_EXPECT_EQ(test, 64, ssdfs_block_bmap_get_pages_capacity(&bmap));

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_clean_with_invalid_blocks(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Allocate some blocks and then invalidate them */
	len = 8;
	err = ssdfs_block_bmap_allocate(&bmap, 10, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Invalidate some of the allocated blocks */
	range.start = 12;
	range.len = 4;
	err = ssdfs_block_bmap_invalidate(&bmap, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Verify we have both valid and invalid blocks */
	KUNIT_EXPECT_EQ(test, 4, ssdfs_block_bmap_get_used_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 4, ssdfs_block_bmap_get_invalid_pages(&bmap));

	/* Clean the bitmap */
	err = ssdfs_block_bmap_clean(&bmap, 64);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify all blocks are now free, including previously invalid ones */
	KUNIT_EXPECT_EQ(test, 64, ssdfs_block_bmap_get_free_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_used_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_invalid_pages(&bmap));

	/* Verify specific blocks that were invalid are now free */
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 12));
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 13));
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 14));
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 15));

	ssdfs_block_bmap_clear_dirty_state(&bmap);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_clean_reset_search_cache(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Do some operations that will populate search cache */
	len = 5;
	err = ssdfs_block_bmap_allocate(&bmap, 20, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	len = 3;
	err = ssdfs_block_bmap_pre_allocate(&bmap, 30, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Clean the bitmap */
	err = ssdfs_block_bmap_clean(&bmap, 64);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* After cleaning, we should be able to allocate from the beginning */
	len = 10;
	err = ssdfs_block_bmap_allocate(&bmap, 0, &len, &range);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 0, range.start);
	KUNIT_EXPECT_EQ(test, 10, range.len);

	ssdfs_block_bmap_clear_dirty_state(&bmap);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

/*
 * Test cases for invalid to clean conversion
 */
static void test_block_bmap_invalid2clean_single_range(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 len;
	int invalid_pages;
	int i, j;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* First allocate some blocks */
	len = 8;
	err = ssdfs_block_bmap_allocate(&bmap, 10, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Invalidate some of the allocated blocks */
	range.start = 12;
	range.len = 4;
	err = ssdfs_block_bmap_invalidate(&bmap, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Verify we have invalid blocks */
	KUNIT_EXPECT_EQ(test, 4, ssdfs_block_bmap_get_invalid_pages(&bmap));
	KUNIT_EXPECT_TRUE(test, is_block_invalid(&bmap, 12));
	KUNIT_EXPECT_TRUE(test, is_block_invalid(&bmap, 13));
	KUNIT_EXPECT_TRUE(test, is_block_invalid(&bmap, 14));
	KUNIT_EXPECT_TRUE(test, is_block_invalid(&bmap, 15));

	/* Convert invalid block to clean */
	invalid_pages = ssdfs_block_bmap_get_invalid_pages(&bmap);

	for (i = 0; i < invalid_pages; i++) {
		err = ssdfs_block_bmap_invalid2clean(&bmap);
		KUNIT_EXPECT_EQ(test, 0, err);

		/* Verify block is now free */
		KUNIT_EXPECT_LT(test,
				ssdfs_block_bmap_get_invalid_pages(&bmap),
				invalid_pages);

		for (j = 0; j < (i + 1); j++)
			KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 12 + j));

		for (j = i + 1; j < invalid_pages; j++)
			KUNIT_EXPECT_TRUE(test, is_block_invalid(&bmap, 12 + j));

		invalid_pages = ssdfs_block_bmap_get_invalid_pages(&bmap);
	}

	/* Other blocks should remain in their original state */
	KUNIT_EXPECT_TRUE(test, is_block_valid(&bmap, 10));
	KUNIT_EXPECT_TRUE(test, is_block_valid(&bmap, 11));
	KUNIT_EXPECT_TRUE(test, is_block_valid(&bmap, 16));
	KUNIT_EXPECT_TRUE(test, is_block_valid(&bmap, 17));

	/* Verify bitmap is marked as dirty */
	KUNIT_EXPECT_TRUE(test, ssdfs_block_bmap_dirtied(&bmap));

	ssdfs_block_bmap_clear_dirty_state(&bmap);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_invalid2clean_multiple_ranges(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 len;
	int err;
	int initial_invalid, remaining_invalid;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Allocate multiple ranges and invalidate them */
	len = 3;
	err = ssdfs_block_bmap_allocate(&bmap, 5, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	len = 4;
	err = ssdfs_block_bmap_allocate(&bmap, 15, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	len = 2;
	err = ssdfs_block_bmap_allocate(&bmap, 25, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Invalidate the first range */
	range.start = 5;
	range.len = 3;
	err = ssdfs_block_bmap_invalidate(&bmap, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Invalidate part of the second range */
	range.start = 16;
	range.len = 2;
	err = ssdfs_block_bmap_invalidate(&bmap, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	initial_invalid = ssdfs_block_bmap_get_invalid_pages(&bmap);
	KUNIT_EXPECT_EQ(test, 5, initial_invalid);

	/* Convert invalid blocks to clean (should convert first range found) */
	err = ssdfs_block_bmap_invalid2clean(&bmap);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Should have reduced invalid count */
	remaining_invalid = ssdfs_block_bmap_get_invalid_pages(&bmap);
	KUNIT_EXPECT_LT(test, remaining_invalid, initial_invalid);
	KUNIT_EXPECT_GE(test, remaining_invalid, 0);

	ssdfs_block_bmap_clear_dirty_state(&bmap);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_invalid2clean_no_invalid_blocks(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Allocate some blocks but don't invalidate any */
	len = 5;
	err = ssdfs_block_bmap_allocate(&bmap, 10, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Verify no invalid blocks exist */
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_invalid_pages(&bmap));

	/* Try to convert invalid blocks when none exist */
	err = ssdfs_block_bmap_invalid2clean(&bmap);
	KUNIT_EXPECT_EQ(test, -ENODATA, err);

	/* Verify state hasn't changed */
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_invalid_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 5, ssdfs_block_bmap_get_used_pages(&bmap));

	ssdfs_block_bmap_clear_dirty_state(&bmap);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_invalid2clean_empty_bitmap(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Try to convert invalid blocks on empty bitmap */
	err = ssdfs_block_bmap_invalid2clean(&bmap);
	KUNIT_EXPECT_EQ(test, -ENODATA, err);

	/* Verify state remains clean */
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_invalid_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_used_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 64, ssdfs_block_bmap_get_free_pages(&bmap));

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_invalid2clean_invalid_params(struct kunit *test)
{
	int err;

	/* Test with NULL bitmap */
	err = ssdfs_block_bmap_invalid2clean(NULL);
	KUNIT_EXPECT_NE(test, 0, err);
}

static void test_block_bmap_invalid2clean_full_conversion(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 len;
	int invalid_count;
	int i;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 32, 32,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Allocate and invalidate a large contiguous range */
	len = 16;
	err = ssdfs_block_bmap_allocate(&bmap, 8, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Invalidate all allocated blocks */
	range.start = 8;
	range.len = 16;
	err = ssdfs_block_bmap_invalidate(&bmap, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	invalid_count = ssdfs_block_bmap_get_invalid_pages(&bmap);
	KUNIT_EXPECT_EQ(test, 16, invalid_count);

	/* Convert all invalid blocks to clean */
	for (i = 0; i < invalid_count; i++) {
		err = ssdfs_block_bmap_invalid2clean(&bmap);
		KUNIT_EXPECT_EQ(test, 0, err);
	}

	/* All invalid blocks should now be free */
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_invalid_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_used_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 32, ssdfs_block_bmap_get_free_pages(&bmap));

	/* Verify all blocks in the range are free */
	for (int i = 8; i < 24; i++) {
		KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, i));
	}

	ssdfs_block_bmap_clear_dirty_state(&bmap);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_invalid2clean_partial_range(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 len;
	int i;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Create a mixed state: some valid, some invalid blocks */
	len = 10;
	err = ssdfs_block_bmap_allocate(&bmap, 20, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Invalidate only middle portion */
	range.start = 23;
	range.len = 4;
	err = ssdfs_block_bmap_invalidate(&bmap, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Initial state verification */
	KUNIT_EXPECT_EQ(test, 6, ssdfs_block_bmap_get_used_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 4, ssdfs_block_bmap_get_invalid_pages(&bmap));

	/* Convert invalid blocks */
	for (i = 0; i < range.len; i++) {
		err = ssdfs_block_bmap_invalid2clean(&bmap);
		KUNIT_EXPECT_EQ(test, 0, err);
	}

	/* Verify partial conversion */
	KUNIT_EXPECT_EQ(test, 6, ssdfs_block_bmap_get_used_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_invalid_pages(&bmap));

	/* Check individual block states */
	KUNIT_EXPECT_TRUE(test, is_block_valid(&bmap, 20));  /* Still valid */
	KUNIT_EXPECT_TRUE(test, is_block_valid(&bmap, 21));  /* Still valid */
	KUNIT_EXPECT_TRUE(test, is_block_valid(&bmap, 22));  /* Still valid */
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 23));   /* Converted to free */
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 24));   /* Converted to free */
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 25));   /* Converted to free */
	KUNIT_EXPECT_TRUE(test, is_block_free(&bmap, 26));   /* Converted to free */
	KUNIT_EXPECT_TRUE(test, is_block_valid(&bmap, 27));  /* Still valid */
	KUNIT_EXPECT_TRUE(test, is_block_valid(&bmap, 28));  /* Still valid */
	KUNIT_EXPECT_TRUE(test, is_block_valid(&bmap, 29));  /* Still valid */

	ssdfs_block_bmap_clear_dirty_state(&bmap);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

/*
 * Test cases for block bitmap snapshot operations
 */
static void test_block_bmap_snapshot_basic(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_folio_vector snapshot;
	struct ssdfs_block_bmap_range range;
	u32 last_free_page, metadata_blks, invalid_blks;
	size_t items_capacity, bytes_count;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Initialize snapshot vector */
	err = ssdfs_folio_vector_create(&snapshot, 0, 0);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Add some operations to make the bitmap interesting */
	len = 5;
	err = ssdfs_block_bmap_allocate(&bmap, 10, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_block_bmap_reserve_metadata_pages(&bmap, 3);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Make bitmap dirty first */
	ssdfs_block_bmap_set_dirty_state(&bmap);

	/* Take snapshot */
	err = ssdfs_block_bmap_snapshot(&bmap, &snapshot,
					&last_free_page, &metadata_blks,
					&invalid_blks, &items_capacity,
					&bytes_count);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify snapshot metadata */
	KUNIT_EXPECT_EQ(test, 64, items_capacity);
	KUNIT_EXPECT_EQ(test, 3, metadata_blks);
	KUNIT_EXPECT_EQ(test, 0, invalid_blks);
	KUNIT_EXPECT_LE(test, last_free_page, items_capacity);

	/* Verify bitmap is no longer dirty after snapshot */
	KUNIT_EXPECT_FALSE(test, ssdfs_block_bmap_dirtied(&bmap));

	/* Verify snapshot has content */
	KUNIT_EXPECT_GT(test, ssdfs_folio_vector_count(&snapshot), 0);

	/* Clean up snapshot */
	ssdfs_block_bmap_forget_snapshot(&snapshot);
	ssdfs_block_bmap_clear_dirty_state(&bmap);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_snapshot_with_invalid_blocks(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_folio_vector snapshot;
	struct ssdfs_block_bmap_range range;
	u32 last_free_page, metadata_blks, invalid_blks;
	size_t items_capacity, bytes_count;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_create(&snapshot, 0, 0);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Create a complex state with valid and invalid blocks */
	len = 8;
	err = ssdfs_block_bmap_allocate(&bmap, 15, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Invalidate some blocks */
	range.start = 17;
	range.len = 3;
	err = ssdfs_block_bmap_invalidate(&bmap, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_block_bmap_reserve_metadata_pages(&bmap, 2);
	KUNIT_ASSERT_EQ(test, 0, err);

	ssdfs_block_bmap_set_dirty_state(&bmap);

	/* Take snapshot */
	err = ssdfs_block_bmap_snapshot(&bmap, &snapshot,
					&last_free_page, &metadata_blks,
					&invalid_blks, &items_capacity,
					&bytes_count);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify snapshot captures invalid blocks */
	KUNIT_EXPECT_EQ(test, 3, invalid_blks);
	KUNIT_EXPECT_EQ(test, 2, metadata_blks);
	KUNIT_EXPECT_EQ(test, 64, items_capacity);

	/* Clean up */
	ssdfs_block_bmap_forget_snapshot(&snapshot);
	ssdfs_block_bmap_clear_dirty_state(&bmap);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_snapshot_empty_bitmap(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_folio_vector snapshot;
	u32 last_free_page, metadata_blks, invalid_blks;
	size_t items_capacity, bytes_count;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 32, 32,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_create(&snapshot, 0, 0);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Take snapshot of empty bitmap */
	err = ssdfs_block_bmap_snapshot(&bmap, &snapshot,
					&last_free_page, &metadata_blks,
					&invalid_blks, &items_capacity,
					&bytes_count);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify empty state */
	KUNIT_EXPECT_EQ(test, 0, metadata_blks);
	KUNIT_EXPECT_EQ(test, 0, invalid_blks);
	KUNIT_EXPECT_EQ(test, 32, items_capacity);
	KUNIT_EXPECT_LE(test, last_free_page, items_capacity);

	/* Clean up */
	ssdfs_block_bmap_forget_snapshot(&snapshot);
	ssdfs_block_bmap_clear_dirty_state(&bmap);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_snapshot_invalid_params(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_folio_vector snapshot;
	u32 last_free_page, metadata_blks, invalid_blks;
	size_t items_capacity, bytes_count;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_create(&snapshot, 0, 0);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test with NULL bitmap */
	err = ssdfs_block_bmap_snapshot(NULL, &snapshot,
					&last_free_page, &metadata_blks,
					&invalid_blks, &items_capacity,
					&bytes_count);
	KUNIT_EXPECT_NE(test, 0, err);

	/* Test with NULL snapshot */
	err = ssdfs_block_bmap_snapshot(&bmap, NULL,
					&last_free_page, &metadata_blks,
					&invalid_blks, &items_capacity,
					&bytes_count);
	KUNIT_EXPECT_NE(test, 0, err);

	/* Test with NULL output parameters */
	err = ssdfs_block_bmap_snapshot(&bmap, &snapshot,
					NULL, &metadata_blks,
					&invalid_blks, &items_capacity,
					&bytes_count);
	KUNIT_EXPECT_NE(test, 0, err);

	err = ssdfs_block_bmap_snapshot(&bmap, &snapshot,
					&last_free_page, NULL,
					&invalid_blks, &items_capacity,
					&bytes_count);
	KUNIT_EXPECT_NE(test, 0, err);

	err = ssdfs_block_bmap_snapshot(&bmap, &snapshot,
					&last_free_page, &metadata_blks,
					&invalid_blks, NULL,
					&bytes_count);
	KUNIT_EXPECT_NE(test, 0, err);

	err = ssdfs_block_bmap_snapshot(&bmap, &snapshot,
					&last_free_page, &metadata_blks,
					&invalid_blks, &items_capacity,
					NULL);
	KUNIT_EXPECT_NE(test, 0, err);

	/* Clean up */
	ssdfs_folio_vector_destroy(&snapshot);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_forget_snapshot_basic(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_folio_vector snapshot;
	struct ssdfs_block_bmap_range range;
	u32 last_free_page, metadata_blks, invalid_blks;
	size_t items_capacity, bytes_count;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_create(&snapshot, 0, 0);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Add some content to bitmap */
	len = 4;
	err = ssdfs_block_bmap_allocate(&bmap, 5, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Take snapshot */
	err = ssdfs_block_bmap_snapshot(&bmap, &snapshot,
					&last_free_page, &metadata_blks,
					&invalid_blks, &items_capacity,
					&bytes_count);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Verify snapshot has content */
	KUNIT_EXPECT_GT(test, ssdfs_folio_vector_count(&snapshot), 0);

	/* Forget snapshot - should clean up resources */
	ssdfs_block_bmap_forget_snapshot(&snapshot);

	/* After forget, snapshot should be empty */
	KUNIT_EXPECT_EQ(test, 0, ssdfs_folio_vector_count(&snapshot));

	ssdfs_block_bmap_clear_dirty_state(&bmap);

	ssdfs_folio_vector_destroy(&snapshot);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_forget_snapshot_null_param(struct kunit *test)
{
	/* Test with NULL snapshot - should not crash */
	ssdfs_block_bmap_forget_snapshot(NULL);
	/* If we reach here, the test passed */
	KUNIT_EXPECT_TRUE(test, true);
}

static void test_block_bmap_snapshot_multiple_cycles(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_folio_vector snapshot1, snapshot2;
	struct ssdfs_block_bmap_range range;
	u32 last_free_page, metadata_blks, invalid_blks;
	size_t items_capacity, bytes_count;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_create(&snapshot1, 0, 0);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_create(&snapshot2, 0, 0);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* First state - allocate some blocks */
	len = 3;
	err = ssdfs_block_bmap_allocate(&bmap, 10, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	ssdfs_block_bmap_set_dirty_state(&bmap);

	/* Take first snapshot */
	err = ssdfs_block_bmap_snapshot(&bmap, &snapshot1,
					&last_free_page, &metadata_blks,
					&invalid_blks, &items_capacity,
					&bytes_count);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Modify bitmap further */
	len = 2;
	err = ssdfs_block_bmap_allocate(&bmap, 20, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	ssdfs_block_bmap_set_dirty_state(&bmap);

	/* Take second snapshot */
	err = ssdfs_block_bmap_snapshot(&bmap, &snapshot2,
					&last_free_page, &metadata_blks,
					&invalid_blks, &items_capacity,
					&bytes_count);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Both snapshots should be valid */
	KUNIT_EXPECT_GT(test, ssdfs_folio_vector_count(&snapshot1), 0);
	KUNIT_EXPECT_GT(test, ssdfs_folio_vector_count(&snapshot2), 0);

	/* Clean up snapshots */
	ssdfs_block_bmap_forget_snapshot(&snapshot1);
	ssdfs_block_bmap_forget_snapshot(&snapshot2);

	ssdfs_folio_vector_destroy(&snapshot1);
	ssdfs_folio_vector_destroy(&snapshot2);
	ssdfs_block_bmap_clear_dirty_state(&bmap);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_snapshot_consistency_check(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_folio_vector snapshot;
	struct ssdfs_block_bmap_range range;
	u32 last_free_page, metadata_blks, invalid_blks;
	size_t items_capacity, bytes_count;
	u32 len;
	int err;
	int original_used, original_invalid, original_metadata;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_create(&snapshot, 0, 0);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Create a complex bitmap state */
	len = 6;
	err = ssdfs_block_bmap_allocate(&bmap, 8, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	range.start = 10;
	range.len = 2;
	err = ssdfs_block_bmap_invalidate(&bmap, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_block_bmap_reserve_metadata_pages(&bmap, 4);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Record original state */
	original_used = ssdfs_block_bmap_get_used_pages(&bmap);
	original_invalid = ssdfs_block_bmap_get_invalid_pages(&bmap);
	original_metadata = ssdfs_block_bmap_get_metadata_pages(&bmap);

	ssdfs_block_bmap_set_dirty_state(&bmap);

	/* Take snapshot */
	err = ssdfs_block_bmap_snapshot(&bmap, &snapshot,
					&last_free_page, &metadata_blks,
					&invalid_blks, &items_capacity,
					&bytes_count);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify snapshot data matches bitmap state */
	KUNIT_EXPECT_EQ(test, original_metadata, metadata_blks);
	KUNIT_EXPECT_EQ(test, original_invalid, invalid_blks);

	/* Clean up */
	ssdfs_block_bmap_forget_snapshot(&snapshot);
	ssdfs_folio_vector_destroy(&snapshot);
	ssdfs_block_bmap_clear_dirty_state(&bmap);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

/*
 * Test cases for block bitmap initialization
 */
static void test_block_bmap_init_basic(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_folio_vector source;
	u8 flags = 0;
	u32 last_free_blk = 32;
	u32 metadata_blks = 5;
	u32 invalid_blks = 3;
	u32 bmap_bytes = 64; /* arbitrary size for test */
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	/* Create bitmap first (with INIT flag to avoid full initialization) */
	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_INIT,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Create source folio vector with some content */
	err = ssdfs_folio_vector_create(&source, 0, 2);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Add at least one folio to make it non-empty */
	err = ssdfs_folio_vector_add(&source, test_alloc_folio(0));
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Now initialize the bitmap */
	err = ssdfs_block_bmap_init(&bmap, &source, flags,
				    last_free_blk, metadata_blks,
				    invalid_blks, bmap_bytes);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify initialization succeeded */
	KUNIT_EXPECT_TRUE(test, ssdfs_block_bmap_initialized(&bmap));
	KUNIT_EXPECT_EQ(test, metadata_blks, ssdfs_block_bmap_get_metadata_pages(&bmap));
	KUNIT_EXPECT_EQ(test, invalid_blks, ssdfs_block_bmap_get_invalid_pages(&bmap));

	/* Clean up */
	ssdfs_folio_vector_release(&source);
	ssdfs_folio_vector_destroy(&source);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_init_inflated_flag(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_folio_vector source;
	u8 flags = SSDFS_INFLATED_BLK_BMAP;
	u32 last_free_blk = 128;  /* Larger than initial capacity */
	u32 metadata_blks = 10;
	u32 invalid_blks = 5;
	u32 bmap_bytes = 128;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	/* Create bitmap with smaller initial capacity */
	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_INIT,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_create(&source, 0, 2);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_add(&source, test_alloc_folio(0));
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Initialize with inflated flag */
	err = ssdfs_block_bmap_init(&bmap, &source, flags,
				    last_free_blk, metadata_blks,
				    invalid_blks, bmap_bytes);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify capacity was expanded */
	KUNIT_EXPECT_GE(test, ssdfs_block_bmap_get_pages_capacity(&bmap), last_free_blk);
	KUNIT_EXPECT_TRUE(test, ssdfs_block_bmap_initialized(&bmap));

	/* Clean up */
	ssdfs_folio_vector_release(&source);
	ssdfs_folio_vector_destroy(&source);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_init_invalid_params(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_folio_vector source, empty_source;
	u8 flags = 0;
	u32 last_free_blk = 32;
	u32 metadata_blks = 5;
	u32 invalid_blks = 3;
	u32 bmap_bytes = 64;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_INIT,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_create(&source, 0, 2);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_add(&source, test_alloc_folio(0));
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_create(&empty_source, 0, 0);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test with NULL bitmap */
	err = ssdfs_block_bmap_init(NULL, &source, flags,
				    last_free_blk, metadata_blks,
				    invalid_blks, bmap_bytes);
	KUNIT_EXPECT_NE(test, 0, err);

	/* Test with NULL source */
	err = ssdfs_block_bmap_init(&bmap, NULL, flags,
				    last_free_blk, metadata_blks,
				    invalid_blks, bmap_bytes);
	KUNIT_EXPECT_NE(test, 0, err);

	/* Test with empty source folio vector */
	err = ssdfs_block_bmap_init(&bmap, &empty_source, flags,
				    last_free_blk, metadata_blks,
				    invalid_blks, bmap_bytes);
	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	/* Test with last_free_blk beyond capacity */
	err = ssdfs_block_bmap_init(&bmap, &source, flags,
				    1000, metadata_blks,
				    invalid_blks, bmap_bytes);
	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	/* Test with metadata_blks beyond allocation pool */
	err = ssdfs_block_bmap_init(&bmap, &source, flags,
				    last_free_blk, 1000,
				    invalid_blks, bmap_bytes);
	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	/* Test with invalid_blks beyond allocation pool */
	err = ssdfs_block_bmap_init(&bmap, &source, flags,
				    last_free_blk, metadata_blks,
				    1000, bmap_bytes);
	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	/* Clean up */
	ssdfs_folio_vector_release(&source);
	ssdfs_folio_vector_destroy(&source);
	ssdfs_folio_vector_destroy(&empty_source);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_init_already_initialized(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_folio_vector source;
	u8 flags = 0;
	u32 last_free_blk = 32;
	u32 metadata_blks = 5;
	u32 invalid_blks = 3;
	u32 bmap_bytes = 64;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	/* Create and fully initialize bitmap first */
	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_create(&source, 0, 2);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_add(&source, test_alloc_folio(0));
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Bitmap should already be initialized and clean */
	KUNIT_EXPECT_TRUE(test, ssdfs_block_bmap_initialized(&bmap));
	KUNIT_EXPECT_FALSE(test, ssdfs_block_bmap_dirtied(&bmap));

	/* Try to initialize again - should succeed for clean initialized bitmap */
	err = ssdfs_block_bmap_init(&bmap, &source, flags,
				    last_free_blk, metadata_blks,
				    invalid_blks, bmap_bytes);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Now make it dirty and try again */
	ssdfs_block_bmap_set_dirty_state(&bmap);
	KUNIT_EXPECT_TRUE(test, ssdfs_block_bmap_dirtied(&bmap));

	err = ssdfs_block_bmap_init(&bmap, &source, flags,
				    last_free_blk, metadata_blks,
				    invalid_blks, bmap_bytes);
	KUNIT_EXPECT_EQ(test, -ERANGE, err);

	/* Clean up */
	ssdfs_folio_vector_release(&source);
	ssdfs_folio_vector_destroy(&source);
	ssdfs_block_bmap_clear_dirty_state(&bmap);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_init_boundary_values(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_folio_vector source;
	u8 flags = 0;
	u32 capacity = 64;
	u32 last_free_blk;
	u32 metadata_blks;
	u32 invalid_blks = 0;
	u32 bmap_bytes = 64;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, capacity, capacity,
				      SSDFS_BLK_BMAP_INIT,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_create(&source, 0, 2);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_add(&source, test_alloc_folio(0));
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test with maximum valid values */
	last_free_blk = capacity; /* At capacity */
	metadata_blks = last_free_blk; /* Max metadata */

	err = ssdfs_block_bmap_init(&bmap, &source, flags,
				    last_free_blk, metadata_blks,
				    invalid_blks, bmap_bytes);
	KUNIT_EXPECT_EQ(test, 0, err);

	KUNIT_EXPECT_TRUE(test, ssdfs_block_bmap_initialized(&bmap));
	KUNIT_EXPECT_EQ(test, metadata_blks,
			ssdfs_block_bmap_get_metadata_pages(&bmap));

	/* Clean up */
	ssdfs_folio_vector_release(&source);
	ssdfs_folio_vector_destroy(&source);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_init_zero_values(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_folio_vector source;
	u8 flags = 0;
	u32 last_free_blk = 0;
	u32 metadata_blks = 0;
	u32 invalid_blks = 0;
	u32 bmap_bytes = 64;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_INIT,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_create(&source, 0, 2);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_add(&source, test_alloc_folio(0));
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test with all zero values */
	err = ssdfs_block_bmap_init(&bmap, &source, flags,
				    last_free_blk, metadata_blks,
				    invalid_blks, bmap_bytes);
	KUNIT_EXPECT_EQ(test, 0, err);

	KUNIT_EXPECT_TRUE(test, ssdfs_block_bmap_initialized(&bmap));
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_metadata_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 0, ssdfs_block_bmap_get_invalid_pages(&bmap));

	/* Clean up */
	ssdfs_folio_vector_release(&source);
	ssdfs_folio_vector_destroy(&source);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_init_state_consistency(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_folio_vector source;
	u8 flags = 0;
	u32 last_free_blk = 20;
	u32 metadata_blks = 8;
	u32 invalid_blks = 4;
	u32 bmap_bytes = 64;
	int err;
	int used_pages_before, used_pages_after;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_INIT,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_create(&source, 0, 2);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_vector_add(&source, test_alloc_folio(0));
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Record state before initialization */
	used_pages_before = ssdfs_block_bmap_get_used_pages(&bmap);

	/* Initialize bitmap */
	err = ssdfs_block_bmap_init(&bmap, &source, flags,
				    last_free_blk, metadata_blks,
				    invalid_blks, bmap_bytes);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify state after initialization */
	used_pages_after = ssdfs_block_bmap_get_used_pages(&bmap);

	KUNIT_EXPECT_TRUE(test, ssdfs_block_bmap_initialized(&bmap));
	KUNIT_EXPECT_EQ(test, metadata_blks, ssdfs_block_bmap_get_metadata_pages(&bmap));
	KUNIT_EXPECT_EQ(test, invalid_blks, ssdfs_block_bmap_get_invalid_pages(&bmap));

	/* Used blocks should be calculated based on actual bitmap content */
	KUNIT_EXPECT_GE(test, used_pages_after, 0);

	/* Clean up */
	ssdfs_folio_vector_release(&source);
	ssdfs_folio_vector_destroy(&source);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

/*
 * Test cases for block bitmap inflation
 */
static void test_block_bmap_inflate_basic(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 used_blocks = 47;
	u32 metadata_blocks = 3;
	u32 free_items = 32;
	u32 len;
	int original_capacity, new_capacity;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Add some used blocks first */
	len = used_blocks;
	err = ssdfs_block_bmap_allocate(&bmap, 5, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_block_bmap_reserve_metadata_pages(&bmap, metadata_blocks);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Record original capacity */
	original_capacity = ssdfs_block_bmap_get_pages_capacity(&bmap);

	/* Inflate bitmap */
	err = ssdfs_block_bmap_inflate(&bmap, free_items);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify capacity increased */
	new_capacity = ssdfs_block_bmap_get_pages_capacity(&bmap);
	KUNIT_EXPECT_GT(test, new_capacity, original_capacity);

	/* Verify allocation pool increased */
	KUNIT_EXPECT_EQ(test, new_capacity,
			ssdfs_block_bmap_get_allocation_pool(&bmap));

	/* Verify used and metadata blocks remain the same */
	KUNIT_EXPECT_EQ(test,
			used_blocks, ssdfs_block_bmap_get_used_pages(&bmap));
	KUNIT_EXPECT_EQ(test, metadata_blocks,
			ssdfs_block_bmap_get_metadata_pages(&bmap));

	ssdfs_block_bmap_clear_dirty_state(&bmap);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_inflate_with_invalid_blocks(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 free_items = 50;
	u32 len;
	int original_capacity, new_capacity;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Create a complex state with used, invalid, and metadata blocks */
	len = 8;
	err = ssdfs_block_bmap_allocate(&bmap, 10, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Invalidate some blocks */
	range.start = 12;
	range.len = 4;
	err = ssdfs_block_bmap_invalidate(&bmap, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_block_bmap_reserve_metadata_pages(&bmap, 6);
	KUNIT_ASSERT_EQ(test, 0, err);

	original_capacity = ssdfs_block_bmap_get_pages_capacity(&bmap);

	/* Inflate bitmap */
	err = ssdfs_block_bmap_inflate(&bmap, free_items);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify capacity is the same */
	new_capacity = ssdfs_block_bmap_get_pages_capacity(&bmap);
	KUNIT_EXPECT_EQ(test, new_capacity, original_capacity);

	/* Verify all block counts remain accurate */
	KUNIT_EXPECT_EQ(test, 4, ssdfs_block_bmap_get_used_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 4, ssdfs_block_bmap_get_invalid_pages(&bmap));
	KUNIT_EXPECT_EQ(test, 6, ssdfs_block_bmap_get_metadata_pages(&bmap));

	ssdfs_block_bmap_clear_dirty_state(&bmap);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_inflate_zero_free_items(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	u32 free_items = 0;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Try to inflate with zero free items */
	err = ssdfs_block_bmap_inflate(&bmap, free_items);
	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_inflate_invalid_params(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	u32 free_items = 25;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test with NULL bitmap */
	err = ssdfs_block_bmap_inflate(NULL, free_items);
	KUNIT_EXPECT_NE(test, 0, err);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_inflate_uninitialized_bitmap(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	u32 free_items = 30;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	/* Create bitmap but don't fully initialize it */
	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_INIT,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Should not be initialized yet */
	KUNIT_EXPECT_FALSE(test, ssdfs_block_bmap_initialized(&bmap));

	/* Try to inflate uninitialized bitmap */
	err = ssdfs_block_bmap_inflate(&bmap, free_items);
	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_inflate_large_increase(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 free_items = 17567; /* Large increase */
	int original_capacity, new_capacity;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 32, 32,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	original_capacity = ssdfs_block_bmap_get_pages_capacity(&bmap);

	/* Add some used blocks first */
	len = 32;
	err = ssdfs_block_bmap_allocate(&bmap, 0, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Inflate by large amount */
	err = ssdfs_block_bmap_inflate(&bmap, free_items);
	KUNIT_EXPECT_EQ(test, 0, err);

	new_capacity = ssdfs_block_bmap_get_pages_capacity(&bmap);

	/* Verify significant capacity increase */
	KUNIT_EXPECT_GE(test, new_capacity, original_capacity + free_items);
	KUNIT_EXPECT_GT(test, new_capacity, original_capacity * 2);

	ssdfs_block_bmap_clear_dirty_state(&bmap);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_inflate_full_bitmap(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 free_items = 40;
	u32 len;
	int original_capacity, new_capacity;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Fill most of the bitmap */
	len = 50;
	err = ssdfs_block_bmap_allocate(&bmap, 0, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_block_bmap_reserve_metadata_pages(&bmap, 10);
	KUNIT_ASSERT_EQ(test, 0, err);

	original_capacity = ssdfs_block_bmap_get_pages_capacity(&bmap);

	/* Should have minimal free space */
	KUNIT_EXPECT_LT(test, ssdfs_block_bmap_get_free_pages(&bmap), 10);

	/* Inflate the bitmap */
	err = ssdfs_block_bmap_inflate(&bmap, free_items);
	KUNIT_EXPECT_EQ(test, 0, err);

	new_capacity = ssdfs_block_bmap_get_pages_capacity(&bmap);

	/* Verify capacity increased appropriately */
	KUNIT_EXPECT_GT(test, new_capacity, original_capacity);
	KUNIT_EXPECT_GE(test, ssdfs_block_bmap_get_free_pages(&bmap), free_items);

	ssdfs_block_bmap_clear_dirty_state(&bmap);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

static void test_block_bmap_inflate_capacity_calculation(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 free_items = 15;
	u32 len;
	int original_used, original_invalid, original_metadata;
	int new_capacity;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Create specific state for capacity calculation test */
	len = 12;
	err = ssdfs_block_bmap_allocate(&bmap, 8, &len, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	range.start = 10;
	range.len = 5;
	err = ssdfs_block_bmap_invalidate(&bmap, &range);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_block_bmap_reserve_metadata_pages(&bmap, 7);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Record current state */
	original_used = ssdfs_block_bmap_get_used_pages(&bmap);
	original_invalid = ssdfs_block_bmap_get_invalid_pages(&bmap);
	original_metadata = ssdfs_block_bmap_get_metadata_pages(&bmap);

	/* Inflate */
	err = ssdfs_block_bmap_inflate(&bmap, free_items);
	KUNIT_EXPECT_EQ(test, 0, err);

	new_capacity = ssdfs_block_bmap_get_pages_capacity(&bmap);

	/* Verify new capacity formula: used_space + free_items */
	/* used_space = metadata_items + used_blks + invalid_blks */
	KUNIT_EXPECT_GE(test, new_capacity,
			original_used + original_invalid + original_metadata + free_items);

	/* Verify state consistency after inflation */
	KUNIT_EXPECT_EQ(test, original_used, ssdfs_block_bmap_get_used_pages(&bmap));
	KUNIT_EXPECT_EQ(test, original_invalid, ssdfs_block_bmap_get_invalid_pages(&bmap));
	KUNIT_EXPECT_EQ(test, original_metadata, ssdfs_block_bmap_get_metadata_pages(&bmap));

	ssdfs_block_bmap_clear_dirty_state(&bmap);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

/*
 * Test cases for edge cases and error conditions
 */
static void test_block_bmap_edge_cases(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bmap bmap;
	struct ssdfs_block_bmap_range range;
	u32 len;
	int err;

	fsi = test_create_fs_info();
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	err = ssdfs_block_bmap_create(fsi, &bmap, 64, 64,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test allocation beyond capacity */
	len = 70;  /* More than capacity */
	err = ssdfs_block_bmap_allocate(&bmap, 0, &len, &range);
	KUNIT_EXPECT_NE(test, 0, err);

	/* Test allocation at invalid start position */
	len = 1;
	err = ssdfs_block_bmap_allocate(&bmap, 70, &len, &range);
	KUNIT_EXPECT_NE(test, 0, err);

	/* Test invalidating non-allocated blocks */
	range.start = 50;
	range.len = 5;
	err = ssdfs_block_bmap_invalidate(&bmap, &range);
	KUNIT_EXPECT_NE(test, 0, err);

	ssdfs_block_bmap_clear_dirty_state(&bmap);
	ssdfs_block_bmap_destroy(&bmap);
	test_free_fs_info(fsi);
}

/*
 * Test suite definition
 */
static struct kunit_case ssdfs_block_bitmap_test_cases[] = {
	KUNIT_CASE(test_block_bmap_create_valid_params),
	KUNIT_CASE(test_block_bmap_create_null_params),
	KUNIT_CASE(test_block_bmap_create_zero_capacity),
	KUNIT_CASE(test_block_bmap_state_checking),
	KUNIT_CASE(test_block_bmap_allocation),
	KUNIT_CASE(test_block_bmap_pre_allocation),
	KUNIT_CASE(test_block_bmap_invalidation),
	KUNIT_CASE(test_block_bmap_metadata_operations),
	KUNIT_CASE(test_block_state_utilities),
	KUNIT_CASE(test_block_bmap_flags),
	KUNIT_CASE(test_block_bmap_collect_garbage_valid_blocks),
	KUNIT_CASE(test_block_bmap_collect_garbage_pre_allocated_blocks),
	KUNIT_CASE(test_block_bmap_collect_garbage_no_blocks_found),
	KUNIT_CASE(test_block_bmap_collect_garbage_invalid_params),
	KUNIT_CASE(test_block_bmap_collect_garbage_boundary_conditions),
	KUNIT_CASE(test_block_bmap_clean_same_capacity),
	KUNIT_CASE(test_block_bmap_clean_expanded_capacity),
	KUNIT_CASE(test_block_bmap_clean_invalid_params),
	KUNIT_CASE(test_block_bmap_clean_with_invalid_blocks),
	KUNIT_CASE(test_block_bmap_clean_reset_search_cache),
	KUNIT_CASE(test_block_bmap_invalid2clean_single_range),
	KUNIT_CASE(test_block_bmap_invalid2clean_multiple_ranges),
	KUNIT_CASE(test_block_bmap_invalid2clean_no_invalid_blocks),
	KUNIT_CASE(test_block_bmap_invalid2clean_empty_bitmap),
	KUNIT_CASE(test_block_bmap_invalid2clean_invalid_params),
	KUNIT_CASE(test_block_bmap_invalid2clean_full_conversion),
	KUNIT_CASE(test_block_bmap_invalid2clean_partial_range),
	KUNIT_CASE(test_block_bmap_snapshot_basic),
	KUNIT_CASE(test_block_bmap_snapshot_with_invalid_blocks),
	KUNIT_CASE(test_block_bmap_snapshot_empty_bitmap),
	KUNIT_CASE(test_block_bmap_snapshot_invalid_params),
	KUNIT_CASE(test_block_bmap_forget_snapshot_basic),
	KUNIT_CASE(test_block_bmap_forget_snapshot_null_param),
	KUNIT_CASE(test_block_bmap_snapshot_multiple_cycles),
	KUNIT_CASE(test_block_bmap_snapshot_consistency_check),
	KUNIT_CASE(test_block_bmap_init_basic),
	KUNIT_CASE(test_block_bmap_init_inflated_flag),
	KUNIT_CASE(test_block_bmap_init_invalid_params),
	KUNIT_CASE(test_block_bmap_init_already_initialized),
	KUNIT_CASE(test_block_bmap_init_boundary_values),
	KUNIT_CASE(test_block_bmap_init_zero_values),
	KUNIT_CASE(test_block_bmap_init_state_consistency),
	KUNIT_CASE(test_block_bmap_inflate_basic),
	KUNIT_CASE(test_block_bmap_inflate_with_invalid_blocks),
	KUNIT_CASE(test_block_bmap_inflate_zero_free_items),
	KUNIT_CASE(test_block_bmap_inflate_invalid_params),
	KUNIT_CASE(test_block_bmap_inflate_uninitialized_bitmap),
	KUNIT_CASE(test_block_bmap_inflate_large_increase),
	KUNIT_CASE(test_block_bmap_inflate_full_bitmap),
	KUNIT_CASE(test_block_bmap_inflate_capacity_calculation),
	KUNIT_CASE(test_block_bmap_edge_cases),
	{}
};

static struct kunit_suite ssdfs_block_bitmap_test_suite = {
	.name = "ssdfs-block-bitmap",
	.test_cases = ssdfs_block_bitmap_test_cases,
};

kunit_test_suite(ssdfs_block_bitmap_test_suite);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Viacheslav Dubeyko <slava@dubeyko.com>");
MODULE_DESCRIPTION("KUnit test for SSDFS block bitmap");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
