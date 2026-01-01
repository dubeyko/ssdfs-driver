// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/folio_array_test.c - KUnit tests for folio array implementation.
 *
 * Copyright (c) 2025-2026 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include "folio_array.h"

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

static void test_free_folio(struct folio *folio)
{
	if (folio) {
		folio_put(folio);
		folio_put(folio);
	}
}

/*
 * Test cases for ssdfs_create_folio_array()
 */
static void test_create_folio_array_valid_params(struct kunit *test)
{
	struct ssdfs_folio_array array;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 10);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, SSDFS_FOLIO_ARRAY_CREATED, atomic_read(&array.state));
	KUNIT_EXPECT_EQ(test, 10, atomic_read(&array.folios_capacity));
	KUNIT_EXPECT_EQ(test, 0, array.folios_count);
	KUNIT_EXPECT_EQ(test, SSDFS_FOLIO_ARRAY_INVALID_LAST_FOLIO, array.last_folio);
	KUNIT_EXPECT_EQ(test, 0, array.order);
	KUNIT_EXPECT_EQ(test, PAGE_SIZE, array.folio_size);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, array.folios);

	ssdfs_destroy_folio_array(&array);
}

static void test_create_folio_array_zero_capacity(struct kunit *test)
{
	struct ssdfs_folio_array array;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 0);

	KUNIT_EXPECT_EQ(test, -EINVAL, err);
	KUNIT_EXPECT_EQ(test, SSDFS_FOLIO_ARRAY_UNKNOWN_STATE, atomic_read(&array.state));
}

static void test_create_folio_array_large_capacity(struct kunit *test)
{
	struct ssdfs_folio_array array;
	int err;
	int capacity = 1000;

	err = ssdfs_create_folio_array(&array, 2, capacity);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, SSDFS_FOLIO_ARRAY_CREATED, atomic_read(&array.state));
	KUNIT_EXPECT_EQ(test, capacity, atomic_read(&array.folios_capacity));
	KUNIT_EXPECT_EQ(test, 2, array.order);
	KUNIT_EXPECT_EQ(test, PAGE_SIZE << 2, array.folio_size);

	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for ssdfs_destroy_folio_array()
 */
static void test_destroy_folio_array_valid(struct kunit *test)
{
	struct ssdfs_folio_array array;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	ssdfs_destroy_folio_array(&array);

	KUNIT_EXPECT_EQ(test, 0, atomic_read(&array.folios_capacity));
	KUNIT_EXPECT_EQ(test, 0, array.folios_count);
	KUNIT_EXPECT_EQ(test, SSDFS_FOLIO_ARRAY_INVALID_LAST_FOLIO, array.last_folio);
	KUNIT_EXPECT_PTR_EQ(test, NULL, array.folios);
}

/*
 * Test cases for ssdfs_reinit_folio_array()
 */
static void test_reinit_folio_array_expand(struct kunit *test)
{
	struct ssdfs_folio_array array;
	int err;
	int original_capacity = 5;
	int new_capacity = 20;

	err = ssdfs_create_folio_array(&array, 0, original_capacity);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_reinit_folio_array(new_capacity, &array);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, new_capacity, atomic_read(&array.folios_capacity));
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, array.folios);

	ssdfs_destroy_folio_array(&array);
}

static void test_reinit_folio_array_shrink(struct kunit *test)
{
	struct ssdfs_folio_array array;
	int err;
	int original_capacity = 20;
	int new_capacity = 5;

	err = ssdfs_create_folio_array(&array, 0, original_capacity);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_reinit_folio_array(new_capacity, &array);

	KUNIT_EXPECT_EQ(test, -EINVAL, err);
	KUNIT_EXPECT_EQ(test, original_capacity, atomic_read(&array.folios_capacity));

	ssdfs_destroy_folio_array(&array);
}

static void test_reinit_folio_array_same_capacity(struct kunit *test)
{
	struct ssdfs_folio_array array;
	int err;
	int capacity = 10;

	err = ssdfs_create_folio_array(&array, 0, capacity);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_reinit_folio_array(capacity, &array);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, capacity, atomic_read(&array.folios_capacity));

	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for is_ssdfs_folio_array_empty()
 */
static void test_is_folio_array_empty_new_array(struct kunit *test)
{
	struct ssdfs_folio_array array;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	KUNIT_EXPECT_TRUE(test, is_ssdfs_folio_array_empty(&array));

	ssdfs_destroy_folio_array(&array);
}

static void test_is_folio_array_empty_with_folios(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

	err = ssdfs_folio_array_add_folio(&array, folio, 0);
	KUNIT_ASSERT_EQ(test, 0, err);

	KUNIT_EXPECT_FALSE(test, is_ssdfs_folio_array_empty(&array));

	test_free_folio(folio);
	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for ssdfs_folio_array_get_last_folio_index()
 */
static void test_get_last_folio_index_empty(struct kunit *test)
{
	struct ssdfs_folio_array array;
	unsigned long last_index;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	last_index = ssdfs_folio_array_get_last_folio_index(&array);

	KUNIT_EXPECT_EQ(test, SSDFS_FOLIO_ARRAY_INVALID_LAST_FOLIO, last_index);

	ssdfs_destroy_folio_array(&array);
}

static void test_get_last_folio_index_with_folios(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio;
	unsigned long last_index;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 10);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

	err = ssdfs_folio_array_add_folio(&array, folio, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	last_index = ssdfs_folio_array_get_last_folio_index(&array);

	KUNIT_EXPECT_EQ(test, 5, last_index);

	test_free_folio(folio);
	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for ssdfs_folio_array_add_folio()
 */
static void test_add_folio_valid(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

	err = ssdfs_folio_array_add_folio(&array, folio, 2);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 1, array.folios_count);
	KUNIT_EXPECT_EQ(test, 2, array.last_folio);
	KUNIT_EXPECT_PTR_EQ(test, folio, array.folios[2]);

	test_free_folio(folio);
	ssdfs_destroy_folio_array(&array);
}

static void test_add_folio_duplicate(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio1, *folio2;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio1 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);

	folio2 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio2);

	err = ssdfs_folio_array_add_folio(&array, folio1, 0);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_array_add_folio(&array, folio2, 0);

	KUNIT_EXPECT_EQ(test, -EEXIST, err);

	test_free_folio(folio1);
	test_free_folio(folio2);
	ssdfs_destroy_folio_array(&array);
}

static void test_add_folio_out_of_range(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

	err = ssdfs_folio_array_add_folio(&array, folio, 10);

	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	test_free_folio(folio);
	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for ssdfs_folio_array_allocate_folio_locked()
 */
static void test_allocate_folio_locked_valid(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = ssdfs_folio_array_allocate_folio_locked(&array, 1);

	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, folio);
	KUNIT_EXPECT_EQ(test, 1, array.folios_count);
	KUNIT_EXPECT_EQ(test, 1, array.last_folio);
	KUNIT_EXPECT_PTR_EQ(test, folio, array.folios[1]);
	KUNIT_EXPECT_TRUE(test, folio_test_locked(folio));

	ssdfs_folio_unlock(folio);
	ssdfs_destroy_folio_array(&array);
}

static void test_allocate_folio_locked_duplicate(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio1, *folio2;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio1 = ssdfs_folio_array_allocate_folio_locked(&array, 2);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);

	folio2 = ssdfs_folio_array_allocate_folio_locked(&array, 2);

	KUNIT_EXPECT_TRUE(test, IS_ERR(folio2));
	KUNIT_EXPECT_EQ(test, -EEXIST, PTR_ERR(folio2));

	ssdfs_folio_unlock(folio1);
	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for ssdfs_folio_array_get_folio()
 */
static void test_get_folio_valid(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio, *retrieved_folio;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

	err = ssdfs_folio_array_add_folio(&array, folio, 3);
	KUNIT_ASSERT_EQ(test, 0, err);

	retrieved_folio = ssdfs_folio_array_get_folio(&array, 3);

	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, retrieved_folio);
	KUNIT_EXPECT_PTR_EQ(test, folio, retrieved_folio);

	ssdfs_folio_put(retrieved_folio);
	test_free_folio(folio);
	ssdfs_destroy_folio_array(&array);
}

static void test_get_folio_not_allocated(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = ssdfs_folio_array_get_folio(&array, 2);

	KUNIT_EXPECT_TRUE(test, IS_ERR(folio));
	KUNIT_EXPECT_EQ(test, -ENOENT, PTR_ERR(folio));

	ssdfs_destroy_folio_array(&array);
}

static void test_get_folio_out_of_range(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = ssdfs_folio_array_get_folio(&array, 10);

	KUNIT_EXPECT_TRUE(test, IS_ERR(folio));
	KUNIT_EXPECT_EQ(test, -EINVAL, PTR_ERR(folio));

	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for ssdfs_folio_array_get_folio_locked()
 */
static void test_get_folio_locked_valid(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio, *locked_folio;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

	err = ssdfs_folio_array_add_folio(&array, folio, 1);
	KUNIT_ASSERT_EQ(test, 0, err);

	locked_folio = ssdfs_folio_array_get_folio_locked(&array, 1);

	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, locked_folio);
	KUNIT_EXPECT_PTR_EQ(test, folio, locked_folio);
	KUNIT_EXPECT_TRUE(test, folio_test_locked(locked_folio));

	ssdfs_folio_unlock(locked_folio);
	ssdfs_folio_put(locked_folio);
	test_free_folio(folio);
	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for ssdfs_folio_array_grab_folio()
 */
static void test_grab_folio_existing(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio, *grabbed_folio;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

	err = ssdfs_folio_array_add_folio(&array, folio, 0);
	KUNIT_ASSERT_EQ(test, 0, err);

	grabbed_folio = ssdfs_folio_array_grab_folio(&array, 0);

	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, grabbed_folio);
	KUNIT_EXPECT_PTR_EQ(test, folio, grabbed_folio);
	KUNIT_EXPECT_TRUE(test, folio_test_locked(grabbed_folio));

	ssdfs_folio_unlock(grabbed_folio);
	ssdfs_folio_put(grabbed_folio);
	test_free_folio(folio);
	ssdfs_destroy_folio_array(&array);
}

static void test_grab_folio_new(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *grabbed_folio;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	grabbed_folio = ssdfs_folio_array_grab_folio(&array, 2);

	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, grabbed_folio);
	KUNIT_EXPECT_EQ(test, 1, array.folios_count);
	KUNIT_EXPECT_EQ(test, 2, array.last_folio);
	KUNIT_EXPECT_PTR_EQ(test, grabbed_folio, array.folios[2]);
	KUNIT_EXPECT_TRUE(test, folio_test_locked(grabbed_folio));

	ssdfs_folio_unlock(grabbed_folio);
	ssdfs_folio_put(grabbed_folio);
	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for ssdfs_folio_array_set_folio_dirty()
 */
static void test_set_folio_dirty_valid(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

	err = ssdfs_folio_array_add_folio(&array, folio, 1);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_array_set_folio_dirty(&array, 1);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, SSDFS_FOLIO_ARRAY_DIRTY, atomic_read(&array.state));
	KUNIT_EXPECT_TRUE(test, folio_test_dirty(folio));

	err = ssdfs_folio_array_clear_dirty_folio(&array, 1);

	KUNIT_EXPECT_EQ(test, 0, err);

	test_free_folio(folio);
	ssdfs_destroy_folio_array(&array);
}

static void test_set_folio_dirty_not_allocated(struct kunit *test)
{
	struct ssdfs_folio_array array;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_array_set_folio_dirty(&array, 3);

	KUNIT_EXPECT_EQ(test, -ENOENT, err);

	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for ssdfs_folio_array_clear_dirty_folio()
 */
static void test_clear_dirty_folio_valid(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

	err = ssdfs_folio_array_add_folio(&array, folio, 1);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_array_set_folio_dirty(&array, 1);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_array_clear_dirty_folio(&array, 1);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, SSDFS_FOLIO_ARRAY_CREATED, atomic_read(&array.state));
	KUNIT_EXPECT_FALSE(test, folio_test_dirty(folio));

	test_free_folio(folio);
	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for ssdfs_folio_array_clear_dirty_range()
 */
static void test_clear_dirty_range_valid(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio1, *folio2, *folio3;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 10);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio1 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);
	folio2 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio2);
	folio3 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio3);

	err = ssdfs_folio_array_add_folio(&array, folio1, 1);
	KUNIT_ASSERT_EQ(test, 0, err);
	err = ssdfs_folio_array_add_folio(&array, folio2, 2);
	KUNIT_ASSERT_EQ(test, 0, err);
	err = ssdfs_folio_array_add_folio(&array, folio3, 3);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_array_set_folio_dirty(&array, 1);
	KUNIT_ASSERT_EQ(test, 0, err);
	err = ssdfs_folio_array_set_folio_dirty(&array, 2);
	KUNIT_ASSERT_EQ(test, 0, err);
	err = ssdfs_folio_array_set_folio_dirty(&array, 3);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_array_clear_dirty_range(&array, 1, 2);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_FALSE(test, folio_test_dirty(folio1));
	KUNIT_EXPECT_FALSE(test, folio_test_dirty(folio2));
	KUNIT_EXPECT_TRUE(test, folio_test_dirty(folio3));

	err = ssdfs_folio_array_clear_dirty_folio(&array, 3);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_FALSE(test, folio_test_dirty(folio3));

	test_free_folio(folio1);
	test_free_folio(folio2);
	test_free_folio(folio3);
	ssdfs_destroy_folio_array(&array);
}

static void test_clear_dirty_range_invalid_range(struct kunit *test)
{
	struct ssdfs_folio_array array;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_array_clear_dirty_range(&array, 3, 1);

	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for ssdfs_folio_array_clear_all_dirty_folios()
 */
static void test_clear_all_dirty_folios_valid(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio1, *folio2;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio1 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);
	folio2 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio2);

	err = ssdfs_folio_array_add_folio(&array, folio1, 0);
	KUNIT_ASSERT_EQ(test, 0, err);
	err = ssdfs_folio_array_add_folio(&array, folio2, 1);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_array_set_folio_dirty(&array, 0);
	KUNIT_ASSERT_EQ(test, 0, err);
	err = ssdfs_folio_array_set_folio_dirty(&array, 1);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_array_clear_all_dirty_folios(&array);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, SSDFS_FOLIO_ARRAY_CREATED, atomic_read(&array.state));
	KUNIT_EXPECT_FALSE(test, folio_test_dirty(folio1));
	KUNIT_EXPECT_FALSE(test, folio_test_dirty(folio2));

	test_free_folio(folio1);
	test_free_folio(folio2);
	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for ssdfs_folio_array_lookup_range()
 */
static void test_lookup_range_dirty_folios(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio1, *folio2;
	struct folio_batch batch;
	unsigned long start = 0;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 10);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio1 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);
	folio2 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio2);

	err = ssdfs_folio_array_add_folio(&array, folio1, 2);
	KUNIT_ASSERT_EQ(test, 0, err);
	err = ssdfs_folio_array_add_folio(&array, folio2, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_array_set_folio_dirty(&array, 2);
	KUNIT_ASSERT_EQ(test, 0, err);
	err = ssdfs_folio_array_set_folio_dirty(&array, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio_batch_init(&batch);

	err = ssdfs_folio_array_lookup_range(&array, &start, 9,
					     SSDFS_DIRTY_FOLIO_TAG, 10, &batch);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 2, folio_batch_count(&batch));
	KUNIT_EXPECT_PTR_EQ(test, folio1, batch.folios[0]);
	KUNIT_EXPECT_PTR_EQ(test, folio2, batch.folios[1]);

	err = ssdfs_folio_array_clear_dirty_folio(&array, 2);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_FALSE(test, folio_test_dirty(folio1));

	err = ssdfs_folio_array_clear_dirty_folio(&array, 5);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_FALSE(test, folio_test_dirty(folio2));

	ssdfs_folio_batch_release(&batch);
	test_free_folio(folio1);
	test_free_folio(folio2);
	ssdfs_destroy_folio_array(&array);
}

static void test_lookup_range_no_dirty_folios(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio_batch batch;
	unsigned long start = 0;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio_batch_init(&batch);

	err = ssdfs_folio_array_lookup_range(&array, &start, 4,
					     SSDFS_DIRTY_FOLIO_TAG, 10, &batch);

	KUNIT_EXPECT_EQ(test, -ENOENT, err);

	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for ssdfs_folio_array_delete_folio()
 */
static void test_delete_folio_valid(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio, *deleted_folio;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

	err = ssdfs_folio_array_add_folio(&array, folio, 2);
	KUNIT_ASSERT_EQ(test, 0, err);

	deleted_folio = ssdfs_folio_array_delete_folio(&array, 2);

	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, deleted_folio);
	KUNIT_EXPECT_PTR_EQ(test, folio, deleted_folio);
	KUNIT_EXPECT_EQ(test, 0, array.folios_count);
	KUNIT_EXPECT_EQ(test, SSDFS_FOLIO_ARRAY_INVALID_LAST_FOLIO, array.last_folio);
	KUNIT_EXPECT_PTR_EQ(test, NULL, array.folios[2]);

	ssdfs_folio_free(deleted_folio);
	ssdfs_destroy_folio_array(&array);
}

static void test_delete_folio_not_allocated(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *deleted_folio;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	deleted_folio = ssdfs_folio_array_delete_folio(&array, 3);

	KUNIT_EXPECT_TRUE(test, IS_ERR(deleted_folio));
	KUNIT_EXPECT_EQ(test, -ENOENT, PTR_ERR(deleted_folio));

	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for ssdfs_folio_array_release_folios()
 */
static void test_release_folios_valid_range(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio1, *folio2, *folio3;
	unsigned long start = 1;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 10);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio1 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);
	folio2 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio2);
	folio3 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio3);

	err = ssdfs_folio_array_add_folio(&array, folio1, 1);
	KUNIT_ASSERT_EQ(test, 0, err);
	err = ssdfs_folio_array_add_folio(&array, folio2, 2);
	KUNIT_ASSERT_EQ(test, 0, err);
	err = ssdfs_folio_array_add_folio(&array, folio3, 4);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_array_release_folios(&array, &start, 2);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 1, array.folios_count);
	KUNIT_EXPECT_EQ(test, 4, array.last_folio);
	KUNIT_EXPECT_PTR_EQ(test, NULL, array.folios[1]);
	KUNIT_EXPECT_PTR_EQ(test, NULL, array.folios[2]);
	KUNIT_EXPECT_PTR_EQ(test, folio3, array.folios[4]);

	test_free_folio(folio3);
	ssdfs_destroy_folio_array(&array);
}

static void test_release_folios_invalid_range(struct kunit *test)
{
	struct ssdfs_folio_array array;
	unsigned long start = 5;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_array_release_folios(&array, &start, 2);

	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for ssdfs_folio_array_release_all_folios()
 */
static void test_release_all_folios_valid(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio1, *folio2;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio1 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);
	folio2 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio2);

	err = ssdfs_folio_array_add_folio(&array, folio1, 0);
	KUNIT_ASSERT_EQ(test, 0, err);
	err = ssdfs_folio_array_add_folio(&array, folio2, 3);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_folio_array_release_all_folios(&array);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 0, array.folios_count);
	KUNIT_EXPECT_EQ(test, SSDFS_FOLIO_ARRAY_INVALID_LAST_FOLIO, array.last_folio);
	KUNIT_EXPECT_PTR_EQ(test, NULL, array.folios[0]);
	KUNIT_EXPECT_PTR_EQ(test, NULL, array.folios[3]);

	ssdfs_destroy_folio_array(&array);
}

/*
 * Test cases for ssdfs_folio_array_get_folios_count()
 */
static void test_get_folios_count_empty(struct kunit *test)
{
	struct ssdfs_folio_array array;
	unsigned long count;
	int err;

	err = ssdfs_create_folio_array(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	count = ssdfs_folio_array_get_folios_count(&array);

	KUNIT_EXPECT_EQ(test, 0, count);

	ssdfs_destroy_folio_array(&array);
}

static void test_get_folios_count_with_folios(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio1, *folio2;
	unsigned long count;
	int err;

	/* Create a simple test that matches the working pattern */
	err = ssdfs_create_folio_array(&array, 0, 10);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio1 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);
	folio2 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio2);

	/* Use same indices as the working test_release_all_folios_valid */
	err = ssdfs_folio_array_add_folio(&array, folio1, 0);
	KUNIT_ASSERT_EQ(test, 0, err);
	err = ssdfs_folio_array_add_folio(&array, folio2, 3);
	KUNIT_ASSERT_EQ(test, 0, err);

	count = ssdfs_folio_array_get_folios_count(&array);
	KUNIT_EXPECT_EQ(test, 2, count);

	err = ssdfs_folio_array_release_all_folios(&array);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 0, array.folios_count);

	ssdfs_destroy_folio_array(&array);
}

/*
 * Complex integration test cases
 */
static void test_folio_array_complex_operations(struct kunit *test)
{
	struct ssdfs_folio_array array;
	struct folio *folio1, *folio2, *folio3;
	struct folio *grabbed_folio, *deleted_folio;
	struct folio_batch batch;
	unsigned long start = 0;
	int err;

	/* Create array */
	err = ssdfs_create_folio_array(&array, 0, 20);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test initial state */
	KUNIT_EXPECT_TRUE(test, is_ssdfs_folio_array_empty(&array));
	KUNIT_EXPECT_EQ(test, 0, ssdfs_folio_array_get_folios_count(&array));

	/* Add some folios */
	folio1 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);
	folio2 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio2);

	err = ssdfs_folio_array_add_folio(&array, folio1, 3);
	KUNIT_ASSERT_EQ(test, 0, err);
	err = ssdfs_folio_array_add_folio(&array, folio2, 7);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Grab a new folio */
	grabbed_folio = ssdfs_folio_array_grab_folio(&array, 10);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, grabbed_folio);

	/* Check state after additions */
	KUNIT_EXPECT_FALSE(test, is_ssdfs_folio_array_empty(&array));
	KUNIT_EXPECT_EQ(test, 3, ssdfs_folio_array_get_folios_count(&array));
	KUNIT_EXPECT_EQ(test, 10, ssdfs_folio_array_get_last_folio_index(&array));

	ssdfs_folio_unlock(grabbed_folio);

	/* Set some folios dirty */
	err = ssdfs_folio_array_set_folio_dirty(&array, 3);
	KUNIT_ASSERT_EQ(test, 0, err);
	err = ssdfs_folio_array_set_folio_dirty(&array, 10);
	KUNIT_ASSERT_EQ(test, 0, err);

	KUNIT_EXPECT_EQ(test, SSDFS_FOLIO_ARRAY_DIRTY, atomic_read(&array.state));

	/* Lookup dirty folios */
	folio_batch_init(&batch);
	err = ssdfs_folio_array_lookup_range(&array, &start, 19,
					     SSDFS_DIRTY_FOLIO_TAG, 10, &batch);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 2, folio_batch_count(&batch));

	/* Clear one dirty folio */
	err = ssdfs_folio_array_clear_dirty_folio(&array, 3);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Delete a folio */
	deleted_folio = ssdfs_folio_array_delete_folio(&array, 7);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, deleted_folio);
	KUNIT_EXPECT_PTR_EQ(test, folio2, deleted_folio);

	ssdfs_folio_put(deleted_folio);
	ssdfs_folio_free(deleted_folio);

	/* Expand array capacity */
	err = ssdfs_reinit_folio_array(50, &array);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 50, atomic_read(&array.folios_capacity));

	/* Add one more folio after expansion */
	folio3 = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio3);
	err = ssdfs_folio_array_add_folio(&array, folio3, 25);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Clear all dirty folios */
	err = ssdfs_folio_array_clear_all_dirty_folios(&array);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, SSDFS_FOLIO_ARRAY_CREATED, atomic_read(&array.state));

	/* Release all remaining folios */
	err = ssdfs_folio_array_release_all_folios(&array);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_TRUE(test, is_ssdfs_folio_array_empty(&array));

	/* Cleanup */
	ssdfs_destroy_folio_array(&array);
}

static struct kunit_case folio_array_test_cases[] = {
	KUNIT_CASE(test_create_folio_array_valid_params),
	KUNIT_CASE(test_create_folio_array_zero_capacity),
	KUNIT_CASE(test_create_folio_array_large_capacity),
	KUNIT_CASE(test_destroy_folio_array_valid),
	KUNIT_CASE(test_reinit_folio_array_expand),
	KUNIT_CASE(test_reinit_folio_array_shrink),
	KUNIT_CASE(test_reinit_folio_array_same_capacity),
	KUNIT_CASE(test_is_folio_array_empty_new_array),
	KUNIT_CASE(test_is_folio_array_empty_with_folios),
	KUNIT_CASE(test_get_last_folio_index_empty),
	KUNIT_CASE(test_get_last_folio_index_with_folios),
	KUNIT_CASE(test_add_folio_valid),
	KUNIT_CASE(test_add_folio_duplicate),
	KUNIT_CASE(test_add_folio_out_of_range),
	KUNIT_CASE(test_allocate_folio_locked_valid),
	KUNIT_CASE(test_allocate_folio_locked_duplicate),
	KUNIT_CASE(test_get_folio_valid),
	KUNIT_CASE(test_get_folio_not_allocated),
	KUNIT_CASE(test_get_folio_out_of_range),
	KUNIT_CASE(test_get_folio_locked_valid),
	KUNIT_CASE(test_grab_folio_existing),
	KUNIT_CASE(test_grab_folio_new),
	KUNIT_CASE(test_set_folio_dirty_valid),
	KUNIT_CASE(test_set_folio_dirty_not_allocated),
	KUNIT_CASE(test_clear_dirty_folio_valid),
	KUNIT_CASE(test_clear_dirty_range_valid),
	KUNIT_CASE(test_clear_dirty_range_invalid_range),
	KUNIT_CASE(test_clear_all_dirty_folios_valid),
	KUNIT_CASE(test_lookup_range_dirty_folios),
	KUNIT_CASE(test_lookup_range_no_dirty_folios),
	KUNIT_CASE(test_delete_folio_valid),
	KUNIT_CASE(test_delete_folio_not_allocated),
	KUNIT_CASE(test_release_folios_valid_range),
	KUNIT_CASE(test_release_folios_invalid_range),
	KUNIT_CASE(test_release_all_folios_valid),
	KUNIT_CASE(test_get_folios_count_empty),
	KUNIT_CASE(test_get_folios_count_with_folios),
	KUNIT_CASE(test_folio_array_complex_operations),
	{}
};

static struct kunit_suite folio_array_test_suite = {
	.name = "ssdfs_folio_array",
	.test_cases = folio_array_test_cases,
};

kunit_test_suites(&folio_array_test_suite);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Viacheslav Dubeyko <slava@dubeyko.com>");
MODULE_DESCRIPTION("KUnit tests for SSDFS folio array");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
