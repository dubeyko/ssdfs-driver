// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/folio_vector_test.c - KUnit tests for folio vector implementation.
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
 * Test cases for ssdfs_folio_vector_create()
 */
static void test_folio_vector_create_valid_params(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	int err;

	err = ssdfs_folio_vector_create(&array, 0, 10);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 0, array.count);
	KUNIT_EXPECT_GT(test, array.capacity, 0);
	KUNIT_EXPECT_EQ(test, 0, array.order);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, array.folios);

	ssdfs_folio_vector_destroy(&array);
}

static void test_folio_vector_create_zero_capacity(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	int err;

	err = ssdfs_folio_vector_create(&array, 0, 0);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 0, array.count);
	KUNIT_EXPECT_GT(test, array.capacity, 0);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, array.folios);

	ssdfs_folio_vector_destroy(&array);
}

static void test_folio_vector_create_large_capacity(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	int err;
	u32 large_capacity = 1000000;

	err = ssdfs_folio_vector_create(&array, 2, large_capacity);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 0, array.count);
	KUNIT_EXPECT_LE(test, array.capacity, ssdfs_folio_vector_max_threshold());
	KUNIT_EXPECT_EQ(test, 2, array.order);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, array.folios);

	ssdfs_folio_vector_destroy(&array);
}

/*
 * Test cases for ssdfs_folio_vector_init()
 */
static void test_folio_vector_init_valid(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	int err;

	err = ssdfs_folio_vector_create(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	array.count = 3;

	err = ssdfs_folio_vector_init(&array);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 0, array.count);

	ssdfs_folio_vector_destroy(&array);
}

/*
 * Test cases for ssdfs_folio_vector_reinit()
 */
static void test_folio_vector_reinit_valid(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	int err;

	err = ssdfs_folio_vector_create(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	array.count = 3;

	err = ssdfs_folio_vector_reinit(&array);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 0, array.count);

	ssdfs_folio_vector_destroy(&array);
}

/*
 * Test cases for ssdfs_folio_vector_inflate()
 */
static void test_folio_vector_inflate_expand(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	int err;
	u32 original_capacity;
	u32 new_capacity = 20;

	err = ssdfs_folio_vector_create(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	original_capacity = array.capacity;

	err = ssdfs_folio_vector_inflate(&array, new_capacity);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_GT(test, array.capacity, original_capacity);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, array.folios);

	ssdfs_folio_vector_destroy(&array);
}

static void test_folio_vector_inflate_no_change(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	int err;
	u32 original_capacity;

	err = ssdfs_folio_vector_create(&array, 0, 10);
	KUNIT_ASSERT_EQ(test, 0, err);

	original_capacity = array.capacity;

	err = ssdfs_folio_vector_inflate(&array, 5);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, original_capacity, array.capacity);

	ssdfs_folio_vector_destroy(&array);
}

/*
 * Test cases for accessor functions
 */
static void test_folio_vector_count(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	int err;

	err = ssdfs_folio_vector_create(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	KUNIT_EXPECT_EQ(test, 0, ssdfs_folio_vector_count(&array));

	array.count = 3;
	KUNIT_EXPECT_EQ(test, 3, ssdfs_folio_vector_count(&array));

	ssdfs_folio_vector_destroy(&array);
}

static void test_folio_vector_space(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	int err;

	err = ssdfs_folio_vector_create(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	KUNIT_EXPECT_EQ(test, array.capacity, ssdfs_folio_vector_space(&array));

	array.count = 2;
	KUNIT_EXPECT_EQ(test, array.capacity - 2, ssdfs_folio_vector_space(&array));

	ssdfs_folio_vector_destroy(&array);
}

static void test_folio_vector_capacity(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	int err;

	err = ssdfs_folio_vector_create(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	KUNIT_EXPECT_EQ(test, array.capacity, ssdfs_folio_vector_capacity(&array));

	ssdfs_folio_vector_destroy(&array);
}

/*
 * Test cases for ssdfs_folio_vector_add()
 */
static void test_folio_vector_add_valid(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	struct folio *folio;
	int err;

	err = ssdfs_folio_vector_create(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = test_alloc_folio(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

	err = ssdfs_folio_vector_add(&array, folio);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 1, array.count);
	KUNIT_EXPECT_PTR_EQ(test, folio, array.folios[0]);

	test_free_folio(folio);
	ssdfs_folio_vector_destroy(&array);
}

/*
 * Test cases for ssdfs_folio_vector_allocate()
 */
static void test_folio_vector_allocate_valid(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	struct folio *folio;
	int err;

	err = ssdfs_folio_vector_create(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = ssdfs_folio_vector_allocate(&array);

	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, folio);
	KUNIT_EXPECT_EQ(test, 1, array.count);
	KUNIT_EXPECT_PTR_EQ(test, folio, array.folios[0]);

	ssdfs_folio_vector_release(&array);
	ssdfs_folio_vector_destroy(&array);
}

static void test_folio_vector_allocate_no_space(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	struct folio *folio;
	int err;
	int i;

	err = ssdfs_folio_vector_create(&array, 0, 2);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Fill the array to capacity */
	for (i = 0; i < array.capacity; i++) {
		folio = ssdfs_folio_vector_allocate(&array);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);
	}

	/* Try to allocate one more - should fail */
	folio = ssdfs_folio_vector_allocate(&array);
	KUNIT_EXPECT_TRUE(test, IS_ERR(folio));
	KUNIT_EXPECT_EQ(test, -E2BIG, PTR_ERR(folio));

	ssdfs_folio_vector_release(&array);
	ssdfs_folio_vector_destroy(&array);
}

/*
 * Test cases for ssdfs_folio_vector_remove()
 */
static void test_folio_vector_remove_valid(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	struct folio *folio, *removed_folio;
	int err;

	err = ssdfs_folio_vector_create(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = ssdfs_folio_vector_allocate(&array);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

	removed_folio = ssdfs_folio_vector_remove(&array, 0);

	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, removed_folio);
	KUNIT_EXPECT_PTR_EQ(test, folio, removed_folio);
	KUNIT_EXPECT_PTR_EQ(test, NULL, array.folios[0]);

	test_free_folio(removed_folio);
	ssdfs_folio_vector_destroy(&array);
}

static void test_folio_vector_remove_empty(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	struct folio *folio;
	int err;

	err = ssdfs_folio_vector_create(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = ssdfs_folio_vector_remove(&array, 0);

	KUNIT_EXPECT_TRUE(test, IS_ERR(folio));
	KUNIT_EXPECT_EQ(test, -ENODATA, PTR_ERR(folio));

	ssdfs_folio_vector_destroy(&array);
}

static void test_folio_vector_remove_out_of_range(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	struct folio *folio, *removed_folio;
	int err;

	err = ssdfs_folio_vector_create(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio = ssdfs_folio_vector_allocate(&array);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

	removed_folio = ssdfs_folio_vector_remove(&array, 10);

	KUNIT_EXPECT_TRUE(test, IS_ERR(removed_folio));
	KUNIT_EXPECT_EQ(test, -ENOENT, PTR_ERR(removed_folio));

	ssdfs_folio_vector_release(&array);
	ssdfs_folio_vector_destroy(&array);
}

/*
 * Test cases for ssdfs_folio_vector_release()
 */
static void test_folio_vector_release_valid(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	struct folio *folio1, *folio2;
	int err;

	err = ssdfs_folio_vector_create(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	folio1 = ssdfs_folio_vector_allocate(&array);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);

	folio2 = ssdfs_folio_vector_allocate(&array);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio2);

	KUNIT_EXPECT_EQ(test, 2, array.count);

	ssdfs_folio_vector_release(&array);

	KUNIT_EXPECT_EQ(test, 0, array.count);
	KUNIT_EXPECT_PTR_EQ(test, NULL, array.folios[0]);
	KUNIT_EXPECT_PTR_EQ(test, NULL, array.folios[1]);

	ssdfs_folio_vector_destroy(&array);
}

/*
 * Test cases for ssdfs_folio_vector_destroy()
 */
static void test_folio_vector_destroy_valid(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	int err;

	err = ssdfs_folio_vector_create(&array, 0, 5);
	KUNIT_ASSERT_EQ(test, 0, err);

	ssdfs_folio_vector_destroy(&array);

	KUNIT_EXPECT_EQ(test, 0, array.count);
	KUNIT_EXPECT_EQ(test, 0, array.capacity);
	KUNIT_EXPECT_PTR_EQ(test, NULL, array.folios);
}

/*
 * Complex integration test cases
 */
static void test_folio_vector_multiple_operations(struct kunit *test)
{
	struct ssdfs_folio_vector array;
	struct folio *folio1, *folio2, *folio3, *removed_folio;
	int err;

	err = ssdfs_folio_vector_create(&array, 0, 10);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Test initial state */
	KUNIT_EXPECT_EQ(test, 0, ssdfs_folio_vector_count(&array));
	KUNIT_EXPECT_EQ(test, array.capacity, ssdfs_folio_vector_space(&array));

	/* Allocate some folios */
	folio1 = ssdfs_folio_vector_allocate(&array);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);

	folio2 = ssdfs_folio_vector_allocate(&array);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio2);

	folio3 = ssdfs_folio_vector_allocate(&array);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio3);

	/* Check state after allocation */
	KUNIT_EXPECT_EQ(test, 3, ssdfs_folio_vector_count(&array));
	KUNIT_EXPECT_EQ(test, array.capacity - 3, ssdfs_folio_vector_space(&array));

	/* Remove middle folio */
	removed_folio = ssdfs_folio_vector_remove(&array, 1);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, removed_folio);
	KUNIT_EXPECT_PTR_EQ(test, folio2, removed_folio);

	/* Free removed folio */
	test_free_folio(removed_folio);

	/* Test inflate */
	err = ssdfs_folio_vector_inflate(&array, 20);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_GE(test, array.capacity, 20);

	/* Release all folios */
	ssdfs_folio_vector_release(&array);
	KUNIT_EXPECT_EQ(test, 0, ssdfs_folio_vector_count(&array));

	ssdfs_folio_vector_destroy(&array);
}

static struct kunit_case folio_vector_test_cases[] = {
	KUNIT_CASE(test_folio_vector_create_valid_params),
	KUNIT_CASE(test_folio_vector_create_zero_capacity),
	KUNIT_CASE(test_folio_vector_create_large_capacity),
	KUNIT_CASE(test_folio_vector_init_valid),
	KUNIT_CASE(test_folio_vector_reinit_valid),
	KUNIT_CASE(test_folio_vector_inflate_expand),
	KUNIT_CASE(test_folio_vector_inflate_no_change),
	KUNIT_CASE(test_folio_vector_count),
	KUNIT_CASE(test_folio_vector_space),
	KUNIT_CASE(test_folio_vector_capacity),
	KUNIT_CASE(test_folio_vector_add_valid),
	KUNIT_CASE(test_folio_vector_allocate_valid),
	KUNIT_CASE(test_folio_vector_allocate_no_space),
	KUNIT_CASE(test_folio_vector_remove_valid),
	KUNIT_CASE(test_folio_vector_remove_empty),
	KUNIT_CASE(test_folio_vector_remove_out_of_range),
	KUNIT_CASE(test_folio_vector_release_valid),
	KUNIT_CASE(test_folio_vector_destroy_valid),
	KUNIT_CASE(test_folio_vector_multiple_operations),
	{}
};

static struct kunit_suite folio_vector_test_suite = {
	.name = "ssdfs_folio_vector",
	.test_cases = folio_vector_test_cases,
};

kunit_test_suites(&folio_vector_test_suite);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Viacheslav Dubeyko <slava@dubeyko.com>");
MODULE_DESCRIPTION("KUnit tests for SSDFS folio vector");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
