// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dynamic_array_test.c - KUnit tests for dynamic array implementation.
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
#include <linux/folio_batch.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "dynamic_array.h"
#include "superblock_payload.h"

/*
 * Test helper structures and functions
 */
struct test_item {
	u32 value1;
	u32 value2;
	u64 value3;
};

#define TEST_PATTERN 0xAB
#define TEST_CAPACITY 100
#define SMALL_CAPACITY 10
#define LARGE_CAPACITY 2000

static void init_test_item(struct test_item *item, u32 index)
{
	item->value1 = index;
	item->value2 = index * 2;
	item->value3 = index * 3;
}

static bool verify_test_item(struct test_item *item, u32 index)
{
	return (item->value1 == index &&
		item->value2 == index * 2 &&
		item->value3 == index * 3);
}

/*
 * Test cases for ssdfs_dynamic_array_create()
 */
static void test_dynamic_array_create_valid_small(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER, array.state);
	KUNIT_EXPECT_EQ(test, SMALL_CAPACITY, array.capacity);
	KUNIT_EXPECT_EQ(test, 0, array.items_count);
	KUNIT_EXPECT_EQ(test, sizeof(struct test_item), array.item_size);
	KUNIT_EXPECT_GT(test, array.bytes_count, 0);
	KUNIT_EXPECT_EQ(test, TEST_PATTERN, array.alloc_pattern);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, array.buf);

	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_create_valid_large(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	int err;

	err = ssdfs_dynamic_array_create(&array, LARGE_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);

	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC, array.state);
	KUNIT_EXPECT_EQ(test, LARGE_CAPACITY, array.capacity);
	KUNIT_EXPECT_EQ(test, 0, array.items_count);
	KUNIT_EXPECT_EQ(test, sizeof(struct test_item), array.item_size);
	KUNIT_EXPECT_GT(test, array.bytes_count, 0);
	KUNIT_EXPECT_EQ(test, TEST_PATTERN, array.alloc_pattern);

	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_create_zero_capacity(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	int err;

	err = ssdfs_dynamic_array_create(&array, 0,
					 sizeof(struct test_item), TEST_PATTERN);

	KUNIT_EXPECT_EQ(test, -EINVAL, err);
	KUNIT_EXPECT_EQ(test, SSDFS_DYNAMIC_ARRAY_STORAGE_ABSENT, array.state);
}

static void test_dynamic_array_create_zero_item_size(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	int err;

	err = ssdfs_dynamic_array_create(&array, TEST_CAPACITY, 0, TEST_PATTERN);

	KUNIT_EXPECT_EQ(test, -EINVAL, err);
	KUNIT_EXPECT_EQ(test, SSDFS_DYNAMIC_ARRAY_STORAGE_ABSENT, array.state);
}

static void test_dynamic_array_create_large_item_size(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	int err;

	err = ssdfs_dynamic_array_create(&array, TEST_CAPACITY,
					 PAGE_SIZE + 1, TEST_PATTERN);

	KUNIT_EXPECT_EQ(test, -EINVAL, err);
	KUNIT_EXPECT_EQ(test, SSDFS_DYNAMIC_ARRAY_STORAGE_ABSENT, array.state);
}

/*
 * Test cases for ssdfs_dynamic_array_destroy()
 */
static void test_dynamic_array_destroy_buffer(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	ssdfs_dynamic_array_destroy(&array);

	KUNIT_EXPECT_EQ(test, SSDFS_DYNAMIC_ARRAY_STORAGE_ABSENT, array.state);
	KUNIT_EXPECT_EQ(test, 0, array.capacity);
	KUNIT_EXPECT_EQ(test, 0, array.items_count);
	KUNIT_EXPECT_EQ(test, 0, array.item_size);
	KUNIT_EXPECT_EQ(test, 0, array.bytes_count);
}

static void test_dynamic_array_destroy_folio_vec(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	int err;

	err = ssdfs_dynamic_array_create(&array, LARGE_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	ssdfs_dynamic_array_destroy(&array);

	KUNIT_EXPECT_EQ(test, SSDFS_DYNAMIC_ARRAY_STORAGE_ABSENT, array.state);
	KUNIT_EXPECT_EQ(test, 0, array.capacity);
	KUNIT_EXPECT_EQ(test, 0, array.items_count);
	KUNIT_EXPECT_EQ(test, 0, array.item_size);
	KUNIT_EXPECT_EQ(test, 0, array.bytes_count);
}

/*
 * Test cases for ssdfs_dynamic_array_get_locked() and ssdfs_dynamic_array_release()
 */
static void test_dynamic_array_get_release_buffer(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item *item;
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	item = ssdfs_dynamic_array_get_locked(&array, 0);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, item);
	KUNIT_EXPECT_EQ(test, 1, array.items_count);

	/* Test release for buffer storage (should be no-op) */
	err = ssdfs_dynamic_array_release(&array, 0, item);
	KUNIT_EXPECT_EQ(test, 0, err);

	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_get_release_folio_vec(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item *item;
	int err;

	err = ssdfs_dynamic_array_create(&array, LARGE_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	item = ssdfs_dynamic_array_get_locked(&array, 0);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, item);
	KUNIT_EXPECT_EQ(test, 1, array.items_count);

	err = ssdfs_dynamic_array_release(&array, 0, item);
	KUNIT_EXPECT_EQ(test, 0, err);

	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_get_out_of_range(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item *item;
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	item = ssdfs_dynamic_array_get_locked(&array, SMALL_CAPACITY);
	KUNIT_EXPECT_TRUE(test, IS_ERR(item));
	KUNIT_EXPECT_EQ(test, -ERANGE, PTR_ERR(item));

	ssdfs_dynamic_array_destroy(&array);
}

/*
 * Test cases for ssdfs_dynamic_array_set()
 */
static void test_dynamic_array_set_buffer(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item, *retrieved_item;
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	init_test_item(&item, 5);

	err = ssdfs_dynamic_array_set(&array, 5, &item);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 6, array.items_count);

	retrieved_item = ssdfs_dynamic_array_get_locked(&array, 5);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, retrieved_item);
	KUNIT_EXPECT_TRUE(test, verify_test_item(retrieved_item, 5));

	err = ssdfs_dynamic_array_release(&array, 5, retrieved_item);
	KUNIT_EXPECT_EQ(test, 0, err);

	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_set_folio_vec(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item, *retrieved_item;
	int err;

	err = ssdfs_dynamic_array_create(&array, LARGE_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	init_test_item(&item, 100);

	err = ssdfs_dynamic_array_set(&array, 100, &item);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 101, array.items_count);

	retrieved_item = ssdfs_dynamic_array_get_locked(&array, 100);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, retrieved_item);
	KUNIT_EXPECT_TRUE(test, verify_test_item(retrieved_item, 100));

	err = ssdfs_dynamic_array_release(&array, 100, retrieved_item);
	KUNIT_EXPECT_EQ(test, 0, err);

	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_set_out_of_range(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item;
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	init_test_item(&item, 0);

	err = ssdfs_dynamic_array_set(&array, SMALL_CAPACITY, &item);
	KUNIT_EXPECT_EQ(test, -ERANGE, err);

	ssdfs_dynamic_array_destroy(&array);
}

/*
 * Test cases for ssdfs_dynamic_array_get_content_locked()
 */
static void test_dynamic_array_get_content_locked_buffer(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item, *content;
	u32 items_count;
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Set some items */
	for (int i = 0; i < 5; i++) {
		init_test_item(&item, i);
		err = ssdfs_dynamic_array_set(&array, i, &item);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	content = ssdfs_dynamic_array_get_content_locked(&array, 2, &items_count);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, content);
	KUNIT_EXPECT_EQ(test, 3, items_count); /* items from index 2 to end */
	KUNIT_EXPECT_TRUE(test, verify_test_item(&content[0], 2));

	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_get_content_locked_folio_vec(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item, *content;
	u32 items_count;
	int err;

	err = ssdfs_dynamic_array_create(&array, LARGE_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Set some items across folio boundaries */
	for (int i = 0; i < 300; i++) {
		init_test_item(&item, i);
		err = ssdfs_dynamic_array_set(&array, i, &item);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	content = ssdfs_dynamic_array_get_content_locked(&array, 100, &items_count);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, content);
	KUNIT_EXPECT_GT(test, items_count, 0);
	KUNIT_EXPECT_TRUE(test, verify_test_item(&content[0], 100));

	ssdfs_dynamic_array_destroy(&array);
}

/*
 * Test cases for ssdfs_dynamic_array_copy_content()
 */
static void test_dynamic_array_copy_content_buffer(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item, *copy_buf;
	size_t buf_size;
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Set some items */
	for (int i = 0; i < 5; i++) {
		init_test_item(&item, i);
		err = ssdfs_dynamic_array_set(&array, i, &item);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	buf_size = 5 * sizeof(struct test_item);
	copy_buf = kzalloc(buf_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, copy_buf);

	err = ssdfs_dynamic_array_copy_content(&array, copy_buf, buf_size);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify copied content */
	for (int i = 0; i < 5; i++) {
		KUNIT_EXPECT_TRUE(test, verify_test_item(&copy_buf[i], i));
	}

	kfree(copy_buf);
	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_copy_content_folio_vec(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item, *copy_buf;
	size_t buf_size;
	int err;

	err = ssdfs_dynamic_array_create(&array, LARGE_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Set some items */
	for (int i = 0; i < 10; i++) {
		init_test_item(&item, i);
		err = ssdfs_dynamic_array_set(&array, i, &item);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	buf_size = 10 * sizeof(struct test_item);
	copy_buf = kzalloc(buf_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, copy_buf);

	err = ssdfs_dynamic_array_copy_content(&array, copy_buf, buf_size);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify copied content */
	for (int i = 0; i < 10; i++) {
		KUNIT_EXPECT_TRUE(test, verify_test_item(&copy_buf[i], i));
	}

	kfree(copy_buf);
	ssdfs_dynamic_array_destroy(&array);
}

/*
 * Test cases for ssdfs_dynamic_array_copy_content_range()
 */
static void test_dynamic_array_copy_content_range_buffer(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item, copy_buf[5];
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);
	KUNIT_ASSERT_EQ(test, SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER, array.state);

	for (int i = 0; i < 8; i++) {
		init_test_item(&item, i);
		err = ssdfs_dynamic_array_set(&array, i, &item);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	memset(copy_buf, 0, sizeof(copy_buf));

	/* Copy items [3, 8) */
	err = ssdfs_dynamic_array_copy_content_range(&array, 3, 5,
						     copy_buf,
						     sizeof(copy_buf));
	KUNIT_EXPECT_EQ(test, 0, err);

	for (int i = 0; i < 5; i++)
		KUNIT_EXPECT_TRUE(test, verify_test_item(&copy_buf[i], 3 + i));

	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_copy_content_range_folio_vec(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item, *copy_buf;
	u32 items_count, start_index, count;
	size_t buf_size;
	int err;

	err = ssdfs_dynamic_array_create(&array, LARGE_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);
	KUNIT_ASSERT_EQ(test, SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC,
			array.state);

	items_count = (array.items_per_folio * 3) + 10;

	for (u32 i = 0; i < items_count; i++) {
		init_test_item(&item, i);
		err = ssdfs_dynamic_array_set(&array, i, &item);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	/* Range starts inside the first folio and crosses two boundaries */
	start_index = array.items_per_folio - 3;
	count = array.items_per_folio + 6;

	buf_size = count * sizeof(struct test_item);
	copy_buf = kzalloc(buf_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, copy_buf);

	err = ssdfs_dynamic_array_copy_content_range(&array, start_index,
						     count, copy_buf,
						     buf_size);
	KUNIT_EXPECT_EQ(test, 0, err);

	for (u32 i = 0; i < count; i++) {
		KUNIT_EXPECT_TRUE(test,
				  verify_test_item(&copy_buf[i],
						   start_index + i));
	}

	kfree(copy_buf);
	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_copy_content_range_invalid(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item, copy_buf[4];
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	for (int i = 0; i < 5; i++) {
		init_test_item(&item, i);
		err = ssdfs_dynamic_array_set(&array, i, &item);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	/* Range is out of items count */
	err = ssdfs_dynamic_array_copy_content_range(&array, 3, 3,
						     copy_buf,
						     sizeof(copy_buf));
	KUNIT_EXPECT_EQ(test, -ERANGE, err);

	/* Buffer is too small */
	err = ssdfs_dynamic_array_copy_content_range(&array, 0, 5,
						     copy_buf,
						     sizeof(copy_buf));
	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	/* Empty range */
	err = ssdfs_dynamic_array_copy_content_range(&array, 5, 0,
						     copy_buf,
						     sizeof(copy_buf));
	KUNIT_EXPECT_EQ(test, 0, err);

	ssdfs_dynamic_array_destroy(&array);
}

/*
 * Test cases for ssdfs_dynamic_array_shift_content_right()
 */
static void test_dynamic_array_shift_content_right_buffer(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item, *retrieved_item;
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Set some items */
	for (int i = 0; i < 5; i++) {
		init_test_item(&item, i);
		err = ssdfs_dynamic_array_set(&array, i, &item);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	/* Shift content right by 2 positions starting from index 2 */
	err = ssdfs_dynamic_array_shift_content_right(&array, 2, 2);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 7, array.items_count);

	/* Verify shifted content */
	retrieved_item = ssdfs_dynamic_array_get_locked(&array, 4);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, retrieved_item);
	KUNIT_EXPECT_TRUE(test, verify_test_item(retrieved_item, 2));
	err = ssdfs_dynamic_array_release(&array, 4, retrieved_item);
	KUNIT_EXPECT_EQ(test, 0, err);

	retrieved_item = ssdfs_dynamic_array_get_locked(&array, 6);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, retrieved_item);
	KUNIT_EXPECT_TRUE(test, verify_test_item(retrieved_item, 4));
	err = ssdfs_dynamic_array_release(&array, 6, retrieved_item);
	KUNIT_EXPECT_EQ(test, 0, err);

	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_shift_content_right_folio_vec(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item, *retrieved_item;
	int err;

	err = ssdfs_dynamic_array_create(&array, LARGE_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Set some items across folio boundaries */
	for (int i = 0; i < 10; i++) {
		init_test_item(&item, i);
		err = ssdfs_dynamic_array_set(&array, i, &item);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	/* Shift content right by 3 positions starting from index 3 */
	err = ssdfs_dynamic_array_shift_content_right(&array, 3, 3);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 13, array.items_count);

	/* Verify shifted content */
	retrieved_item = ssdfs_dynamic_array_get_locked(&array, 6);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, retrieved_item);
	KUNIT_EXPECT_TRUE(test, verify_test_item(retrieved_item, 3));
	err = ssdfs_dynamic_array_release(&array, 6, retrieved_item);
	KUNIT_EXPECT_EQ(test, 0, err);

	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_shift_out_of_capacity(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item;
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Fill array to capacity */
	for (int i = 0; i < SMALL_CAPACITY; i++) {
		init_test_item(&item, i);
		err = ssdfs_dynamic_array_set(&array, i, &item);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	/* Try to shift with shift value that would exceed capacity */
	err = ssdfs_dynamic_array_shift_content_right(&array, 5, 10);
	KUNIT_EXPECT_EQ(test, -ERANGE, err);

	ssdfs_dynamic_array_destroy(&array);
}

/*
 * Test cases for ssdfs_dynamic_array_shift_content_left()
 */
static void test_dynamic_array_shift_content_left_buffer(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item, *retrieved_item;
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Set some items */
	for (int i = 0; i < 7; i++) {
		init_test_item(&item, i);
		err = ssdfs_dynamic_array_set(&array, i, &item);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	/* Shift content left by 2 positions starting from index 4 */
	err = ssdfs_dynamic_array_shift_content_left(&array, 4, 2);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 5, array.items_count);

	/* Verify untouched and shifted content */
	for (int i = 0; i < 5; i++) {
		u32 expected = i < 2 ? i : i + 2;

		retrieved_item = ssdfs_dynamic_array_get_locked(&array, i);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, retrieved_item);
		KUNIT_EXPECT_TRUE(test,
				  verify_test_item(retrieved_item, expected));
		err = ssdfs_dynamic_array_release(&array, i, retrieved_item);
		KUNIT_EXPECT_EQ(test, 0, err);
	}

	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_shift_content_left_folio_vec(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item, *retrieved_item;
	u32 items_count;
	u32 shift = 5;
	u32 start_index;
	int err;

	err = ssdfs_dynamic_array_create(&array, LARGE_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Set items across several folio boundaries */
	items_count = (array.items_per_folio * 2) + 10;
	start_index = array.items_per_folio - 2;

	for (u32 i = 0; i < items_count; i++) {
		init_test_item(&item, i);
		err = ssdfs_dynamic_array_set(&array, i, &item);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	err = ssdfs_dynamic_array_shift_content_left(&array,
						     start_index, shift);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, items_count - shift, array.items_count);

	/* Verify untouched and shifted content */
	for (u32 i = 0; i < items_count - shift; i++) {
		u32 expected = i < (start_index - shift) ? i : i + shift;

		retrieved_item = ssdfs_dynamic_array_get_locked(&array, i);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, retrieved_item);
		KUNIT_EXPECT_TRUE(test,
				  verify_test_item(retrieved_item, expected));
		err = ssdfs_dynamic_array_release(&array, i, retrieved_item);
		KUNIT_EXPECT_EQ(test, 0, err);
	}

	/* Vacated tail is initialized by allocation pattern */
	for (u32 i = items_count - shift; i < items_count; i++) {
		retrieved_item = ssdfs_dynamic_array_get_locked(&array, i);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, retrieved_item);
		KUNIT_EXPECT_EQ(test, *(u8 *)retrieved_item, (u8)TEST_PATTERN);
		err = ssdfs_dynamic_array_release(&array, i, retrieved_item);
		KUNIT_EXPECT_EQ(test, 0, err);
	}

	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_shift_left_invalid(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item;
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	for (int i = 0; i < 5; i++) {
		init_test_item(&item, i);
		err = ssdfs_dynamic_array_set(&array, i, &item);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	/* Shift is bigger than start index */
	err = ssdfs_dynamic_array_shift_content_left(&array, 2, 3);
	KUNIT_EXPECT_EQ(test, -ERANGE, err);

	/* Start index is beyond items count */
	err = ssdfs_dynamic_array_shift_content_left(&array, 6, 1);
	KUNIT_EXPECT_EQ(test, -ERANGE, err);

	KUNIT_EXPECT_EQ(test, 5, array.items_count);

	ssdfs_dynamic_array_destroy(&array);
}

/*
 * Test cases for ssdfs_dynamic_array_set_content()
 */
static u8 payload_test_byte(u32 index, u32 byte)
{
	return (u8)((index * 7) + byte + 1);
}

/*
 * fill @payload by @count items of @item_size as contiguous byte stream
 * that is stored into folios of @order
 */
static int __create_test_payload(struct ssdfs_payload_content *payload,
				 size_t item_size, u32 count,
				 unsigned int order)
{
	u32 payload_folio_size = PAGE_SIZE << order;
	u32 bytes_count = count * item_size;
	u32 folios_count = DIV_ROUND_UP(bytes_count, payload_folio_size);
	u32 i;
	int err;

	err = ssdfs_folio_vector_create(&payload->batch, order,
					max_t(u32, folios_count, 1));
	if (err)
		return err;

	payload->bytes_count = bytes_count;

	for (i = 0; i < folios_count; i++) {
		struct folio *folio;
		u32 page_off;

		folio = ssdfs_folio_vector_allocate(&payload->batch);
		if (IS_ERR_OR_NULL(folio))
			return folio == NULL ? -ENOMEM : PTR_ERR(folio);

		if (folio_size(folio) != payload_folio_size)
			return -ERANGE;

		for (page_off = 0; page_off < payload_folio_size;
		     page_off += PAGE_SIZE) {
			u8 *kaddr = kmap_local_folio(folio, page_off);
			u32 j;

			for (j = 0; j < PAGE_SIZE; j++) {
				u32 offset = (i * payload_folio_size) + page_off + j;

				kaddr[j] = payload_test_byte(offset / item_size,
							offset % item_size);
			}
			kunmap_local(kaddr);
		}
	}

	return 0;
}

static int create_test_payload(struct ssdfs_payload_content *payload,
			       size_t item_size, u32 count)
{
	return __create_test_payload(payload, item_size, count, 0);
}

static void destroy_test_payload(struct ssdfs_payload_content *payload)
{
	ssdfs_folio_vector_release(&payload->batch);
	ssdfs_folio_vector_destroy(&payload->batch);
	payload->bytes_count = 0;
}

static bool verify_payload_item_at(struct ssdfs_dynamic_array *array,
				   u32 index, u32 data_index)
{
	u8 *kaddr;
	bool is_valid = true;
	u32 j;
	int err;

	kaddr = ssdfs_dynamic_array_get_locked(array, index);
	if (IS_ERR_OR_NULL(kaddr))
		return false;

	for (j = 0; j < array->item_size; j++) {
		if (kaddr[j] != payload_test_byte(data_index, j)) {
			is_valid = false;
			break;
		}
	}

	err = ssdfs_dynamic_array_release(array, index, kaddr);
	return is_valid && !err;
}

static bool verify_payload_item(struct ssdfs_dynamic_array *array, u32 index)
{
	return verify_payload_item_at(array, index, index);
}

static bool verify_pattern_item(struct ssdfs_dynamic_array *array, u32 index)
{
	u8 *kaddr;
	bool is_valid;
	int err;

	kaddr = ssdfs_dynamic_array_get_locked(array, index);
	if (IS_ERR_OR_NULL(kaddr))
		return false;

	is_valid = memchr_inv(kaddr, array->alloc_pattern,
			      array->item_size) == NULL;

	err = ssdfs_dynamic_array_release(array, index, kaddr);
	return is_valid && !err;
}

static void test_dynamic_array_set_content_buffer(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct ssdfs_payload_content payload;
	struct test_item item;
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);
	KUNIT_ASSERT_EQ(test, SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER, array.state);

	/* Previous content is longer than the payload */
	for (int i = 0; i < 8; i++) {
		init_test_item(&item, i);
		err = ssdfs_dynamic_array_set(&array, i, &item);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	err = create_test_payload(&payload, sizeof(struct test_item), 6);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_dynamic_array_set_content(&array, &payload);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 6, array.items_count);

	for (u32 i = 0; i < 6; i++)
		KUNIT_EXPECT_TRUE(test, verify_payload_item(&array, i));

	/* Stale items are initialized by allocation pattern */
	for (u32 i = 6; i < 8; i++)
		KUNIT_EXPECT_TRUE(test, verify_pattern_item(&array, i));

	destroy_test_payload(&payload);
	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_set_content_folio_vec(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct ssdfs_payload_content payload;
	/* item size that doesn't divide page size: items cross folios */
	size_t item_size = 24;
	u32 items_count = 500;
	int err;

	err = ssdfs_dynamic_array_create(&array, LARGE_CAPACITY,
					 item_size, TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);
	KUNIT_ASSERT_EQ(test, SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC,
			array.state);
	KUNIT_ASSERT_LT(test, array.items_per_folio * 2, items_count);

	err = create_test_payload(&payload, item_size, items_count);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_dynamic_array_set_content(&array, &payload);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, items_count, array.items_count);

	for (u32 i = 0; i < items_count; i++)
		KUNIT_EXPECT_TRUE(test, verify_payload_item(&array, i));

	destroy_test_payload(&payload);
	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_set_content_folio_order(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct ssdfs_payload_content payload;
	/* item size that doesn't divide folio size: items cross folios */
	size_t item_size = 24;
	u32 items_count = 1000;
	unsigned int order = 1;
	int err;

	err = ssdfs_dynamic_array_create(&array, LARGE_CAPACITY,
					 item_size, TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);
	KUNIT_ASSERT_EQ(test, SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC,
			array.state);

	/* 24000 bytes: three 8K folios */
	err = __create_test_payload(&payload, item_size, items_count, order);
	KUNIT_ASSERT_EQ(test, 0, err);
	KUNIT_ASSERT_EQ(test, 3, ssdfs_folio_vector_count(&payload.batch));

	err = ssdfs_dynamic_array_set_content(&array, &payload);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, items_count, array.items_count);

	for (u32 i = 0; i < items_count; i++)
		KUNIT_EXPECT_TRUE(test, verify_payload_item(&array, i));

	destroy_test_payload(&payload);
	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_set_content_invalid(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct ssdfs_payload_content payload;
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Payload is bigger than array's capacity */
	err = create_test_payload(&payload, sizeof(struct test_item),
				  SMALL_CAPACITY + 1);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_dynamic_array_set_content(&array, &payload);
	KUNIT_EXPECT_EQ(test, -E2BIG, err);

	/* Payload isn't aligned on item size */
	payload.bytes_count = sizeof(struct test_item) + 1;
	err = ssdfs_dynamic_array_set_content(&array, &payload);
	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	KUNIT_EXPECT_EQ(test, 0, array.items_count);

	destroy_test_payload(&payload);
	ssdfs_dynamic_array_destroy(&array);
}

/*
 * Set payload content, shift it right to fill the capacity exactly,
 * and set the head items (the way meta extents array is built).
 */
static void check_set_content_shift_and_set_head(struct kunit *test,
						 u32 head_count,
						 u32 tail_count,
						 int expected_state)
{
	struct ssdfs_dynamic_array array;
	struct ssdfs_payload_content payload;
	struct test_item item;
	u32 capacity = head_count + tail_count;
	int err;

	err = ssdfs_dynamic_array_create(&array, capacity,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);
	KUNIT_ASSERT_EQ(test, expected_state, array.state);

	err = create_test_payload(&payload, sizeof(struct test_item),
				  tail_count);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_dynamic_array_set_content(&array, &payload);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, tail_count, array.items_count);

	err = ssdfs_dynamic_array_shift_content_right(&array, 0, head_count);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, capacity, array.items_count);

	for (u32 i = 0; i < head_count; i++) {
		init_test_item(&item, i);
		err = ssdfs_dynamic_array_set(&array, i, &item);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	KUNIT_EXPECT_EQ(test, capacity, array.items_count);

	for (u32 i = 0; i < head_count; i++) {
		struct test_item *retrieved_item;

		retrieved_item = ssdfs_dynamic_array_get_locked(&array, i);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, retrieved_item);
		KUNIT_EXPECT_TRUE(test, verify_test_item(retrieved_item, i));
		err = ssdfs_dynamic_array_release(&array, i, retrieved_item);
		KUNIT_EXPECT_EQ(test, 0, err);
	}

	for (u32 i = 0; i < tail_count; i++) {
		KUNIT_EXPECT_TRUE(test,
				  verify_payload_item_at(&array,
							 head_count + i, i));
	}

	destroy_test_payload(&payload);
	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_set_content_shift_buffer(struct kunit *test)
{
	check_set_content_shift_and_set_head(test, 3, 7,
					SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER);
}

static void test_dynamic_array_set_content_shift_folio_vec(struct kunit *test)
{
	/* 16 bytes items: 300 items need two folios */
	check_set_content_shift_and_set_head(test, 4, 296,
					SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC);
}

/*
 * Test cases for inline functions
 */
static void test_dynamic_array_allocated_bytes(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	KUNIT_EXPECT_EQ(test, array.bytes_count,
			ssdfs_dynamic_array_allocated_bytes(&array));

	ssdfs_dynamic_array_destroy(&array);
}

static void test_dynamic_array_items_count(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	int err;

	err = ssdfs_dynamic_array_create(&array, SMALL_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	KUNIT_EXPECT_GT(test, ssdfs_dynamic_array_items_count(&array), 0);

	ssdfs_dynamic_array_destroy(&array);
}

/*
 * Complex integration test cases
 */
static void test_dynamic_array_complex_operations(struct kunit *test)
{
	struct ssdfs_dynamic_array array;
	struct test_item item, *retrieved_item, *copy_buf;
	size_t buf_size;
	int err;

	/* Create array */
	err = ssdfs_dynamic_array_create(&array, TEST_CAPACITY,
					 sizeof(struct test_item), TEST_PATTERN);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Set some initial items */
	for (int i = 0; i < 10; i++) {
		init_test_item(&item, i);
		err = ssdfs_dynamic_array_set(&array, i, &item);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	/* Shift content to make room for insertion */
	err = ssdfs_dynamic_array_shift_content_right(&array, 5, 2);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Insert new items in the gap */
	init_test_item(&item, 100);
	err = ssdfs_dynamic_array_set(&array, 5, &item);
	KUNIT_EXPECT_EQ(test, 0, err);

	init_test_item(&item, 101);
	err = ssdfs_dynamic_array_set(&array, 6, &item);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify the complex structure */
	retrieved_item = ssdfs_dynamic_array_get_locked(&array, 5);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, retrieved_item);
	KUNIT_EXPECT_TRUE(test, verify_test_item(retrieved_item, 100));
	err = ssdfs_dynamic_array_release(&array, 5, retrieved_item);
	KUNIT_EXPECT_EQ(test, 0, err);

	retrieved_item = ssdfs_dynamic_array_get_locked(&array, 7);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, retrieved_item);
	KUNIT_EXPECT_TRUE(test, verify_test_item(retrieved_item, 5));
	err = ssdfs_dynamic_array_release(&array, 7, retrieved_item);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Copy the entire content */
	buf_size = array.items_count * sizeof(struct test_item);
	copy_buf = kzalloc(buf_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, copy_buf);

	err = ssdfs_dynamic_array_copy_content(&array, copy_buf, buf_size);
	KUNIT_EXPECT_EQ(test, 0, err);

	/* Verify some key positions in the copy */
	KUNIT_EXPECT_TRUE(test, verify_test_item(&copy_buf[5], 100));
	KUNIT_EXPECT_TRUE(test, verify_test_item(&copy_buf[6], 101));
	KUNIT_EXPECT_TRUE(test, verify_test_item(&copy_buf[7], 5));

	kfree(copy_buf);
	ssdfs_dynamic_array_destroy(&array);
}

static struct kunit_case dynamic_array_test_cases[] = {
	KUNIT_CASE(test_dynamic_array_create_valid_small),
	KUNIT_CASE(test_dynamic_array_create_valid_large),
	KUNIT_CASE(test_dynamic_array_create_zero_capacity),
	KUNIT_CASE(test_dynamic_array_create_zero_item_size),
	KUNIT_CASE(test_dynamic_array_create_large_item_size),
	KUNIT_CASE(test_dynamic_array_destroy_buffer),
	KUNIT_CASE(test_dynamic_array_destroy_folio_vec),
	KUNIT_CASE(test_dynamic_array_get_release_buffer),
	KUNIT_CASE(test_dynamic_array_get_release_folio_vec),
	KUNIT_CASE(test_dynamic_array_get_out_of_range),
	KUNIT_CASE(test_dynamic_array_set_buffer),
	KUNIT_CASE(test_dynamic_array_set_folio_vec),
	KUNIT_CASE(test_dynamic_array_set_out_of_range),
	KUNIT_CASE(test_dynamic_array_get_content_locked_buffer),
	KUNIT_CASE(test_dynamic_array_get_content_locked_folio_vec),
	KUNIT_CASE(test_dynamic_array_copy_content_buffer),
	KUNIT_CASE(test_dynamic_array_copy_content_folio_vec),
	KUNIT_CASE(test_dynamic_array_copy_content_range_buffer),
	KUNIT_CASE(test_dynamic_array_copy_content_range_folio_vec),
	KUNIT_CASE(test_dynamic_array_copy_content_range_invalid),
	KUNIT_CASE(test_dynamic_array_shift_content_right_buffer),
	KUNIT_CASE(test_dynamic_array_shift_content_right_folio_vec),
	KUNIT_CASE(test_dynamic_array_shift_content_left_buffer),
	KUNIT_CASE(test_dynamic_array_shift_content_left_folio_vec),
	KUNIT_CASE(test_dynamic_array_shift_left_invalid),
	KUNIT_CASE(test_dynamic_array_set_content_buffer),
	KUNIT_CASE(test_dynamic_array_set_content_folio_vec),
	KUNIT_CASE(test_dynamic_array_set_content_folio_order),
	KUNIT_CASE(test_dynamic_array_set_content_invalid),
	KUNIT_CASE(test_dynamic_array_set_content_shift_buffer),
	KUNIT_CASE(test_dynamic_array_set_content_shift_folio_vec),
	KUNIT_CASE(test_dynamic_array_shift_out_of_capacity),
	KUNIT_CASE(test_dynamic_array_allocated_bytes),
	KUNIT_CASE(test_dynamic_array_items_count),
	KUNIT_CASE(test_dynamic_array_complex_operations),
	{}
};

static struct kunit_suite dynamic_array_test_suite = {
	.name = "ssdfs_dynamic_array",
	.test_cases = dynamic_array_test_cases,
};

kunit_test_suites(&dynamic_array_test_suite);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Viacheslav Dubeyko <slava@dubeyko.com>");
MODULE_DESCRIPTION("KUnit tests for SSDFS dynamic array");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
