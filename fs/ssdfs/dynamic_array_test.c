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
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "dynamic_array.h"

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
	KUNIT_CASE(test_dynamic_array_shift_content_right_buffer),
	KUNIT_CASE(test_dynamic_array_shift_content_right_folio_vec),
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
