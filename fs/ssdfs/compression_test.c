// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/compression_test.c - KUnit tests for compression functionality.
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
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "compression.h"

/*
 * Test data helper functions
 */
static void fill_test_data(unsigned char *data, size_t size, int pattern)
{
	size_t i;

	switch (pattern) {
	case 0: /* zeros */
		memset(data, 0, size);
		break;
	case 1: /* repeating pattern */
		for (i = 0; i < size; i++)
			data[i] = (unsigned char)(i % 256);
		break;
	case 2: /* highly compressible */
		for (i = 0; i < size; i++)
			data[i] = (unsigned char)(i % 4);
		break;
	case 3: /* random data */
		get_random_bytes(data, size);
		break;
	default:
		memset(data, 0xAA, size);
		break;
	}
}

static struct page *create_test_page(int pattern)
{
	struct page *page;
	unsigned char *kaddr;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return NULL;

	kaddr = kmap_local_page(page);
	fill_test_data(kaddr, PAGE_SIZE, pattern);
	kunmap_local(kaddr);

	return page;
}

/*
 * Test cases for compression algorithms registry
 */
static void test_register_unregister_compressor(struct kunit *test)
{
	struct ssdfs_compressor test_compr = {
		.type = SSDFS_COMPR_NONE,
		.name = "test",
		.compr_ops = NULL,
	};
	int err;

	/* Test register */
	err = ssdfs_register_compressor(&test_compr);
	KUNIT_EXPECT_EQ(test, err, 0);
	KUNIT_EXPECT_PTR_EQ(test, ssdfs_compressors[SSDFS_COMPR_NONE], &test_compr);

	/* Test unregister */
	err = ssdfs_unregister_compressor(&test_compr);
	KUNIT_EXPECT_EQ(test, err, 0);
	KUNIT_EXPECT_PTR_EQ(test, ssdfs_compressors[SSDFS_COMPR_NONE], NULL);
}

/*
 * Test cases for compression capability checking
 */
static void test_can_compress_data_zeros(struct kunit *test)
{
	struct page *page;
	bool result;

	page = create_test_page(0); /* zeros */
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, page);

	result = ssdfs_can_compress_data(page, PAGE_SIZE);
	KUNIT_EXPECT_TRUE(test, result);

	__free_page(page);
}

static void test_can_compress_data_compressible(struct kunit *test)
{
	struct page *page;
	bool result;

	page = create_test_page(2); /* highly compressible */
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, page);

	result = ssdfs_can_compress_data(page, PAGE_SIZE);
	KUNIT_EXPECT_TRUE(test, result);

	__free_page(page);
}

static void test_can_compress_data_random(struct kunit *test)
{
	struct page *page;
	bool result;

	page = create_test_page(3); /* random data */
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, page);

	result = ssdfs_can_compress_data(page, PAGE_SIZE);
	KUNIT_EXPECT_FALSE(test, result);

	__free_page(page);
}

static void test_can_compress_data_invalid_size(struct kunit *test)
{
	struct page *page;
	bool result;

	page = create_test_page(0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, page);

	result = ssdfs_can_compress_data(page, 0);
	KUNIT_EXPECT_TRUE(test, result);

	__free_page(page);
}

/*
 * Test cases for NONE compression
 */
static void test_none_compress_valid_input(struct kunit *test)
{
	unsigned char *data_in, *cdata_out;
	size_t srclen = PAGE_SIZE;
	size_t destlen = PAGE_SIZE;
	int err;

	data_in = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	cdata_out = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data_in);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cdata_out);

	fill_test_data(data_in, PAGE_SIZE, 1);

	err = ssdfs_compress(SSDFS_COMPR_NONE, data_in, cdata_out,
			     &srclen, &destlen);
	KUNIT_EXPECT_EQ(test, err, 0);
	KUNIT_EXPECT_EQ(test, srclen, PAGE_SIZE);
	KUNIT_EXPECT_EQ(test, destlen, PAGE_SIZE);
	KUNIT_EXPECT_MEMEQ(test, data_in, cdata_out, PAGE_SIZE);

	kvfree(data_in);
	kvfree(cdata_out);
}

static void test_none_compress_small_dest_buffer(struct kunit *test)
{
	unsigned char *data_in, *cdata_out;
	size_t srclen = PAGE_SIZE;
	size_t destlen = PAGE_SIZE / 2;
	int err;

	data_in = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	cdata_out = kvzalloc(PAGE_SIZE / 2, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data_in);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cdata_out);

	fill_test_data(data_in, PAGE_SIZE, 1);

	err = ssdfs_compress(SSDFS_COMPR_NONE, data_in, cdata_out,
			     &srclen, &destlen);
	KUNIT_EXPECT_EQ(test, err, -E2BIG);

	kvfree(data_in);
	kvfree(cdata_out);
}

/*
 * Test cases for compression/decompression with invalid types
 */
static void test_compress_invalid_type(struct kunit *test)
{
	unsigned char *data_in, *cdata_out;
	size_t srclen = PAGE_SIZE;
	size_t destlen = PAGE_SIZE;
	int err;

	data_in = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	cdata_out = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data_in);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cdata_out);

	/* Test with invalid compression type */
	err = ssdfs_compress(SSDFS_COMPR_TYPES_CNT, data_in, cdata_out,
			     &srclen, &destlen);
	KUNIT_EXPECT_EQ(test, err, -EOPNOTSUPP);

	kvfree(data_in);
	kvfree(cdata_out);
}

static void test_decompress_invalid_type(struct kunit *test)
{
	unsigned char *cdata_in, *data_out;
	size_t srclen = PAGE_SIZE;
	size_t destlen = PAGE_SIZE;
	int err;

	cdata_in = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	data_out = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cdata_in);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data_out);

	/* Test with invalid compression type */
	err = ssdfs_decompress(SSDFS_COMPR_TYPES_CNT, cdata_in, data_out,
			       srclen, destlen);
	KUNIT_EXPECT_EQ(test, err, -EOPNOTSUPP);

	kvfree(cdata_in);
	kvfree(data_out);
}

/*
 * Test cases for compression subsystem initialization
 */
static void test_compressors_init_exit(struct kunit *test)
{
	int err;

	/* Test initialization */
	err = ssdfs_compressors_init();
	KUNIT_EXPECT_EQ(test, err, 0);

	/* Verify that compressors are registered */
	KUNIT_EXPECT_NOT_NULL(test, ssdfs_compressors[SSDFS_COMPR_NONE]);

	/* Test cleanup */
	ssdfs_compressors_exit();

	/* After exit, none compressor should be unregistered */
	KUNIT_EXPECT_NULL(test, ssdfs_compressors[SSDFS_COMPR_NONE]);
}

/*
 * KUnit test suite definition
 */
static struct kunit_case ssdfs_compression_test_cases[] = {
	KUNIT_CASE(test_register_unregister_compressor),
	KUNIT_CASE(test_can_compress_data_zeros),
	KUNIT_CASE(test_can_compress_data_compressible),
	KUNIT_CASE(test_can_compress_data_random),
	KUNIT_CASE(test_can_compress_data_invalid_size),
	KUNIT_CASE(test_none_compress_valid_input),
	KUNIT_CASE(test_none_compress_small_dest_buffer),
	KUNIT_CASE(test_compress_invalid_type),
	KUNIT_CASE(test_decompress_invalid_type),
	KUNIT_CASE(test_compressors_init_exit),
	{}
};

static int ssdfs_compression_test_init(struct kunit *test)
{
	/* Initialize compression subsystem for testing */
	return ssdfs_compressors_init();
}

static void ssdfs_compression_test_exit(struct kunit *test)
{
	/* Cleanup compression subsystem */
	ssdfs_compressors_exit();
}

static struct kunit_suite ssdfs_compression_test_suite = {
	.name = "ssdfs-compression",
	.init = ssdfs_compression_test_init,
	.exit = ssdfs_compression_test_exit,
	.test_cases = ssdfs_compression_test_cases,
};

kunit_test_suite(ssdfs_compression_test_suite);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Viacheslav Dubeyko <slava@dubeyko.com>");
MODULE_DESCRIPTION("KUnit tests for SSDFS compression functionality");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
