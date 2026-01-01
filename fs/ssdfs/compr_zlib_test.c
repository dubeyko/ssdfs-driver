// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/compr_zlib_test.c - KUnit tests for ZLIB compression.
 *
 * Copyright (c) 2025-2026 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <linux/zlib.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "compression.h"

/*
 * Test data patterns
 */
static void fill_test_pattern(unsigned char *data, size_t size, int pattern)
{
	size_t i;

	switch (pattern) {
	case 0: /* zeros */
		memset(data, 0, size);
		break;
	case 1: /* ones */
		memset(data, 0xFF, size);
		break;
	case 2: /* alternating bytes */
		for (i = 0; i < size; i++)
			data[i] = (i % 2) ? 0xAA : 0x55;
		break;
	case 3: /* sequential pattern */
		for (i = 0; i < size; i++)
			data[i] = (unsigned char)(i % 256);
		break;
	case 4: /* highly compressible */
		for (i = 0; i < size; i++)
			data[i] = (unsigned char)(i % 8);
		break;
	case 5: /* random data */
		get_random_bytes(data, size);
		break;
	default:
		memset(data, 0xCC, size);
		break;
	}
}

/*
 * Test ZLIB initialization and cleanup
 */
static void test_zlib_init_exit(struct kunit *test)
{
	int err;

	/* Test ZLIB initialization */
	err = ssdfs_zlib_init();
	KUNIT_EXPECT_EQ(test, err, 0);

	/* Verify ZLIB compressor is registered */
	KUNIT_EXPECT_NOT_NULL(test, ssdfs_compressors[SSDFS_COMPR_ZLIB]);
	if (ssdfs_compressors[SSDFS_COMPR_ZLIB]) {
		KUNIT_EXPECT_STREQ(test, ssdfs_compressors[SSDFS_COMPR_ZLIB]->name, "zlib");
		KUNIT_EXPECT_EQ(test, ssdfs_compressors[SSDFS_COMPR_ZLIB]->type, SSDFS_COMPR_ZLIB);
		KUNIT_EXPECT_NOT_NULL(test, ssdfs_compressors[SSDFS_COMPR_ZLIB]->compr_ops);
	}

	/* Test ZLIB cleanup */
	ssdfs_zlib_exit();

	/* Verify ZLIB compressor is unregistered */
	KUNIT_EXPECT_NULL(test, ssdfs_compressors[SSDFS_COMPR_ZLIB]);
}

/*
 * Test ZLIB workspace allocation and deallocation
 */
static void test_zlib_workspace_alloc_free(struct kunit *test)
{
	struct list_head *workspace;
	const struct ssdfs_compress_ops *ops;
	int err;

	/* Initialize ZLIB */
	err = ssdfs_zlib_init();
	KUNIT_ASSERT_EQ(test, err, 0);

	ops = ssdfs_compressors[SSDFS_COMPR_ZLIB]->compr_ops;
	KUNIT_ASSERT_NOT_NULL(test, ops);
	KUNIT_ASSERT_NOT_NULL(test, ops->alloc_workspace);
	KUNIT_ASSERT_NOT_NULL(test, ops->free_workspace);

	/* Test workspace allocation */
	workspace = ops->alloc_workspace();
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, workspace);

	/* Test workspace deallocation */
	if (!IS_ERR_OR_NULL(workspace))
		ops->free_workspace(workspace);

	/* Cleanup */
	ssdfs_zlib_exit();
}

/*
 * Test ZLIB compression with different data patterns
 */
static void test_zlib_compress_zeros(struct kunit *test)
{
	unsigned char *data_in, *cdata_out;
	size_t srclen = PAGE_SIZE;
	size_t destlen = PAGE_SIZE;
	int err;

	/* Initialize ZLIB */
	err = ssdfs_zlib_init();
	KUNIT_ASSERT_EQ(test, err, 0);

	data_in = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	cdata_out = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data_in);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cdata_out);

	/* Fill with zeros (highly compressible) */
	fill_test_pattern(data_in, PAGE_SIZE, 0);

	err = ssdfs_compress(SSDFS_COMPR_ZLIB, data_in, cdata_out,
			     &srclen, &destlen);
	KUNIT_EXPECT_EQ(test, err, 0);
	KUNIT_EXPECT_EQ(test, srclen, PAGE_SIZE);
	KUNIT_EXPECT_LT(test, destlen, PAGE_SIZE); /* Should compress well */

	kvfree(data_in);
	kvfree(cdata_out);
	ssdfs_zlib_exit();
}

static void test_zlib_compress_compressible(struct kunit *test)
{
	unsigned char *data_in, *cdata_out;
	size_t srclen = PAGE_SIZE;
	size_t destlen = PAGE_SIZE;
	int err;

	/* Initialize ZLIB */
	err = ssdfs_zlib_init();
	KUNIT_ASSERT_EQ(test, err, 0);

	data_in = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	cdata_out = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data_in);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cdata_out);

	/* Fill with highly compressible pattern */
	fill_test_pattern(data_in, PAGE_SIZE, 4);

	err = ssdfs_compress(SSDFS_COMPR_ZLIB, data_in, cdata_out,
			     &srclen, &destlen);
	KUNIT_EXPECT_EQ(test, err, 0);
	KUNIT_EXPECT_EQ(test, srclen, PAGE_SIZE);
	KUNIT_EXPECT_LT(test, destlen, PAGE_SIZE); /* Should compress well */

	kvfree(data_in);
	kvfree(cdata_out);
	ssdfs_zlib_exit();
}

static void test_zlib_compress_random(struct kunit *test)
{
	unsigned char *data_in, *cdata_out;
	size_t srclen = PAGE_SIZE;
	size_t destlen = PAGE_SIZE;
	int err;

	/* Initialize ZLIB */
	err = ssdfs_zlib_init();
	KUNIT_ASSERT_EQ(test, err, 0);

	data_in = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	cdata_out = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data_in);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cdata_out);

	/* Fill with random data (may not compress well) */
	fill_test_pattern(data_in, PAGE_SIZE, 5);

	err = ssdfs_compress(SSDFS_COMPR_ZLIB, data_in, cdata_out,
			     &srclen, &destlen);
	/* Random data may not compress, so -E2BIG is acceptable */
	KUNIT_EXPECT_TRUE(test, err == 0 || err == -E2BIG);

	kvfree(data_in);
	kvfree(cdata_out);
	ssdfs_zlib_exit();
}

static void test_zlib_compress_small_buffer(struct kunit *test)
{
	unsigned char *data_in, *cdata_out;
	size_t srclen = PAGE_SIZE;
	size_t destlen = 16; /* Very small buffer */
	int err;

	/* Initialize ZLIB */
	err = ssdfs_zlib_init();
	KUNIT_ASSERT_EQ(test, err, 0);

	data_in = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	cdata_out = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data_in);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cdata_out);

	fill_test_pattern(data_in, PAGE_SIZE, 1);

	err = ssdfs_compress(SSDFS_COMPR_ZLIB, data_in, cdata_out,
			     &srclen, &destlen);
	KUNIT_EXPECT_EQ(test, err, -E2BIG); /* Should fail due to small buffer */

	kvfree(data_in);
	kvfree(cdata_out);
	ssdfs_zlib_exit();
}

/*
 * Test ZLIB decompression
 */
static void test_zlib_decompress_valid_data(struct kunit *test)
{
	unsigned char *data_in, *cdata_out, *data_decompressed;
	size_t srclen = PAGE_SIZE;
	size_t destlen = PAGE_SIZE;
	size_t compressed_size;
	int err;

	/* Initialize ZLIB */
	err = ssdfs_zlib_init();
	KUNIT_ASSERT_EQ(test, err, 0);

	data_in = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	cdata_out = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	data_decompressed = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data_in);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cdata_out);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data_decompressed);

	/* Fill with compressible data */
	fill_test_pattern(data_in, PAGE_SIZE, 0);

	/* Compress first */
	err = ssdfs_compress(SSDFS_COMPR_ZLIB, data_in, cdata_out,
			     &srclen, &destlen);
	KUNIT_ASSERT_EQ(test, err, 0);
	compressed_size = destlen;

	/* Now decompress */
	err = ssdfs_decompress(SSDFS_COMPR_ZLIB, cdata_out, data_decompressed,
			       compressed_size, PAGE_SIZE);
	KUNIT_EXPECT_EQ(test, err, 0);

	/* Verify data integrity */
	KUNIT_EXPECT_MEMEQ(test, data_in, data_decompressed, PAGE_SIZE);

	kvfree(data_in);
	kvfree(cdata_out);
	kvfree(data_decompressed);
	ssdfs_zlib_exit();
}

static void test_zlib_decompress_corrupted_data(struct kunit *test)
{
	unsigned char *cdata_in, *data_out;
	size_t srclen = PAGE_SIZE;
	size_t destlen = PAGE_SIZE;
	int err;

	/* Initialize ZLIB */
	err = ssdfs_zlib_init();
	KUNIT_ASSERT_EQ(test, err, 0);

	cdata_in = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	data_out = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cdata_in);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data_out);

	/* Fill with random data (not valid compressed data) */
	fill_test_pattern(cdata_in, PAGE_SIZE, 5);

	err = ssdfs_decompress(SSDFS_COMPR_ZLIB, cdata_in, data_out,
			       srclen, destlen);
	KUNIT_EXPECT_NE(test, err, 0); /* Should fail */

	kvfree(cdata_in);
	kvfree(data_out);
	ssdfs_zlib_exit();
}

/*
 * Test multiple compression/decompression cycles
 */
static void test_zlib_multiple_cycles(struct kunit *test)
{
	unsigned char *data_in, *cdata_tmp, *data_out;
	size_t srclen, destlen, compressed_size;
	int err, i;

	/* Initialize ZLIB */
	err = ssdfs_zlib_init();
	KUNIT_ASSERT_EQ(test, err, 0);

	data_in = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	cdata_tmp = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	data_out = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data_in);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cdata_tmp);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data_out);

	/* Test multiple patterns */
	for (i = 0; i < 5; i++) {
		srclen = PAGE_SIZE;
		destlen = PAGE_SIZE;

		fill_test_pattern(data_in, PAGE_SIZE, i);

		/* Compress */
		err = ssdfs_compress(SSDFS_COMPR_ZLIB, data_in, cdata_tmp,
				     &srclen, &destlen);
		if (err == -E2BIG)
			continue; /* Skip non-compressible data */

		KUNIT_EXPECT_EQ(test, err, 0);
		compressed_size = destlen;

		/* Decompress */
		err = ssdfs_decompress(SSDFS_COMPR_ZLIB, cdata_tmp, data_out,
				       compressed_size, PAGE_SIZE);
		KUNIT_EXPECT_EQ(test, err, 0);

		/* Verify data integrity */
		KUNIT_EXPECT_MEMEQ(test, data_in, data_out, PAGE_SIZE);
	}

	kvfree(data_in);
	kvfree(cdata_tmp);
	kvfree(data_out);
	ssdfs_zlib_exit();
}

/*
 * KUnit test suite definition
 */
static struct kunit_case ssdfs_compr_zlib_test_cases[] = {
	KUNIT_CASE(test_zlib_init_exit),
	KUNIT_CASE(test_zlib_workspace_alloc_free),
	KUNIT_CASE(test_zlib_compress_zeros),
	KUNIT_CASE(test_zlib_compress_compressible),
	KUNIT_CASE(test_zlib_compress_random),
	KUNIT_CASE(test_zlib_compress_small_buffer),
	KUNIT_CASE(test_zlib_decompress_valid_data),
	KUNIT_CASE(test_zlib_decompress_corrupted_data),
	KUNIT_CASE(test_zlib_multiple_cycles),
	{}
};

static int ssdfs_compr_zlib_test_init(struct kunit *test)
{
	/* Initialize compression subsystem */
	return ssdfs_compressors_init();
}

static void ssdfs_compr_zlib_test_exit(struct kunit *test)
{
	/* Cleanup compression subsystem */
	ssdfs_compressors_exit();
}

static struct kunit_suite ssdfs_compr_zlib_test_suite = {
	.name = "ssdfs-compr-zlib",
	.init = ssdfs_compr_zlib_test_init,
	.exit = ssdfs_compr_zlib_test_exit,
	.test_cases = ssdfs_compr_zlib_test_cases,
};

kunit_test_suite(ssdfs_compr_zlib_test_suite);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Viacheslav Dubeyko <slava@dubeyko.com>");
MODULE_DESCRIPTION("KUnit tests for SSDFS ZLIB compression");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
