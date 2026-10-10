// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/superblock_payload_test.c - KUnit tests for superblock
 *                                      segment's payload areas.
 *
 * Copyright (c) 2026 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include "compression.h"
#include "dynamic_array.h"
#include "superblock_payload.h"

#define TEST_CHAINS_COUNT	(2)
#define TEST_EMBEDDED_ROWS	(4)
#define TEST_FRAGMENT_SIZE	(4096)

static void init_test_extent(struct ssdfs_meta_area_extent *extent, u32 index)
{
	extent->start_id = cpu_to_le64(1000 + index);
	extent->len = cpu_to_le32((index % 7) + 1);
	extent->type = cpu_to_le16(SSDFS_SEG_EXTENT_TYPE);
	extent->flags = cpu_to_le16(0);
}

/* create complete extents array: embedded rows + @overflow_count extents */
static void create_test_extents(struct kunit *test,
				struct ssdfs_dynamic_array *extents,
				u32 overflow_count)
{
	u32 embedded_count = TEST_EMBEDDED_ROWS * TEST_CHAINS_COUNT;
	u32 total_count = embedded_count + overflow_count;
	struct ssdfs_meta_area_extent extent;
	int err;

	err = ssdfs_dynamic_array_create(extents, total_count,
					 sizeof(struct ssdfs_meta_area_extent),
					 0);
	KUNIT_ASSERT_EQ(test, 0, err);

	for (u32 i = 0; i < total_count; i++) {
		init_test_extent(&extent, i);
		err = ssdfs_dynamic_array_set(extents, i, &extent);
		KUNIT_ASSERT_EQ(test, 0, err);
	}

	KUNIT_ASSERT_EQ(test, total_count, extents->items_count);
}

/* read @len bytes from payload's byte stream at @offset */
static int read_test_payload(struct ssdfs_payload_content *payload,
			     u32 offset, void *dst, u32 len)
{
	u32 copied = 0;

	if ((u64)offset + len > payload->bytes_count)
		return -ERANGE;

	while (copied < len) {
		u32 folio_index = (offset + copied) / PAGE_SIZE;
		u32 offset_in_folio = (offset + copied) % PAGE_SIZE;
		u32 bytes = min_t(u32, PAGE_SIZE - offset_in_folio,
				  len - copied);
		struct folio *folio;
		void *kaddr;

		folio = ssdfs_folio_vector_get(&payload->batch, folio_index);
		if (!folio)
			return -ERANGE;

		kaddr = kmap_local_folio(folio, 0);
		memcpy((u8 *)dst + copied, (u8 *)kaddr + offset_in_folio,
		       bytes);
		kunmap_local(kaddr);

		copied += bytes;
	}

	return 0;
}

/*
 * Decode @payload by the same rules as the mount path does and
 * check that the decoded extents are the overflow extents.
 */
static void check_encoded_payload(struct kunit *test,
				  struct ssdfs_payload_content *payload,
				  u32 overflow_count,
				  u32 *tables_count)
{
	struct ssdfs_metadata_extents_table *tbl;
	size_t hdr_size = sizeof(struct ssdfs_metadata_extents_table);
	size_t item_size = sizeof(struct ssdfs_meta_area_extent);
	struct ssdfs_meta_area_extent *decoded, expected;
	u8 *raw;
	u32 table_offset = 0;
	u32 decoded_bytes = 0;
	u32 max_end = 0;
	int err;

	*tables_count = 0;

	KUNIT_ASSERT_GE(test, payload->bytes_count, (u32)hdr_size);
	KUNIT_EXPECT_EQ(test, DIV_ROUND_UP(payload->bytes_count, PAGE_SIZE),
			ssdfs_folio_vector_count(&payload->batch));

	tbl = kzalloc(hdr_size, GFP_KERNEL);
	raw = kzalloc(TEST_FRAGMENT_SIZE, GFP_KERNEL);
	decoded = kzalloc(overflow_count * item_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, tbl);
	KUNIT_ASSERT_NOT_NULL(test, raw);
	KUNIT_ASSERT_NOT_NULL(test, decoded);

	for (;;) {
		u32 prev_end = table_offset + hdr_size;
		u16 fragments_count;

		err = read_test_payload(payload, table_offset, tbl, hdr_size);
		KUNIT_ASSERT_EQ(test, 0, err);

		(*tables_count)++;
		max_end = max_t(u32, max_end, table_offset + hdr_size);

		KUNIT_ASSERT_EQ(test, SSDFS_CHAIN_HDR_MAGIC,
				tbl->chain_hdr.magic);
		KUNIT_ASSERT_EQ(test, (u16)sizeof(struct ssdfs_fragment_desc),
				le16_to_cpu(tbl->chain_hdr.desc_size));

		fragments_count = le16_to_cpu(tbl->chain_hdr.fragments_count);
		KUNIT_ASSERT_GT(test, fragments_count, 0);
		KUNIT_ASSERT_LE(test, fragments_count,
				SSDFS_NEXT_META_EXT_TABLE_INDEX);

		for (u16 i = 0; i < fragments_count; i++) {
			struct ssdfs_fragment_desc *frag = &tbl->blk[i];
			u32 offset = le32_to_cpu(frag->offset);
			u32 compr_size = le16_to_cpu(frag->compr_size);
			u32 uncompr_size = le16_to_cpu(frag->uncompr_size);
			u8 *dst = (u8 *)decoded + decoded_bytes;

			KUNIT_ASSERT_EQ(test, SSDFS_FRAGMENT_DESC_MAGIC,
					frag->magic);
			KUNIT_ASSERT_EQ(test, (u8)i, frag->sequence_id);
			KUNIT_ASSERT_GE(test, offset, prev_end);
			KUNIT_ASSERT_GT(test, compr_size, 0);
			KUNIT_ASSERT_LE(test, compr_size, uncompr_size);
			KUNIT_ASSERT_LE(test, uncompr_size,
					(u32)TEST_FRAGMENT_SIZE);
			KUNIT_ASSERT_EQ(test, 0, (int)(uncompr_size % item_size));
			KUNIT_ASSERT_LE(test, decoded_bytes + uncompr_size,
					(u32)(overflow_count * item_size));

			err = read_test_payload(payload, offset,
						raw, compr_size);
			KUNIT_ASSERT_EQ(test, 0, err);

			if (frag->type == SSDFS_META_EXT_BLOB) {
				KUNIT_ASSERT_EQ(test, compr_size, uncompr_size);
				memcpy(dst, raw, uncompr_size);
			} else {
				int compr_type;

				switch (frag->type) {
				case SSDFS_META_EXT_ZLIB:
					compr_type = SSDFS_COMPR_ZLIB;
					break;
				case SSDFS_META_EXT_LZO:
					compr_type = SSDFS_COMPR_LZO;
					break;
				case SSDFS_META_EXT_LZ4:
					compr_type = SSDFS_COMPR_LZ4;
					break;
				case SSDFS_META_EXT_ZSTD:
					compr_type = SSDFS_COMPR_ZSTD;
					break;
				default:
					KUNIT_FAIL(test, "unexpected type %#x",
						   frag->type);
					goto free_buffers;
				}

				err = ssdfs_decompress(compr_type, raw, dst,
						       compr_size,
						       uncompr_size);
				KUNIT_ASSERT_EQ(test, 0, err);
			}

			KUNIT_ASSERT_TRUE(test,
					  frag->flags & SSDFS_FRAGMENT_HAS_CSUM);
			KUNIT_EXPECT_EQ(test,
					le32_to_cpu(frag->checksum),
					le32_to_cpu(ssdfs_crc32_le(dst,
							uncompr_size)));

			decoded_bytes += uncompr_size;
			prev_end = offset + compr_size;
			max_end = max_t(u32, max_end, prev_end);
		}

		if (!(le16_to_cpu(tbl->chain_hdr.flags) &
						SSDFS_MULTIPLE_HDR_CHAIN)) {
			KUNIT_EXPECT_EQ(test,
				0, (int)tbl->blk[SSDFS_NEXT_META_EXT_TABLE_INDEX].magic);
			break;
		}

		KUNIT_ASSERT_EQ(test, SSDFS_NEXT_META_EXT_TABLE_INDEX,
				(int)fragments_count);
		KUNIT_ASSERT_EQ(test, SSDFS_NEXT_TABLE_DESC,
				tbl->blk[SSDFS_NEXT_META_EXT_TABLE_INDEX].type);
		KUNIT_ASSERT_EQ(test, (u8)SSDFS_NEXT_META_EXT_TABLE_INDEX,
			tbl->blk[SSDFS_NEXT_META_EXT_TABLE_INDEX].sequence_id);

		/* the next table follows the last fragment */
		KUNIT_ASSERT_GE(test,
		    le32_to_cpu(tbl->blk[SSDFS_NEXT_META_EXT_TABLE_INDEX].offset),
		    prev_end);
		table_offset =
		    le32_to_cpu(tbl->blk[SSDFS_NEXT_META_EXT_TABLE_INDEX].offset);
	}

	KUNIT_EXPECT_EQ(test, overflow_count * (u32)item_size, decoded_bytes);
	KUNIT_EXPECT_EQ(test, payload->bytes_count, max_end);

	for (u32 i = 0; i < overflow_count; i++) {
		init_test_extent(&expected,
				 (TEST_EMBEDDED_ROWS * TEST_CHAINS_COUNT) + i);
		if (memcmp(&decoded[i], &expected, item_size) != 0) {
			KUNIT_FAIL(test, "extent %u mismatch", i);
			break;
		}
	}

free_buffers:
	kfree(decoded);
	kfree(raw);
	kfree(tbl);
}

static void check_round_trip(struct kunit *test, u32 overflow_count,
			     int compr_type, u32 expected_tables)
{
	struct ssdfs_dynamic_array extents;
	struct ssdfs_payload_content snapshot;
	struct ssdfs_payload_content payload;
	u32 tables_count;
	u32 max_size;
	int err;

	create_test_extents(test, &extents, overflow_count);

	err = ssdfs_snapshot_meta_extents_payload(&extents,
						  TEST_EMBEDDED_ROWS,
						  TEST_CHAINS_COUNT,
						  &snapshot);
	KUNIT_ASSERT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test,
			overflow_count *
				(u32)sizeof(struct ssdfs_meta_area_extent),
			snapshot.bytes_count);

	err = ssdfs_encode_meta_extents_payload(&snapshot, compr_type,
						&payload);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* the reserved log's space is never smaller than the area */
	max_size = ssdfs_meta_extents_max_payload_size(&extents,
						       TEST_EMBEDDED_ROWS,
						       TEST_CHAINS_COUNT);
	if (compr_type == SSDFS_COMPR_NONE)
		KUNIT_EXPECT_EQ(test, max_size, payload.bytes_count);
	else
		KUNIT_EXPECT_LE(test, payload.bytes_count, max_size);

	check_encoded_payload(test, &payload, overflow_count, &tables_count);
	KUNIT_EXPECT_EQ(test, expected_tables, tables_count);

	ssdfs_payload_content_destroy(&payload);
	ssdfs_payload_content_destroy(&snapshot);
	ssdfs_dynamic_array_destroy(&extents);
}

/*
 * Test cases
 */
static void test_snapshot_without_overflow(struct kunit *test)
{
	struct ssdfs_dynamic_array extents;
	struct ssdfs_payload_content snapshot;
	int err;

	create_test_extents(test, &extents, 0);

	err = ssdfs_snapshot_meta_extents_payload(&extents,
						  TEST_EMBEDDED_ROWS,
						  TEST_CHAINS_COUNT,
						  &snapshot);
	KUNIT_EXPECT_EQ(test, -ENODATA, err);
	KUNIT_EXPECT_EQ(test, 0, snapshot.bytes_count);
	KUNIT_EXPECT_EQ(test, 0,
			ssdfs_meta_extents_max_payload_size(&extents,
							TEST_EMBEDDED_ROWS,
							TEST_CHAINS_COUNT));

	ssdfs_payload_content_destroy(&snapshot);
	ssdfs_dynamic_array_destroy(&extents);
}

static void test_encode_one_small_fragment(struct kunit *test)
{
	/* 6 extents: one raw fragment (below compression threshold) */
	check_round_trip(test, 6, SSDFS_COMPR_NONE, 1);
}

static void test_encode_one_table(struct kunit *test)
{
	/* 3 full fragments and a partial one in one table */
	check_round_trip(test, (3 * 256) + 10, SSDFS_COMPR_NONE, 1);
}

static void test_encode_full_table(struct kunit *test)
{
	/* exactly 14 full fragments: one table without next table */
	check_round_trip(test, 14 * 256, SSDFS_COMPR_NONE, 1);
}

static void test_encode_several_tables(struct kunit *test)
{
	/* 31 fragments: three tables (14 + 14 + 3) */
	check_round_trip(test, (30 * 256) + 2, SSDFS_COMPR_NONE, 3);
}

static void test_encode_several_tables_zlib(struct kunit *test)
{
#ifdef CONFIG_SSDFS_ZLIB
	check_round_trip(test, (30 * 256) + 2, SSDFS_COMPR_ZLIB, 3);
#else
	kunit_skip(test, "CONFIG_SSDFS_ZLIB is disabled");
#endif /* CONFIG_SSDFS_ZLIB */
}

/*
 * Test cases for the layout of superblock segment's log
 */
#define TEST_HDR_SIZE	((u32)sizeof(struct ssdfs_segment_header))

static void set_layout_sizes(struct ssdfs_sb_log_layout *layout,
			     u32 segbmap_size, u32 maptbl_size,
			     u32 cache_size)
{
	memset(layout, 0xFF, sizeof(*layout));
	layout->size[SSDFS_SB_LOG_SEGBMAP_EXTENTS] = segbmap_size;
	layout->size[SSDFS_SB_LOG_MAPTBL_EXTENTS] = maptbl_size;
	layout->size[SSDFS_SB_LOG_MAPTBL_CACHE] = cache_size;
}

static void test_sb_log_layout_inline(struct kunit *test)
{
	struct ssdfs_sb_log_layout layout;

	/* all three areas are packed into the header's page */
	set_layout_sizes(&layout, 100, 200, 300);
	ssdfs_define_sb_log_layout(&layout);

	KUNIT_EXPECT_EQ(test, TEST_HDR_SIZE,
			layout.offset[SSDFS_SB_LOG_SEGBMAP_EXTENTS]);
	KUNIT_EXPECT_EQ(test, TEST_HDR_SIZE + 100,
			layout.offset[SSDFS_SB_LOG_MAPTBL_EXTENTS]);
	KUNIT_EXPECT_EQ(test, TEST_HDR_SIZE + 300,
			layout.offset[SSDFS_SB_LOG_MAPTBL_CACHE]);
	KUNIT_EXPECT_EQ(test, 1, layout.body_pages);
	KUNIT_EXPECT_EQ(test, 2, layout.log_pages);
}

static void test_sb_log_layout_absent_areas(struct kunit *test)
{
	struct ssdfs_sb_log_layout layout;

	/* only maptbl cache: it follows the header directly */
	set_layout_sizes(&layout, 0, 0, 1000);
	ssdfs_define_sb_log_layout(&layout);

	KUNIT_EXPECT_EQ(test, 0, layout.offset[SSDFS_SB_LOG_SEGBMAP_EXTENTS]);
	KUNIT_EXPECT_EQ(test, 0, layout.offset[SSDFS_SB_LOG_MAPTBL_EXTENTS]);
	KUNIT_EXPECT_EQ(test, TEST_HDR_SIZE,
			layout.offset[SSDFS_SB_LOG_MAPTBL_CACHE]);
	KUNIT_EXPECT_EQ(test, 1, layout.body_pages);
	KUNIT_EXPECT_EQ(test, 2, layout.log_pages);

	/* no payload at all: header and footer */
	set_layout_sizes(&layout, 0, 0, 0);
	ssdfs_define_sb_log_layout(&layout);

	KUNIT_EXPECT_EQ(test, 1, layout.body_pages);
	KUNIT_EXPECT_EQ(test, 2, layout.log_pages);
}

static void test_sb_log_layout_page_boundary(struct kunit *test)
{
	struct ssdfs_sb_log_layout layout;
	u32 inline_capacity = PAGE_SIZE - TEST_HDR_SIZE;

	/* the areas fill the header's page completely */
	set_layout_sizes(&layout, 64, 64, inline_capacity - 128);
	ssdfs_define_sb_log_layout(&layout);

	KUNIT_EXPECT_EQ(test, 1, layout.body_pages);
	KUNIT_EXPECT_EQ(test, 2, layout.log_pages);

	/* one byte more: the maptbl cache crosses the page boundary */
	set_layout_sizes(&layout, 64, 64, inline_capacity - 127);
	ssdfs_define_sb_log_layout(&layout);

	KUNIT_EXPECT_EQ(test, TEST_HDR_SIZE + 128,
			layout.offset[SSDFS_SB_LOG_MAPTBL_CACHE]);
	KUNIT_EXPECT_EQ(test, 2, layout.body_pages);
	KUNIT_EXPECT_EQ(test, 3, layout.log_pages);
}

static void test_sb_log_layout_big_areas(struct kunit *test)
{
	struct ssdfs_sb_log_layout layout;
	u32 end;

	/* extents are inline, the maptbl cache takes several pages */
	set_layout_sizes(&layout, 512, 256, (3 * PAGE_SIZE) + 100);
	ssdfs_define_sb_log_layout(&layout);

	KUNIT_EXPECT_EQ(test, TEST_HDR_SIZE + 768,
			layout.offset[SSDFS_SB_LOG_MAPTBL_CACHE]);

	end = TEST_HDR_SIZE + 768 + (3 * PAGE_SIZE) + 100;
	KUNIT_EXPECT_EQ(test, DIV_ROUND_UP(end, PAGE_SIZE),
			layout.body_pages);
	KUNIT_EXPECT_EQ(test, layout.body_pages + 1, layout.log_pages);
}

/* create maptbl cache's folios with the last fragment of @last_bytes */
static void create_test_maptbl_cache(struct kunit *test,
				     struct ssdfs_folio_vector *vector,
				     u32 folios_count, u16 last_bytes)
{
	int err;

	err = ssdfs_folio_vector_create(vector, 0, max_t(u32, folios_count, 1));
	KUNIT_ASSERT_EQ(test, 0, err);

	for (u32 i = 0; i < folios_count; i++) {
		struct ssdfs_maptbl_cache_header *hdr;
		struct folio *folio;

		folio = ssdfs_folio_vector_allocate(vector);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

		hdr = kmap_local_folio(folio, 0);
		hdr->bytes_count = cpu_to_le16(i == (folios_count - 1) ?
						last_bytes : PAGE_SIZE);
		kunmap_local(hdr);
	}
}

static void test_maptbl_cache_area_size(struct kunit *test)
{
	struct ssdfs_folio_vector vector;

	create_test_maptbl_cache(test, &vector, 0, 0);
	KUNIT_EXPECT_EQ(test, 0, ssdfs_maptbl_cache_area_size(&vector));
	ssdfs_folio_vector_release(&vector);
	ssdfs_folio_vector_destroy(&vector);

	/* one fragment: the area is the fragment's content only */
	create_test_maptbl_cache(test, &vector, 1, 500);
	KUNIT_EXPECT_EQ(test, 500, ssdfs_maptbl_cache_area_size(&vector));
	ssdfs_folio_vector_release(&vector);
	ssdfs_folio_vector_destroy(&vector);

	/* every fragment, except the last one, occupies the whole page */
	create_test_maptbl_cache(test, &vector, 3, 1000);
	KUNIT_EXPECT_EQ(test, (2 * PAGE_SIZE) + 1000,
			ssdfs_maptbl_cache_area_size(&vector));
	ssdfs_folio_vector_release(&vector);
	ssdfs_folio_vector_destroy(&vector);
}

static struct kunit_case superblock_payload_test_cases[] = {
	KUNIT_CASE(test_snapshot_without_overflow),
	KUNIT_CASE(test_encode_one_small_fragment),
	KUNIT_CASE(test_encode_one_table),
	KUNIT_CASE(test_encode_full_table),
	KUNIT_CASE(test_encode_several_tables),
	KUNIT_CASE(test_encode_several_tables_zlib),
	KUNIT_CASE(test_sb_log_layout_inline),
	KUNIT_CASE(test_sb_log_layout_absent_areas),
	KUNIT_CASE(test_sb_log_layout_page_boundary),
	KUNIT_CASE(test_sb_log_layout_big_areas),
	KUNIT_CASE(test_maptbl_cache_area_size),
	{}
};

static struct kunit_suite superblock_payload_test_suite = {
	.name = "ssdfs_superblock_payload",
	.test_cases = superblock_payload_test_cases,
};

kunit_test_suites(&superblock_payload_test_suite);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Viacheslav Dubeyko <slava@dubeyko.com>");
MODULE_DESCRIPTION("KUnit tests for SSDFS superblock payload");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
