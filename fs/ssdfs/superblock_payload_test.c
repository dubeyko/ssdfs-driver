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

/*
 * Test cases for the compressed PEB mapping table cache
 */
#define TEST_CACHE_HDR_SIZE \
	((u32)sizeof(struct ssdfs_maptbl_cache_header))

/* size of @index fragment: some fragments in the middle are partial */
static u16 test_cache_fragment_size(u32 index, u32 fragments_count)
{
	if (index == (fragments_count - 1))
		return TEST_CACHE_HDR_SIZE + 100 + (index % 5) * 10;

	if ((index % 3) == 1)
		return PAGE_SIZE / 2 + index;

	return PAGE_SIZE;
}

static u8 test_cache_byte(u32 index, u32 offset)
{
	return (u8)((index * 7 + (offset / 16)) & 0x3F);
}

/* create maptbl cache's snapshot: one fragment per folio */
static void create_test_cache_snapshot(struct kunit *test,
				       struct ssdfs_payload_content *snapshot,
				       u32 fragments_count)
{
	int err;

	err = ssdfs_folio_vector_create(&snapshot->batch, 0,
					max_t(u32, fragments_count, 1));
	KUNIT_ASSERT_EQ(test, 0, err);
	snapshot->bytes_count = fragments_count * PAGE_SIZE;
	snapshot->compr_type = SSDFS_COMPR_NONE;

	for (u32 i = 0; i < fragments_count; i++) {
		struct ssdfs_maptbl_cache_header *hdr;
		struct folio *folio;
		u16 bytes_count = test_cache_fragment_size(i, fragments_count);
		u8 *kaddr;

		folio = ssdfs_folio_vector_allocate(&snapshot->batch);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

		kaddr = kmap_local_folio(folio, 0);
		memset(kaddr, 0, PAGE_SIZE);
		for (u32 j = TEST_CACHE_HDR_SIZE; j < bytes_count; j++)
			kaddr[j] = test_cache_byte(i, j);

		hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
		hdr->magic.common = cpu_to_le32(SSDFS_SUPER_MAGIC);
		hdr->magic.key = cpu_to_le16(SSDFS_MAPTBL_CACHE_MAGIC);
		hdr->sequence_id = cpu_to_le16((u16)i);
		hdr->bytes_count = cpu_to_le16(bytes_count);
		hdr->start_leb = cpu_to_le64(i * 1000);
		hdr->end_leb = cpu_to_le64(i * 1000 + 999);
		kunmap_local(kaddr);
	}
}

/* compare decoded fragment with the original one */
static bool check_test_cache_fragment(u8 *fragment, u32 index,
				      u32 fragments_count, u32 size)
{
	struct ssdfs_maptbl_cache_header *hdr =
			(struct ssdfs_maptbl_cache_header *)fragment;

	if (size != test_cache_fragment_size(index, fragments_count))
		return false;

	if (le16_to_cpu(hdr->sequence_id) != index ||
	    le16_to_cpu(hdr->bytes_count) != size ||
	    le64_to_cpu(hdr->start_leb) != (u64)index * 1000)
		return false;

	for (u32 j = TEST_CACHE_HDR_SIZE; j < size; j++) {
		if (fragment[j] != test_cache_byte(index, j))
			return false;
	}

	return true;
}

/*
 * Decode @payload by the same rules as the mount path does: the offsets
 * of fragments and of the next table are relative to the area's
 * beginning, the sequence ID of a fragment is its index in the table.
 */
static void check_encoded_cache(struct kunit *test,
				struct ssdfs_payload_content *payload,
				int compr_type, u32 fragments_count,
				u32 *tables_count)
{
	struct ssdfs_maptbl_cache_table *tbl;
	size_t tbl_size = sizeof(struct ssdfs_maptbl_cache_table);
	u8 *raw, *decoded;
	u32 table_offset = 0;
	u32 fragment_index = 0;
	u32 max_end = 0;
	u32 max_compr_size = 0;
	u32 compressed_count = 0;
	int err;

	*tables_count = 0;

	KUNIT_ASSERT_EQ(test, compr_type, payload->compr_type);
	KUNIT_ASSERT_GE(test, payload->bytes_count, (u32)tbl_size);
	KUNIT_EXPECT_EQ(test, payload->bytes_count,
			ssdfs_maptbl_cache_payload_size(payload));
	KUNIT_EXPECT_LE(test, payload->bytes_count,
		ssdfs_maptbl_cache_max_payload_size(fragments_count *
						    PAGE_SIZE));

	tbl = kzalloc(tbl_size, GFP_KERNEL);
	raw = kzalloc(PAGE_SIZE, GFP_KERNEL);
	decoded = kzalloc(PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, tbl);
	KUNIT_ASSERT_NOT_NULL(test, raw);
	KUNIT_ASSERT_NOT_NULL(test, decoded);

	for (;;) {
		u32 prev_end = table_offset + tbl_size;
		u16 count;

		err = read_test_payload(payload, table_offset, tbl, tbl_size);
		KUNIT_ASSERT_EQ(test, 0, err);

		(*tables_count)++;
		max_end = max_t(u32, max_end, table_offset + tbl_size);

		KUNIT_ASSERT_EQ(test, SSDFS_CHAIN_HDR_MAGIC,
				tbl->chain_hdr.magic);
		KUNIT_ASSERT_EQ(test,
				(u8)(SSDFS_MAPTBL_CACHE_CHAIN_HDR + compr_type),
				tbl->chain_hdr.type);

		count = le16_to_cpu(tbl->chain_hdr.fragments_count);
		KUNIT_ASSERT_GT(test, count, 0);
		KUNIT_ASSERT_LE(test, count,
				SSDFS_NEXT_MAPTBL_CACHE_TABLE_INDEX);

		for (u16 i = 0; i < count; i++) {
			struct ssdfs_fragment_desc *frag = &tbl->blk[i];
			u32 offset = le32_to_cpu(frag->offset);
			u32 compr_size = le16_to_cpu(frag->compr_size);
			u32 uncompr_size = le16_to_cpu(frag->uncompr_size);

			KUNIT_ASSERT_EQ(test, SSDFS_FRAGMENT_DESC_MAGIC,
					frag->magic);
			KUNIT_ASSERT_EQ(test, (u8)i, frag->sequence_id);
			KUNIT_ASSERT_GE(test, offset, prev_end);
			KUNIT_ASSERT_GT(test, compr_size, 0);
			KUNIT_ASSERT_LE(test, compr_size, uncompr_size);
			KUNIT_ASSERT_LE(test, uncompr_size, (u32)PAGE_SIZE);
			KUNIT_ASSERT_LT(test, fragment_index, fragments_count);

			err = read_test_payload(payload, offset,
						raw, compr_size);
			KUNIT_ASSERT_EQ(test, 0, err);

			if (frag->type == SSDFS_MAPTBL_CACHE_BLOB) {
				KUNIT_ASSERT_EQ(test, compr_size, uncompr_size);
				memcpy(decoded, raw, uncompr_size);
			} else {
				compressed_count++;
				KUNIT_ASSERT_EQ(test,
					(u8)(SSDFS_MAPTBL_CACHE_BLOB +
						compr_type),
					frag->type);
				err = ssdfs_decompress(compr_type, raw, decoded,
						       compr_size,
						       uncompr_size);
				KUNIT_ASSERT_EQ(test, 0, err);
			}

			KUNIT_ASSERT_TRUE(test,
					  frag->flags & SSDFS_FRAGMENT_HAS_CSUM);
			KUNIT_EXPECT_EQ(test,
					le32_to_cpu(frag->checksum),
					le32_to_cpu(ssdfs_crc32_le(decoded,
							uncompr_size)));

			if (!check_test_cache_fragment(decoded, fragment_index,
						       fragments_count,
						       uncompr_size)) {
				KUNIT_FAIL(test, "fragment %u mismatch",
					   fragment_index);
				goto free_buffers;
			}

			fragment_index++;
			prev_end = offset + compr_size;
			max_end = max_t(u32, max_end, prev_end);
			max_compr_size = max_t(u32, max_compr_size,
						compr_size);
		}

		if (!(le16_to_cpu(tbl->chain_hdr.flags) &
						SSDFS_MULTIPLE_HDR_CHAIN))
			break;

		KUNIT_ASSERT_EQ(test, SSDFS_NEXT_MAPTBL_CACHE_TABLE_INDEX,
				(int)count);
		KUNIT_ASSERT_EQ(test, SSDFS_NEXT_TABLE_DESC,
			tbl->blk[SSDFS_NEXT_MAPTBL_CACHE_TABLE_INDEX].type);
		KUNIT_ASSERT_GE(test,
		    le32_to_cpu(tbl->blk[SSDFS_NEXT_MAPTBL_CACHE_TABLE_INDEX].offset),
		    prev_end);
		table_offset =
		    le32_to_cpu(tbl->blk[SSDFS_NEXT_MAPTBL_CACHE_TABLE_INDEX].offset);
	}

	KUNIT_EXPECT_EQ(test, fragments_count, fragment_index);
	KUNIT_EXPECT_EQ(test, payload->bytes_count, max_end);
	/* the test fragments are compressible */
	KUNIT_EXPECT_GT(test, compressed_count, 0U);
	/* the biggest fragment is kept for the log size's estimation */
	KUNIT_EXPECT_EQ(test, max_compr_size, payload->max_fragment_bytes);

free_buffers:
	kfree(decoded);
	kfree(raw);
	kfree(tbl);
}

static void check_cache_round_trip(struct kunit *test, u32 fragments_count,
				   int compr_type, u32 expected_tables)
{
	struct ssdfs_payload_content snapshot;
	struct ssdfs_payload_content payload;
	u32 tables_count;
	int err;

	create_test_cache_snapshot(test, &snapshot, fragments_count);

	err = ssdfs_encode_maptbl_cache_payload(&snapshot, compr_type,
						&payload);
	KUNIT_ASSERT_EQ(test, 0, err);

	check_encoded_cache(test, &payload, compr_type, fragments_count,
			    &tables_count);
	KUNIT_EXPECT_EQ(test, expected_tables, tables_count);

	ssdfs_payload_content_destroy(&payload);
	ssdfs_payload_content_destroy(&snapshot);
}

static void test_encode_maptbl_cache_invalid(struct kunit *test)
{
	struct ssdfs_payload_content snapshot;
	struct ssdfs_payload_content payload;
	int err;

	create_test_cache_snapshot(test, &snapshot, 2);

	/* the uncompressed cache isn't encoded into the tables' chain */
	err = ssdfs_encode_maptbl_cache_payload(&snapshot, SSDFS_COMPR_NONE,
						&payload);
	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	ssdfs_payload_content_destroy(&snapshot);

	/* empty snapshot */
	create_test_cache_snapshot(test, &snapshot, 0);
	snapshot.bytes_count = 0;
	err = ssdfs_encode_maptbl_cache_payload(&snapshot, SSDFS_COMPR_ZLIB,
						&payload);
	KUNIT_EXPECT_EQ(test, -ENODATA, err);

	ssdfs_payload_content_destroy(&payload);
	ssdfs_payload_content_destroy(&snapshot);
}

static void test_maptbl_cache_max_payload_size(struct kunit *test)
{
	u32 tbl_size = (u32)sizeof(struct ssdfs_maptbl_cache_table);

	KUNIT_EXPECT_EQ(test, PAGE_SIZE + tbl_size,
			ssdfs_maptbl_cache_max_payload_size(PAGE_SIZE));
	KUNIT_EXPECT_EQ(test, (14 * PAGE_SIZE) + tbl_size,
			ssdfs_maptbl_cache_max_payload_size(14 * PAGE_SIZE));
	KUNIT_EXPECT_EQ(test, (15 * PAGE_SIZE) + (2 * tbl_size),
			ssdfs_maptbl_cache_max_payload_size(15 * PAGE_SIZE));
}

#define DEFINE_CACHE_ROUND_TRIP_TEST(name, config, compr, frags, tables) \
static void test_encode_maptbl_cache_##name(struct kunit *test)	\
{									\
	if (!IS_ENABLED(config))					\
		kunit_skip(test, #config " is disabled");		\
	check_cache_round_trip(test, frags, compr, tables);		\
}

/* one fragment, several fragments, exactly one full table, 3 tables */
DEFINE_CACHE_ROUND_TRIP_TEST(one_fragment_zlib, CONFIG_SSDFS_ZLIB,
			     SSDFS_COMPR_ZLIB, 1, 1)
DEFINE_CACHE_ROUND_TRIP_TEST(one_table_zlib, CONFIG_SSDFS_ZLIB,
			     SSDFS_COMPR_ZLIB, 7, 1)
DEFINE_CACHE_ROUND_TRIP_TEST(full_table_zlib, CONFIG_SSDFS_ZLIB,
			     SSDFS_COMPR_ZLIB, 14, 1)
DEFINE_CACHE_ROUND_TRIP_TEST(several_tables_zlib, CONFIG_SSDFS_ZLIB,
			     SSDFS_COMPR_ZLIB, 31, 3)
DEFINE_CACHE_ROUND_TRIP_TEST(several_tables_lzo, CONFIG_SSDFS_LZO,
			     SSDFS_COMPR_LZO, 31, 3)
DEFINE_CACHE_ROUND_TRIP_TEST(several_tables_lz4, CONFIG_SSDFS_LZ4,
			     SSDFS_COMPR_LZ4, 31, 3)
DEFINE_CACHE_ROUND_TRIP_TEST(several_tables_zstd, CONFIG_SSDFS_ZSTD,
			     SSDFS_COMPR_ZSTD, 31, 3)

/*
 * The compression type of the maptbl cache's area is defined by
 * the flags of the area's metadata check (a round trip of every type
 * and the rejection of several compression flags).
 */
static void test_area_compr_type(struct kunit *test)
{
	int compr_type;
	u16 flags;

	KUNIT_EXPECT_EQ(test, SSDFS_COMPR_NONE, ssdfs_area_compr_type(0));
	KUNIT_EXPECT_EQ(test, SSDFS_COMPR_NONE,
			ssdfs_area_compr_type(SSDFS_CRC32));
	KUNIT_EXPECT_EQ(test, 0,
			ssdfs_area_compression_flag(SSDFS_COMPR_NONE));

	for (compr_type = SSDFS_COMPR_ZLIB;
	     compr_type < SSDFS_COMPR_TYPES_CNT; compr_type++) {
		flags = ssdfs_area_compression_flag(compr_type);
		KUNIT_EXPECT_NE(test, 0, flags);
		KUNIT_EXPECT_EQ(test, compr_type,
				ssdfs_area_compr_type(SSDFS_CRC32 | flags));
	}

	KUNIT_EXPECT_EQ(test, -EIO,
			ssdfs_area_compr_type(SSDFS_ZLIB_COMPRESSED |
					      SSDFS_ZSTD_COMPRESSED));
	KUNIT_EXPECT_EQ(test, -EIO,
			ssdfs_area_compr_type(SSDFS_CRC32 |
					      SSDFS_LZO_COMPRESSED |
					      SSDFS_LZ4_COMPRESSED));
}

/*
 * The superblock's commit stores the new state of the maptbl cache:
 * uncompressed if it fits into the inline area, otherwise compressed by
 * the compression type of the area that has been read during the mount
 * or, if the area was uncompressed, by the compression type of user data
 * (ZLIB if the compression of user data is disabled).
 */
static void check_commit_maptbl_cache(struct kunit *test,
				      int area_compr_type,
				      int user_data_compr_type,
				      u32 fragments_count,
				      u32 inline_capacity,
				      int expected_compr_type)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_payload_content snapshot;
	struct ssdfs_payload_content payload;
	u32 tables_count;
	int err;

	fsi = kunit_kzalloc(test, sizeof(*fsi), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	create_test_cache_snapshot(test, &snapshot, fragments_count);

	init_rwsem(&fsi->maptbl_cache.lock);
	fsi->maptbl_cache.batch = snapshot.batch;
	atomic_set(&fsi->maptbl_cache.bytes_count, snapshot.bytes_count);
	fsi->maptbl_cache.compr_type = area_compr_type;
	fsi->metadata_options.user_data.compression = user_data_compr_type;

	err = ssdfs_folio_vector_create(&payload.batch, 0, 0);
	KUNIT_ASSERT_EQ(test, 0, err);
	payload.bytes_count = 0;
	payload.compr_type = SSDFS_COMPR_NONE;

	err = ssdfs_snapshot_maptbl_cache_payload(fsi, inline_capacity,
						  &payload);
	KUNIT_ASSERT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, expected_compr_type, payload.compr_type);

	if (expected_compr_type == SSDFS_COMPR_NONE) {
		KUNIT_EXPECT_EQ(test, fragments_count,
				ssdfs_folio_vector_count(&payload.batch));
		KUNIT_EXPECT_EQ(test, snapshot.bytes_count,
				payload.bytes_count);
	} else {
		check_encoded_cache(test, &payload, expected_compr_type,
				    fragments_count, &tables_count);
	}

	ssdfs_payload_content_destroy(&payload);
	ssdfs_payload_content_destroy(&snapshot);
}

static void test_commit_maptbl_cache(struct kunit *test)
{
	u32 small_size = test_cache_fragment_size(0, 1);

	if (!IS_ENABLED(CONFIG_SSDFS_ZLIB) || !IS_ENABLED(CONFIG_SSDFS_LZO))
		kunit_skip(test, "CONFIG_SSDFS_ZLIB/LZO is disabled");

	/* mkfs stored the cache uncompressed and it still fits inline */
	check_commit_maptbl_cache(test, SSDFS_COMPR_NONE, SSDFS_COMPR_ZLIB,
				  1, small_size, SSDFS_COMPR_NONE);

	/* it doesn't fit inline anymore: compression type of user data */
	check_commit_maptbl_cache(test, SSDFS_COMPR_NONE, SSDFS_COMPR_ZLIB,
				  1, small_size - 1, SSDFS_COMPR_ZLIB);
	check_commit_maptbl_cache(test, SSDFS_COMPR_NONE, SSDFS_COMPR_LZO,
				  3, PAGE_SIZE, SSDFS_COMPR_LZO);

	/* compression of user data is disabled: ZLIB by default */
	check_commit_maptbl_cache(test, SSDFS_COMPR_NONE, SSDFS_COMPR_NONE,
				  3, PAGE_SIZE, SSDFS_COMPR_ZLIB);
	check_commit_maptbl_cache(test, SSDFS_COMPR_NONE, SSDFS_COMPR_NONE,
				  1, small_size - 1, SSDFS_COMPR_ZLIB);
	check_commit_maptbl_cache(test, SSDFS_COMPR_NONE, SSDFS_COMPR_NONE,
				  1, small_size, SSDFS_COMPR_NONE);

	/* the compressed area keeps its compression type */
	check_commit_maptbl_cache(test, SSDFS_COMPR_LZO, SSDFS_COMPR_ZLIB,
				  3, PAGE_SIZE, SSDFS_COMPR_LZO);
	check_commit_maptbl_cache(test, SSDFS_COMPR_LZO, SSDFS_COMPR_NONE,
				  3, PAGE_SIZE, SSDFS_COMPR_LZO);

	/* the compressed area becomes uncompressed if it fits inline */
	check_commit_maptbl_cache(test, SSDFS_COMPR_LZO, SSDFS_COMPR_ZLIB,
				  1, small_size, SSDFS_COMPR_NONE);
}

/*
 * The place of superblock segment's log is defined by the real size
 * of the log: the compressed maptbl cache can be much smaller than
 * the cache's pages (upper bound of the area's size). For example,
 * the 128KB PEB (32 pages) with 15 used pages and 16 pages of the maptbl
 * cache: the upper bound of the log (18 pages) cannot fit into the rest
 * of the PEB but the real log can.
 */
static void test_sb_log_payload_layout(struct kunit *test)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_payload_content snapshot;
	struct ssdfs_sb_log_payload payload;
	struct ssdfs_sb_log_layout layout;
	struct ssdfs_sb_log_layout upper_bound = {0};
	u32 fragments_count = 16;
	u32 pages_per_peb = SZ_128K / PAGE_SIZE;
	u32 used_pages = 15;
	int err;

	if (!IS_ENABLED(CONFIG_SSDFS_ZLIB))
		kunit_skip(test, "CONFIG_SSDFS_ZLIB is disabled");

	fsi = kunit_kzalloc(test, sizeof(*fsi), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fsi);

	create_test_cache_snapshot(test, &snapshot, fragments_count);

	init_rwsem(&fsi->maptbl_cache.lock);
	fsi->maptbl_cache.batch = snapshot.batch;
	atomic_set(&fsi->maptbl_cache.bytes_count, snapshot.bytes_count);
	fsi->maptbl_cache.compr_type = SSDFS_COMPR_ZLIB;
	fsi->metadata_options.user_data.compression = SSDFS_COMPR_NONE;

	err = ssdfs_sb_log_payload_create(&payload);
	KUNIT_ASSERT_EQ(test, 0, err);

	err = ssdfs_snapshot_maptbl_cache_payload(fsi,
				PAGE_SIZE - sizeof(struct ssdfs_segment_header),
				&payload.maptbl_cache);
	KUNIT_ASSERT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, SSDFS_COMPR_ZLIB, payload.maptbl_cache.compr_type);

	ssdfs_define_sb_log_payload_layout(&payload, &layout);
	KUNIT_EXPECT_EQ(test, 0U, layout.size[SSDFS_SB_LOG_SEGBMAP_EXTENTS]);
	KUNIT_EXPECT_EQ(test, 0U, layout.size[SSDFS_SB_LOG_MAPTBL_EXTENTS]);
	KUNIT_EXPECT_EQ(test, payload.maptbl_cache.bytes_count,
			layout.size[SSDFS_SB_LOG_MAPTBL_CACHE]);
	KUNIT_EXPECT_EQ(test, (u32)sizeof(struct ssdfs_segment_header),
			layout.offset[SSDFS_SB_LOG_MAPTBL_CACHE]);
	KUNIT_EXPECT_EQ(test, layout.body_pages + 1, layout.log_pages);
	KUNIT_EXPECT_EQ(test, layout.body_pages,
			DIV_ROUND_UP((u32)sizeof(struct ssdfs_segment_header) +
				     payload.maptbl_cache.bytes_count,
				     PAGE_SIZE));

	upper_bound.size[SSDFS_SB_LOG_MAPTBL_CACHE] =
		ssdfs_maptbl_cache_max_payload_size(snapshot.bytes_count);
	ssdfs_define_sb_log_layout(&upper_bound);

	KUNIT_EXPECT_GT(test, used_pages + upper_bound.log_pages,
			pages_per_peb);
	KUNIT_EXPECT_LE(test, used_pages + layout.log_pages, pages_per_peb);

	ssdfs_sb_log_payload_destroy(&payload);
	ssdfs_payload_content_destroy(&snapshot);
}

/*
 * A fragment is compressed only if it is bigger than
 * SSDFS_UNCOMPR_BLOB_UPPER_THRESHOLD and the compression makes it smaller.
 */
static void test_encode_payload_fragment(struct kunit *test)
{
	u8 *src, *dst;
	u32 encoded_size;
	bool is_compressed;
	int err;

	src = kunit_kzalloc(test, PAGE_SIZE, GFP_KERNEL);
	dst = kunit_kzalloc(test, PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, src);
	KUNIT_ASSERT_NOT_NULL(test, dst);

	/* mostly zeros: compressible data */
	for (u32 i = 0; i < PAGE_SIZE; i += 64)
		src[i] = (u8)(i / 64);

	/* invalid sizes */
	err = ssdfs_encode_payload_fragment(SSDFS_COMPR_NONE, src, 0,
					    dst, PAGE_SIZE,
					    &encoded_size, &is_compressed);
	KUNIT_EXPECT_EQ(test, -EINVAL, err);
	err = ssdfs_encode_payload_fragment(SSDFS_COMPR_NONE, src, 64,
					    dst, 32,
					    &encoded_size, &is_compressed);
	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	/* uncompressed type */
	err = ssdfs_encode_payload_fragment(SSDFS_COMPR_NONE, src, PAGE_SIZE,
					    dst, PAGE_SIZE,
					    &encoded_size, &is_compressed);
	KUNIT_ASSERT_EQ(test, 0, err);
	KUNIT_EXPECT_FALSE(test, is_compressed);
	KUNIT_EXPECT_EQ(test, (u32)PAGE_SIZE, encoded_size);
	KUNIT_EXPECT_EQ(test, 0, memcmp(src, dst, PAGE_SIZE));

	if (!IS_ENABLED(CONFIG_SSDFS_ZLIB))
		kunit_skip(test, "CONFIG_SSDFS_ZLIB is disabled");

	/* small fragment is never compressed */
	err = ssdfs_encode_payload_fragment(SSDFS_COMPR_ZLIB, src,
					    SSDFS_UNCOMPR_BLOB_UPPER_THRESHOLD,
					    dst, PAGE_SIZE,
					    &encoded_size, &is_compressed);
	KUNIT_ASSERT_EQ(test, 0, err);
	KUNIT_EXPECT_FALSE(test, is_compressed);
	KUNIT_EXPECT_EQ(test, (u32)SSDFS_UNCOMPR_BLOB_UPPER_THRESHOLD,
			encoded_size);

	/* compressible fragment */
	err = ssdfs_encode_payload_fragment(SSDFS_COMPR_ZLIB, src, PAGE_SIZE,
					    dst, PAGE_SIZE,
					    &encoded_size, &is_compressed);
	KUNIT_ASSERT_EQ(test, 0, err);
	KUNIT_EXPECT_TRUE(test, is_compressed);
	KUNIT_EXPECT_GT(test, encoded_size, 0U);
	KUNIT_EXPECT_LT(test, encoded_size, (u32)PAGE_SIZE);
}

static void test_meta_extents_estimate_area_size(struct kunit *test)
{
	struct ssdfs_meta_extents_area_info info = {0};

	/* no area */
	KUNIT_EXPECT_EQ(test, 0U,
		ssdfs_meta_extents_estimate_area_size(&info, 0,
						      SSDFS_COMPR_ZLIB));

	/* unknown size: upper bound */
	KUNIT_EXPECT_EQ(test, 1000U,
		ssdfs_meta_extents_estimate_area_size(&info, 1000,
						      SSDFS_COMPR_ZLIB));

	info.is_known = true;
	info.compr_type = SSDFS_COMPR_ZLIB;
	info.uncompr_bytes = 1000;
	info.bytes_count = 300;

	/* known size */
	KUNIT_EXPECT_EQ(test, 300U,
		ssdfs_meta_extents_estimate_area_size(&info, 1000,
						      SSDFS_COMPR_ZLIB));

	/* uncompressed area: uncompressed size directly */
	KUNIT_EXPECT_EQ(test, 1000U,
		ssdfs_meta_extents_estimate_area_size(&info, 1000,
						      SSDFS_COMPR_NONE));

	/* known size of another compression type */
	KUNIT_EXPECT_EQ(test, 1000U,
		ssdfs_meta_extents_estimate_area_size(&info, 1000,
						      SSDFS_COMPR_LZ4));

	/* known size of another uncompressed size */
	KUNIT_EXPECT_EQ(test, 2000U,
		ssdfs_meta_extents_estimate_area_size(&info, 2000,
						      SSDFS_COMPR_ZLIB));
}

static void test_maptbl_cache_estimate_area_size(struct kunit *test)
{
	u32 tbl_size = (u32)sizeof(struct ssdfs_maptbl_cache_table);

	KUNIT_EXPECT_EQ(test, 0U,
			ssdfs_maptbl_cache_estimate_area_size(0, 0, 0));

	/* one fragment: only the last one */
	KUNIT_EXPECT_EQ(test, tbl_size + 100,
			ssdfs_maptbl_cache_estimate_area_size(1, 100, 500));

	/* the biggest fragment for every fragment, except the last one */
	KUNIT_EXPECT_EQ(test, tbl_size + (2 * 500) + 100,
			ssdfs_maptbl_cache_estimate_area_size(3, 100, 500));

	/* the last fragment is bigger than the known biggest one */
	KUNIT_EXPECT_EQ(test, tbl_size + (2 * 700) + 700,
			ssdfs_maptbl_cache_estimate_area_size(3, 700, 500));

	/* unknown biggest fragment: upper bound */
	KUNIT_EXPECT_EQ(test, tbl_size + (2 * PAGE_SIZE) + 100,
			ssdfs_maptbl_cache_estimate_area_size(3, 100, 0));

	/* several tables */
	KUNIT_EXPECT_EQ(test, (2 * tbl_size) + (14 * 500) + 100,
			ssdfs_maptbl_cache_estimate_area_size(15, 100, 500));
}

/*
 * The estimation by the biggest fragment of the previous encoding and
 * by the last encoded fragment isn't smaller than the real size of
 * the encoded maptbl cache.
 */
static void check_cache_estimation(struct kunit *test, u32 fragments_count,
				   int compr_type)
{
	struct ssdfs_payload_content snapshot;
	struct ssdfs_payload_content payload;
	struct folio *folio;
	u8 *dst;
	void *kaddr;
	u32 last_bytes;
	u32 encoded_bytes;
	u32 estimation;
	bool is_compressed;
	int err;

	dst = kunit_kzalloc(test, PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, dst);

	create_test_cache_snapshot(test, &snapshot, fragments_count);

	err = ssdfs_encode_maptbl_cache_payload(&snapshot, compr_type,
						&payload);
	KUNIT_ASSERT_EQ(test, 0, err);
	KUNIT_ASSERT_GT(test, payload.max_fragment_bytes, 0U);

	last_bytes = test_cache_fragment_size(fragments_count - 1,
					      fragments_count);
	folio = ssdfs_folio_vector_get(&snapshot.batch, fragments_count - 1);
	KUNIT_ASSERT_NOT_NULL(test, folio);

	kaddr = kmap_local_folio(folio, 0);
	err = ssdfs_encode_payload_fragment(compr_type, kaddr, last_bytes,
					    dst, PAGE_SIZE,
					    &encoded_bytes, &is_compressed);
	kunmap_local(kaddr);
	KUNIT_ASSERT_EQ(test, 0, err);
	KUNIT_EXPECT_LE(test, encoded_bytes, payload.max_fragment_bytes);

	estimation = ssdfs_maptbl_cache_estimate_area_size(fragments_count,
						encoded_bytes,
						payload.max_fragment_bytes);
	KUNIT_EXPECT_GE(test, estimation, payload.bytes_count);
	KUNIT_EXPECT_LE(test, estimation,
		ssdfs_maptbl_cache_max_payload_size(fragments_count *
						    PAGE_SIZE));

	/* unknown biggest fragment */
	estimation = ssdfs_maptbl_cache_estimate_area_size(fragments_count,
							   encoded_bytes, 0);
	KUNIT_EXPECT_GE(test, estimation, payload.bytes_count);

	ssdfs_payload_content_destroy(&payload);
	ssdfs_payload_content_destroy(&snapshot);
}

#define DEFINE_CACHE_ESTIMATION_TEST(name, config, compr, frags)	\
static void test_estimate_maptbl_cache_##name(struct kunit *test)	\
{									\
	if (!IS_ENABLED(config))					\
		kunit_skip(test, #config " is disabled");		\
	check_cache_estimation(test, frags, compr);			\
}

DEFINE_CACHE_ESTIMATION_TEST(one_fragment_zlib, CONFIG_SSDFS_ZLIB,
			     SSDFS_COMPR_ZLIB, 1)
DEFINE_CACHE_ESTIMATION_TEST(several_tables_zlib, CONFIG_SSDFS_ZLIB,
			     SSDFS_COMPR_ZLIB, 31)
DEFINE_CACHE_ESTIMATION_TEST(several_tables_lzo, CONFIG_SSDFS_LZO,
			     SSDFS_COMPR_LZO, 31)
DEFINE_CACHE_ESTIMATION_TEST(several_tables_lz4, CONFIG_SSDFS_LZ4,
			     SSDFS_COMPR_LZ4, 31)
DEFINE_CACHE_ESTIMATION_TEST(several_tables_zstd, CONFIG_SSDFS_ZSTD,
			     SSDFS_COMPR_ZSTD, 31)

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
	KUNIT_CASE(test_maptbl_cache_max_payload_size),
	KUNIT_CASE(test_encode_maptbl_cache_invalid),
	KUNIT_CASE(test_encode_maptbl_cache_one_fragment_zlib),
	KUNIT_CASE(test_encode_maptbl_cache_one_table_zlib),
	KUNIT_CASE(test_encode_maptbl_cache_full_table_zlib),
	KUNIT_CASE(test_encode_maptbl_cache_several_tables_zlib),
	KUNIT_CASE(test_encode_maptbl_cache_several_tables_lzo),
	KUNIT_CASE(test_encode_maptbl_cache_several_tables_lz4),
	KUNIT_CASE(test_encode_maptbl_cache_several_tables_zstd),
	KUNIT_CASE(test_area_compr_type),
	KUNIT_CASE(test_commit_maptbl_cache),
	KUNIT_CASE(test_sb_log_payload_layout),
	KUNIT_CASE(test_encode_payload_fragment),
	KUNIT_CASE(test_meta_extents_estimate_area_size),
	KUNIT_CASE(test_maptbl_cache_estimate_area_size),
	KUNIT_CASE(test_estimate_maptbl_cache_one_fragment_zlib),
	KUNIT_CASE(test_estimate_maptbl_cache_several_tables_zlib),
	KUNIT_CASE(test_estimate_maptbl_cache_several_tables_lzo),
	KUNIT_CASE(test_estimate_maptbl_cache_several_tables_lz4),
	KUNIT_CASE(test_estimate_maptbl_cache_several_tables_zstd),
	{}
};

static int superblock_payload_test_init(struct kunit *test)
{
	/* the encoding of payload areas needs the registered compressors */
	return ssdfs_compressors_init();
}

static void superblock_payload_test_exit(struct kunit *test)
{
	ssdfs_compressors_exit();
}

static struct kunit_suite superblock_payload_test_suite = {
	.name = "ssdfs_superblock_payload",
	.init = superblock_payload_test_init,
	.exit = superblock_payload_test_exit,
	.test_cases = superblock_payload_test_cases,
};

kunit_test_suites(&superblock_payload_test_suite);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Viacheslav Dubeyko <slava@dubeyko.com>");
MODULE_DESCRIPTION("KUnit tests for SSDFS superblock payload");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
