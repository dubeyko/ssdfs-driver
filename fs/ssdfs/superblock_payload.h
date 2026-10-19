/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/superblock_payload.h - superblock segment's payload areas.
 *
 * Copyright (c) 2026 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_SUPERBLOCK_PAYLOAD_H
#define _SSDFS_SUPERBLOCK_PAYLOAD_H

#include "folio_vector.h"
#include "dynamic_array.h"

/*
 * struct ssdfs_payload_content - cached content of a payload area
 * @batch: folios that keep the area's on-disk encoded content
 * @bytes_count: size of the meaningful content in bytes
 * @compr_type: compression type of the encoded content
 * @max_fragment_bytes: size of the biggest encoded fragment in bytes
 *                      (0 - the content isn't the fragments' chain)
 *
 * This is the on-disk encoded form of a superblock segment's payload
 * area (the PEB mapping table cache, or a metadata extents area).
 *
 * The PEB mapping table cache's content can be in two states:
 * (1) SSDFS_COMPR_NONE - the sequence of the cache's fragments
 *     (every fragment occupies its own memory page);
 * (2) SSDFS_COMPR_ZLIB/LZO/LZ4/ZSTD - the chain of
 *     struct ssdfs_maptbl_cache_table tables with compressed fragments.
 */
struct ssdfs_payload_content {
	struct ssdfs_folio_vector batch;
	u32 bytes_count;
	int compr_type;
	u32 max_fragment_bytes;
};

/*
 * Kinds of payload areas that are stored as fragments' chain
 *
 * The metadata extents area and the compressed PEB mapping table cache
 * area have the same structure: the chain of tables (struct
 * ssdfs_metadata_extents_table or struct ssdfs_maptbl_cache_table) and
 * every table describes up to SSDFS_FRAGMENTS_CHAIN_MAX fragments.
 * Both tables have the identical layout.
 */
enum {
	SSDFS_META_EXTENTS_PAYLOAD,
	SSDFS_MAPTBL_CACHE_PAYLOAD,
	SSDFS_PAYLOAD_KIND_MAX
};

/*
 * struct ssdfs_payload_iterator - payload iterator
 * @kind: kind of payload area
 * @cur_offset: current offset in payload
 * @fragment_id: current fragment ID
 * @area: area descriptor
 * @tbl: fragments' chain table descriptor
 * @buffer: buffer descriptor
 * @raw_buf: raw buffer
 */
struct ssdfs_payload_iterator {
	int kind;
	u32 cur_offset;
	u8 fragment_id;

	struct ssdfs_metadata_descriptor area;
	struct ssdfs_metadata_extents_table tbl;
	struct ssdfs_buffer buffer;
	u8 raw_buf[PAGE_SIZE];
};

/*
 * struct ssdfs_meta_extents_area_info - known size of overflow extents area
 * @is_known: is the size of the encoded area known?
 * @compr_type: compression type the area has been encoded with
 * @uncompr_bytes: size of the area in uncompressed state
 * @bytes_count: size of the encoded area in bytes
 *
 * The overflow metadata extents of segment bitmap and PEB mapping table
 * are defined during mkfs phase and the number of extents doesn't change
 * later. So, the size of the encoded area is defined by the first
 * encoding of the area and it is reused for the estimation of
 * superblock segment's log size. The size is valid only for the same
 * compression type and the same size of the uncompressed area.
 */
struct ssdfs_meta_extents_area_info {
	bool is_known;
	int compr_type;
	u32 uncompr_bytes;
	u32 bytes_count;
};

/*
 * struct ssdfs_meta_extents - metadata extents of metadata structure
 * @array: metadata extents array (every row, embedded and overflow)
 * @area: known size of the encoded overflow extents area
 *
 * The segment bitmap and the PEB mapping table keep the rows of main
 * and copy extents of their segments. The embedded rows are stored in
 * the volume header and the overflow rows are stored in the payload
 * area of superblock segment's log. The size of the encoded overflow
 * area is kept for the estimation of superblock segment's log size
 * (it is accessed under fsi->volume_sem).
 */
struct ssdfs_meta_extents {
	struct ssdfs_dynamic_array array;
	struct ssdfs_meta_extents_area_info area;
};

/*
 * struct ssdfs_sb_log_payload - payload areas of a superblock segment's log
 * @maptbl_cache: PEB mapping table cache's content
 * @segbmap_meta_extents: segment bitmap's overflow extents
 * @maptbl_meta_extents: PEB mapping table's overflow extents
 */
struct ssdfs_sb_log_payload {
	struct ssdfs_payload_content maptbl_cache;
	struct ssdfs_payload_content segbmap_meta_extents;
	struct ssdfs_payload_content maptbl_meta_extents;
};

/*
 * SSDFS_META_EXTENT_INDEX() - index of extent in metadata extents array
 * @chains_count: count of chains (columns) per row
 * @chain: chain index (main or copy)
 * @row: row index
 */
static inline
u32 SSDFS_META_EXTENT_INDEX(u32 chains_count, u32 chain, u32 row)
{
	return (row * chains_count) + chain;
}

/* Payload areas of superblock segment's log (in the log's order) */
enum {
	SSDFS_SB_LOG_SEGBMAP_EXTENTS,
	SSDFS_SB_LOG_MAPTBL_EXTENTS,
	SSDFS_SB_LOG_MAPTBL_CACHE,
	SSDFS_SB_LOG_AREAS_MAX
};

/*
 * struct ssdfs_sb_log_layout - layout of superblock segment's log
 * @offset: offset of every payload area from the log's beginning
 * @size: size of every payload area in bytes (0 - area is absent)
 * @body_pages: count of pages of segment header and payload areas
 * @log_pages: count of pages of the whole log (body + footer)
 *
 * The log starts from the segment header. The payload areas are
 * packed one after another right after the segment header: the
 * rest of the header's page is the inline area and the payload areas
 * occupy it first. An area can start at any offset and it can cross
 * the page boundary. So, if all payload areas are small enough (for
 * example, in compressed state), then the whole body of the log is
 * one page. The log footer occupies the page after the body.
 */
struct ssdfs_sb_log_layout {
	u32 offset[SSDFS_SB_LOG_AREAS_MAX];
	u32 size[SSDFS_SB_LOG_AREAS_MAX];
	u32 body_pages;
	u32 log_pages;
};

/*
 * ssdfs_meta_extents_total_rows() - total count of rows (embedded + overflow)
 * @extents: metadata extents array
 * @chains_count: count of chains (columns) per row
 */
static inline
u32 ssdfs_meta_extents_total_rows(struct ssdfs_dynamic_array *extents,
				  u32 chains_count)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!extents);
	BUG_ON(chains_count == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	return extents->capacity / chains_count;
}

/*
 * ssdfs_meta_extents_get() - get metadata extent by row/chain index
 * @extents: metadata extents array
 * @chains_count: count of chains (columns) per row
 * @chain: requested chain index (main or copy)
 * @row: requested row index
 * @extent: requested extent [out]
 *
 * This method copies the extent that corresponds to the requested
 * row/chain pair into @extent.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - @chain is out of range.
 * %-ENODATA    - @row is out of the array's range.
 */
static inline
int ssdfs_meta_extents_get(struct ssdfs_dynamic_array *extents,
			   u32 chains_count, u32 chain, u32 row,
			   struct ssdfs_meta_area_extent *extent)
{
	struct ssdfs_meta_area_extent *kaddr;
	u32 index;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!extents || !extent);
#endif /* CONFIG_SSDFS_DEBUG */

	if (chain >= chains_count)
		return -EINVAL;

	if (row >= ssdfs_meta_extents_total_rows(extents, chains_count))
		return -ENODATA;

	index = SSDFS_META_EXTENT_INDEX(chains_count, chain, row);

	kaddr = ssdfs_dynamic_array_get_locked(extents, index);
	if (IS_ERR_OR_NULL(kaddr))
		return kaddr == NULL ? -ENODATA : PTR_ERR(kaddr);

	err = ssdfs_memcpy(extent, 0, sizeof(struct ssdfs_meta_area_extent),
			   kaddr, 0, sizeof(struct ssdfs_meta_area_extent),
			   sizeof(struct ssdfs_meta_area_extent));

	ssdfs_dynamic_array_release(extents, index, kaddr);

	return err;
}

void ssdfs_sb_payload_memory_leaks_init(void);
void ssdfs_sb_payload_check_memory_leaks(void);

void ssdfs_payload_content_destroy(struct ssdfs_payload_content *payload);
int ssdfs_sb_log_payload_create(struct ssdfs_sb_log_payload *payload);
void ssdfs_sb_log_payload_destroy(struct ssdfs_sb_log_payload *payload);

int ssdfs_create_meta_extents_array(struct ssdfs_fs_info *fsi,
				    int desc_index,
				    struct ssdfs_meta_area_extent *embedded,
				    u32 embedded_rows, u32 chains_count,
				    struct ssdfs_dynamic_array *extents);
int ssdfs_snapshot_meta_extents_payload(struct ssdfs_dynamic_array *extents,
					u32 embedded_rows, u32 chains_count,
					struct ssdfs_payload_content *snapshot);
int ssdfs_encode_meta_extents_payload(struct ssdfs_payload_content *snapshot,
				      int compr_type,
				      struct ssdfs_payload_content *payload);

int ssdfs_encode_maptbl_cache_payload(struct ssdfs_payload_content *snapshot,
				      int compr_type,
				      struct ssdfs_payload_content *payload);

int ssdfs_read_maptbl_cache(struct ssdfs_fs_info *fsi);
int ssdfs_area_compr_type(u16 flags);
int ssdfs_snapshot_maptbl_cache_payload(struct ssdfs_fs_info *fsi,
					u32 inline_capacity,
					struct ssdfs_payload_content *payload);
u16 ssdfs_area_compression_flag(int compr_type);

void ssdfs_define_sb_log_layout(struct ssdfs_sb_log_layout *layout);
u32 ssdfs_maptbl_cache_area_size(struct ssdfs_folio_vector *vector);
u32 ssdfs_maptbl_cache_max_payload_size(u32 cache_bytes);
u32 ssdfs_maptbl_cache_payload_size(struct ssdfs_payload_content *payload);
void ssdfs_define_sb_log_payload_layout(struct ssdfs_sb_log_payload *payload,
					struct ssdfs_sb_log_layout *layout);
u32 ssdfs_meta_extents_max_payload_size(struct ssdfs_dynamic_array *extents,
					u32 embedded_rows, u32 chains_count);
u32 ssdfs_meta_extents_estimate_area_size(struct ssdfs_meta_extents_area_info *info,
					  u32 uncompr_bytes, int compr_type);
u32 ssdfs_maptbl_cache_estimate_area_size(u32 fragments_count,
					  u32 last_fragment_bytes,
					  u32 max_fragment_bytes);
int ssdfs_encode_payload_fragment(int compr_type,
				  void *src, u32 uncompr_size,
				  void *dst, u32 dst_size,
				  u32 *encoded_size, bool *is_compressed);
int ssdfs_estimate_sb_log_layout(struct super_block *sb,
				 struct ssdfs_sb_log_layout *layout);
int ssdfs_snapshot_sb_log_payload(struct super_block *sb,
				  struct ssdfs_sb_log_payload *payload);
void ssdfs_prepare_maptbl_cache_descriptor(struct ssdfs_metadata_descriptor *desc,
					   u32 offset,
					   struct ssdfs_payload_content *payload,
					   u32 payload_size);
void ssdfs_prepare_meta_extents_descriptor(struct ssdfs_metadata_descriptor *desc,
					   u32 offset,
					   struct ssdfs_payload_content *payload);

#endif /* _SSDFS_SUPERBLOCK_PAYLOAD_H */
