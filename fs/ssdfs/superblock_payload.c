/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/superblock_payload.c - superblock segment's payload areas.
 *
 * Copyright (c) 2026 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/slab.h>
#include <linux/folio_batch.h>
#include <linux/crc32.h>

#include <kunit/visibility.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "folio_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "segment_bitmap.h"
#include "peb_mapping_table.h"
#include "compression.h"
#include "superblock_payload.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_sb_payload_folio_leaks;
atomic64_t ssdfs_sb_payload_memory_leaks;
atomic64_t ssdfs_sb_payload_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_sb_payload_cache_leaks_increment(void *kaddr)
 * void ssdfs_sb_payload_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_sb_payload_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_sb_payload_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_sb_payload_kvzalloc(size_t size, gfp_t flags)
 * void *ssdfs_sb_payload_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_sb_payload_kfree(void *kaddr)
 * void ssdfs_sb_payload_kvfree(void *kaddr)
 * struct folio *ssdfs_sb_payload_alloc_folio(gfp_t gfp_mask,
 *                                            unsigned int order)
 * struct folio *ssdfs_sb_payload_add_batch_folio(struct folio_batch *batch,
 *                                                unsigned int order)
 * void ssdfs_sb_payload_free_folio(struct folio *folio)
 * void ssdfs_sb_payload_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(sb_payload)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(sb_payload)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_sb_payload_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_sb_payload_folio_leaks, 0);
	atomic64_set(&ssdfs_sb_payload_memory_leaks, 0);
	atomic64_set(&ssdfs_sb_payload_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_sb_payload_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_sb_payload_folio_leaks) != 0) {
		SSDFS_ERR("SB PAYLOAD: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_sb_payload_folio_leaks));
	}

	if (atomic64_read(&ssdfs_sb_payload_memory_leaks) != 0) {
		SSDFS_ERR("SB PAYLOAD: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_sb_payload_memory_leaks));
	}

	if (atomic64_read(&ssdfs_sb_payload_cache_leaks) != 0) {
		SSDFS_ERR("SB PAYLOAD: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_sb_payload_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

#define SSDFS_META_EXTENTS_FRAGMENT_SIZE	(SSDFS_4KB)

#define SSDFS_META_EXTENTS_PER_FRAGMENT \
	(SSDFS_META_EXTENTS_FRAGMENT_SIZE / \
	 sizeof(struct ssdfs_meta_area_extent))

/* a fragment's sequence ID is 8 bits wide */
#define SSDFS_META_EXTENTS_MAX_FRAGMENTS	(U8_MAX)

#define SSDFS_META_EXTENTS_MAX_COUNT \
	(SSDFS_META_EXTENTS_MAX_FRAGMENTS * SSDFS_META_EXTENTS_PER_FRAGMENT)

/*
 * Fragment types of every kind of payload (indexed by compression type)
 */
static const u8
ssdfs_payload_frag_types[SSDFS_PAYLOAD_KIND_MAX][SSDFS_COMPR_TYPES_CNT] = {
	[SSDFS_META_EXTENTS_PAYLOAD] = {
		[SSDFS_COMPR_NONE]	= SSDFS_META_EXT_BLOB,
		[SSDFS_COMPR_ZLIB]	= SSDFS_META_EXT_ZLIB,
		[SSDFS_COMPR_LZO]	= SSDFS_META_EXT_LZO,
		[SSDFS_COMPR_LZ4]	= SSDFS_META_EXT_LZ4,
		[SSDFS_COMPR_ZSTD]	= SSDFS_META_EXT_ZSTD,
	},
	[SSDFS_MAPTBL_CACHE_PAYLOAD] = {
		[SSDFS_COMPR_NONE]	= SSDFS_MAPTBL_CACHE_BLOB,
		[SSDFS_COMPR_ZLIB]	= SSDFS_MAPTBL_CACHE_ZLIB,
		[SSDFS_COMPR_LZO]	= SSDFS_MAPTBL_CACHE_LZO,
		[SSDFS_COMPR_LZ4]	= SSDFS_MAPTBL_CACHE_LZ4,
		[SSDFS_COMPR_ZSTD]	= SSDFS_MAPTBL_CACHE_ZSTD,
	},
};

/*
 * Chain header types of every kind of payload (indexed by compression type)
 */
static const u8
ssdfs_payload_chain_types[SSDFS_PAYLOAD_KIND_MAX][SSDFS_COMPR_TYPES_CNT] = {
	[SSDFS_META_EXTENTS_PAYLOAD] = {
		[SSDFS_COMPR_NONE]	= SSDFS_META_EXT_CHAIN_HDR,
		[SSDFS_COMPR_ZLIB]	= SSDFS_META_EXT_ZLIB_CHAIN_HDR,
		[SSDFS_COMPR_LZO]	= SSDFS_META_EXT_LZO_CHAIN_HDR,
		[SSDFS_COMPR_LZ4]	= SSDFS_META_EXT_LZ4_CHAIN_HDR,
		[SSDFS_COMPR_ZSTD]	= SSDFS_META_EXT_ZSTD_CHAIN_HDR,
	},
	[SSDFS_MAPTBL_CACHE_PAYLOAD] = {
		[SSDFS_COMPR_NONE]	= SSDFS_MAPTBL_CACHE_CHAIN_HDR,
		[SSDFS_COMPR_ZLIB]	= SSDFS_MAPTBL_CACHE_ZLIB_CHAIN_HDR,
		[SSDFS_COMPR_LZO]	= SSDFS_MAPTBL_CACHE_LZO_CHAIN_HDR,
		[SSDFS_COMPR_LZ4]	= SSDFS_MAPTBL_CACHE_LZ4_CHAIN_HDR,
		[SSDFS_COMPR_ZSTD]	= SSDFS_MAPTBL_CACHE_ZSTD_CHAIN_HDR,
	},
};

/*
 * SSDFS_PAYLOAD_FRAG_COMPR_TYPE() - map a fragment type to a compressor
 * @kind: kind of payload
 * @frag_type: fragment type
 *
 * RETURN:
 * [success] - SSDFS_COMPR_* type (SSDFS_COMPR_NONE - uncompressed fragment)
 * [failure] - error code:
 *
 * %-EOPNOTSUPP - unknown fragment type.
 */
static inline
int SSDFS_PAYLOAD_FRAG_COMPR_TYPE(int kind, u8 frag_type)
{
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(kind < 0 || kind >= SSDFS_PAYLOAD_KIND_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < SSDFS_COMPR_TYPES_CNT; i++) {
		if (ssdfs_payload_frag_types[kind][i] == frag_type)
			return i;
	}

	return -EOPNOTSUPP;
}

/*
 * SSDFS_PAYLOAD_COMPR_FRAG_TYPE() - map a compressor to a fragment type
 * @kind: kind of payload
 * @compr_type: SSDFS_COMPR_NONE/ZLIB/LZO/LZ4/ZSTD
 *
 * RETURN: the matching fragment type of @kind, or the type of
 * uncompressed fragment for unknown @compr_type.
 */
static inline
u8 SSDFS_PAYLOAD_COMPR_FRAG_TYPE(int kind, int compr_type)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(kind < 0 || kind >= SSDFS_PAYLOAD_KIND_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	if (compr_type < 0 || compr_type >= SSDFS_COMPR_TYPES_CNT)
		compr_type = SSDFS_COMPR_NONE;

	return ssdfs_payload_frag_types[kind][compr_type];
}

/*
 * SSDFS_PAYLOAD_CHAIN_HDR_TYPE() - map a compressor to a chain header type
 * @kind: kind of payload
 * @compr_type: SSDFS_COMPR_NONE/ZLIB/LZO/LZ4/ZSTD
 */
static inline
u8 SSDFS_PAYLOAD_CHAIN_HDR_TYPE(int kind, int compr_type)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(kind < 0 || kind >= SSDFS_PAYLOAD_KIND_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	if (compr_type < 0 || compr_type >= SSDFS_COMPR_TYPES_CNT)
		compr_type = SSDFS_COMPR_NONE;

	return ssdfs_payload_chain_types[kind][compr_type];
}

/*
 * IS_SSDFS_PAYLOAD_CHAIN_HDR_TYPE_VALID() - check chain header's type
 * @kind: kind of payload
 * @chain_type: chain header type
 */
static inline
bool IS_SSDFS_PAYLOAD_CHAIN_HDR_TYPE_VALID(int kind, u8 chain_type)
{
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(kind < 0 || kind >= SSDFS_PAYLOAD_KIND_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < SSDFS_COMPR_TYPES_CNT; i++) {
		if (ssdfs_payload_chain_types[kind][i] == chain_type)
			return true;
	}

	return false;
}

/* the tables of every kind of payload have the identical layout */
static_assert(sizeof(struct ssdfs_metadata_extents_table) ==
		sizeof(struct ssdfs_maptbl_cache_table));
static_assert(offsetof(struct ssdfs_metadata_extents_table, blk) ==
		offsetof(struct ssdfs_maptbl_cache_table, blk));
static_assert(SSDFS_NEXT_META_EXT_TABLE_INDEX ==
		SSDFS_NEXT_MAPTBL_CACHE_TABLE_INDEX);

void ssdfs_payload_content_destroy(struct ssdfs_payload_content *payload)
{
	if (!payload)
		return;

	ssdfs_folio_vector_release(&payload->batch);
	ssdfs_folio_vector_destroy(&payload->batch);
	payload->bytes_count = 0;
	payload->compr_type = SSDFS_COMPR_NONE;
	payload->max_fragment_bytes = 0;
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_payload_content_destroy);

/*
 * ssdfs_sb_log_payload_create() - create every payload area's folio vector
 * @payload: payload areas [out]
 *
 * This establishes every payload area (the PEB mapping table cache's
 * content, and the segment bitmap's and the PEB mapping table's
 * overflow extents) in a valid, empty state: it must be called before
 * @payload is passed to ssdfs_snapshot_sb_log_payload(), and even if
 * that never happens (for example, a caller that bails out before
 * reaching the snapshot), @payload is already safe to pass to
 * ssdfs_sb_log_payload_destroy().
 */
int ssdfs_sb_log_payload_create(struct ssdfs_sb_log_payload *payload)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!payload);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_folio_vector_create(&payload->maptbl_cache.batch,
					get_order(PAGE_SIZE), 0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create folio vector: err %d\n", err);
		return err;
	}
	payload->maptbl_cache.bytes_count = 0;
	payload->maptbl_cache.compr_type = SSDFS_COMPR_NONE;
	payload->maptbl_cache.max_fragment_bytes = 0;

	err = ssdfs_folio_vector_create(&payload->segbmap_meta_extents.batch,
					get_order(PAGE_SIZE), 0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create folio vector: err %d\n", err);
		goto fail_create_segbmap_meta_extents;
	}
	payload->segbmap_meta_extents.bytes_count = 0;
	payload->segbmap_meta_extents.compr_type = SSDFS_COMPR_NONE;
	payload->segbmap_meta_extents.max_fragment_bytes = 0;

	err = ssdfs_folio_vector_create(&payload->maptbl_meta_extents.batch,
					get_order(PAGE_SIZE), 0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create folio vector: err %d\n", err);
		goto fail_create_maptbl_meta_extents;
	}
	payload->maptbl_meta_extents.bytes_count = 0;
	payload->maptbl_meta_extents.compr_type = SSDFS_COMPR_NONE;
	payload->maptbl_meta_extents.max_fragment_bytes = 0;

	return 0;

fail_create_maptbl_meta_extents:
	ssdfs_folio_vector_destroy(&payload->segbmap_meta_extents.batch);

fail_create_segbmap_meta_extents:
	ssdfs_folio_vector_destroy(&payload->maptbl_cache.batch);

	return err;
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_sb_log_payload_create);

/*
 * ssdfs_sb_log_payload_destroy() - destroy every payload area's folio vector
 * @payload: payload areas
 */
void ssdfs_sb_log_payload_destroy(struct ssdfs_sb_log_payload *payload)
{
	if (!payload)
		return;

	ssdfs_payload_content_destroy(&payload->maptbl_cache);
	ssdfs_payload_content_destroy(&payload->segbmap_meta_extents);
	ssdfs_payload_content_destroy(&payload->maptbl_meta_extents);
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_sb_log_payload_destroy);

/*
 * ssdfs_payload_get_folio() - get payload's folio (allocate if absent)
 * @payload: payload content
 * @folio_index: index of the folio
 *
 * This method returns the folio with @folio_index. The folios
 * [count, @folio_index] are allocated if they are absent yet.
 */
static
struct folio *ssdfs_payload_get_folio(struct ssdfs_payload_content *payload,
				      u32 folio_index)
{
	struct folio *folio;
	int err;

	err = ssdfs_folio_vector_inflate(&payload->batch, folio_index + 1);
	if (unlikely(err)) {
		SSDFS_ERR("fail to inflate payload: "
			  "folios_count %u, err %d\n",
			  folio_index + 1, err);
		return ERR_PTR(err);
	}

	while (ssdfs_folio_vector_count(&payload->batch) <= folio_index) {
		folio = ssdfs_folio_vector_allocate(&payload->batch);
		if (IS_ERR_OR_NULL(folio)) {
			err = !folio ? -ENOMEM : PTR_ERR(folio);
			SSDFS_ERR("fail to add folio into vector: err %d\n",
				  err);
			return ERR_PTR(err);
		}
	}

	folio = ssdfs_folio_vector_get(&payload->batch, folio_index);
	if (!folio) {
		SSDFS_ERR("folio is absent: folio_index %u\n",
			  folio_index);
		return ERR_PTR(-ERANGE);
	}

	return folio;
}

/*
 * ssdfs_payload_write() - write bytes into payload content
 * @payload: payload content
 * @offset: byte offset within @payload to start writing at
 * @src: source buffer
 * @len: number of bytes to write
 *
 * This method copies @len bytes from @src into @payload's folios
 * starting at @offset, transparently crossing folio boundaries.
 * The folios that cover the range are allocated if they are absent
 * yet, so @payload never keeps a folio beyond the last written byte.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_payload_write(struct ssdfs_payload_content *payload,
			u32 offset, void *src, u32 len)
{
	struct folio *folio;
	u32 folio_size = PAGE_SIZE << payload->batch.order;
	u32 copied = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!payload || !src);

	SSDFS_DBG("payload %p, offset %u, len %u\n",
		  payload, offset, len);
#endif /* CONFIG_SSDFS_DEBUG */

	while (copied < len) {
		u32 folio_index = (offset + copied) / folio_size;
		u32 offset_in_folio = (offset + copied) % folio_size;
		u32 bytes_count = min_t(u32, folio_size - offset_in_folio,
					len - copied);

		folio = ssdfs_payload_get_folio(payload, folio_index);
		if (IS_ERR(folio))
			return PTR_ERR(folio);

		ssdfs_folio_lock(folio);
		err = __ssdfs_memcpy_to_folio(folio,
					      offset_in_folio, folio_size,
					      src, copied, len,
					      bytes_count);
		folio_mark_uptodate(folio);
		ssdfs_folio_unlock(folio);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: offset %u, len %u, err %d\n",
				  offset, len, err);
			return err;
		}

		copied += bytes_count;
	}

	return 0;
}

/*
 * SSDFS_PAYLOAD_ITER_INIT() - init payload iterator
 * @iter: iterator pointer
 * @kind: kind of payload
 * @desc: metadata area descriptor
 */
static inline
void SSDFS_PAYLOAD_ITER_INIT(struct ssdfs_payload_iterator *iter, int kind,
			     struct ssdfs_metadata_descriptor *desc)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!iter || !desc);
	BUG_ON(kind < 0 || kind >= SSDFS_PAYLOAD_KIND_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	iter->kind = kind;

	ssdfs_memcpy(&iter->area, 0, sizeof(struct ssdfs_metadata_descriptor),
		     desc, 0, sizeof(struct ssdfs_metadata_descriptor),
		     sizeof(struct ssdfs_metadata_descriptor));

	iter->cur_offset = le32_to_cpu(desc->offset);
	iter->fragment_id = 0;

	iter->buffer.ptr = iter->raw_buf;
	iter->buffer.offset = U64_MAX;
	iter->buffer.size = PAGE_SIZE;
}

/*
 * IS_SSDFS_PAYLOAD_ITER_VALID() - is payload iterator valid?
 * @iter: iterator pointer
 */
static inline
bool IS_SSDFS_PAYLOAD_ITER_VALID(struct ssdfs_payload_iterator *iter)
{
	u32 area_offset, area_size;

	area_offset = le32_to_cpu(iter->area.offset);
	area_size = le32_to_cpu(iter->area.size);

	return area_offset > 0 && area_size > 0 &&
		iter->cur_offset >= area_offset &&
		iter->cur_offset < (area_offset + area_size);
}

/*
 * IS_SSDFS_PAYLOAD_BUFFER_VALID() - is payload buffer valid?
 * @iter: iterator pointer
 */
static inline
bool IS_SSDFS_PAYLOAD_BUFFER_VALID(struct ssdfs_payload_iterator *iter)
{
	u32 area_offset, area_size;

	if (!IS_SSDFS_PAYLOAD_ITER_VALID(iter))
		return false;

	if (!iter->buffer.ptr)
		return false;

	if (iter->buffer.size != PAGE_SIZE)
		return false;

	if (iter->buffer.offset >= U64_MAX)
		return true;

	area_offset = le32_to_cpu(iter->area.offset);
	area_size = le32_to_cpu(iter->area.size);

	if (iter->buffer.offset < area_offset ||
	    iter->buffer.offset >= (area_offset + area_size))
		return false;

	return true;
}

/*
 * SSDFS_PAYLOAD_CHAIN_FRAGMENTS() - get number of fragments in the chain
 * @iter: iterator pointer
 */
static inline
u16 SSDFS_PAYLOAD_CHAIN_FRAGMENTS(struct ssdfs_payload_iterator *iter)
{
	if (!IS_SSDFS_PAYLOAD_ITER_VALID(iter))
		return 0;

	return le16_to_cpu(iter->tbl.chain_hdr.fragments_count);
}

/*
 * IS_SSDFS_PAYLOAD_CHAIN_HAS_NEXT() - has the chain the next table?
 * @iter: iterator pointer
 */
static inline
bool IS_SSDFS_PAYLOAD_CHAIN_HAS_NEXT(struct ssdfs_payload_iterator *iter)
{
	return le16_to_cpu(iter->tbl.chain_hdr.flags) &
						SSDFS_MULTIPLE_HDR_CHAIN;
}

/*
 * IS_SSDFS_PAYLOAD_CHAIN_ENDED() - is fragments chain ended?
 * @iter: iterator pointer
 *
 * The chain that has the next table isn't ended after the last
 * fragment because the descriptor of the next table
 * (SSDFS_NEXT_META_EXT_TABLE_INDEX) has to be processed yet by
 * ssdfs_get_payload_next_fragment().
 */
static inline
bool IS_SSDFS_PAYLOAD_CHAIN_ENDED(struct ssdfs_payload_iterator *iter)
{
	if (!IS_SSDFS_PAYLOAD_ITER_VALID(iter))
		return true;

	if (IS_SSDFS_PAYLOAD_CHAIN_HAS_NEXT(iter))
		return iter->fragment_id > SSDFS_NEXT_META_EXT_TABLE_INDEX;

	return iter->fragment_id >= SSDFS_PAYLOAD_CHAIN_FRAGMENTS(iter);
}

/*
 * IS_SSDFS_PAYLOAD_ENDED() - is payload stream ended?
 * @iter: iterator pointer
 *
 * The payload stream is ended if the end of the area is reached or
 * the last chain (the chain without the next table) has been
 * processed completely.
 */
static inline
bool IS_SSDFS_PAYLOAD_ENDED(struct ssdfs_payload_iterator *iter)
{
	u32 area_offset, area_size;

	if (!IS_SSDFS_PAYLOAD_ITER_VALID(iter))
		return true;

	area_offset = le32_to_cpu(iter->area.offset);
	area_size = le32_to_cpu(iter->area.size);

	if (iter->cur_offset >= (area_offset + area_size))
		return true;

	if (iter->tbl.chain_hdr.magic != SSDFS_CHAIN_HDR_MAGIC) {
		/* no chain has been read yet */
		return false;
	}

	return !IS_SSDFS_PAYLOAD_CHAIN_HAS_NEXT(iter) &&
		IS_SSDFS_PAYLOAD_CHAIN_ENDED(iter);
}

/*
 * ssdfs_read_payload_buffer() - read area's content into iterator's buffer
 * @fsi: file system info object
 * @iter: iterator pointer
 * @offset: offset in the log to start reading at
 *
 * This method reads the iterator's buffer starting at @offset. The read
 * never goes beyond the area's end: the bytes of the buffer beyond
 * the area's end are never used because every fragment is checked
 * to be inside of the area.
 */
static
int ssdfs_read_payload_buffer(struct ssdfs_fs_info *fsi,
			      struct ssdfs_payload_iterator *iter,
			      u32 offset)
{
	u64 peb_id = fsi->sbi.last_log.peb_id;
	u32 area_offset = le32_to_cpu(iter->area.offset);
	u32 area_size = le32_to_cpu(iter->area.size);
	u32 area_end = area_offset + area_size;
	u32 read_bytes;
	int err;

	if (offset < area_offset || offset >= area_end) {
		SSDFS_ERR("offset %u is out of area: "
			  "area_offset %u, area_size %u\n",
			  offset, area_offset, area_size);
		return -ERANGE;
	}

	read_bytes = min_t(u32, iter->buffer.size, area_end - offset);

	err = ssdfs_unaligned_read_buffer(fsi, peb_id, PAGE_SIZE,
					  offset, iter->buffer.ptr,
					  read_bytes);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read payload area: "
			  "peb_id %llu, offset %u, "
			  "size %u, err %d\n",
			  peb_id, offset, read_bytes, err);
		return err;
	}

	iter->buffer.offset = offset;
	return 0;
}

/*
 * ssdfs_read_payload_next_chain() - read the next fragments chain
 * @fsi: file system info object
 * @iter: iterator pointer
 */
static
int ssdfs_read_payload_next_chain(struct ssdfs_fs_info *fsi,
				  struct ssdfs_payload_iterator *iter)
{
	size_t hdr_size = sizeof(struct ssdfs_metadata_extents_table);
	size_t desc_size = sizeof(struct ssdfs_fragment_desc);
	u32 area_offset, area_size;
	u32 rest_bytes;
	u16 fragments_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !iter);

	SSDFS_DBG("fsi %p, iter %p\n",
		  fsi, iter);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!IS_SSDFS_PAYLOAD_BUFFER_VALID(iter)) {
		SSDFS_ERR("buffer is invalid\n");
		return -EINVAL;
	}

	area_offset = le32_to_cpu(iter->area.offset);
	area_size = le32_to_cpu(iter->area.size);
	rest_bytes = area_size - (iter->cur_offset - area_offset);

	if (rest_bytes < hdr_size) {
		SSDFS_ERR("table is out of area: "
			  "cur_offset %u, area_offset %u, area_size %u\n",
			  iter->cur_offset, area_offset, area_size);
		return -EIO;
	}

	err = ssdfs_read_payload_buffer(fsi, iter, iter->cur_offset);
	if (unlikely(err))
		return err;

	err = ssdfs_memcpy(&iter->tbl, 0, hdr_size,
			   iter->buffer.ptr, 0, iter->buffer.size,
			   hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		return err;
	}

	if (iter->cur_offset == area_offset &&
	    (le16_to_cpu(iter->area.check.flags) & SSDFS_CRC32)) {
		__le32 csum;

		/* the area's checksum covers the first table's header */
		if (le16_to_cpu(iter->area.check.bytes) != hdr_size) {
			SSDFS_ERR("invalid checked bytes %u\n",
				  le16_to_cpu(iter->area.check.bytes));
			return -EIO;
		}

		csum = ssdfs_crc32_le(&iter->tbl, hdr_size);
		if (csum != iter->area.check.csum) {
			SSDFS_ERR("invalid first table's checksum: "
				  "csum1 %#x, csum2 %#x\n",
				  le32_to_cpu(csum),
				  le32_to_cpu(iter->area.check.csum));
			return -EIO;
		}
	}

	if (iter->tbl.chain_hdr.magic != SSDFS_CHAIN_HDR_MAGIC) {
		SSDFS_ERR("invalid chain header's magic %#x\n",
			  iter->tbl.chain_hdr.magic);
		return -EIO;
	}

	if (!IS_SSDFS_PAYLOAD_CHAIN_HDR_TYPE_VALID(iter->kind,
						   iter->tbl.chain_hdr.type)) {
		SSDFS_ERR("invalid chain header's type %#x: kind %d\n",
			  iter->tbl.chain_hdr.type, iter->kind);
		return -EIO;
	}

	if (le16_to_cpu(iter->tbl.chain_hdr.desc_size) != desc_size) {
		SSDFS_ERR("invalid descriptor size %u\n",
			  le16_to_cpu(iter->tbl.chain_hdr.desc_size));
		return -EIO;
	}

	if (le32_to_cpu(iter->tbl.chain_hdr.compr_bytes) > rest_bytes) {
		SSDFS_ERR("compr_bytes %u, rest_bytes %u\n",
			  le32_to_cpu(iter->tbl.chain_hdr.compr_bytes),
			  rest_bytes);
		return -EIO;
	}

	fragments_count = le16_to_cpu(iter->tbl.chain_hdr.fragments_count);

	if (fragments_count > SSDFS_NEXT_META_EXT_TABLE_INDEX) {
		SSDFS_ERR("fragments_count %u > MAX %u\n",
			  fragments_count,
			  SSDFS_NEXT_META_EXT_TABLE_INDEX);
		return -EIO;
	}

	if (IS_SSDFS_PAYLOAD_CHAIN_HAS_NEXT(iter) &&
	    fragments_count != SSDFS_NEXT_META_EXT_TABLE_INDEX) {
		SSDFS_ERR("chain with next table isn't full: "
			  "fragments_count %u\n",
			  fragments_count);
		return -EIO;
	}

	iter->cur_offset += hdr_size;
	iter->fragment_id = 0;

	return 0;
}

/*
 * ssdfs_get_payload_next_fragment() - get a next fragment in payload
 * @fsi: file system info object
 * @iter: iterator pointer
 *
 * This method positions @iter on the current fragment of the chain
 * and makes sure that the whole fragment is inside of the iterator's
 * buffer. If the current fragment is the descriptor of the next
 * table (SSDFS_NEXT_META_EXT_TABLE_INDEX), then @iter is positioned
 * on the next table and %-ENODATA is returned.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - @iter is positioned on the next table.
 * %-EIO        - area is corrupted.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_get_payload_next_fragment(struct ssdfs_fs_info *fsi,
				    struct ssdfs_payload_iterator *iter)
{
	struct ssdfs_fragment_desc *frag;
	u32 area_offset, area_size;
	u32 frag_offset;
	u32 compr_size;
	u32 upper_bound1, upper_bound2;
	u16 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !iter);

	SSDFS_DBG("fsi %p, iter %p\n",
		  fsi, iter);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!IS_SSDFS_PAYLOAD_BUFFER_VALID(iter)) {
		SSDFS_ERR("buffer is invalid\n");
		return -EINVAL;
	}

	if (iter->fragment_id > SSDFS_NEXT_META_EXT_TABLE_INDEX) {
		SSDFS_ERR("fragment_id %u > MAX %u\n",
			  iter->fragment_id,
			  SSDFS_NEXT_META_EXT_TABLE_INDEX);
		return -EIO;
	}

	area_offset = le32_to_cpu(iter->area.offset);
	area_size = le32_to_cpu(iter->area.size);

	frag = &iter->tbl.blk[iter->fragment_id];

	if (frag->sequence_id != iter->fragment_id) {
		SSDFS_ERR("corrupted fragment[%u]: "
			  "sequence_id %u\n",
			  iter->fragment_id,
			  frag->sequence_id);
		return -EIO;
	}

	frag_offset = le32_to_cpu(frag->offset);
	compr_size = le16_to_cpu(frag->compr_size);

	if (frag_offset >= area_size || compr_size == 0 ||
	    compr_size > iter->buffer.size) {
		SSDFS_ERR("corrupted fragment[%u]: "
			  "area_size %u, frag_offset %u, compr_size %u\n",
			  iter->fragment_id, area_size,
			  frag_offset, compr_size);
		return -EIO;
	}

	frag_offset += area_offset;

	upper_bound1 = frag_offset + compr_size;
	upper_bound2 = area_offset + area_size;

	if (upper_bound1 > upper_bound2) {
		SSDFS_ERR("corrupted fragment[%u]: "
			  "area_offset %u, area_size %u, "
			  "frag_offset %u, compr_size %u\n",
			  iter->fragment_id,
			  area_offset, area_size,
			  frag_offset, compr_size);
		return -EIO;
	}

	/* fragments and tables can only go forward */
	if (iter->cur_offset > frag_offset) {
		SSDFS_ERR("corrupted fragment[%u]: "
			  "area_offset %u, area_size %u, "
			  "frag_offset %u, compr_size %u, "
			  "iter->cur_offset %u\n",
			  iter->fragment_id,
			  area_offset, area_size,
			  frag_offset, compr_size,
			  iter->cur_offset);
		return -EIO;
	}

	if (iter->fragment_id == SSDFS_NEXT_META_EXT_TABLE_INDEX) {
		flags = le16_to_cpu(iter->tbl.chain_hdr.flags);

		if (!(flags & SSDFS_MULTIPLE_HDR_CHAIN)) {
			SSDFS_ERR("corrupted chain header: flags %#x\n",
				  flags);
			return -EIO;
		}

		if (frag->type != SSDFS_NEXT_TABLE_DESC) {
			SSDFS_ERR("invalid next table descriptor type %#x\n",
				  frag->type);
			return -EIO;
		}

		iter->cur_offset = frag_offset;

		/* finish processing the chain */
		return -ENODATA;
	}

	upper_bound2 = iter->buffer.offset + iter->buffer.size;

	if (iter->cur_offset < iter->buffer.offset ||
	    iter->cur_offset > upper_bound2) {
		SSDFS_ERR("corrupted iterator: "
			  "iter->cur_offset %u, "
			  "iter->buffer.offset %llu\n",
			  iter->cur_offset,
			  iter->buffer.offset);
		return -ERANGE;
	}

	if (upper_bound1 > upper_bound2) {
		/* fragment isn't in the buffer completely */
		err = ssdfs_read_payload_buffer(fsi, iter, frag_offset);
		if (unlikely(err))
			return err;
	}

	iter->cur_offset = frag_offset;

	return 0;
}

/*
 * ssdfs_extract_payload_fragment() - extract fragment's payload
 * @iter: iterator pointer
 * @payload: payload content
 *
 * This method extracts the current fragment from the iterator's buffer
 * and stores the fragment's uncompressed content into @payload.
 *
 * The metadata extents' fragments are appended to @payload as contiguous
 * sequence of bytes. Every fragment, except the last one, has to be full
 * (SSDFS_META_EXTENTS_FRAGMENT_SIZE). So, every fragment starts on
 * SSDFS_META_EXTENTS_FRAGMENT_SIZE boundary of @payload.
 *
 * Every fragment of the PEB mapping table cache occupies its own memory
 * page of @payload (the rest of the page is zeroed) because any fragment
 * of the cache can be partially filled. So, @payload's bytes_count is
 * the number of pages multiplied by PAGE_SIZE.
 *
 * In both cases, the fragment is never split between folios: the fragment
 * is decompressed directly into @payload's folio.
 */
static
int ssdfs_extract_payload_fragment(struct ssdfs_payload_iterator *iter,
				   struct ssdfs_payload_content *payload)
{
	struct ssdfs_fragment_desc *frag;
	struct folio *folio;
	size_t item_size = sizeof(struct ssdfs_meta_area_extent);
	size_t cache_hdr_size = sizeof(struct ssdfs_maptbl_cache_header);
	u32 folio_size = PAGE_SIZE << payload->batch.order;
	u8 *src_ptr, *dst_ptr;
	u32 area_offset;
	u32 upper_bound1, upper_bound2;
	u32 frag_offset;
	u32 compr_size;
	u32 uncompr_size;
	u32 read_offset;
	u32 offset_in_folio;
	u32 stored_bytes;
	__le32 csum;
	int compr_type;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!iter || !payload);

	SSDFS_DBG("iter %p, payload %p\n",
		  iter, payload);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!IS_SSDFS_PAYLOAD_BUFFER_VALID(iter)) {
		SSDFS_ERR("buffer is invalid\n");
		return -EINVAL;
	}

	if (iter->fragment_id >= SSDFS_NEXT_META_EXT_TABLE_INDEX) {
		SSDFS_ERR("fragment_id %u >= MAX %u\n",
			  iter->fragment_id,
			  SSDFS_NEXT_META_EXT_TABLE_INDEX);
		return -EIO;
	}

	frag = &iter->tbl.blk[iter->fragment_id];

	if (frag->sequence_id != iter->fragment_id) {
		SSDFS_ERR("corrupted fragment[%u]: "
			  "sequence_id %u\n",
			  iter->fragment_id,
			  frag->sequence_id);
		return -EIO;
	}

	area_offset = le32_to_cpu(iter->area.offset);

	frag_offset = le32_to_cpu(frag->offset);
	frag_offset += area_offset;
	compr_size = le16_to_cpu(frag->compr_size);
	uncompr_size = le16_to_cpu(frag->uncompr_size);

	switch (iter->kind) {
	case SSDFS_META_EXTENTS_PAYLOAD:
		if (uncompr_size == 0 || (uncompr_size % item_size) != 0 ||
		    uncompr_size > SSDFS_META_EXTENTS_FRAGMENT_SIZE) {
			SSDFS_ERR("invalid fragment size: "
				  "compr_size %u, uncompr_size %u\n",
				  compr_size, uncompr_size);
			return -EIO;
		}

		BUILD_BUG_ON(SSDFS_META_EXTENTS_FRAGMENT_SIZE > PAGE_SIZE);

		if ((payload->bytes_count %
				SSDFS_META_EXTENTS_FRAGMENT_SIZE) != 0) {
			SSDFS_ERR("only the last fragment can be partial: "
				  "fragment_id %u, bytes_count %u\n",
				  iter->fragment_id, payload->bytes_count);
			return -EIO;
		}

		stored_bytes = uncompr_size;
		break;

	case SSDFS_MAPTBL_CACHE_PAYLOAD:
		if (uncompr_size < cache_hdr_size ||
		    uncompr_size > PAGE_SIZE) {
			SSDFS_ERR("invalid fragment size: "
				  "compr_size %u, uncompr_size %u\n",
				  compr_size, uncompr_size);
			return -EIO;
		}

		if ((payload->bytes_count % PAGE_SIZE) != 0) {
			SSDFS_ERR("corrupted payload: bytes_count %u\n",
				  payload->bytes_count);
			return -ERANGE;
		}

		/* every fragment occupies the whole memory page */
		stored_bytes = PAGE_SIZE;
		break;

	default:
		SSDFS_ERR("unexpected payload kind %d\n", iter->kind);
		return -ERANGE;
	}

	upper_bound1 = iter->buffer.offset + iter->buffer.size;
	upper_bound2 = frag_offset + compr_size;

	if (frag_offset < iter->buffer.offset || upper_bound2 > upper_bound1) {
		SSDFS_ERR("invalid iterator state: "
			  "iter->buffer.offset %llu, iter->buffer.size %u, "
			  "frag_offset %u, compr_size %u\n",
			  iter->buffer.offset,
			  iter->buffer.size,
			  frag_offset,
			  compr_size);
		return -ERANGE;
	}

	read_offset = frag_offset - iter->buffer.offset;
	src_ptr = iter->buffer.ptr + read_offset;

	compr_type = SSDFS_PAYLOAD_FRAG_COMPR_TYPE(iter->kind, frag->type);
	if (compr_type < 0) {
		SSDFS_ERR("unsupported fragment type %#x: kind %d\n",
			  frag->type, iter->kind);
		return -EOPNOTSUPP;
	}

	if (compr_type == SSDFS_COMPR_NONE) {
		if (compr_size != uncompr_size) {
			SSDFS_ERR("invalid fragment size: "
				  "compr_size %u, uncompr_size %u\n",
				  compr_size, uncompr_size);
			return -EIO;
		}
	} else {
		if (compr_size == 0 || compr_size > uncompr_size) {
			SSDFS_ERR("invalid fragment size: "
				  "compr_size %u, uncompr_size %u\n",
				  compr_size, uncompr_size);
			return -EIO;
		}
	}

	folio = ssdfs_payload_get_folio(payload,
					payload->bytes_count / folio_size);
	if (IS_ERR(folio))
		return PTR_ERR(folio);

	/*
	 * The fragment starts on the fragment's size boundary (or
	 * on the page boundary) and it isn't bigger than the memory
	 * page. So, the fragment is inside of one memory page
	 * of the folio.
	 */
	offset_in_folio = payload->bytes_count % folio_size;

	ssdfs_folio_lock(folio);
	dst_ptr = kmap_local_folio(folio, offset_in_folio);

	if (compr_type == SSDFS_COMPR_NONE) {
		memcpy(dst_ptr, src_ptr, uncompr_size);
	} else {
		err = ssdfs_decompress(compr_type,
					src_ptr, dst_ptr,
					compr_size, uncompr_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to decompress fragment: "
				  "kind %d, err %d\n",
				  iter->kind, err);
		}
	}

	if (!err && (frag->flags & SSDFS_FRAGMENT_HAS_CSUM)) {
		csum = ssdfs_crc32_le(dst_ptr, uncompr_size);

		if (csum != frag->checksum) {
			SSDFS_ERR("invalid fragment checksum: "
				  "csum1 %#x, csum2 %#x\n",
				  le32_to_cpu(csum),
				  le32_to_cpu(frag->checksum));
			err = -EIO;
		}
	}

	if (!err && stored_bytes > uncompr_size)
		memset(dst_ptr + uncompr_size, 0, stored_bytes - uncompr_size);

	flush_dcache_folio(folio);
	kunmap_local(dst_ptr);
	folio_mark_uptodate(folio);
	ssdfs_folio_unlock(folio);

	if (unlikely(err))
		return err;

	iter->cur_offset += compr_size;
	payload->bytes_count += stored_bytes;
	payload->max_fragment_bytes = max_t(u32, payload->max_fragment_bytes,
					    compr_size);
	iter->fragment_id++;

	return 0;
}

/*
 * ssdfs_extract_payload() - extract area's payload
 * @fsi: file system info object
 * @kind: kind of payload
 * @desc: metadata area descriptor
 * @payload: payload content [out]
 *
 * This method walks through the chain of tables of the area and stores
 * the uncompressed content of every fragment into @payload (see
 * ssdfs_extract_payload_fragment()). @payload's folio vector is created
 * by this method and the caller is responsible for destroying @payload
 * (even if the method fails).
 */
static
int ssdfs_extract_payload(struct ssdfs_fs_info *fsi, int kind,
			  struct ssdfs_metadata_descriptor *desc,
			  struct ssdfs_payload_content *payload)
{
	struct ssdfs_payload_iterator *iter;
	size_t iter_size = sizeof(struct ssdfs_payload_iterator);
	u16 fragments_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !desc || !payload);

	SSDFS_DBG("fsi %p, kind %d, desc %p, payload %p\n",
		  fsi, kind, desc, payload);
#endif /* CONFIG_SSDFS_DEBUG */

	payload->bytes_count = 0;
	payload->compr_type = SSDFS_COMPR_NONE;
	payload->max_fragment_bytes = 0;
	err = ssdfs_folio_vector_create(&payload->batch,
					get_order(PAGE_SIZE),
					0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create folio vector: err %d\n",
			  err);
		return err;
	}

	if (le32_to_cpu(desc->size) == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("metadata area is empty\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	iter = ssdfs_sb_payload_kzalloc(iter_size, GFP_KERNEL);
	if (!iter) {
		SSDFS_ERR("fail to allocate memory\n");
		return -ENOMEM;
	}

	err = -ENODATA;
	SSDFS_PAYLOAD_ITER_INIT(iter, kind, desc);

	while (!IS_SSDFS_PAYLOAD_ENDED(iter)) {
		err = ssdfs_read_payload_next_chain(fsi, iter);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read next fragments chain: "
				  "err %d\n", err);
			goto finish_extract_payload;
		}

		fragments_count = SSDFS_PAYLOAD_CHAIN_FRAGMENTS(iter);
		if (fragments_count == 0 ||
		    fragments_count > SSDFS_NEXT_META_EXT_TABLE_INDEX) {
			err = -EIO;
			SSDFS_ERR("invalid fragments count: "
				  "fragments_count %u\n",
				  fragments_count);
			goto finish_extract_payload;
		}

		while (!IS_SSDFS_PAYLOAD_CHAIN_ENDED(iter)) {
			err = ssdfs_get_payload_next_fragment(fsi, iter);
			if (err == -ENODATA) {
				/* SSDFS_NEXT_META_EXT_TABLE_INDEX */
				err = 0;
				break;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to get next fragment: "
					  "err %d\n", err);
				goto finish_extract_payload;
			}

			err = ssdfs_extract_payload_fragment(iter, payload);
			if (unlikely(err)) {
				SSDFS_ERR("fail to extract fragment: "
					  "err %d\n", err);
				goto finish_extract_payload;
			}
		}
	}

finish_extract_payload:
	ssdfs_sb_payload_kfree(iter);
	return err;
}

/*
 * ssdfs_create_meta_extents_array() - build the combined extents array
 * @fsi: file system info object
 * @desc_index: SSDFS_SEGBMAP_META_EXTENTS_INDEX or
 *              SSDFS_MAPTBL_META_EXTENTS_INDEX
 * @embedded: pointer on the first item of the volume header's embedded
 *            extents array
 * @embedded_rows: count of rows in the embedded array
 * @chains_count: count of chains (columns) per row
 * @extents: metadata extents array to create and populate [out]
 *
 * This method builds @extents out of the volume header's embedded
 * extents (rows [0, embedded_rows)) followed by the extents that
 * overflow the volume header, if any (rows [embedded_rows, total)):
 * the latter are read and parsed from the metadata extents area of
 * the current superblock segment's log. That area is absent for the
 * great majority of volumes: it exists only when mkfs.ssdfs has
 * allocated more segments for the segment bitmap or for the PEB
 * mapping table than the volume header's embedded extents can
 * describe. An absent area isn't an error: @extents ends up holding
 * only the embedded rows.
 *
 * @embedded and the on-disk overflow area both keep every chain's
 * extent of a row side by side (that's the on-disk format), and
 * @extents keeps the same layout in memory (see
 * SSDFS_META_EXTENT_INDEX()). So, the overflow extents are stored
 * into @extents at first, then they are shifted right behind
 * the embedded ones, and, finally, the embedded extents are stored
 * into the head of @extents.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid @desc_index.
 * %-EIO        - area is corrupted.
 * %-EOPNOTSUPP - area's content isn't supported.
 * %-ENOMEM     - fail to allocate memory.
 */
int ssdfs_create_meta_extents_array(struct ssdfs_fs_info *fsi,
				    int desc_index,
				    struct ssdfs_meta_area_extent *embedded,
				    u32 embedded_rows, u32 chains_count,
				    struct ssdfs_dynamic_array *extents)
{
	struct ssdfs_segment_header *seg_hdr;
	struct ssdfs_metadata_descriptor *meta_desc = NULL;
	struct ssdfs_payload_content payload;
	size_t item_size = sizeof(struct ssdfs_meta_area_extent);
	bool has_overflow_area;
	u32 area_offset, area_size;
	u32 extents_count = 0;
	u32 embedded_count;
	u32 total_count;
	u32 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !embedded || !extents);
	BUG_ON(embedded_rows == 0 || chains_count == 0);

	SSDFS_DBG("fsi %p, desc_index %d\n", fsi, desc_index);
#endif /* CONFIG_SSDFS_DEBUG */

	seg_hdr = SSDFS_SEG_HDR(fsi->sbi.vh_buf);

	switch (desc_index) {
	case SSDFS_SEGBMAP_META_EXTENTS_INDEX:
		has_overflow_area = ssdfs_log_has_segbmap_ext_chain(seg_hdr);
		break;

	case SSDFS_MAPTBL_META_EXTENTS_INDEX:
		has_overflow_area = ssdfs_log_has_maptbl_ext_chain(seg_hdr);
		break;

	default:
		SSDFS_ERR("invalid descriptor index %d\n", desc_index);
		return -EINVAL;
	}

	embedded_count = embedded_rows * chains_count;
	total_count = embedded_count;

	if (has_overflow_area) {
		meta_desc = &seg_hdr->desc_array[desc_index];
		area_offset = le32_to_cpu(meta_desc->offset);
		area_size = le32_to_cpu(meta_desc->size);

		if (area_offset == 0 || area_size == 0 ||
		    (area_offset + area_size) > fsi->erasesize) {
			SSDFS_ERR("corrupted metadata area descriptor: "
				  "area_offset %u, area_size %u\n",
				  area_offset, area_size);
			return -EIO;
		}

		err = ssdfs_extract_payload(fsi, SSDFS_META_EXTENTS_PAYLOAD,
					    meta_desc, &payload);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract payload: err %d\n", err);
			goto finish_process_overflow_area;
		}

		extents_count = payload.bytes_count / item_size;

		if ((payload.bytes_count % item_size) != 0 ||
		    extents_count == 0 ||
		    extents_count > SSDFS_META_EXTENTS_MAX_COUNT ||
		    (extents_count % chains_count) != 0) {
			SSDFS_ERR("invalid extents_count %u\n", extents_count);
			err = -EIO;
			goto finish_process_overflow_area;
		}

		total_count += extents_count;

		err = ssdfs_dynamic_array_create(extents, total_count,
						 item_size, 0);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create meta extents array: "
				  "total_count %u, err %d\n",
				  total_count, err);
			goto finish_process_overflow_area;
		}

		err = ssdfs_dynamic_array_set_content(extents, &payload);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set overflow extents: "
				  "extents_count %u, err %d\n",
				  extents_count, err);
			ssdfs_dynamic_array_destroy(extents);
			goto finish_process_overflow_area;
		}

		/* move overflow extents behind the embedded ones */
		err = ssdfs_dynamic_array_shift_content_right(extents, 0,
							      embedded_count);
		if (unlikely(err)) {
			SSDFS_ERR("fail to shift overflow extents: "
				  "embedded_count %u, err %d\n",
				  embedded_count, err);
			ssdfs_dynamic_array_destroy(extents);
			goto finish_process_overflow_area;
		}

finish_process_overflow_area:
		ssdfs_payload_content_destroy(&payload);

		if (unlikely(err))
			return err;
	} else {
		err = ssdfs_dynamic_array_create(extents, total_count,
						 item_size, 0);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create meta extents array: "
				  "total_count %u, err %d\n",
				  total_count, err);
			return err;
		}
	}

	/* embedded extents: items [0, embedded_count) */
	for (i = 0; i < embedded_count; i++) {
		err = ssdfs_dynamic_array_set(extents, i, &embedded[i]);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set embedded extent: "
				  "row %u, chain %u, err %d\n",
				  i / chains_count, i % chains_count, err);
			goto fail_populate_array;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(extents->items_count != total_count);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;

fail_populate_array:
	ssdfs_dynamic_array_destroy(extents);
	return err;
}

/*
 * ssdfs_snapshot_meta_extents_payload() - snapshot extents into a payload
 * @extents: metadata extents array (every row, embedded and overflow)
 * @embedded_rows: count of rows in the embedded array
 * @chains_count: count of chains (columns) per row
 * @snapshot: extents snapshot [out]
 *
 * This method copies the overflow extents (the extents past the
 * embedded ones, which the volume header already keeps) into
 * @snapshot. Every folio of @snapshot keeps the content of one
 * fragment (up to SSDFS_META_EXTENTS_PER_FRAGMENT extents) and
 * @snapshot's bytes_count is the total size of the overflow extents.
 *
 * @snapshot's folio vector is always created by this method (even
 * if the method fails or there are no overflow extents) and the
 * caller is responsible for destroying @snapshot.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - there are no overflow extents.
 * %-E2BIG      - too many extents.
 * %-ENOMEM     - fail to allocate memory.
 * %-ERANGE     - internal error.
 */
int ssdfs_snapshot_meta_extents_payload(struct ssdfs_dynamic_array *extents,
					u32 embedded_rows, u32 chains_count,
					struct ssdfs_payload_content *snapshot)
{
	struct folio *folio;
	void *kaddr;
	u32 per_fragment = SSDFS_META_EXTENTS_PER_FRAGMENT;
	u32 total_count;
	u32 embedded_count;
	u32 overflow_count;
	u32 copied;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!extents || !snapshot);
	BUG_ON(embedded_rows == 0 || chains_count == 0);
	BUG_ON(extents->capacity < (embedded_rows * chains_count));
	BUG_ON(extents->item_size != sizeof(struct ssdfs_meta_area_extent));

	SSDFS_DBG("extents %p, snapshot %p\n",
		  extents, snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_folio_vector_create(&snapshot->batch,
					get_order(PAGE_SIZE), 0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create folio vector: err %d\n", err);
		return err;
	}
	snapshot->bytes_count = 0;
	snapshot->compr_type = SSDFS_COMPR_NONE;
	snapshot->max_fragment_bytes = 0;

	embedded_count = embedded_rows * chains_count;

	total_count = extents->items_count;
	if (total_count < embedded_count || total_count != extents->capacity) {
		SSDFS_ERR("metadata extents array isn't complete: "
			  "items_count %u, capacity %u, embedded_count %u\n",
			  total_count, extents->capacity, embedded_count);
		return -ERANGE;
	}

	overflow_count = total_count - embedded_count;

	if (overflow_count == 0) {
		/* the volume header keeps all the extents */
		return -ENODATA;
	}

	if (overflow_count > SSDFS_META_EXTENTS_MAX_COUNT) {
		SSDFS_ERR("too many metadata extents: count %u\n",
			  overflow_count);
		return -E2BIG;
	}

	err = ssdfs_folio_vector_inflate(&snapshot->batch,
				DIV_ROUND_UP(overflow_count, per_fragment));
	if (unlikely(err)) {
		SSDFS_ERR("fail to inflate snapshot: err %d\n", err);
		return err;
	}

	copied = 0;
	while (copied < overflow_count) {
		u32 start_index = embedded_count + copied;
		u32 count = min_t(u32, per_fragment, overflow_count - copied);

		folio = ssdfs_folio_vector_allocate(&snapshot->batch);
		if (IS_ERR_OR_NULL(folio)) {
			err = !folio ? -ENOMEM : PTR_ERR(folio);
			SSDFS_ERR("fail to add folio into batch: err %d\n",
				  err);
			return err;
		}

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);
		err = ssdfs_dynamic_array_copy_content_range(extents,
							     start_index,
							     count,
							     kaddr,
							     PAGE_SIZE);
		kunmap_local(kaddr);
		flush_dcache_folio(folio);
		folio_mark_uptodate(folio);
		ssdfs_folio_unlock(folio);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy content: "
				  "start_index %u, count %u, err %d\n",
				  start_index, count, err);
			return err;
		}

		copied += count;
		snapshot->bytes_count += count * extents->item_size;
	}

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_snapshot_meta_extents_payload);

/*
 * ssdfs_payload_chain_header_init() - init chain header
 * @iter: iterator pointer
 * @compr_type: compresssion type
 */
static inline
void ssdfs_payload_chain_header_init(struct ssdfs_payload_iterator *iter,
				     int compr_type)
{
	struct ssdfs_metadata_extents_table *table;
	size_t desc_size = sizeof(struct ssdfs_fragment_desc);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!iter);

	SSDFS_DBG("iter %p\n", iter);
#endif /* CONFIG_SSDFS_DEBUG */

	table = &iter->tbl;
	memset(table, 0, sizeof(struct ssdfs_metadata_extents_table));

	table->chain_hdr.compr_bytes = cpu_to_le32(0);
	table->chain_hdr.uncompr_bytes = cpu_to_le32(0);
	table->chain_hdr.fragments_count = cpu_to_le16(0);
	table->chain_hdr.desc_size = cpu_to_le16((u16)desc_size);
	table->chain_hdr.magic = SSDFS_CHAIN_HDR_MAGIC;
	table->chain_hdr.type = SSDFS_PAYLOAD_CHAIN_HDR_TYPE(iter->kind,
							     compr_type);
	table->chain_hdr.flags = cpu_to_le16(0);
}

/*
 * ssdfs_save_fragment_into_payload() - save fragment into a payload
 * @iter: iterator pointer
 * @compr_size: compressed size in bytes
 * @payload: encoded payload [out]
 *
 * This method stores the fragment from the iterator's buffer into
 * @payload at the iterator's current write position
 * (iter->buffer.offset) and moves the write position.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_save_fragment_into_payload(struct ssdfs_payload_iterator *iter,
				     u32 compr_size,
				     struct ssdfs_payload_content *payload)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!iter || !payload);

	SSDFS_DBG("iter %p, payload %p, compr_size %u\n",
		  iter, payload, compr_size);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_payload_write(payload, (u32)iter->buffer.offset,
				  iter->buffer.ptr, compr_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store fragment into payload: "
			  "offset %llu, compr_size %u, err %d\n",
			  iter->buffer.offset, compr_size, err);
		return err;
	}

	iter->buffer.offset += compr_size;

	return 0;
}

/*
 * ssdfs_encode_payload_fragment() - encode fragment of payload area
 * @compr_type: compression type
 * @src: uncompressed fragment
 * @uncompr_size: uncompressed size of fragment in bytes
 * @dst: buffer for encoded fragment
 * @dst_size: size of @dst in bytes
 * @encoded_size: size of encoded fragment in bytes [out]
 * @is_compressed: is fragment stored in compressed state? [out]
 *
 * A fragment is compressed only if its uncompressed size is bigger
 * than SSDFS_UNCOMPR_BLOB_UPPER_THRESHOLD and the compression makes
 * the fragment smaller. Otherwise, the fragment is stored uncompressed.
 * This method is used by the encoding of payload area as well as by
 * the estimation of payload area's size. So, both of them define
 * the same size of encoded fragment.
 *
 * RETURN:
 * [success] - @dst contains encoded fragment.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_encode_payload_fragment(int compr_type,
				  void *src, u32 uncompr_size,
				  void *dst, u32 dst_size,
				  u32 *encoded_size, bool *is_compressed)
{
	size_t srclen = uncompr_size;
	size_t destlen = uncompr_size;
	bool need_compress;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!src || !dst || !encoded_size || !is_compressed);

	SSDFS_DBG("compr_type %d, uncompr_size %u, dst_size %u\n",
		  compr_type, uncompr_size, dst_size);
#endif /* CONFIG_SSDFS_DEBUG */

	*encoded_size = 0;
	*is_compressed = false;

	if (uncompr_size == 0 || uncompr_size > dst_size) {
		SSDFS_ERR("invalid size: uncompr_size %u, dst_size %u\n",
			  uncompr_size, dst_size);
		return -EINVAL;
	}

	if (compr_type < SSDFS_COMPR_NONE ||
	    compr_type >= SSDFS_COMPR_TYPES_CNT) {
		SSDFS_ERR("invalid compression type %d\n", compr_type);
		return -EINVAL;
	}

	need_compress = uncompr_size > SSDFS_UNCOMPR_BLOB_UPPER_THRESHOLD;

	if (need_compress) {
		err = ssdfs_compress(compr_type, src, dst,
				     &srclen, &destlen);
		if (!err && destlen >= uncompr_size) {
			/* compression is useless */
			err = -E2BIG;
		}
	}

	if (!need_compress || err == -E2BIG || err == -EOPNOTSUPP) {
		/* store uncompressed */
		err = ssdfs_memcpy(dst, 0, dst_size,
				   src, 0, uncompr_size,
				   uncompr_size);
		destlen = uncompr_size;
		need_compress = false;
	}

	if (unlikely(err))
		return err;

	*encoded_size = (u32)destlen;
	*is_compressed = need_compress;

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_encode_payload_fragment);

/*
 * ssdfs_add_fragment2chain() - add fragment into chain
 * @iter: iterator pointer
 * @folio: uncompressed data
 * @uncompr_size: uncompressed size in bytes
 * @compr_type: compresssion type
 * @payload: encoded payload [out]
 *
 * The iterator keeps the current table (iter->tbl) whose header will
 * be stored at iter->cur_offset, and the write position of the next
 * fragment (iter->buffer.offset). If the current table is full, then
 * the table is stored into @payload with the descriptor of the next
 * table, and the next table is started at the write position.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_add_fragment2chain(struct ssdfs_payload_iterator *iter,
			     struct folio *folio,
			     u32 uncompr_size,
			     int compr_type,
			     struct ssdfs_payload_content *payload)
{
	struct ssdfs_metadata_extents_table *table;
	struct ssdfs_fragments_chain_header *chain_hdr;
	struct ssdfs_fragment_desc *fdesc;
	void *kaddr;
	size_t hdr_size = sizeof(struct ssdfs_metadata_extents_table);
	__le32 checksum;
	u32 destlen = 0;
	bool need_compress = false;
	u8 frag_type;
	u32 calculated;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!iter || !folio || !payload);
	BUG_ON(uncompr_size == 0);
	BUG_ON(uncompr_size > iter->buffer.size);

	SSDFS_DBG("iter %p, folio %p, payload %p\n",
		  iter, folio, payload);
#endif /* CONFIG_SSDFS_DEBUG */

	if (iter->fragment_id > SSDFS_NEXT_META_EXT_TABLE_INDEX) {
		SSDFS_ERR("fragment_id %u > MAX %u\n",
			  iter->fragment_id,
			  SSDFS_NEXT_META_EXT_TABLE_INDEX);
		return -ERANGE;
	}

	if (iter->fragment_id == SSDFS_NEXT_META_EXT_TABLE_INDEX) {
		u32 next_chain_offset = (u32)iter->buffer.offset;

		table = &iter->tbl;
		chain_hdr = &table->chain_hdr;
		fdesc = &table->blk[iter->fragment_id];

		chain_hdr->flags = cpu_to_le16(SSDFS_MULTIPLE_HDR_CHAIN);

		fdesc->magic = SSDFS_FRAGMENT_DESC_MAGIC;
		fdesc->type = SSDFS_NEXT_TABLE_DESC;
		fdesc->flags = 0;
		fdesc->sequence_id = (u8)iter->fragment_id;
		fdesc->offset = cpu_to_le32(next_chain_offset);
		fdesc->compr_size = cpu_to_le16((u16)hdr_size);
		fdesc->uncompr_size = cpu_to_le16((u16)hdr_size);
		fdesc->checksum = 0;

		err = ssdfs_payload_write(payload, iter->cur_offset,
					  table, hdr_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store header into payload: "
				  "offset %u, hdr_size %zu, err %d\n",
				  iter->cur_offset, hdr_size, err);
			return err;
		}

		ssdfs_payload_chain_header_init(iter, compr_type);

		iter->cur_offset = next_chain_offset;
		iter->buffer.offset = next_chain_offset + hdr_size;
		iter->fragment_id = 0;
	}

	ssdfs_folio_lock(folio);
	kaddr = kmap_local_folio(folio, 0);
	checksum = ssdfs_crc32_le(kaddr, uncompr_size);
	err = ssdfs_encode_payload_fragment(compr_type,
					    kaddr, uncompr_size,
					    iter->buffer.ptr,
					    iter->buffer.size,
					    &destlen, &need_compress);
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);

	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare fragment: "
			  "index %u, err %d\n",
			  iter->fragment_id, err);
		return err;
	}

	if (need_compress) {
		frag_type = SSDFS_PAYLOAD_COMPR_FRAG_TYPE(iter->kind,
							  compr_type);
	} else {
		frag_type = SSDFS_PAYLOAD_COMPR_FRAG_TYPE(iter->kind,
							  SSDFS_COMPR_NONE);
	}

	table = &iter->tbl;
	chain_hdr = &table->chain_hdr;
	fdesc = &table->blk[iter->fragment_id];

	fdesc->magic = SSDFS_FRAGMENT_DESC_MAGIC;
	fdesc->type = frag_type;
	fdesc->flags = SSDFS_FRAGMENT_HAS_CSUM;
	fdesc->sequence_id = (u8)iter->fragment_id;
	fdesc->offset = cpu_to_le32((u32)iter->buffer.offset);
	fdesc->compr_size = cpu_to_le16((u16)destlen);
	fdesc->uncompr_size = cpu_to_le16((u16)uncompr_size);
	fdesc->checksum = checksum;

	calculated = le32_to_cpu(chain_hdr->compr_bytes);
	calculated += destlen;
	chain_hdr->compr_bytes = cpu_to_le32(calculated);
	calculated = le32_to_cpu(chain_hdr->uncompr_bytes);
	calculated += uncompr_size;
	chain_hdr->uncompr_bytes = cpu_to_le32(calculated);
	calculated = le16_to_cpu(chain_hdr->fragments_count);
	calculated++;
	chain_hdr->fragments_count = cpu_to_le16((u16)calculated);

	err = ssdfs_save_fragment_into_payload(iter, destlen, payload);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store fragment into payload: "
			  "err %d\n", err);
		return err;
	}

	payload->max_fragment_bytes = max_t(u32, payload->max_fragment_bytes,
					    destlen);
	iter->fragment_id++;

	return 0;
}

/*
 * ssdfs_payload_fragment_size() - define size of snapshot's fragment
 * @kind: kind of payload
 * @snapshot: snapshot of payload
 * @folio: snapshot's folio (fragment)
 * @index: index of @folio in @snapshot
 * @fragment_size: size of fragment in bytes [out]
 *
 * Every folio of the metadata extents' snapshot keeps up to
 * SSDFS_META_EXTENTS_FRAGMENT_SIZE bytes of the contiguous sequence
 * of extents. Every folio of the PEB mapping table cache's snapshot keeps
 * one fragment of the cache and the fragment's header defines its size.
 */
static
int ssdfs_payload_fragment_size(int kind,
				struct ssdfs_payload_content *snapshot,
				struct folio *folio, u32 index,
				u32 *fragment_size)
{
	struct ssdfs_maptbl_cache_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_maptbl_cache_header);
	u32 processed_bytes;
	void *kaddr;

	switch (kind) {
	case SSDFS_META_EXTENTS_PAYLOAD:
		processed_bytes = SSDFS_META_EXTENTS_FRAGMENT_SIZE * index;
		*fragment_size = min_t(u32,
					snapshot->bytes_count - processed_bytes,
					SSDFS_META_EXTENTS_FRAGMENT_SIZE);
		return 0;

	case SSDFS_MAPTBL_CACHE_PAYLOAD:
		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);
		hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
		*fragment_size = le16_to_cpu(hdr->bytes_count);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);

		if (*fragment_size < hdr_size || *fragment_size > PAGE_SIZE) {
			SSDFS_ERR("corrupted maptbl cache's fragment: "
				  "index %u, bytes_count %u\n",
				  index, *fragment_size);
			return -ERANGE;
		}
		return 0;

	default:
		break;
	}

	SSDFS_ERR("unexpected payload kind %d\n", kind);
	return -ERANGE;
}

/*
 * __ssdfs_encode_payload() - encode snapshot into a payload
 * @kind: kind of payload
 * @snapshot: snapshot of payload area's content
 * @compr_type: SSDFS_COMPR_NONE/ZLIB/LZO/LZ4/ZSTD
 * @payload: encoded payload [out]
 *
 * This method encodes @snapshot into the on-disk fragments' chain format,
 * ready to be copied into a new superblock segment's log during its commit.
 * Every folio of @snapshot is encoded as one fragment. The offsets of
 * fragments and of the next table are relative to the area's beginning.
 * The sequence ID of a fragment is the fragment's index in the table.
 *
 * A fragment is compressed only if its uncompressed size is bigger
 * than SSDFS_UNCOMPR_BLOB_UPPER_THRESHOLD; smaller fragments are
 * stored raw without even attempting compression, the same threshold
 * the blk2off table's own fragments are held to.
 *
 * @payload's folio vector is created by this method and the caller
 * is responsible for destroying @payload (even if the method fails).
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - @snapshot is empty.
 * %-ENOMEM     - fail to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_encode_payload(int kind,
			   struct ssdfs_payload_content *snapshot,
			   int compr_type,
			   struct ssdfs_payload_content *payload)
{
	struct ssdfs_metadata_descriptor desc = {0};
	struct ssdfs_payload_iterator *iter;
	struct folio *folio;
	size_t hdr_size = sizeof(struct ssdfs_metadata_extents_table);
	size_t iter_size = sizeof(struct ssdfs_payload_iterator);
	u32 fragment_size = SSDFS_META_EXTENTS_FRAGMENT_SIZE;
	u32 folios_count;
	u32 uncompr_size;
	u32 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!snapshot || !payload);
	BUG_ON(kind < 0 || kind >= SSDFS_PAYLOAD_KIND_MAX);

	SSDFS_DBG("kind %d, snapshot %p, payload %p\n",
		  kind, snapshot, payload);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_folio_vector_create(&payload->batch,
					get_order(PAGE_SIZE), 0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create folio vector: err %d\n", err);
		return err;
	}
	payload->bytes_count = 0;
	payload->compr_type = compr_type;
	payload->max_fragment_bytes = 0;

	folios_count = ssdfs_folio_vector_count(&snapshot->batch);

	if (folios_count == 0 || snapshot->bytes_count == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("empty snapshot\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	if (kind == SSDFS_META_EXTENTS_PAYLOAD &&
	    DIV_ROUND_UP(snapshot->bytes_count, fragment_size) !=
							folios_count) {
		SSDFS_ERR("corrupted snapshot: "
			  "bytes_count %u, folios_count %u\n",
			  snapshot->bytes_count, folios_count);
		return -ERANGE;
	}

	iter = ssdfs_sb_payload_kzalloc(iter_size, GFP_KERNEL);
	if (!iter) {
		SSDFS_ERR("fail to allocate memory\n");
		return -ENOMEM;
	}

	SSDFS_PAYLOAD_ITER_INIT(iter, kind, &desc);
	ssdfs_payload_chain_header_init(iter, compr_type);
	/* the first table starts at the area's beginning */
	iter->cur_offset = 0;
	/* fragments follow the table's header */
	iter->buffer.offset = hdr_size;

	for (i = 0; i < folios_count; i++) {
		folio = ssdfs_folio_vector_get(&snapshot->batch, i);
		if (!folio) {
			err = -ERANGE;
			SSDFS_ERR("snapshot's folio is absent: index %u\n",
				  i);
			goto finish_encode_payload;
		}

		err = ssdfs_payload_fragment_size(kind, snapshot, folio, i,
						  &uncompr_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to define fragment's size: "
				  "index %u, err %d\n", i, err);
			goto finish_encode_payload;
		}

		err = ssdfs_add_fragment2chain(iter, folio, uncompr_size,
					       compr_type, payload);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add fragment into chain: "
				  "index %u, err %d\n", i, err);
			goto finish_encode_payload;
		}
	}

	/* store the header of the last table */
	err = ssdfs_payload_write(payload, iter->cur_offset,
				  &iter->tbl, hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store header into payload: "
			  "offset %u, err %d\n",
			  iter->cur_offset, err);
		goto finish_encode_payload;
	}

	payload->bytes_count = (u32)iter->buffer.offset;

finish_encode_payload:
	ssdfs_sb_payload_kfree(iter);
	return err;
}

/*
 * ssdfs_encode_meta_extents_payload() - encode extents into a payload
 * @snapshot: extents snapshot (see ssdfs_snapshot_meta_extents_payload())
 * @compr_type: SSDFS_COMPR_NONE/ZLIB/LZO/LZ4/ZSTD to compress every
 *             fragment with (mirrors fsi->metadata_options.user_data.
 *             compression: the driver doesn't carry a dedicated
 *             compression setting for the segment bitmap's/PEB
 *             mapping table's own extents, and mkfs.ssdfs itself
 *             defaults every metadata area's compression to the same
 *             volume-wide choice as user data unless told otherwise)
 * @payload: encoded payload [out]
 *
 * This method encodes the overflow extents of @snapshot into the
 * on-disk metadata extents table chain format (see
 * __ssdfs_encode_payload()).
 *
 * @payload's folio vector is created by this method and the caller
 * is responsible for destroying @payload (even if the method fails).
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - @snapshot is empty.
 * %-ENOMEM     - fail to allocate memory.
 * %-ERANGE     - internal error.
 */
int ssdfs_encode_meta_extents_payload(struct ssdfs_payload_content *snapshot,
				      int compr_type,
				      struct ssdfs_payload_content *payload)
{
	return __ssdfs_encode_payload(SSDFS_META_EXTENTS_PAYLOAD,
				      snapshot, compr_type, payload);
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_encode_meta_extents_payload);

/*
 * ssdfs_encode_maptbl_cache_payload() - encode maptbl cache into a payload
 * @snapshot: maptbl cache's snapshot (one fragment per folio)
 * @compr_type: SSDFS_COMPR_ZLIB/LZO/LZ4/ZSTD to compress every fragment with
 * @payload: encoded payload [out]
 *
 * This method encodes the fragments of the PEB mapping table cache
 * into the chain of struct ssdfs_maptbl_cache_table tables (see
 * __ssdfs_encode_payload()). Every fragment is the whole fragment of
 * the cache (starting from struct ssdfs_maptbl_cache_header) of
 * the fragment header's bytes_count size.
 *
 * @payload's folio vector is created by this method and the caller
 * is responsible for destroying @payload (even if the method fails).
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - @compr_type is SSDFS_COMPR_NONE.
 * %-ENODATA    - @snapshot is empty.
 * %-ENOMEM     - fail to allocate memory.
 * %-ERANGE     - internal error.
 */
int ssdfs_encode_maptbl_cache_payload(struct ssdfs_payload_content *snapshot,
				      int compr_type,
				      struct ssdfs_payload_content *payload)
{
	if (compr_type <= SSDFS_COMPR_NONE ||
	    compr_type >= SSDFS_COMPR_TYPES_CNT) {
		SSDFS_ERR("invalid compression type %d\n", compr_type);
		return -EINVAL;
	}

	return __ssdfs_encode_payload(SSDFS_MAPTBL_CACHE_PAYLOAD,
				      snapshot, compr_type, payload);
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_encode_maptbl_cache_payload);

/************************************************************************
 *                     PEB mapping table cache payload                   *
 ************************************************************************/

/*
 * ssdfs_check_maptbl_cache_header() - check maptbl cache fragment's header
 * @hdr: maptbl cache fragment's header
 * @sequence_id: expected sequence ID of the fragment
 * @prev_end_leb: end LEB ID of the previous fragment (U64_MAX if none)
 */
static
int ssdfs_check_maptbl_cache_header(struct ssdfs_maptbl_cache_header *hdr,
				    u16 sequence_id,
				    u64 prev_end_leb)
{
	size_t bytes_count, calculated;
	u64 start_leb, end_leb;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr);

	SSDFS_DBG("maptbl_cache_hdr %p\n", hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	if (hdr->magic.common != cpu_to_le32(SSDFS_SUPER_MAGIC) ||
	    hdr->magic.key != cpu_to_le16(SSDFS_MAPTBL_CACHE_MAGIC)) {
		SSDFS_ERR("invalid maptbl cache magic signature\n");
		return -EIO;
	}

	if (le16_to_cpu(hdr->sequence_id) != sequence_id) {
		SSDFS_ERR("invalid sequence_id\n");
		return -EIO;
	}

	bytes_count = le16_to_cpu(hdr->bytes_count);

	if (bytes_count > PAGE_SIZE) {
		SSDFS_ERR("invalid bytes_count %zu\n",
			  bytes_count);
		return -EIO;
	}

	calculated = le16_to_cpu(hdr->items_count) *
			sizeof(struct ssdfs_leb2peb_pair);

	if (bytes_count < calculated) {
		SSDFS_ERR("bytes_count %zu < calculated %zu\n",
			  bytes_count, calculated);
		return -EIO;
	}

	start_leb = le64_to_cpu(hdr->start_leb);
	end_leb = le64_to_cpu(hdr->end_leb);

	if (start_leb > end_leb ||
	    (prev_end_leb != U64_MAX && prev_end_leb > start_leb)) {
		SSDFS_ERR("invalid LEB range: start_leb %llu, "
			  "end_leb %llu, prev_end_leb %llu\n",
			  start_leb, end_leb, prev_end_leb);
		return -EIO;
	}

	return 0;
}

#define SSDFS_AREA_COMPRESSION_FLAGS \
	(SSDFS_ZLIB_COMPRESSED | SSDFS_LZO_COMPRESSED | \
	 SSDFS_LZ4_COMPRESSED | SSDFS_ZSTD_COMPRESSED)

/*
 * ssdfs_area_compr_type() - compression type of metadata area
 * @flags: flags of the area's metadata check
 *
 * RETURN:
 * [success] - SSDFS_COMPR_NONE/ZLIB/LZO/LZ4/ZSTD.
 * [failure] - error code:
 *
 * %-EIO     - several compression flags are set.
 */
int ssdfs_area_compr_type(u16 flags)
{
	switch (flags & SSDFS_AREA_COMPRESSION_FLAGS) {
	case 0:
		return SSDFS_COMPR_NONE;
	case SSDFS_ZLIB_COMPRESSED:
		return SSDFS_COMPR_ZLIB;
	case SSDFS_LZO_COMPRESSED:
		return SSDFS_COMPR_LZO;
	case SSDFS_LZ4_COMPRESSED:
		return SSDFS_COMPR_LZ4;
	case SSDFS_ZSTD_COMPRESSED:
		return SSDFS_COMPR_ZSTD;
	default:
		break;
	}

	return -EIO;
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_area_compr_type);

/*
 * ssdfs_read_uncompr_maptbl_cache() - read uncompressed maptbl cache area
 * @fsi: file system info object
 * @desc: maptbl cache area's descriptor
 *
 * The uncompressed area is the sequence of the cache's fragments. Every
 * fragment, except the last one, occupies the whole memory page. Every
 * fragment is read into its own folio of fsi->maptbl_cache.batch.
 *
 * The caller has to hold fsi->maptbl_cache.lock.
 */
static
int ssdfs_read_uncompr_maptbl_cache(struct ssdfs_fs_info *fsi,
				    struct ssdfs_metadata_descriptor *desc)
{
	struct ssdfs_maptbl_cache *cache = &fsi->maptbl_cache;
	struct folio *folio;
	void *kaddr;
	u32 read_off = le32_to_cpu(desc->offset);
	u32 bytes_count = le32_to_cpu(desc->size);
	u32 read_bytes = 0;
	u32 folios_count;
	u64 peb_id = fsi->sbi.last_log.peb_id;
	u32 i;
	int err;

	folios_count = (bytes_count + PAGE_SIZE - 1) >> PAGE_SHIFT;

	for (i = 0; i < folios_count; i++) {
		size_t size;

		size = min_t(size_t, (size_t)PAGE_SIZE,
				(size_t)(bytes_count - read_bytes));

		folio = ssdfs_maptbl_cache_add_batch_folio(cache);
		if (unlikely(IS_ERR_OR_NULL(folio))) {
			err = !folio ? -ENOMEM : PTR_ERR(folio);
			SSDFS_ERR("fail to add folio into batch: err %d\n",
				  err);
			return err;
		}

		ssdfs_folio_lock(folio);

		kaddr = kmap_local_folio(folio, 0);
		err = ssdfs_unaligned_read_buffer(fsi, peb_id, PAGE_SIZE,
						  read_off, kaddr, size);
		kunmap_local(kaddr);

		if (unlikely(err)) {
			ssdfs_folio_unlock(folio);
			SSDFS_ERR("fail to read folio: "
				  "peb %llu, offset %u, "
				  "size %zu, err %d\n",
				  peb_id, read_off, size, err);
			return err;
		}

		flush_dcache_folio(folio);
		ssdfs_folio_unlock(folio);

		read_off += size;
		read_bytes += size;
	}

	return 0;
}

/*
 * ssdfs_read_compr_maptbl_cache() - read compressed maptbl cache area
 * @fsi: file system info object
 * @desc: maptbl cache area's descriptor
 *
 * The compressed area is the chain of struct ssdfs_maptbl_cache_table
 * tables. Every fragment is decompressed into its own folio of
 * fsi->maptbl_cache.batch. The area's checksum covers the first table
 * and every fragment has its own checksum (they are checked by
 * ssdfs_extract_payload()). The size of the biggest compressed fragment
 * is kept for the estimation of the next logs' size.
 *
 * The caller has to hold fsi->maptbl_cache.lock.
 */
static
int ssdfs_read_compr_maptbl_cache(struct ssdfs_fs_info *fsi,
				  struct ssdfs_metadata_descriptor *desc)
{
	struct ssdfs_maptbl_cache *cache = &fsi->maptbl_cache;
	struct ssdfs_payload_content payload;
	struct folio *sfolio, *dfolio;
	u32 folios_count;
	u32 i;
	int err;

	err = ssdfs_extract_payload(fsi, SSDFS_MAPTBL_CACHE_PAYLOAD,
				    desc, &payload);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract maptbl cache: err %d\n", err);
		goto finish_read_compr_maptbl_cache;
	}

	folios_count = ssdfs_folio_vector_count(&payload.batch);

	if (folios_count == 0 ||
	    payload.bytes_count != (folios_count * PAGE_SIZE)) {
		err = -EIO;
		SSDFS_ERR("corrupted maptbl cache: "
			  "folios_count %u, bytes_count %u\n",
			  folios_count, payload.bytes_count);
		goto finish_read_compr_maptbl_cache;
	}

	for (i = 0; i < folios_count; i++) {
		sfolio = ssdfs_folio_vector_get(&payload.batch, i);
		if (!sfolio) {
			err = -ERANGE;
			SSDFS_ERR("folio is absent: index %u\n", i);
			goto finish_read_compr_maptbl_cache;
		}

		dfolio = ssdfs_maptbl_cache_add_batch_folio(cache);
		if (unlikely(IS_ERR_OR_NULL(dfolio))) {
			err = !dfolio ? -ENOMEM : PTR_ERR(dfolio);
			SSDFS_ERR("fail to add folio into batch: err %d\n",
				  err);
			goto finish_read_compr_maptbl_cache;
		}

		ssdfs_folio_lock(sfolio);
		ssdfs_folio_lock(dfolio);
		err = __ssdfs_memcpy_folio(dfolio, 0, PAGE_SIZE,
					   sfolio, 0, PAGE_SIZE,
					   PAGE_SIZE);
		ssdfs_folio_unlock(dfolio);
		ssdfs_folio_unlock(sfolio);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy fragment: "
				  "index %u, err %d\n", i, err);
			goto finish_read_compr_maptbl_cache;
		}
	}

	/* the next logs are encoded by the same compression type */
	cache->max_fragment_bytes = payload.max_fragment_bytes;

finish_read_compr_maptbl_cache:
	ssdfs_payload_content_destroy(&payload);
	return err;
}

/*
 * ssdfs_read_maptbl_cache() - read the PEB mapping table cache's content
 * @fsi: file system info object
 *
 * This method reads the PEB mapping table cache's content from the
 * current superblock segment's log into fsi->maptbl_cache. The flags
 * of the area's metadata check show whether the area is compressed and
 * by which compression type. This compression type is used for storing
 * the cache by the next logs of superblock segment.
 */
int ssdfs_read_maptbl_cache(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_segment_header *seg_hdr;
	struct ssdfs_metadata_descriptor *meta_desc;
	struct ssdfs_maptbl_cache_header *maptbl_cache_hdr;
	struct folio *folio;
	void *kaddr;
	u32 bytes_count;
	u32 folios_count;
	u64 prev_end_leb;
	u32 csum = ~0;
	int compr_type;
	bool is_compressed;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!fsi->devops->read);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	seg_hdr = SSDFS_SEG_HDR(fsi->sbi.vh_buf);

	if (!ssdfs_log_has_maptbl_cache(seg_hdr)) {
		SSDFS_ERR("sb segment hasn't maptbl cache\n");
		return -EIO;
	}

	down_write(&fsi->maptbl_cache.lock);

	fsi->maptbl_cache.max_fragment_bytes = 0;

	meta_desc = &seg_hdr->desc_array[SSDFS_MAPTBL_CACHE_INDEX];
	bytes_count = le32_to_cpu(meta_desc->size);

	compr_type = ssdfs_area_compr_type(le16_to_cpu(meta_desc->check.flags));
	if (compr_type < 0) {
		err = compr_type;
		SSDFS_ERR("invalid maptbl cache area's flags %#x\n",
			  le16_to_cpu(meta_desc->check.flags));
		goto finish_read_maptbl_cache;
	}

	is_compressed = compr_type != SSDFS_COMPR_NONE;

	/*
	 * The maptbl cache's payload lives inside the superblock
	 * segment's log, so it cannot legitimately be bigger than the
	 * PEB that holds that log.
	 */
	if (bytes_count == 0 || bytes_count > fsi->erasesize ||
	    le32_to_cpu(meta_desc->offset) == 0 ||
	    (le32_to_cpu(meta_desc->offset) + bytes_count) > fsi->erasesize) {
		SSDFS_ERR("invalid maptbl cache area: offset %u, size %u\n",
			  le32_to_cpu(meta_desc->offset), bytes_count);
		err = -EFBIG;
		goto finish_read_maptbl_cache;
	}

	if (is_compressed)
		err = ssdfs_read_compr_maptbl_cache(fsi, meta_desc);
	else
		err = ssdfs_read_uncompr_maptbl_cache(fsi, meta_desc);

	if (unlikely(err)) {
		SSDFS_ERR("fail to read maptbl cache: "
			  "compr_type %d, err %d\n",
			  compr_type, err);
		goto finish_read_maptbl_cache;
	}

	prev_end_leb = U64_MAX;
	folios_count = ssdfs_folio_vector_count(&fsi->maptbl_cache.batch);

	for (i = 0; i < folios_count; i++) {
		folio = ssdfs_folio_vector_get(&fsi->maptbl_cache.batch, i);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(i >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);

		maptbl_cache_hdr = SSDFS_MAPTBL_CACHE_HDR(kaddr);

		err = ssdfs_check_maptbl_cache_header(maptbl_cache_hdr,
						      (u16)i,
						      prev_end_leb);
		if (unlikely(err)) {
			SSDFS_ERR("invalid maptbl cache header: "
				  "folio_index %d, err %d\n",
				  i, err);
			goto unlock_cur_folio;
		}

		prev_end_leb = le64_to_cpu(maptbl_cache_hdr->end_leb);
		csum = crc32(csum, kaddr,
			     le16_to_cpu(maptbl_cache_hdr->bytes_count));

unlock_cur_folio:
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);

		if (unlikely(err))
			goto finish_read_maptbl_cache;
	}

	/* the checksum of compressed area has been checked already */
	if (!is_compressed && csum != le32_to_cpu(meta_desc->check.csum)) {
		err = -EIO;
		SSDFS_ERR("invalid checksum: "
			  "csum1 %#x, csum2 %#x\n",
			  csum,
			  le32_to_cpu(meta_desc->check.csum));
		goto finish_read_maptbl_cache;
	}

	bytes_count = folios_count * PAGE_SIZE;
	atomic_set(&fsi->maptbl_cache.bytes_count, bytes_count);
	fsi->maptbl_cache.compr_type = compr_type;

finish_read_maptbl_cache:
	if (unlikely(err))
		ssdfs_maptbl_cache_forget_batch(&fsi->maptbl_cache);

	up_write(&fsi->maptbl_cache.lock);

	return err;
}

/*
 * ssdfs_define_sb_log_layout() - define layout of superblock segment's log
 * @layout: layout with sizes of payload areas [in|out]
 */
void ssdfs_define_sb_log_layout(struct ssdfs_sb_log_layout *layout)
{
	u32 cur_offset = sizeof(struct ssdfs_segment_header);
	int i;

	for (i = 0; i < SSDFS_SB_LOG_AREAS_MAX; i++) {
		if (layout->size[i] == 0) {
			layout->offset[i] = 0;
			continue;
		}

		layout->offset[i] = cur_offset;
		cur_offset += layout->size[i];
	}

	layout->body_pages = DIV_ROUND_UP(cur_offset, PAGE_SIZE);
	layout->log_pages = layout->body_pages + 1; /* footer */

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("segbmap extents (offset %u, size %u), "
		  "maptbl extents (offset %u, size %u), "
		  "maptbl cache (offset %u, size %u), "
		  "body_pages %u, log_pages %u\n",
		  layout->offset[SSDFS_SB_LOG_SEGBMAP_EXTENTS],
		  layout->size[SSDFS_SB_LOG_SEGBMAP_EXTENTS],
		  layout->offset[SSDFS_SB_LOG_MAPTBL_EXTENTS],
		  layout->size[SSDFS_SB_LOG_MAPTBL_EXTENTS],
		  layout->offset[SSDFS_SB_LOG_MAPTBL_CACHE],
		  layout->size[SSDFS_SB_LOG_MAPTBL_CACHE],
		  layout->body_pages, layout->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_define_sb_log_layout);

/*
 * ssdfs_maptbl_cache_area_size() - define the maptbl cache area's size
 * @vector: maptbl cache's folio vector
 *
 * Every fragment of the maptbl cache is kept by one memory page. On
 * the volume, every fragment occupies the whole page, except the last
 * one: the area ends right after the last fragment's content. So,
 * the area can be placed at any offset in the log and it can be
 * shorter than the page if the maptbl cache has only one fragment.
 *
 * RETURN: size of the maptbl cache area in bytes.
 */
u32 ssdfs_maptbl_cache_area_size(struct ssdfs_folio_vector *vector)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct folio *folio;
	void *kaddr;
	u32 folios_count;
	u16 fragment_bytes_count;

	folios_count = ssdfs_folio_vector_count(vector);
	if (folios_count == 0)
		return 0;

	folio = ssdfs_folio_vector_get(vector, folios_count - 1);
	if (!folio) {
		SSDFS_WARN("folio is absent: index %u\n",
			   folios_count - 1);
		return folios_count * PAGE_SIZE;
	}

	ssdfs_folio_lock(folio);
	kaddr = kmap_local_folio(folio, 0);
	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
	fragment_bytes_count = le16_to_cpu(hdr->bytes_count);
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);

	if (fragment_bytes_count == 0 || fragment_bytes_count > PAGE_SIZE) {
		SSDFS_WARN("invalid fragment's bytes_count %u\n",
			   fragment_bytes_count);
		fragment_bytes_count = PAGE_SIZE;
	}

	return ((folios_count - 1) * PAGE_SIZE) + fragment_bytes_count;
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_maptbl_cache_area_size);

/*
 * ssdfs_maptbl_cache_max_payload_size() - upper bound of maptbl cache area
 * @cache_bytes: size of the maptbl cache's content (whole pages)
 *
 * The uncompressed area is never bigger than the cache's pages. The
 * compressed area is never bigger than the cache's pages and the headers
 * of the tables because a fragment is stored compressed only if
 * the compression makes it smaller.
 *
 * RETURN: upper bound of the area's size in bytes.
 */
u32 ssdfs_maptbl_cache_max_payload_size(u32 cache_bytes)
{
	size_t tbl_size = sizeof(struct ssdfs_maptbl_cache_table);
	u32 fragments_count = DIV_ROUND_UP(cache_bytes, PAGE_SIZE);
	u32 tables_count;

	tables_count = DIV_ROUND_UP(fragments_count,
				    SSDFS_NEXT_MAPTBL_CACHE_TABLE_INDEX);

	return (tables_count * tbl_size) + cache_bytes;
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_maptbl_cache_max_payload_size);

/*
 * ssdfs_maptbl_cache_payload_size() - size of maptbl cache area in the log
 * @payload: maptbl cache's content (uncompressed or encoded)
 *
 * RETURN: size of the maptbl cache area in bytes.
 */
u32 ssdfs_maptbl_cache_payload_size(struct ssdfs_payload_content *payload)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!payload);
#endif /* CONFIG_SSDFS_DEBUG */

	if (payload->compr_type != SSDFS_COMPR_NONE)
		return payload->bytes_count;

	return ssdfs_maptbl_cache_area_size(&payload->batch);
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_maptbl_cache_payload_size);

/*
 * ssdfs_define_sb_log_payload_layout() - define layout of the real log
 * @payload: snapshot of the payload areas
 * @layout: layout of the log [out]
 *
 * This method defines the layout of superblock segment's log by
 * the real sizes of the payload areas (uncompressed or encoded).
 */
void ssdfs_define_sb_log_payload_layout(struct ssdfs_sb_log_payload *payload,
					struct ssdfs_sb_log_layout *layout)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!payload || !layout);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(layout, 0, sizeof(struct ssdfs_sb_log_layout));

	layout->size[SSDFS_SB_LOG_SEGBMAP_EXTENTS] =
				payload->segbmap_meta_extents.bytes_count;
	layout->size[SSDFS_SB_LOG_MAPTBL_EXTENTS] =
				payload->maptbl_meta_extents.bytes_count;
	layout->size[SSDFS_SB_LOG_MAPTBL_CACHE] =
		ssdfs_maptbl_cache_payload_size(&payload->maptbl_cache);

	ssdfs_define_sb_log_layout(layout);
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_define_sb_log_payload_layout);

/*
 * ssdfs_meta_extents_max_payload_size() - upper bound of encoded extents
 * @extents: metadata extents array (every row, embedded and overflow)
 * @embedded_rows: count of rows in the embedded array
 * @chains_count: count of chains (columns) per row
 *
 * This method calculates the size of the overflow extents' area in
 * the uncompressed state. The encoded area is never bigger because
 * a fragment is stored compressed only if the compression makes it
 * smaller.
 *
 * RETURN: upper bound of the area's size in bytes (0 - no area).
 */
u32 ssdfs_meta_extents_max_payload_size(struct ssdfs_dynamic_array *extents,
					u32 embedded_rows, u32 chains_count)
{
	size_t hdr_size = sizeof(struct ssdfs_metadata_extents_table);
	size_t item_size = sizeof(struct ssdfs_meta_area_extent);
	u32 embedded_count = embedded_rows * chains_count;
	u32 overflow_count;
	u32 fragments_count;
	u32 tables_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!extents);
#endif /* CONFIG_SSDFS_DEBUG */

	if (extents->capacity <= embedded_count)
		return 0;

	overflow_count = extents->capacity - embedded_count;
	fragments_count = DIV_ROUND_UP(overflow_count,
				       SSDFS_META_EXTENTS_PER_FRAGMENT);
	tables_count = DIV_ROUND_UP(fragments_count,
				    SSDFS_NEXT_META_EXT_TABLE_INDEX);

	return (tables_count * hdr_size) + (overflow_count * item_size);
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_meta_extents_max_payload_size);

/*
 * ssdfs_snapshot_maptbl_cache() - snapshot PEB mapping table cache
 * @fsi: file system info object
 * @snapshot: snapshot of the maptbl cache's content [out]
 *
 * This method copies the PEB mapping table cache's content into
 * @snapshot under the maptbl cache's lock.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_snapshot_maptbl_cache(struct ssdfs_fs_info *fsi,
				struct ssdfs_payload_content *snapshot)
{
	struct folio *sfolio, *dfolio;
	unsigned folios_count;
	unsigned i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !snapshot);
	BUG_ON(ssdfs_folio_vector_count(&snapshot->batch) != 0);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&fsi->maptbl_cache.lock);

	folios_count = ssdfs_folio_vector_count(&fsi->maptbl_cache.batch);

	ssdfs_folio_vector_inflate(&snapshot->batch, folios_count);

	for (i = 0; i < folios_count; i++) {
		dfolio = ssdfs_folio_vector_allocate(&snapshot->batch);
		if (unlikely(IS_ERR_OR_NULL(dfolio))) {
			err = !dfolio ? -ENOMEM : PTR_ERR(dfolio);
			SSDFS_ERR("fail to add folio into vector: "
				  "index %u, err %d\n",
				  i, err);
			goto finish_maptbl_snapshot;
		}

		sfolio = ssdfs_folio_vector_get(&fsi->maptbl_cache.batch, i);
		if (unlikely(!sfolio)) {
			err = -ERANGE;
			SSDFS_ERR("source folio is absent: index %u\n",
				  i);
			goto finish_maptbl_snapshot;
		}

		ssdfs_folio_lock(sfolio);
		ssdfs_folio_lock(dfolio);
		__ssdfs_memcpy_folio(dfolio, 0, PAGE_SIZE,
				     sfolio, 0, PAGE_SIZE,
				     PAGE_SIZE);
		ssdfs_folio_unlock(dfolio);
		ssdfs_folio_unlock(sfolio);
	}

	snapshot->bytes_count = atomic_read(&fsi->maptbl_cache.bytes_count);
	snapshot->compr_type = SSDFS_COMPR_NONE;
	snapshot->max_fragment_bytes = 0;

finish_maptbl_snapshot:
	up_read(&fsi->maptbl_cache.lock);

	return err;
}

/*
 * ssdfs_maptbl_cache_compr_type() - compression type of maptbl cache
 * @fsi: file system info object
 *
 * The PEB mapping table cache is compressed by the compression type
 * that the flags of the area's metadata check have shown during
 * the mount (see ssdfs_read_maptbl_cache()). If the cache has been
 * stored uncompressed (it had fit into the inline area), then
 * the area's flags have no compression type. In this case,
 * the compression type of the volume's user data is used (as for
 * the overflow extents of segment bitmap and mapping table). If
 * the compression of user data is disabled, then ZLIB is used by
 * default (the cache is stored uncompressed if ZLIB support is
 * disabled in the kernel's configuration).
 */
static
int ssdfs_maptbl_cache_compr_type(struct ssdfs_fs_info *fsi)
{
	int compr_type = fsi->maptbl_cache.compr_type;

	if (compr_type > SSDFS_COMPR_NONE && compr_type < SSDFS_COMPR_TYPES_CNT)
		return compr_type;

	compr_type = fsi->metadata_options.user_data.compression;

	if (compr_type > SSDFS_COMPR_NONE && compr_type < SSDFS_COMPR_TYPES_CNT)
		return compr_type;

	if (IS_ENABLED(CONFIG_SSDFS_ZLIB))
		return SSDFS_COMPR_ZLIB;

	return SSDFS_COMPR_NONE;
}

/*
 * ssdfs_copy_maptbl_cache_snapshot() - copy uncompressed maptbl cache
 * @snapshot: maptbl cache's snapshot (one fragment per folio)
 * @payload: maptbl cache's payload [out]
 *
 * @payload's folio vector has to be created (empty) by the caller.
 */
static
int ssdfs_copy_maptbl_cache_snapshot(struct ssdfs_payload_content *snapshot,
				     struct ssdfs_payload_content *payload)
{
	struct folio *folio;
	void *kaddr;
	u32 folios_count;
	u32 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!snapshot || !payload);
	BUG_ON(ssdfs_folio_vector_count(&payload->batch) != 0);
#endif /* CONFIG_SSDFS_DEBUG */

	folios_count = ssdfs_folio_vector_count(&snapshot->batch);

	for (i = 0; i < folios_count; i++) {
		folio = ssdfs_folio_vector_get(&snapshot->batch, i);
		if (!folio) {
			SSDFS_ERR("snapshot's folio is absent: index %u\n",
				  i);
			return -ERANGE;
		}

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);
		err = ssdfs_payload_write(payload, i * PAGE_SIZE,
					  kaddr, PAGE_SIZE);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy fragment: "
				  "index %u, err %d\n", i, err);
			return err;
		}
	}

	payload->bytes_count = snapshot->bytes_count;
	payload->compr_type = SSDFS_COMPR_NONE;
	payload->max_fragment_bytes = 0;

	return 0;
}

/*
 * ssdfs_snapshot_maptbl_cache_payload() - snapshot and encode maptbl cache
 * @fsi: file system info object
 * @inline_capacity: free space of the segment header's page (inline area)
 * @payload: maptbl cache's payload [out]
 *
 * This method takes a snapshot of the PEB mapping table cache during
 * the superblock's commit. The new state of the cache is stored
 * uncompressed if it consists of one fragment that fits into the inline
 * area. Otherwise, the snapshot is encoded into the chain of compressed
 * fragments out of the cache's lock. The compression type is the type
 * of the area that has been read during the mount. If mkfs.ssdfs (or
 * the previous mount) has stored the cache uncompressed, then
 * the compression type of user data or, if it is disabled, ZLIB is
 * used (see ssdfs_maptbl_cache_compr_type()). The size of the biggest
 * compressed fragment is kept for the estimation of the next logs' size
 * (see ssdfs_estimate_sb_log_layout()).
 *
 * @payload's folio vector has to be created (empty) by the caller.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 * %-ERANGE     - internal error.
 */
int ssdfs_snapshot_maptbl_cache_payload(struct ssdfs_fs_info *fsi,
					u32 inline_capacity,
					struct ssdfs_payload_content *payload)
{
	struct ssdfs_payload_content snapshot;
	u32 folios_count;
	u32 area_size;
	int compr_type;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !payload);
	BUG_ON(ssdfs_folio_vector_count(&payload->batch) != 0);
#endif /* CONFIG_SSDFS_DEBUG */

	compr_type = ssdfs_maptbl_cache_compr_type(fsi);

	if (compr_type == SSDFS_COMPR_NONE) {
		/* store the cache uncompressed */
		return ssdfs_snapshot_maptbl_cache(fsi, payload);
	}

	err = ssdfs_folio_vector_create(&snapshot.batch,
					get_order(PAGE_SIZE), 0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create folio vector: err %d\n", err);
		return err;
	}
	snapshot.bytes_count = 0;
	snapshot.compr_type = SSDFS_COMPR_NONE;
	snapshot.max_fragment_bytes = 0;

	err = ssdfs_snapshot_maptbl_cache(fsi, &snapshot);
	if (unlikely(err)) {
		SSDFS_ERR("fail to snapshot maptbl cache: err %d\n", err);
		goto finish_snapshot_maptbl_cache;
	}

	folios_count = ssdfs_folio_vector_count(&snapshot.batch);
	if (folios_count == 0) {
		/* nothing to store */
		goto finish_snapshot_maptbl_cache;
	}

	area_size = ssdfs_maptbl_cache_area_size(&snapshot.batch);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folios_count %u, area_size %u, "
		  "inline_capacity %u, compr_type %d\n",
		  folios_count, area_size, inline_capacity, compr_type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (folios_count == 1 && area_size <= inline_capacity) {
		err = ssdfs_copy_maptbl_cache_snapshot(&snapshot, payload);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy maptbl cache: err %d\n",
				  err);
		}
	} else {
		err = ssdfs_encode_maptbl_cache_payload(&snapshot, compr_type,
							payload);
		if (unlikely(err)) {
			SSDFS_ERR("fail to encode maptbl cache: err %d\n",
				  err);
		} else {
			/* keep for the estimation of the next logs' size */
			down_write(&fsi->maptbl_cache.lock);
			fsi->maptbl_cache.max_fragment_bytes =
						payload->max_fragment_bytes;
			up_write(&fsi->maptbl_cache.lock);
		}
	}

finish_snapshot_maptbl_cache:
	ssdfs_payload_content_destroy(&snapshot);
	return err;
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_snapshot_maptbl_cache_payload);

/*
 * ssdfs_snapshot_meta_extents() - snapshot and encode overflow extents
 * @extents: metadata extents array (every row, embedded and overflow)
 * @lock: lock that protects @extents
 * @embedded_rows: count of rows in the embedded array
 * @chains_count: count of chains (columns) per row
 * @compr_type: compression type of fragments
 * @payload: encoded overflow extents [out]
 *
 * This method takes a snapshot of the overflow extents of @extents
 * under @lock and encodes the snapshot into @payload out of the lock
 * (the compression doesn't need to block the extents' owner). If
 * the volume header keeps all the extents, then @payload stays empty.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-E2BIG      - too many extents.
 * %-ENOMEM     - fail to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_snapshot_meta_extents(struct ssdfs_dynamic_array *extents,
				struct rw_semaphore *lock,
				u32 embedded_rows, u32 chains_count,
				int compr_type,
				struct ssdfs_payload_content *payload)
{
	struct ssdfs_payload_content snapshot;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!extents || !lock || !payload);
	BUG_ON(ssdfs_folio_vector_count(&payload->batch) != 0);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(lock);
	err = ssdfs_snapshot_meta_extents_payload(extents,
						  embedded_rows,
						  chains_count,
						  &snapshot);
	up_read(lock);

	if (!err)
		err = ssdfs_encode_meta_extents_payload(&snapshot, compr_type,
							payload);

	ssdfs_payload_content_destroy(&snapshot);

	if (err == -ENODATA) {
		/* the volume header keeps all the extents */
		return 0;
	}

	return err;
}

/*
 * ssdfs_remember_meta_extents_area() - keep size of encoded extents area
 * @info: known size of overflow extents area [out]
 * @uncompr_bytes: size of the area in uncompressed state
 * @compr_type: compression type the area has been encoded with
 * @payload: encoded overflow extents
 *
 * The caller has to hold fsi->volume_sem.
 */
static inline
void ssdfs_remember_meta_extents_area(struct ssdfs_meta_extents_area_info *info,
				      u32 uncompr_bytes, int compr_type,
				      struct ssdfs_payload_content *payload)
{
	info->is_known = true;
	info->compr_type = compr_type;
	info->uncompr_bytes = uncompr_bytes;
	info->bytes_count = payload->bytes_count;
}

/*
 * ssdfs_meta_extents_estimate_area_size() - estimate encoded extents area
 * @info: known size of overflow extents area
 * @uncompr_bytes: size of the area in uncompressed state
 *                 (see ssdfs_meta_extents_max_payload_size())
 * @compr_type: compression type of the area
 *
 * The number of overflow extents is defined during mkfs phase and it
 * doesn't change later. If the area is not compressed, then the size of
 * the area is the uncompressed size. Otherwise, the size of the encoded
 * area has been defined by the previous log's commit. If the size is
 * unknown yet (the first commit after the mount) or it has been defined
 * for another compression type, then the uncompressed size is used as
 * the upper bound of the area's size.
 *
 * RETURN: estimated size of the area in bytes (0 - no area).
 */
u32 ssdfs_meta_extents_estimate_area_size(struct ssdfs_meta_extents_area_info *info,
					  u32 uncompr_bytes, int compr_type)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!info);
#endif /* CONFIG_SSDFS_DEBUG */

	if (uncompr_bytes == 0)
		return 0;

	if (compr_type == SSDFS_COMPR_NONE)
		return uncompr_bytes;

	if (info->is_known &&
	    info->compr_type == compr_type &&
	    info->uncompr_bytes == uncompr_bytes)
		return info->bytes_count;

	return uncompr_bytes;
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_meta_extents_estimate_area_size);

/*
 * ssdfs_maptbl_cache_estimate_area_size() - estimate compressed cache area
 * @fragments_count: count of maptbl cache's fragments
 * @last_fragment_bytes: size of the encoded last fragment
 * @max_fragment_bytes: size of the biggest encoded fragment (0 - unknown)
 *
 * The last fragment of the cache is under modification and it is
 * encoded for the estimation. The size of every other fragment is
 * estimated by the size of the biggest encoded fragment (it is known
 * from the previous log's commit or from the mount). If this size is
 * unknown, then the uncompressed size of fragment (PAGE_SIZE) is used
 * as the upper bound. Every table of the fragments' chain is taken
 * into account too.
 *
 * RETURN: estimated size of the area in bytes (0 - no area).
 */
u32 ssdfs_maptbl_cache_estimate_area_size(u32 fragments_count,
					  u32 last_fragment_bytes,
					  u32 max_fragment_bytes)
{
	size_t tbl_size = sizeof(struct ssdfs_maptbl_cache_table);
	u32 tables_count;
	u32 fragment_bytes;

	if (fragments_count == 0)
		return 0;

	if (max_fragment_bytes == 0 || max_fragment_bytes > PAGE_SIZE)
		fragment_bytes = PAGE_SIZE;
	else
		fragment_bytes = max_t(u32, max_fragment_bytes,
					last_fragment_bytes);

	tables_count = DIV_ROUND_UP(fragments_count,
				    SSDFS_NEXT_MAPTBL_CACHE_TABLE_INDEX);

	return (tables_count * tbl_size) +
		((fragments_count - 1) * fragment_bytes) +
		last_fragment_bytes;
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_maptbl_cache_estimate_area_size);

/*
 * ssdfs_estimate_maptbl_cache_payload_size() - estimate maptbl cache area
 * @fsi: file system info object
 * @inline_capacity: free space of the segment header's page (inline area)
 * @area_size: estimated size of the area in bytes [out]
 *
 * This method estimates the size of the maptbl cache area without
 * taking the snapshot of the whole cache. If the cache is stored
 * uncompressed (or it fits into the inline area), then the size of
 * the area is the cache's bytes count. Otherwise, only the last
 * fragment is compressed and the rest fragments are estimated by
 * the size of the biggest compressed fragment (see
 * ssdfs_maptbl_cache_estimate_area_size()).
 *
 * RETURN:
 * [success] - @area_size contains the estimated size.
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_estimate_maptbl_cache_payload_size(struct ssdfs_fs_info *fsi,
					     u32 inline_capacity,
					     u32 *area_size)
{
	struct ssdfs_maptbl_cache *cache = &fsi->maptbl_cache;
	struct folio *folio;
	void *kaddr;
	u8 *buf = NULL;
	u32 folios_count;
	u32 last_bytes;
	u32 encoded_bytes;
	u32 max_fragment_bytes;
	bool is_compressed;
	int compr_type;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !area_size);
#endif /* CONFIG_SSDFS_DEBUG */

	*area_size = 0;

	compr_type = ssdfs_maptbl_cache_compr_type(fsi);

	if (compr_type != SSDFS_COMPR_NONE) {
		/* source and destination buffers of the last fragment */
		buf = ssdfs_sb_payload_kmalloc(2 * PAGE_SIZE, GFP_KERNEL);
		if (!buf) {
			SSDFS_ERR("fail to allocate buffer\n");
			return -ENOMEM;
		}
	}

	down_read(&cache->lock);

	folios_count = ssdfs_folio_vector_count(&cache->batch);
	if (folios_count == 0) {
		/* nothing to store */
		goto finish_estimate_under_lock;
	}

	*area_size = ssdfs_maptbl_cache_area_size(&cache->batch);

	if (compr_type == SSDFS_COMPR_NONE ||
	    (folios_count == 1 && *area_size <= inline_capacity)) {
		/* the cache is stored uncompressed */
		goto finish_estimate_under_lock;
	}

	last_bytes = *area_size - ((folios_count - 1) * PAGE_SIZE);
	max_fragment_bytes = cache->max_fragment_bytes;

	folio = ssdfs_folio_vector_get(&cache->batch, folios_count - 1);
	if (!folio) {
		err = -ERANGE;
		SSDFS_ERR("folio is absent: index %u\n",
			  folios_count - 1);
		goto finish_estimate_under_lock;
	}

	ssdfs_folio_lock(folio);
	kaddr = kmap_local_folio(folio, 0);
	err = ssdfs_memcpy(buf, 0, PAGE_SIZE,
			   kaddr, 0, PAGE_SIZE,
			   last_bytes);
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);

	up_read(&cache->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to copy last fragment: err %d\n", err);
		goto finish_estimate;
	}

	/* compress the last fragment out of the cache's lock */
	err = ssdfs_encode_payload_fragment(compr_type,
					    buf, last_bytes,
					    buf + PAGE_SIZE, PAGE_SIZE,
					    &encoded_bytes, &is_compressed);
	if (unlikely(err)) {
		SSDFS_ERR("fail to encode last fragment: err %d\n", err);
		goto finish_estimate;
	}

	*area_size = ssdfs_maptbl_cache_estimate_area_size(folios_count,
							   encoded_bytes,
							   max_fragment_bytes);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folios_count %u, last_bytes %u, encoded_bytes %u, "
		  "max_fragment_bytes %u, area_size %u\n",
		  folios_count, last_bytes, encoded_bytes,
		  max_fragment_bytes, *area_size);
#endif /* CONFIG_SSDFS_DEBUG */

	goto finish_estimate;

finish_estimate_under_lock:
	up_read(&cache->lock);

finish_estimate:
	if (buf)
		ssdfs_sb_payload_kfree(buf);

	if (unlikely(err))
		*area_size = 0;

	return err;
}

/*
 * ssdfs_estimate_sb_log_layout() - estimate layout of superblock log
 * @sb: superblock object
 * @layout: estimated layout of the log [out]
 *
 * This method estimates the size of superblock segment's log without
 * taking the snapshot of the payload areas. The sizes of the overflow
 * extents areas of segment bitmap and PEB mapping table are known
 * from the previous log's commit (or they are defined by uncompressed
 * size). The size of the maptbl cache area is estimated by means of
 * compression of the last fragment only. The real layout of the log is
 * defined by the commit (see ssdfs_define_sb_log_payload_layout()).
 *
 * The caller has to hold fsi->volume_sem.
 *
 * RETURN:
 * [success] - @layout contains the estimated layout.
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 * %-ERANGE     - internal error.
 */
int ssdfs_estimate_sb_log_layout(struct super_block *sb,
				 struct ssdfs_sb_log_layout *layout)
{
	struct ssdfs_fs_info *fsi;
	u32 uncompr_bytes;
	u32 used_bytes;
	u32 inline_capacity;
	int compr_type;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !layout);

	SSDFS_DBG("sb %p, layout %p\n", sb, layout);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = SSDFS_FS_I(sb);
	compr_type = fsi->metadata_options.user_data.compression;

	memset(layout, 0, sizeof(struct ssdfs_sb_log_layout));

	if (fsi->segbmap) {
		uncompr_bytes = ssdfs_meta_extents_max_payload_size(
					&fsi->segbmap->extents.array,
					SSDFS_SEGBMAP_RESERVED_EXTENTS,
					SSDFS_SEGBMAP_SEG_COPY_MAX);
		layout->size[SSDFS_SB_LOG_SEGBMAP_EXTENTS] =
			ssdfs_meta_extents_estimate_area_size(
					&fsi->segbmap->extents.area,
					uncompr_bytes, compr_type);
	}

	if (fsi->maptbl) {
		uncompr_bytes = ssdfs_meta_extents_max_payload_size(
					&fsi->maptbl->extents.array,
					SSDFS_MAPTBL_RESERVED_EXTENTS,
					SSDFS_MAPTBL_SEG_COPY_MAX);
		layout->size[SSDFS_SB_LOG_MAPTBL_EXTENTS] =
			ssdfs_meta_extents_estimate_area_size(
					&fsi->maptbl->extents.area,
					uncompr_bytes, compr_type);
	}

	/* see ssdfs_snapshot_sb_log_payload() */
	used_bytes = sizeof(struct ssdfs_segment_header);
	used_bytes += layout->size[SSDFS_SB_LOG_SEGBMAP_EXTENTS];
	used_bytes += layout->size[SSDFS_SB_LOG_MAPTBL_EXTENTS];
	inline_capacity = used_bytes < PAGE_SIZE ? PAGE_SIZE - used_bytes : 0;

	err = ssdfs_estimate_maptbl_cache_payload_size(fsi, inline_capacity,
				&layout->size[SSDFS_SB_LOG_MAPTBL_CACHE]);
	if (unlikely(err)) {
		SSDFS_ERR("fail to estimate maptbl cache's size: err %d\n",
			  err);
		return err;
	}

	ssdfs_define_sb_log_layout(layout);

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_estimate_sb_log_layout);

/*
 * ssdfs_snapshot_sb_log_payload() - snapshot every payload area
 * @sb: superblock object
 * @payload: snapshot of the payload areas [out]
 *
 * This method takes a consistent snapshot of every payload area that
 * has to be stored into a new log of the superblock segment: the PEB
 * mapping table cache's content (uncompressed or compressed, see
 * ssdfs_snapshot_maptbl_cache_payload()), and (if any) the segment
 * bitmap's and the PEB mapping table's overflow extents. Every field of
 * @payload is an independent, owned copy that the caller must release
 * (see ssdfs_sb_log_payload_destroy()), even the two meta extents
 * ones: unlike the maptbl cache, the segment bitmap's/PEB mapping
 * table's extents never change at runtime (the driver doesn't
 * support growing them yet), but they aren't kept pre-encoded either
 * (that would duplicate the very same content that ssdfs_segbmap's/
 * ssdfs_maptbl's own extents dynamic array already holds); instead,
 * they are encoded afresh out of that array every time this method
 * is called.
 *
 * The sizes of the encoded areas are kept for the estimation of
 * the next logs' size (see ssdfs_estimate_sb_log_layout()).
 *
 * The caller must have already called ssdfs_sb_log_payload_create()
 * on @payload.
 */
int ssdfs_snapshot_sb_log_payload(struct super_block *sb,
				  struct ssdfs_sb_log_payload *payload)
{
	struct ssdfs_fs_info *fsi;
	u32 uncompr_bytes;
	u32 used_bytes;
	u32 inline_capacity;
	int compr_type;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !payload);

	SSDFS_DBG("sb %p, payload %p\n",
		  sb, payload);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = SSDFS_FS_I(sb);
	compr_type = fsi->metadata_options.user_data.compression;

	if (fsi->segbmap) {
		err = ssdfs_snapshot_meta_extents(&fsi->segbmap->extents.array,
					&fsi->segbmap->resize_lock,
					SSDFS_SEGBMAP_RESERVED_EXTENTS,
					SSDFS_SEGBMAP_SEG_COPY_MAX,
					compr_type,
					&payload->segbmap_meta_extents);
		if (unlikely(err)) {
			SSDFS_ERR("fail to encode segbmap's overflow extents: "
				  "err %d\n", err);
			goto fail_snapshot_payload;
		}

		uncompr_bytes = ssdfs_meta_extents_max_payload_size(
					&fsi->segbmap->extents.array,
					SSDFS_SEGBMAP_RESERVED_EXTENTS,
					SSDFS_SEGBMAP_SEG_COPY_MAX);
		ssdfs_remember_meta_extents_area(&fsi->segbmap->extents.area,
					uncompr_bytes, compr_type,
					&payload->segbmap_meta_extents);
	}

	if (fsi->maptbl) {
		err = ssdfs_snapshot_meta_extents(&fsi->maptbl->extents.array,
					&fsi->maptbl->tbl_lock,
					SSDFS_MAPTBL_RESERVED_EXTENTS,
					SSDFS_MAPTBL_SEG_COPY_MAX,
					compr_type,
					&payload->maptbl_meta_extents);
		if (unlikely(err)) {
			SSDFS_ERR("fail to encode maptbl's overflow extents: "
				  "err %d\n", err);
			goto fail_snapshot_payload;
		}

		uncompr_bytes = ssdfs_meta_extents_max_payload_size(
					&fsi->maptbl->extents.array,
					SSDFS_MAPTBL_RESERVED_EXTENTS,
					SSDFS_MAPTBL_SEG_COPY_MAX);
		ssdfs_remember_meta_extents_area(&fsi->maptbl->extents.area,
					uncompr_bytes, compr_type,
					&payload->maptbl_meta_extents);
	}

	/*
	 * The payload areas are packed right after the segment header
	 * (see ssdfs_define_sb_log_layout()) and the maptbl cache is
	 * the last one. So, the rest of the header's page after the
	 * metadata extents' areas is the inline area of the maptbl cache.
	 */
	used_bytes = sizeof(struct ssdfs_segment_header);
	used_bytes += payload->segbmap_meta_extents.bytes_count;
	used_bytes += payload->maptbl_meta_extents.bytes_count;
	inline_capacity = used_bytes < PAGE_SIZE ? PAGE_SIZE - used_bytes : 0;

	err = ssdfs_snapshot_maptbl_cache_payload(fsi, inline_capacity,
						  &payload->maptbl_cache);
	if (unlikely(err)) {
		SSDFS_ERR("fail to snapshot maptbl cache: err %d\n", err);
		goto fail_snapshot_payload;
	}

	return 0;

fail_snapshot_payload:
	ssdfs_sb_log_payload_destroy(payload);
	return err;
}

/*
 * ssdfs_area_compression_flag() - metadata check's flag of compression type
 * @compr_type: SSDFS_COMPR_ZLIB/LZO/LZ4/ZSTD
 */
u16 ssdfs_area_compression_flag(int compr_type)
{
	switch (compr_type) {
	case SSDFS_COMPR_ZLIB:
		return SSDFS_ZLIB_COMPRESSED;
	case SSDFS_COMPR_LZO:
		return SSDFS_LZO_COMPRESSED;
	case SSDFS_COMPR_LZ4:
		return SSDFS_LZ4_COMPRESSED;
	case SSDFS_COMPR_ZSTD:
		return SSDFS_ZSTD_COMPRESSED;
	default:
		break;
	}

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_area_compression_flag);

/*
 * ssdfs_prepare_compr_maptbl_cache_descriptor() - prepare descriptor
 * @desc: metadata descriptor [out]
 * @payload: maptbl cache's encoded content
 *
 * The flags of the descriptor show the compression type of the area.
 * The descriptor's checksum covers the first table's header (every
 * fragment carries its own checksum).
 */
static
void ssdfs_prepare_compr_maptbl_cache_descriptor(struct ssdfs_metadata_descriptor *desc,
					struct ssdfs_payload_content *payload)
{
	size_t tbl_size = sizeof(struct ssdfs_maptbl_cache_table);
	struct folio *folio;
	void *kaddr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(payload->bytes_count < tbl_size);
	BUG_ON(ssdfs_folio_vector_count(&payload->batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	desc->check.bytes = cpu_to_le16((u16)tbl_size);
	desc->check.flags = cpu_to_le16(SSDFS_CRC32 |
				ssdfs_area_compression_flag(payload->compr_type));

	folio = ssdfs_folio_vector_get(&payload->batch, 0);

	ssdfs_folio_lock(folio);
	kaddr = kmap_local_folio(folio, 0);
	desc->check.csum = ssdfs_crc32_le(kaddr, tbl_size);
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);
}

/*
 * ssdfs_prepare_uncompr_maptbl_cache_descriptor() - prepare descriptor
 * @desc: metadata descriptor [out]
 * @payload: maptbl cache's content
 * @payload_size: maptbl cache's size in bytes
 *
 * The descriptor's checksum covers the content of every fragment.
 */
static
void ssdfs_prepare_uncompr_maptbl_cache_descriptor(struct ssdfs_metadata_descriptor *desc,
					struct ssdfs_payload_content *payload,
					u32 payload_size)
{
	u32 i;
	u32 csum = ~0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(payload_size >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	desc->check.bytes = cpu_to_le16((u16)payload_size);
	desc->check.flags = cpu_to_le16(SSDFS_CRC32);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(ssdfs_folio_vector_count(&payload->batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < ssdfs_folio_vector_count(&payload->batch); i++) {
		struct folio *folio = ssdfs_folio_vector_get(&payload->batch, i);
		struct ssdfs_maptbl_cache_header *hdr;
		void *kaddr;
		u16 bytes_count;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);

		hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
		bytes_count = le16_to_cpu(hdr->bytes_count);

		csum = crc32(csum, kaddr, bytes_count);

		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);
	}

	desc->check.csum = cpu_to_le32(csum);
}

/*
 * ssdfs_prepare_maptbl_cache_descriptor() - prepare maptbl cache's descriptor
 * @desc: metadata descriptor [out]
 * @offset: maptbl cache's offset in the log
 * @payload: maptbl cache's content (uncompressed or encoded)
 * @payload_size: maptbl cache's size in bytes
 */
void
ssdfs_prepare_maptbl_cache_descriptor(struct ssdfs_metadata_descriptor *desc,
				      u32 offset,
				      struct ssdfs_payload_content *payload,
				      u32 payload_size)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !payload);

	SSDFS_DBG("desc %p, offset %u, payload %p, compr_type %d\n",
		  desc, offset, payload, payload->compr_type);
#endif /* CONFIG_SSDFS_DEBUG */

	desc->offset = cpu_to_le32(offset);
	desc->size = cpu_to_le32(payload_size);

	if (payload->compr_type != SSDFS_COMPR_NONE) {
		ssdfs_prepare_compr_maptbl_cache_descriptor(desc, payload);
	} else {
		ssdfs_prepare_uncompr_maptbl_cache_descriptor(desc, payload,
							      payload_size);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("payload_size %u, flags %#x, csum %#x\n",
		  payload_size,
		  le16_to_cpu(desc->check.flags),
		  le32_to_cpu(desc->check.csum));
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * ssdfs_prepare_meta_extents_descriptor() - prepare extents area's descriptor
 * @desc: metadata descriptor [out]
 * @offset: area's offset in the log
 * @payload: area's encoded content
 *
 * This mirrors mkfs.ssdfs's convention exactly: the descriptor-level
 * checksum covers only the first table's header (every fragment
 * already carries its own checksum).
 */
void
ssdfs_prepare_meta_extents_descriptor(struct ssdfs_metadata_descriptor *desc,
				      u32 offset,
				      struct ssdfs_payload_content *payload)
{
	size_t hdr_size = sizeof(struct ssdfs_metadata_extents_table);
	struct folio *folio;
	void *kaddr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !payload);
	BUG_ON(payload->bytes_count < hdr_size);
	BUG_ON(ssdfs_folio_vector_count(&payload->batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	desc->offset = cpu_to_le32(offset);
	desc->size = cpu_to_le32(payload->bytes_count);

	desc->check.bytes = cpu_to_le16((u16)hdr_size);
	desc->check.flags = cpu_to_le16(SSDFS_CRC32);

	folio = ssdfs_folio_vector_get(&payload->batch, 0);

	ssdfs_folio_lock(folio);
	kaddr = kmap_local_folio(folio, 0);
	desc->check.csum = ssdfs_crc32_le(kaddr, hdr_size);
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);
}
