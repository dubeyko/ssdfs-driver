// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/diff_on_write_user_data.c - Diff-On-Write user data implementation.
 *
 * Copyright (c) 2021-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "common_bitmap.h"
#include "folio_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "request_queue.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "compression.h"
#include "diff_on_write.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_diff_folio_leaks;
atomic64_t ssdfs_diff_memory_leaks;
atomic64_t ssdfs_diff_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_diff_cache_leaks_increment(void *kaddr)
 * void ssdfs_diff_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_diff_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_diff_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_diff_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_diff_kfree(void *kaddr)
 * struct folio *ssdfs_diff_alloc_folio(gfp_t gfp_mask,
 *                                      unsigned int order)
 * struct folio *ssdfs_diff_add_batch_folio(struct folio_batch *batch,
 *                                          unsigned int order)
 * void ssdfs_diff_free_folio(struct folio *folio)
 * void ssdfs_diff_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(diff)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(diff)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_diff_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_diff_folio_leaks, 0);
	atomic64_set(&ssdfs_diff_memory_leaks, 0);
	atomic64_set(&ssdfs_diff_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_diff_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_diff_folio_leaks) != 0) {
		SSDFS_ERR("DIFF subsystem: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_diff_folio_leaks));
	}

	if (atomic64_read(&ssdfs_diff_memory_leaks) != 0) {
		SSDFS_ERR("DIFF subsystem: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_diff_memory_leaks));
	}

	if (atomic64_read(&ssdfs_diff_cache_leaks) != 0) {
		SSDFS_ERR("DIFF subsystem: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_diff_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

#define GET_CHECKSUM(kaddr) \
	((__le32 *)((u8 *)kaddr + \
		sizeof(struct ssdfs_diff_blob_header)))

/*
 * ssdfs_reserve_diff_blob_header() - reserve diff blob header
 * @hdr: diff blob header
 * @write_offset: current write offset
 */
static inline
void ssdfs_reserve_diff_blob_header(struct ssdfs_diff_blob_header *hdr,
				    u32 *write_offset)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr || !write_offset);

	SSDFS_DBG("hdr %p, write_offset %u\n",
		  hdr, *write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr->magic = cpu_to_le16(SSDFS_DIFF_BLOB_MAGIC);
	hdr->type = SSDFS_USER_DATA_DIFF_BLOB;
	hdr->flags = cpu_to_le16(0);

	*write_offset += sizeof(struct ssdfs_diff_blob_header);
}

/*
 * ssdfs_user_data_prepare_diff() - prepare logical block's diff
 * @pebc: PEB container object
 * @desc_off: block descriptor offset
 * @pos: offset position
 * @req: segment request
 *
 * This method tries to prepare the logical block's diff for flush operation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENOENT     - unable to prepare diff (old state is absent).
 * %-E2BIG      - unable to prepare diff (delta is too big).
 */
int ssdfs_user_data_prepare_diff(struct ssdfs_peb_container *pebc,
				 struct ssdfs_phys_offset_descriptor *desc_off,
				 struct ssdfs_offset_position *pos,
				 struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor desc_array[SSDFS_SEG_HDR_DESC_MAX];
	struct ssdfs_diff_blob_header hdr;
	size_t hdr_size = sizeof(struct ssdfs_diff_blob_header);
	u32 hdr_offset = 0;
	u32 write_offset = 0;
	u32 blob_offset = 0;
	u32 blob_size;
	struct folio *diff_folio, *old_folio, *new_folio;
	void *kaddr1, *kaddr2;
	void *bmap = NULL;
	size_t batch_size1, batch_size2;
	size_t bits_count = PAGE_SIZE * BITS_PER_BYTE;
	unsigned long bits_threshold;
	unsigned long dirty_bits = 0;
	u8 compression_type;
	u32 mem_pages_per_block;
	int folio_index;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);
	BUG_ON(!pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req || !desc_off || !pos);

	SSDFS_DBG("seg %llu, peb_index %u, ino %llu, "
		  "processed_blks %d\n",
		  req->place.start.seg_id, pebc->peb_index,
		  req->extent.ino, req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_ssdfs_peb_containing_user_data(pebc)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("PEB contains NOT user data: "
			  "seg %llu, peb_index %u, ino %llu\n",
			  req->place.start.seg_id,
			  pebc->peb_index,
			  req->extent.ino);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOENT;
	}

	fsi = pebc->parent_si->fsi;
	compression_type = fsi->metadata_options.user_data.compression;

	mem_pages_per_block = fsi->pagesize / PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(mem_pages_per_block == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	bits_threshold =
		bits_count * CONFIG_SSDFS_DIFF_ON_WRITE_USER_DATA_THRESHOLD;
	bits_threshold /= 100;

	req->private.flags |= SSDFS_REQ_READ_ONLY_CACHE |
				SSDFS_REQ_PREPARE_DIFF;

	err = ssdfs_request_add_old_state_folio_locked(req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate old state folio: "
			  "err %d\n", err);
		return err;
	}

	err = ssdfs_peb_read_block_state(pebc, req, desc_off, pos,
					 desc_array,
					 SSDFS_SEG_HDR_DESC_MAX);
	if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to read block state: "
			  "seg %llu, peb_index %u, ino %llu, "
			  "logical_offset %llu, "
			  "processed_blocks %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index,
			  req->extent.ino,
			  req->extent.logical_offset,
			  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read block state: "
			  "seg %llu, peb_index %u, ino %llu, "
			  "logical_offset %llu, processed_blocks %d, "
			  "err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index,
			  req->extent.ino,
			  req->extent.logical_offset,
			  req->result.processed_blks,
			  err);
		return err;
	}

	diff_folio = ssdfs_request_allocate_locked_diff_folio(req, 0);
	if (unlikely(IS_ERR_OR_NULL(diff_folio))) {
		err = diff_folio == NULL ? -ERANGE : PTR_ERR(diff_folio);
		SSDFS_ERR("fail to add folio into request: "
			  "err %d\n", err);
		return err;
	}

	folio_start_writeback(diff_folio);

	bmap = ssdfs_diff_kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (unlikely(!bmap)) {
		SSDFS_ERR("fail to allocate bitmap buffer\n");
		return -ENOMEM;
	}

	batch_size1 = folio_batch_count(&req->result.old_state);
	batch_size2 = folio_batch_count(&req->result.batch);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("batch_size1 %zu, batch_size2 %zu, "
		  "req->result.processed_blks %d\n",
		  batch_size1, batch_size2,
		  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < batch_size1; i++) {
		size_t uncompr_size = PAGE_SIZE;
		size_t compr_size;
		__le32 csum = ~0;
		__le32 *csum_ptr = NULL;

		memset(&hdr, 0, hdr_size);
		ssdfs_reserve_diff_blob_header(&hdr, &write_offset);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("RESERVE DIFF BLOB HEADER: "
			  "folio_index %d, write_offset %u\n",
			  i, write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

		if (write_offset >= PAGE_SIZE) {
			err = -E2BIG;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to prepare diff blob: "
				  "folio_index %d, write_offset %u\n",
				  i, write_offset);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_prepare_diff;
		}

		blob_offset = write_offset;

		old_folio = req->result.old_state.folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!old_folio);
#endif /* CONFIG_SSDFS_DEBUG */

		folio_index = req->result.processed_blks + i;

		if (folio_index >= batch_size2) {
			err = -ERANGE;
			SSDFS_ERR("folio_index %d >= batch_size %zu\n",
				  folio_index, batch_size2);
			goto finish_prepare_diff;
		}

		new_folio = req->result.batch.folios[folio_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!new_folio);
#endif /* CONFIG_SSDFS_DEBUG */

		kaddr1 = kmap_local_folio(old_folio, 0);
		kaddr2 = kmap_local_folio(new_folio, 0);
		bitmap_xor(bmap, kaddr1, kaddr2, bits_count);
		csum = cpu_to_le32(crc32(csum, kaddr2, PAGE_SIZE));
		kunmap_local(kaddr2);
		kunmap_local(kaddr1);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("PREPARE DIFF BITMAP: "
			  "folio_index %d, write_offset %u\n",
			  i, write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

		dirty_bits += bitmap_weight(bmap, bits_count);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio_index %d, dirty_bits %lu\n",
			  i, dirty_bits);
#endif /* CONFIG_SSDFS_DEBUG */

		if (dirty_bits > bits_threshold) {
			err = -E2BIG;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to prepare diff blob: "
				  "folio_index %d, write_offset %u\n",
				  i, write_offset);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_prepare_diff;
		}

		kaddr1 = kmap_local_folio(diff_folio, 0);

		csum_ptr = GET_CHECKSUM(kaddr1);
		*csum_ptr = csum;
		write_offset += sizeof(__le32);

		compr_size = PAGE_SIZE - write_offset;
		err = ssdfs_compress(compression_type,
				     bmap, (u8 *)kaddr1 + write_offset,
				     &uncompr_size, &compr_size);

		flush_dcache_folio(diff_folio);
		kunmap_local(kaddr1);

		if (err == -E2BIG) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to prepare diff blob: "
				  "folio_index %d, write_offset %u\n",
				  i, write_offset);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_prepare_diff;
		} else if (unlikely(err)) {
			SSDFS_ERR("unable to prepare diff blob: "
				  "folio_index %d, write_offset %u, "
				  "err %d\n",
				  i, write_offset, err);
			goto finish_prepare_diff;
		}

		write_offset += compr_size;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("COMPRESS DIFF BITMAP: "
			  "folio_index %d, write_offset %u\n",
			  i, write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

		blob_size = write_offset - blob_offset;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(blob_size >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		hdr.blob_size = cpu_to_le16((u16)blob_size);

		if (i < (batch_size1 - 1)) {
			hdr.flags =
			    cpu_to_le16(SSDFS_DIFF_CHAIN_CONTAINS_NEXT_BLOB);
		}

		err = __ssdfs_memcpy_to_folio(diff_folio, hdr_offset, PAGE_SIZE,
					      &hdr, 0, hdr_size,
					      hdr_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy diff blob's header: "
				  "hdr_offset %u, err %d\n",
				  hdr_offset, err);
			goto finish_prepare_diff;
		}

		hdr_offset = write_offset;
	}

	err = ssdfs_request_switch_update_on_diff(fsi, diff_folio, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to switch block update on diff: "
			  "err %d\n", err);
		goto finish_prepare_diff;
	}

finish_prepare_diff:
	ssdfs_diff_kfree(bmap);

	return err;
}

static inline
u32 ssdfs_content_folio_batch_size(struct ssdfs_segment_request *req)
{
	struct folio_batch *batch = NULL;

	if (req->private.flags & SSDFS_REQ_PREPARE_DIFF)
		batch = &req->result.old_state;
	else
		batch = &req->result.batch;

	return folio_batch_count(batch);
}

static inline
struct folio *ssdfs_get_content_folio(struct ssdfs_segment_request *req,
				      int folio_index)
{
	struct folio_batch *batch = NULL;

	if (req->private.flags & SSDFS_REQ_PREPARE_DIFF)
		batch = &req->result.old_state;
	else
		batch = &req->result.batch;

	if (folio_index >= folio_batch_count(batch)) {
		SSDFS_WARN("folio_index %d >= batch_size %u\n",
			   folio_index,
			   folio_batch_count(batch));
		return NULL;
	}

	return batch->folios[folio_index];
}

/*
 * ssdfs_user_data_apply_diff_page() - apply diff on memory folio
 * @fsi: file system info object
 * @req: segment request
 * @folio: memory folio [in|out]
 *
 * This method tries to apply the diff on memory folio.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - diff is corrupted.
 */
static
int ssdfs_user_data_apply_diff_page(struct ssdfs_fs_info *fsi,
				    struct ssdfs_segment_request *req,
				    struct folio *folio)
{
	struct ssdfs_diff_blob_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_diff_blob_header);
	void *bmap = NULL;
	void *diff_kaddr, *content_kaddr;
	struct folio *content_folio = NULL;
	size_t bits_count = PAGE_SIZE * BITS_PER_BYTE;
	u16 diff_flags = SSDFS_DIFF_CHAIN_CONTAINS_NEXT_BLOB;
	u32 offset = 0;
	u16 blob_size;
	u32 batch_size;
	__le32 calculated_csum;
	__le32 csum;
	u8 compression_type;
	u32 mem_pages_per_block;
	int i;
#ifdef CONFIG_SSDFS_DEBUG
	int j;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req || !folio);
	WARN_ON(!folio_test_locked(folio));

	SSDFS_DBG("req %p, folio %p\n", req, folio);
#endif /* CONFIG_SSDFS_DEBUG */

	mem_pages_per_block = fsi->pagesize / PAGE_SIZE;
	compression_type = fsi->metadata_options.user_data.compression;
	batch_size = ssdfs_content_folio_batch_size(req);

	bmap = ssdfs_diff_kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (unlikely(!bmap)) {
		SSDFS_ERR("fail to allocate bitmap buffer\n");
		return -ENOMEM;
	}

	diff_kaddr = kmap_local_folio(folio, 0);

	for (i = 0; i < batch_size; i++) {
		if (!(diff_flags & SSDFS_DIFF_CHAIN_CONTAINS_NEXT_BLOB)) {
			err = -EIO;
			SSDFS_ERR("corrupted diff state: "
				  "offset %u, diff_flags %#x\n",
				  offset, diff_flags);
			goto finish_apply_diff_folio;
		}

		hdr = (struct ssdfs_diff_blob_header *)((u8 *)diff_kaddr +
								offset);

		if (le16_to_cpu(hdr->magic) != SSDFS_DIFF_BLOB_MAGIC) {
			err = -EIO;
			SSDFS_ERR("invalid header magic %#x\n",
				  le16_to_cpu(hdr->magic));
			goto finish_apply_diff_folio;
		}

		if (hdr->type != SSDFS_USER_DATA_DIFF_BLOB) {
			err = -EIO;
			SSDFS_ERR("invalid blob type %#x\n",
				  hdr->type);
			goto finish_apply_diff_folio;
		}

		diff_flags = le16_to_cpu(hdr->flags);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("diff_flags %#x\n",
			  diff_flags);
#endif /* CONFIG_SSDFS_DEBUG */

		if (diff_flags & ~SSDFS_DIFF_BLOB_FLAGS_MASK) {
			err = -EIO;
			SSDFS_ERR("invalid set of flags: "
				  "diff_flags %#x\n",
				  diff_flags);
			goto finish_apply_diff_folio;
		}

		/* copy checksum at first */
		csum = *GET_CHECKSUM(diff_kaddr);

		offset += hdr_size + sizeof(__le32);

		if (offset >= PAGE_SIZE) {
			err = -EIO;
			SSDFS_ERR("corrupted diff blob: "
				  "hdr_size %zu, desc_size %u\n",
				  hdr_size, hdr->desc_size);
			goto finish_apply_diff_folio;
		}

		blob_size = le16_to_cpu(hdr->blob_size);

		if ((offset + blob_size) > PAGE_SIZE) {
			err = -EIO;
			SSDFS_ERR("corrupted diff blob: "
				  "offset %u, blob_size %u\n",
				  offset, blob_size);
			goto finish_apply_diff_folio;
		}

		err = ssdfs_decompress(compression_type,
					(u8 *)diff_kaddr + offset, bmap,
					blob_size, PAGE_SIZE);
		if (unlikely(err)) {
			SSDFS_ERR("fail to decompress: "
				  "offset %u, blob_size %u, err %d\n",
				  offset, blob_size, err);
			goto finish_apply_diff_folio;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("DECOMPRESS DIFF BLOB: "
			  "offset %u, page_index %d\n",
			  offset, i);
#endif /* CONFIG_SSDFS_DEBUG */

		content_folio = ssdfs_get_content_folio(req, i);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!content_folio);
#endif /* CONFIG_SSDFS_DEBUG */

		calculated_csum = ~0;

		content_kaddr = kmap_local_folio(content_folio, 0);
		bitmap_xor(content_kaddr, bmap, content_kaddr, bits_count);
		calculated_csum = cpu_to_le32(crc32(calculated_csum,
						    content_kaddr, PAGE_SIZE));
		flush_dcache_folio(content_folio);
		kunmap_local(content_kaddr);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("APPLY DIFF BLOB: "
			  "offset %u, page_index %d\n",
			  offset, i);
#endif /* CONFIG_SSDFS_DEBUG */

		if (calculated_csum != csum) {
			SSDFS_WARN("invalid checksum: "
				   "calculated_csum %#x != csum %#x\n",
				   le32_to_cpu(calculated_csum),
				   le32_to_cpu(csum));

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("LOGICAL BLOCK CONTENT: batch_size %u\n",
				  folio_batch_count(&req->result.batch));

			for (i = 0; i < batch_size; i++) {
				content_folio = ssdfs_get_content_folio(req, i);

				if (!content_folio)
					continue;

				for (j = 0; j < mem_pages_per_block; j++) {
					content_kaddr =
						kmap_local_folio(content_folio,
								 j * PAGE_SIZE);
					SSDFS_DBG("PAGE DUMP: folio_index %d, "
						  "page_index %d\n",
						  i, j);
					print_hex_dump_bytes("",
							     DUMP_PREFIX_OFFSET,
							     content_kaddr,
							     PAGE_SIZE);
					SSDFS_DBG("\n");
					kunmap_local(content_kaddr);
				}
			}

			BUG();
#else
			err = -EIO;
			goto finish_apply_diff_folio;
#endif /* CONFIG_SSDFS_DEBUG */
		}
	}

	if (diff_flags & SSDFS_DIFF_CHAIN_CONTAINS_NEXT_BLOB) {
		err = -EIO;
		SSDFS_ERR("corrupted diff state: "
			  "offset %u, diff_flags %#x\n",
			  offset, diff_flags);
		goto finish_apply_diff_folio;
	}

finish_apply_diff_folio:
	kunmap_local(diff_kaddr);
	ssdfs_diff_kfree(bmap);

	if (unlikely(err)) {
		SSDFS_ERR("fail to apply diff page: err %d\n",
			  err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("FINISHED: offset %u\n",
		  offset);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_user_data_apply_diffs() - apply diffs on logical block
 * @pebi: PEB object
 * @req: segment request
 *
 * This method tries to apply the diffs on logical block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - diff is corrupted.
 */
int ssdfs_user_data_apply_diffs(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct folio *folio;
	u32 mem_pages_per_block;
	int i;
#ifdef CONFIG_SSDFS_DEBUG
	void *kaddr;
	int j;
#endif /* CONFIG_SSDFS_DEBUG */
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !req);

	SSDFS_DBG("seg %llu, peb %llu, "
		  "class %#x, cmd %#x, type %#x, "
		  "ino %llu, logical_offset %llu, data_bytes %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  req->private.class, req->private.cmd, req->private.type,
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	mem_pages_per_block = fsi->pagesize / PAGE_SIZE;

	if (folio_batch_count(&req->result.diffs) == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("diff batch is empty: "
			  "seg %llu, peb %llu, "
			  "class %#x, cmd %#x, type %#x, "
			  "ino %llu, logical_offset %llu, data_bytes %u\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  req->private.class, req->private.cmd,
			  req->private.type, req->extent.ino,
			  req->extent.logical_offset,
			  req->extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("LOGICAL BLOCK CONTENT: batch_size %u\n",
		  folio_batch_count(&req->result.batch));

	for (i = 0; i < folio_batch_count(&req->result.batch); i++) {
		folio = req->result.batch.folios[i];

		if (!folio)
			continue;

		for (j = 0; j < mem_pages_per_block; j++) {
			kaddr = kmap_local_folio(folio, j * PAGE_SIZE);
			SSDFS_DBG("PAGE DUMP: folio_index %d, page_index %d\n",
				  i, j);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr,
					     PAGE_SIZE);
			SSDFS_DBG("\n");
			kunmap_local(kaddr);
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < folio_batch_count(&req->result.diffs); i++) {
		folio = req->result.diffs.folios[i];

		if (!folio) {
			SSDFS_WARN("folio %d is NULL\n", i);
			continue;
		}

#ifdef CONFIG_SSDFS_DEBUG
		WARN_ON(!folio_test_locked(folio));

		for (j = 0; j < mem_pages_per_block; j++) {
			kaddr = kmap_local_folio(folio, j * PAGE_SIZE);
			SSDFS_DBG("DIFF DUMP: folio_index %d, page_index %d\n",
				  i, j);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr,
					     PAGE_SIZE);
			SSDFS_DBG("\n");
			kunmap_local(kaddr);
		}
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_user_data_apply_diff_page(fsi, req, folio);
		if (unlikely(err)) {
			SSDFS_ERR("fail to apply diff folio: "
				  "seg %llu, peb %llu, page_index %d, "
				  "class %#x, cmd %#x, type %#x, "
				  "ino %llu, logical_offset %llu, "
				  "data_bytes %u\n",
				  pebi->pebc->parent_si->seg_id, pebi->peb_id,
				  i, req->private.class, req->private.cmd,
				  req->private.type, req->extent.ino,
				  req->extent.logical_offset,
				  req->extent.data_bytes);
			return err;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("LOGICAL BLOCK CONTENT: batch_size %u\n",
		  folio_batch_count(&req->result.batch));

	for (i = 0; i < folio_batch_count(&req->result.batch); i++) {
		folio = req->result.batch.folios[i];

		if (!folio)
			continue;

		for (j = 0; j < mem_pages_per_block; j++) {
			kaddr = kmap_local_folio(folio, j * PAGE_SIZE);
			SSDFS_DBG("PAGE DUMP: folio_index %d, page_index %d\n",
				  i, j);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr,
					     PAGE_SIZE);
			SSDFS_DBG("\n");
			kunmap_local(kaddr);
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}
