// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_deduplication.c - PEB-based deduplication logic.
 *
 * Copyright (c) 2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/pagevec.h>
#include <crypto/hash.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "folio_array.h"
#include "request_queue.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "fingerprint.h"
#include "fingerprint_array.h"

/*
 * ssdfs_calculate_fingerprint() - calculate block's fingerprint
 * @pebi: pointer on PEB object
 * @req: I/O request
 * @hash: calculated fingerprint hash [out]
 *
 * This method tries to calculate block's fingerprint.
 */
static
int ssdfs_calculate_fingerprint(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				struct ssdfs_fingerprint *hash)
{
	struct ssdfs_fs_info *fsi;
	SHASH_DESC_ON_STACK(shash, pebi->dedup.shash_tfm);
	u32 mem_pages_per_folio;
	u32 rest_bytes;
	u32 start_folio = 0;
	u32 num_folios = 0;
	u32 processed_bytes = 0;
	int i, j;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req || !hash);
	BUG_ON(req->place.len >= U16_MAX);
	BUG_ON(req->result.processed_blks > req->place.len);

	SSDFS_DBG("ino %llu, seg_id %llu, logical_offset %llu, "
		  "processed_blks %d, logical_block %u, data_bytes %u, "
		  "cno %llu, parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id,
		  req->extent.logical_offset, req->result.processed_blks,
		  req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	mem_pages_per_folio = fsi->pagesize / PAGE_SIZE;

	shash->tfm = pebi->dedup.shash_tfm;
	crypto_shash_init(shash);

	rest_bytes = ssdfs_request_rest_bytes(pebi, req);

	start_folio = req->result.processed_blks;
	rest_bytes = min_t(u32, rest_bytes, fsi->pagesize);
	num_folios = rest_bytes + fsi->pagesize - 1;
	num_folios >>= fsi->log_pagesize;

	for (i = 0; i < num_folios; i++) {
		struct folio *folio;
		void *kaddr;
		int folio_index = i + start_folio;
		u32 portion_size;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(folio_index >= folio_batch_count(&req->result.batch));
#endif /* CONFIG_SSDFS_DEBUG */

		folio = req->result.batch.folios[folio_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		for (j = 0; j < mem_pages_per_folio; j++) {
			portion_size = min_t(u32, PAGE_SIZE,
						  rest_bytes - processed_bytes);

			kaddr = kmap_local_folio(folio, j * PAGE_SIZE);
			crypto_shash_update(shash, kaddr, portion_size);
			kunmap_local(kaddr);

			processed_bytes += portion_size;
		}
	}

	crypto_shash_final(shash, hash->buf);

	hash->type = SSDFS_DEFAULT_FINGERPRINT_TYPE();
	hash->len = SSDFS_DEFAULT_FINGERPRINT_LENGTH();

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("HASH (type %#x, len %u)\n",
		  hash->type, hash->len);

	SSDFS_DBG("FINGERPRINT DUMP:\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     hash->buf,
			     SSDFS_FINGERPRINT_LENGTH_MAX);
	SSDFS_DBG("\n");

	BUG_ON(!IS_FINGERPRINT_VALID(hash));
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * is_data_size_fingerprint_ready() - is data size bigger than page size
 * @pebi: pointer on PEB object
 * @req: I/O request
 */
static inline
bool is_data_size_fingerprint_ready(struct ssdfs_peb_info *pebi,
				    struct ssdfs_segment_request *req)
{
	u32 pagesize;
	u32 logical_block;
	u32 processed_blks;
	u64 rest_bytes;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(req->place.len >= U16_MAX);
	BUG_ON(req->result.processed_blks > req->place.len);

	SSDFS_DBG("ino %llu, seg %llu, peb %llu, "
		  "peb_index %u, logical_offset %llu, "
		  "processed_blks %d, logical_block %u, data_bytes %u, "
		  "cno %llu, parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id,
		  pebi->peb_id, pebi->peb_index,
		  req->extent.logical_offset, req->result.processed_blks,
		  req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	pagesize = pebi->pebc->parent_si->fsi->pagesize;

	processed_blks = req->result.processed_blks;
	logical_block = req->place.start.blk_index + processed_blks;

	rest_bytes = processed_blks * pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(rest_bytes >= req->extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	rest_bytes = req->extent.data_bytes - rest_bytes;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("data_size %llu, pagesize %u\n",
		  rest_bytes, pagesize);
#endif /* CONFIG_SSDFS_DEBUG */

	if (rest_bytes < PAGE_SIZE)
		return false;

	return true;
}

/*
 * is_ssdfs_block_duplicated() - check that block is duplicated
 * @pebi: pointer on PEB object
 * @req: I/O request
 * @pair: fingerprint pair [out]
 *
 * This method tries to check that block is duplicated.
 * Pre-allocated blocks will be ignored.
 */
bool is_ssdfs_block_duplicated(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				struct ssdfs_fingerprint_pair *pair)
{
	u32 logical_block;
	u32 processed_blks;
	bool is_duplicated = false;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req || !pair);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(req->place.len >= U16_MAX);
	BUG_ON(req->result.processed_blks > req->place.len);

	SSDFS_DBG("ino %llu, seg %llu, peb %llu, "
		  "peb_index %u, logical_offset %llu, "
		  "processed_blks %d, logical_block %u, data_bytes %u, "
		  "cno %llu, parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id,
		  pebi->peb_id, pebi->peb_index,
		  req->extent.logical_offset, req->result.processed_blks,
		  req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_ssdfs_peb_containing_user_data(pebi->pebc)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("ignore metadata\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	if (!is_data_size_fingerprint_ready(pebi, req)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("data is too small for fingerprint calculation\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	processed_blks = req->result.processed_blks;
	logical_block = req->place.start.blk_index + processed_blks;

	memset(&pair->item.hash, 0, sizeof(struct ssdfs_fingerprint));
	pair->item.logical_blk = logical_block;
	SSDFS_BLK_DESC_INIT(&pair->item.blk_desc);

	err = ssdfs_calculate_fingerprint(pebi, req, &pair->item.hash);
	if (unlikely(err)) {
		SSDFS_ERR("fail to calculate fingerprint: "
			  "logical_block %u, err %d\n",
			  logical_block, err);
		return false;
	}

	err = ssdfs_fingerprint_array_find(&pebi->dedup.fingerprints,
					   &pair->item.hash,
					   &pair->item_index);
	if (err == -ENOENT) {
		is_duplicated = false;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find fingerprint: "
			  "logical_block %u, err %d\n",
			  logical_block, err);
		return false;
	} else {
		is_duplicated = true;
	}

	return is_duplicated;
}

/*
 * should_ssdfs_save_fingerprint() - should fingerprint to be saved
 * @pebi: pointer on PEB object
 * @req: I/O request
 */
bool should_ssdfs_save_fingerprint(struct ssdfs_peb_info *pebi,
				   struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(req->place.len >= U16_MAX);
	BUG_ON(req->result.processed_blks > req->place.len);

	SSDFS_DBG("ino %llu, seg %llu, peb %llu, "
		  "peb_index %u, logical_offset %llu, "
		  "processed_blks %d, logical_block %u, data_bytes %u, "
		  "cno %llu, parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id,
		  pebi->peb_id, pebi->peb_index,
		  req->extent.logical_offset, req->result.processed_blks,
		  req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_ssdfs_peb_containing_user_data(pebi->pebc)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("ignore metadata\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	if (!is_data_size_fingerprint_ready(pebi, req)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("data is too small for fingerprint calculation\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	return true;
}

/*
 * ssdfs_peb_deduplicate_logical_block() - deduplicate a logical block
 * @pebi: pointer on PEB object
 * @req: I/O request
 * @pair: fingerprint pair
 * @blk_desc: pointer on buffer for block descriptor [out]
 *
 * This method tries to deduplicate the logical block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_deduplicate_logical_block(struct ssdfs_peb_info *pebi,
					struct ssdfs_segment_request *req,
					struct ssdfs_fingerprint_pair *pair,
					struct ssdfs_block_descriptor *blk_desc)
{
	struct ssdfs_fingerprint_item item;
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	int res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);
	BUG_ON(!pair || !blk_desc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(req->place.len >= U16_MAX);
	BUG_ON(req->result.processed_blks > req->place.len);

	SSDFS_DBG("ino %llu, seg %llu, peb %llu, "
		  "peb_index %u, logical_offset %llu, "
		  "processed_blks %d, logical_block %u, data_bytes %u, "
		  "cno %llu, parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id,
		  pebi->peb_id, pebi->peb_index,
		  req->extent.logical_offset, req->result.processed_blks,
		  req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pair->item.logical_blk >= U32_MAX) {
		SSDFS_ERR("invalid logical block\n");
		return -EINVAL;
	}

	if (!IS_FINGERPRINT_VALID(&pair->item.hash)) {
		SSDFS_ERR("invalid hash: logical block %u\n",
			  pair->item.logical_blk);
		return -EINVAL;
	}

	err = ssdfs_fingerprint_array_get(&pebi->dedup.fingerprints,
					  pair->item_index, &item);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get fingerprint item: "
			  "item_index %u, err %d\n",
			  pair->item_index, err);
		return err;
	}

	res = ssdfs_check_fingerprint_item(&pair->item.hash, &item);
	if (res == -EEXIST) {
		/*
		 * fingerprints are identical
		 */
	} else {
		SSDFS_ERR("fingerprints are different\n");
		return -ERANGE;
	}

	ssdfs_memcpy(blk_desc, 0, blk_desc_size,
		     &item.blk_desc, 0, blk_desc_size,
		     blk_desc_size);

	return 0;
}

/*
 * ssdfs_peb_save_fingerprint() - save new fingerprint into array
 * @pebi: pointer on PEB object
 * @req: I/O request
 * @blk_desc: block descriptor of logical block
 * @pair: fingerprint pair
 *
 * This method tries to store the new fingerprint of logical
 * block into the fingerprint array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_save_fingerprint(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				struct ssdfs_block_descriptor *blk_desc,
				struct ssdfs_fingerprint_pair *pair)
{
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req || !blk_desc || !pair);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(req->place.len >= U16_MAX);
	BUG_ON(req->result.processed_blks > req->place.len);

	SSDFS_DBG("ino %llu, seg %llu, peb %llu, "
		  "peb_index %u, logical_offset %llu, "
		  "processed_blks %d, logical_block %u, data_bytes %u, "
		  "cno %llu, parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id,
		  pebi->peb_id, pebi->peb_index,
		  req->extent.logical_offset, req->result.processed_blks,
		  req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pair->item.logical_blk >= U32_MAX) {
		SSDFS_ERR("invalid logical block\n");
		return -EINVAL;
	}

	if (!IS_FINGERPRINT_VALID(&pair->item.hash)) {
		SSDFS_ERR("invalid hash: logical block %u\n",
			  pair->item.logical_blk);
		return -EINVAL;
	}

	ssdfs_memcpy(&pair->item.blk_desc, 0, blk_desc_size,
		     blk_desc, 0, blk_desc_size,
		     blk_desc_size);

	err = ssdfs_fingerprint_array_add(&pebi->dedup.fingerprints, &pair->item,
					  pair->item_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add fingerprint item: "
			  "logical_block %u, item_index %u, err %d\n",
			  pair->item.logical_blk, pair->item_index, err);
		return err;
	}

	return 0;
}
