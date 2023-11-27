// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/readwrite.c - read/write primitive operations.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 *
 * (C) Copyright 2014-2019, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot
 *                  Zvonimir Bandic
 */

#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"

#include <trace/events/ssdfs.h>

/*
 * ssdfs_read_folio_from_volume() - read logical block from volume
 * @fsi: pointer on shared file system object
 * @peb_id: PEB identification number
 * @bytes_offset: offset from PEB's begining in bytes
 * @folio: memory folio
 *
 * This function tries to read logical block from the volume.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EIO        - I/O error.
 */
int ssdfs_read_folio_from_volume(struct ssdfs_fs_info *fsi,
				 u64 peb_id, u32 bytes_offset,
				 struct folio *folio)
{
	struct super_block *sb;
	loff_t offset;
	u32 peb_size;
	u32 pagesize;
	u32 pages_per_peb;
	u32 folio_index;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !folio);
	BUG_ON(!fsi->devops->read_block);

	SSDFS_DBG("fsi %p, peb_id %llu, "
		  "bytes_offset %u, folio %p\n",
		  fsi, peb_id, bytes_offset, folio);
#endif /* CONFIG_SSDFS_DEBUG */

	sb = fsi->sb;
	pagesize = fsi->pagesize;
	pages_per_peb = fsi->pages_per_peb;
	folio_index = bytes_offset / pagesize;

	if (pages_per_peb >= (U32_MAX / pagesize)) {
		SSDFS_ERR("pages_per_peb %u >= U32_MAX / pagesize %u\n",
			  pages_per_peb, pagesize);
		return -EINVAL;
	}

	peb_size = pages_per_peb * pagesize;

	if (peb_id >= div_u64(ULLONG_MAX, peb_size)) {
		SSDFS_ERR("peb_id %llu >= ULLONG_MAX / peb_size %u\n",
			  peb_id, peb_size);
		return -EINVAL;
	}

	offset = peb_id * peb_size;

	if (folio_index >= pages_per_peb) {
		SSDFS_ERR("folio_index %u >= pages_per_peb %u\n",
			  folio_index, pages_per_peb);
		return -EINVAL;
	}

	if (folio_index >= (U32_MAX / pagesize)) {
		SSDFS_ERR("folio_index %u >= U32_MAX / pagesize %u\n",
			  folio_index, fsi->pagesize);
		return -EINVAL;
	}

	offset += bytes_offset;

	if (fsi->devops->peb_isbad) {
		err = fsi->devops->peb_isbad(sb, offset);
		if (err) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("offset %llu is in bad PEB: err %d\n",
				  (unsigned long long)offset, err);
#endif /* CONFIG_SSDFS_DEBUG */
			return -EIO;
		}
	}

	err = fsi->devops->read_block(sb, folio, offset);
	if (unlikely(err)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fail to read block: offset %llu, err %d\n",
			  (unsigned long long)offset, err);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_read_folio_batch_from_volume() - read folio batch from volume
 * @fsi: pointer on shared file system object
 * @peb_id: PEB identification number
 * @bytes_offset: offset from PEB's begining in bytes
 * @batch: folio batch [in|out]
 *
 * This function tries to read logical blocks from the volume.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EIO        - I/O error.
 */
int ssdfs_read_folio_batch_from_volume(struct ssdfs_fs_info *fsi,
					u64 peb_id, u32 bytes_offset,
					struct folio_batch *batch)
{
	struct super_block *sb;
	loff_t offset;
	u32 peb_size;
	u32 pagesize;
	u32 pages_per_peb;
	u32 folio_index;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !batch);
	BUG_ON(!fsi->devops->read_blocks);

	SSDFS_DBG("fsi %p, peb_id %llu, "
		  "bytes_offset %u, batch %p\n",
		  fsi, peb_id, bytes_offset, batch);
#endif /* CONFIG_SSDFS_DEBUG */

	sb = fsi->sb;
	pagesize = fsi->pagesize;
	pages_per_peb = fsi->pages_per_peb;
	folio_index = bytes_offset / pagesize;

	if (pages_per_peb >= (U32_MAX / pagesize)) {
		SSDFS_ERR("pages_per_peb %u >= U32_MAX / pagesize %u\n",
			  pages_per_peb, pagesize);
		return -EINVAL;
	}

	peb_size = pages_per_peb * pagesize;

	if (peb_id >= div_u64(ULLONG_MAX, peb_size)) {
		SSDFS_ERR("peb_id %llu >= ULLONG_MAX / peb_size %u\n",
			  peb_id, peb_size);
		return -EINVAL;
	}

	offset = peb_id * peb_size;

	if (folio_index >= pages_per_peb) {
		SSDFS_ERR("folio_index %u >= pages_per_peb %u\n",
			  folio_index, pages_per_peb);
		return -EINVAL;
	}

	if (folio_index >= (U32_MAX / pagesize)) {
		SSDFS_ERR("folio_index %u >= U32_MAX / pagesize %u\n",
			  folio_index, fsi->pagesize);
		return -EINVAL;
	}

	offset += bytes_offset;

	if (fsi->devops->peb_isbad) {
		err = fsi->devops->peb_isbad(sb, offset);
		if (err) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("offset %llu is in bad PEB: err %d\n",
				  (unsigned long long)offset, err);
#endif /* CONFIG_SSDFS_DEBUG */
			return -EIO;
		}
	}

	err = fsi->devops->read_blocks(sb, batch, offset);
	if (unlikely(err)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fail to read batch: offset %llu, err %d\n",
			  (unsigned long long)offset, err);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_aligned_read_buffer() - aligned read from volume into buffer
 * @fsi: pointer on shared file system object
 * @peb_id: PEB identification number
 * @block_size: block size in bytes
 * @bytes_off: offset from PEB's begining in bytes
 * @buf: buffer
 * @size: buffer size
 * @read_bytes: really read bytes
 *
 * This function tries to read in buffer by means of page aligned
 * request. It reads part of requested data in the case of unaligned
 * request. The @read_bytes returns value of really read data.
 *
 * RETURN:
 * [success] - buffer contains data of @read_bytes in size.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EIO        - I/O error.
 */
int ssdfs_aligned_read_buffer(struct ssdfs_fs_info *fsi,
			      u64 peb_id, u32 block_size,
			      u32 bytes_off,
			      void *buf, size_t size,
			      size_t *read_bytes)
{
	struct super_block *sb;
	loff_t offset;
	u32 peb_size;
	u32 pages_per_peb;
	u32 pages_off;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !buf);
	BUG_ON(!fsi->devops->read);

	SSDFS_DBG("fsi %p, peb_id %llu, block_size %u, "
		  "bytes_off %u, buf %p, size %zu\n",
		  fsi, peb_id, block_size, bytes_off, buf, size);
#endif /* CONFIG_SSDFS_DEBUG */

	sb = fsi->sb;
	pages_per_peb = fsi->erasesize / block_size;
	pages_off = bytes_off / block_size;

	if (pages_per_peb >= (U32_MAX / block_size)) {
		SSDFS_ERR("pages_per_peb %u >= U32_MAX / block_size %u\n",
			  pages_per_peb, block_size);
		return -EINVAL;
	}

	peb_size = pages_per_peb * block_size;

	if (peb_id >= div_u64(ULLONG_MAX, peb_size)) {
		SSDFS_ERR("peb_id %llu >= ULLONG_MAX / peb_size %u\n",
			  peb_id, peb_size);
		return -EINVAL;
	}

	offset = peb_id * peb_size;

	if (pages_off >= pages_per_peb) {
		SSDFS_ERR("pages_off %u >= pages_per_peb %u\n",
			  pages_off, pages_per_peb);
		return -EINVAL;
	}

	if (pages_off >= (U32_MAX / block_size)) {
		SSDFS_ERR("pages_off %u >= U32_MAX / block_size %u\n",
			  pages_off, block_size);
		return -EINVAL;
	}

	if (size > block_size) {
		SSDFS_ERR("size %zu > block_size %u\n",
			  size, block_size);
		return -EINVAL;
	}

	offset += bytes_off;

	*read_bytes = ((pages_off + 1) * block_size) - bytes_off;
	*read_bytes = min_t(size_t, *read_bytes, size);

	if (fsi->devops->peb_isbad) {
		err = fsi->devops->peb_isbad(sb, offset);
		if (err) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("offset %llu is in bad PEB: err %d\n",
				  (unsigned long long)offset, err);
#endif /* CONFIG_SSDFS_DEBUG */
			return -EIO;
		}
	}

	err = fsi->devops->read(sb, block_size, offset, *read_bytes, buf);
	if (unlikely(err)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fail to read from offset %llu, size %zu, err %d\n",
			  (unsigned long long)offset, *read_bytes, err);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_unaligned_read_buffer() - unaligned read from volume into buffer
 * @fsi: pointer on shared file system object
 * @peb_id: PEB identification number
 * @block_size: block size in bytes
 * @bytes_off: offset from PEB's begining in bytes
 * @buf: buffer
 * @size: buffer size
 *
 * This function tries to read in buffer by means of page unaligned
 * request.
 *
 * RETURN:
 * [success] - buffer contains data of @size in bytes.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EIO        - I/O error.
 */
int ssdfs_unaligned_read_buffer(struct ssdfs_fs_info *fsi,
				u64 peb_id, u32 block_size,
				u32 bytes_off,
				void *buf, size_t size)
{
	size_t read_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !buf);
	BUG_ON(!fsi->devops->read);

	SSDFS_DBG("fsi %p, peb_id %llu, block_size %u, "
		  "bytes_off %u, buf %p, size %zu\n",
		  fsi, peb_id, block_size, bytes_off, buf, size);
#endif /* CONFIG_SSDFS_DEBUG */

	do {
		size_t iter_size = size - read_bytes;
		size_t iter_read_bytes;

		err = ssdfs_aligned_read_buffer(fsi, peb_id, block_size,
						bytes_off + read_bytes,
						buf + read_bytes,
						iter_size,
						&iter_read_bytes);
		if (err) {
			SSDFS_ERR("fail to read from peb_id %llu, offset %zu, "
				  "size %zu, err %d\n",
				  peb_id, (size_t)(bytes_off + read_bytes),
				  iter_size, err);
			return err;
		}

		read_bytes += iter_read_bytes;
	} while (read_bytes < size);

	return 0;
}

/*
 * ssdfs_can_write_sb_log() - check that superblock log can be written
 * @sb: pointer on superblock object
 * @sb_log: superblock log's extent
 *
 * This function checks that superblock log can be written
 * successfully.
 *
 * RETURN:
 * [success] - superblock log can be written successfully.
 * [failure] - error code:
 *
 * %-ERANGE     - invalid extent.
 */
int ssdfs_can_write_sb_log(struct super_block *sb,
			   struct ssdfs_peb_extent *sb_log)
{
	struct ssdfs_fs_info *fsi;
	u64 cur_peb;
	u32 page_offset;
	u32 log_size;
	loff_t byte_off;
	u32 pages_per_peb;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !sb_log);

	SSDFS_DBG("leb_id %llu, peb_id %llu, "
		  "page_offset %u, pages_count %u\n",
		  sb_log->leb_id, sb_log->peb_id,
		  sb_log->page_offset, sb_log->pages_count);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = SSDFS_FS_I(sb);

	if (!fsi->devops->can_write_block)
		return 0;

	cur_peb = sb_log->peb_id;
	page_offset = sb_log->page_offset;
	log_size = sb_log->pages_count;
	pages_per_peb = fsi->erasesize / PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("cur_peb %llu, page_offset %u, "
		  "log_size %u, pages_per_peb %u\n",
		  cur_peb, page_offset,
		  log_size, pages_per_peb);

	if (log_size > pages_per_peb) {
		SSDFS_ERR("log_size value %u is too big\n",
			  log_size);
		return -ERANGE;
	}

	if (cur_peb > div_u64(ULLONG_MAX, fsi->pebs_per_seg)) {
		SSDFS_ERR("cur_peb value %llu is too big\n",
			  cur_peb);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	byte_off = cur_peb * pages_per_peb;

#ifdef CONFIG_SSDFS_DEBUG
	if (byte_off > div_u64(ULLONG_MAX, PAGE_SIZE)) {
		SSDFS_ERR("byte_off value %llu is too big\n",
			  byte_off);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	byte_off *= PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
	if ((u64)page_offset > div_u64(ULLONG_MAX, PAGE_SIZE)) {
		SSDFS_ERR("page_offset value %u is too big\n",
			  page_offset);
		return -ERANGE;
	}

	if (byte_off > (ULLONG_MAX - ((u64)page_offset * PAGE_SIZE))) {
		SSDFS_ERR("byte_off value %llu is too big\n",
			  byte_off);
			return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	byte_off += (u64)page_offset * PAGE_SIZE;

	for (i = 0; i < log_size; i++) {
#ifdef CONFIG_SSDFS_DEBUG
		if (byte_off > (ULLONG_MAX - (i * PAGE_SIZE))) {
			SSDFS_ERR("offset value %llu is too big\n",
				  byte_off);
			return -ERANGE;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		err = fsi->devops->can_write_block(sb, PAGE_SIZE,
						   byte_off, true);
		if (err) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page can't be written: err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		}

		byte_off += PAGE_SIZE;
	}

	return 0;
}

/*
 * ssdfs_unaligned_read_folio_batch() - unaligned read from batch into buffer
 * @batch: folio batch with data
 * @offset: offset in bytes into folio batch
 * @size: buffer size in bytes
 * @buf: buffer for extracting data
 *
 * This function tries to read a portion of data from
 * folio batch into buffer.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-E2BIG      - request is out of folio batch's content.
 * %-ERANGE     - internal error.
 */
int ssdfs_unaligned_read_folio_batch(struct folio_batch *batch,
				     u32 offset, u32 size,
				     void *buf)
{
	struct folio *folio;
	u32 block_size;
	u32 folio_index;
	u32 bytes_offset;
	size_t read_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!batch || !buf);

	SSDFS_DBG("batch %p, offset %u, size %u, buf %p\n",
		  batch, offset, size, buf);
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio_batch_count(batch) == 0) {
		SSDFS_ERR("empty batch\n");
		return -EINVAL;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!batch->folios[0]);
#endif /* CONFIG_SSDFS_DEBUG */

	block_size = folio_size(batch->folios[0]);

	do {
		size_t iter_read_bytes;
		size_t cur_offset;

		bytes_offset = offset + read_bytes;
		folio_index = bytes_offset / block_size;
		cur_offset = bytes_offset % block_size;

		iter_read_bytes = min_t(size_t,
					(size_t)(size - read_bytes),
					(size_t)(block_size - cur_offset));

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio_index %u, cur_offset %zu, "
			  "iter_read_bytes %zu\n",
			  folio_index, cur_offset,
			  iter_read_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio_index >= folio_batch_count(batch)) {
			SSDFS_DBG("folio is out of range: index %u: "
				  "offset %zu, batch_count %u\n",
				  folio_index, cur_offset,
				  folio_batch_count(batch));
			return -E2BIG;
		}

		folio = batch->folios[folio_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(folio);
		err = __ssdfs_memcpy_from_folio(buf, read_bytes, size,
						folio, cur_offset, block_size,
						iter_read_bytes);
		ssdfs_folio_unlock(folio);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: "
				  "read_bytes %zu, offset %zu, "
				  "iter_read_bytes %zu, err %d\n",
				  read_bytes, cur_offset,
				  iter_read_bytes, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

		read_bytes += iter_read_bytes;
	} while (read_bytes < size);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("BUF DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     buf, size);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_unaligned_read_folio_vector() - unaligned read from folio vector
 * @fsi: pointer on shared file system object
 * @batch: folio vector with data
 * @offset: offset in bytes into folio batch
 * @size: buffer size in bytes
 * @buf: buffer for extracting data
 *
 * This function tries to read a portion of data from
 * folio vector into buffer.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-E2BIG      - request is out of folio vector's content.
 * %-ERANGE     - internal error.
 */
int ssdfs_unaligned_read_folio_vector(struct ssdfs_fs_info *fsi,
				      struct ssdfs_folio_vector *batch,
				      u32 offset, u32 size,
				      void *buf)
{
	struct ssdfs_smart_folio folio;
	u32 block_size;
	u32 bytes_off;
	size_t read_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!batch || !buf);

	SSDFS_DBG("batch %p, offset %u, size %u, buf %p\n",
		  batch, offset, size, buf);
#endif /* CONFIG_SSDFS_DEBUG */

	if (ssdfs_folio_vector_count(batch) == 0) {
		SSDFS_ERR("empty batch\n");
		return -EINVAL;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!batch->folios[0]);
#endif /* CONFIG_SSDFS_DEBUG */

	block_size = folio_size(batch->folios[0]);

	do {
		size_t iter_read_bytes;

		bytes_off = offset + read_bytes;

		err = SSDFS_OFF2FOLIO(block_size, bytes_off, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "bytes_off %u, err %d\n",
				  bytes_off, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		iter_read_bytes = min_t(size_t,
					(size_t)(size - read_bytes),
					(size_t)(PAGE_SIZE -
						 folio.desc.offset_inside_page));

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("bytes_off %u, read_bytes %zu, "
			  "iter_read_bytes %zu\n",
			  bytes_off, read_bytes,
			  iter_read_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio.desc.folio_index >= ssdfs_folio_vector_count(batch)) {
			SSDFS_ERR("invalid folio_index: "
				  "index %d, batch_size %u\n",
				  folio.desc.folio_index,
				  ssdfs_folio_vector_count(batch));
			return -E2BIG;
		}

		folio.ptr = batch->folios[folio.desc.folio_index];

		ssdfs_folio_lock(folio.ptr);
		err = ssdfs_memcpy_from_folio(buf, read_bytes, size,
					      &folio, iter_read_bytes);
		ssdfs_folio_unlock(folio.ptr);

		if (unlikely(err)) {
			SSDFS_ERR("bytes_off %u, read_bytes %zu, "
				  "iter_read_bytes %zu, err %d\n",
				  bytes_off, read_bytes,
				  iter_read_bytes, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  folio.ptr, folio_ref_count(folio.ptr));
#endif /* CONFIG_SSDFS_DEBUG */

		read_bytes += iter_read_bytes;
	} while (read_bytes < size);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("BUF DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     buf, size);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_unaligned_write_folio_batch() - unaligned write into folio batch
 * @fsi: pointer on shared file system object
 * @batch: folio batch
 * @offset: offset in bytes into folio batch
 * @size: size of data in bytes
 * @buf: buffer with data
 *
 * This function tries to write a portion of data from buffer
 * into folio batch.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-E2BIG      - request is out of folio batch's content.
 * %-ERANGE     - internal error.
 */
int ssdfs_unaligned_write_folio_batch(struct ssdfs_fs_info *fsi,
				      struct folio_batch *batch,
				      u32 offset, u32 size,
				      void *buf)
{
	struct ssdfs_smart_folio folio;
	u32 block_size;
	u32 bytes_off;
	size_t written_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !batch || !buf);

	SSDFS_DBG("batch %p, offset %u, size %u, buf %p\n",
		  batch, offset, size, buf);
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio_batch_count(batch) == 0) {
		SSDFS_ERR("empty batch\n");
		return -EINVAL;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!batch->folios[0]);
#endif /* CONFIG_SSDFS_DEBUG */

	block_size = folio_size(batch->folios[0]);

	do {
		size_t iter_write_bytes;

		bytes_off = offset + written_bytes;

		err = SSDFS_OFF2FOLIO(block_size, bytes_off, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "bytes_off %u, err %d\n",
				  bytes_off, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		iter_write_bytes = min_t(size_t,
					 (size_t)(size - written_bytes),
					 (size_t)(PAGE_SIZE -
					    folio.desc.offset_inside_page));

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("bytes_off %u, written_bytes %zu, "
			  "iter_write_bytes %zu\n",
			  bytes_off, written_bytes,
			  iter_write_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio.desc.folio_index >= folio_batch_count(batch)) {
			SSDFS_ERR("invalid folio_index: "
				  "index %d, batch_size %u\n",
				  folio.desc.folio_index,
				  folio_batch_count(batch));
			return -E2BIG;
		}

		folio.ptr = batch->folios[folio.desc.folio_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio.ptr);
		WARN_ON(!folio_test_locked(folio.ptr));
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_memcpy_to_folio(&folio,
					    buf, written_bytes, size,
					    iter_write_bytes);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: "
				  "written_bytes %zu, offset %u, "
				  "iter_write_bytes %zu, err %d\n",
				  written_bytes, bytes_off,
				  iter_write_bytes, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  folio.ptr, folio_ref_count(folio.ptr));
#endif /* CONFIG_SSDFS_DEBUG */

		written_bytes += iter_write_bytes;
	} while (written_bytes < size);

	return 0;
}

/*
 * ssdfs_unaligned_write_folio_vector() - unaligned write into folio vector
 * @fsi: pointer on shared file system object
 * @batch: folio vector
 * @offset: offset in bytes into folio batch
 * @size: size of data in bytes
 * @buf: buffer with data
 *
 * This function tries to write a portion of data from buffer
 * into folio vector.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-E2BIG      - request is out of folio vector's content.
 * %-ERANGE     - internal error.
 */
int ssdfs_unaligned_write_folio_vector(struct ssdfs_fs_info *fsi,
					struct ssdfs_folio_vector *batch,
					u32 offset, u32 size,
					void *buf)
{
	struct ssdfs_smart_folio folio;
	u32 block_size;
	u32 bytes_off;
	size_t written_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!batch || !buf);

	SSDFS_DBG("batch %p, offset %u, size %u, buf %p\n",
		  batch, offset, size, buf);
#endif /* CONFIG_SSDFS_DEBUG */

	if (ssdfs_folio_vector_count(batch) == 0) {
		SSDFS_ERR("empty batch\n");
		return -EINVAL;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!batch->folios[0]);
#endif /* CONFIG_SSDFS_DEBUG */

	block_size = folio_size(batch->folios[0]);

	do {
		size_t iter_write_bytes;

		bytes_off = offset + written_bytes;

		err = SSDFS_OFF2FOLIO(block_size, bytes_off, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "bytes_off %u, err %d\n",
				  bytes_off, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		iter_write_bytes = min_t(size_t,
					 (size_t)(size - written_bytes),
					 (size_t)(PAGE_SIZE -
					    folio.desc.offset_inside_page));

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("bytes_off %u, written_bytes %zu, "
			  "iter_write_bytes %zu\n",
			  bytes_off, written_bytes,
			  iter_write_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio.desc.folio_index >= ssdfs_folio_vector_count(batch)) {
			SSDFS_ERR("invalid folio_index: "
				  "index %d, batch_size %u\n",
				  folio.desc.folio_index,
				  ssdfs_folio_vector_count(batch));
			return -E2BIG;
		}

		folio.ptr = batch->folios[folio.desc.folio_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio.ptr);
		WARN_ON(!folio_test_locked(folio.ptr));
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_memcpy_to_folio(&folio,
					    buf, written_bytes, size,
					    iter_write_bytes);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: "
				  "written_bytes %zu, offset %u, "
				  "iter_write_bytes %zu, err %d\n",
				  written_bytes, bytes_off,
				  iter_write_bytes, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  folio.ptr, folio_ref_count(folio.ptr));
#endif /* CONFIG_SSDFS_DEBUG */

		written_bytes += iter_write_bytes;
	} while (written_bytes < size);

	return 0;
}
