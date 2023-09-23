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
#include "page_vector.h"
#include "folio_vector.h"
#include "ssdfs.h"

#include <trace/events/ssdfs.h>

/*
 * ssdfs_read_page_from_volume() - read page from volume
 * @fsi: pointer on shared file system object
 * @peb_id: PEB identification number
 * @bytes_off: offset from PEB's begining in bytes
 * @page: memory page
 *
 * This function tries to read page from the volume.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EIO        - I/O error.
 */
int ssdfs_read_page_from_volume(struct ssdfs_fs_info *fsi,
				u64 peb_id, u32 bytes_off,
				struct page *page)
{
	struct super_block *sb;
	loff_t offset;
	u32 peb_size;
	u32 pagesize;
	u32 pages_per_peb;
	u32 pages_off;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !page);
	BUG_ON(!fsi->devops->readpage);

	SSDFS_DBG("fsi %p, peb_id %llu, bytes_off %u, page %p\n",
		  fsi, peb_id, bytes_off, page);
#endif /* CONFIG_SSDFS_DEBUG */

	sb = fsi->sb;
	pagesize = fsi->pagesize;
	pages_per_peb = fsi->pages_per_peb;
	pages_off = bytes_off / pagesize;

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

	if (pages_off >= pages_per_peb) {
		SSDFS_ERR("pages_off %u >= pages_per_peb %u\n",
			  pages_off, pages_per_peb);
		return -EINVAL;
	}

	if (pages_off >= (U32_MAX / pagesize)) {
		SSDFS_ERR("pages_off %u >= U32_MAX / pagesize %u\n",
			  pages_off, fsi->pagesize);
		return -EINVAL;
	}

	offset += bytes_off;

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

	err = fsi->devops->readpage(sb, page, offset);
	if (unlikely(err)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fail to read page: offset %llu, err %d\n",
			  (unsigned long long)offset, err);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_read_pagevec_from_volume() - read pagevec from volume
 * @fsi: pointer on shared file system object
 * @peb_id: PEB identification number
 * @bytes_off: offset from PEB's begining in bytes
 * @pvec: pagevec [in|out]
 *
 * This function tries to read pages from the volume.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EIO        - I/O error.
 */
int ssdfs_read_pagevec_from_volume(struct ssdfs_fs_info *fsi,
				   u64 peb_id, u32 bytes_off,
				   struct pagevec *pvec)
{
	struct super_block *sb;
	loff_t offset;
	u32 peb_size;
	u32 pagesize;
	u32 pages_per_peb;
	u32 pages_off;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pvec);
	BUG_ON(!fsi->devops->readpages);

	SSDFS_DBG("fsi %p, peb_id %llu, bytes_off %u, pvec %p\n",
		  fsi, peb_id, bytes_off, pvec);
#endif /* CONFIG_SSDFS_DEBUG */

	sb = fsi->sb;
	pagesize = fsi->pagesize;
	pages_per_peb = fsi->pages_per_peb;
	pages_off = bytes_off / pagesize;

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

	if (pages_off >= pages_per_peb) {
		SSDFS_ERR("pages_off %u >= pages_per_peb %u\n",
			  pages_off, pages_per_peb);
		return -EINVAL;
	}

	if (pages_off >= (U32_MAX / pagesize)) {
		SSDFS_ERR("pages_off %u >= U32_MAX / pagesize %u\n",
			  pages_off, fsi->pagesize);
		return -EINVAL;
	}

	offset += bytes_off;

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

	err = fsi->devops->readpages(sb, pvec, offset);
	if (unlikely(err)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fail to read pvec: offset %llu, err %d\n",
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
			      u64 peb_id, u32 bytes_off,
			      void *buf, size_t size,
			      size_t *read_bytes)
{
	struct super_block *sb;
	loff_t offset;
	u32 peb_size;
	u32 pagesize;
	u32 pages_per_peb;
	u32 pages_off;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !buf);
	BUG_ON(!fsi->devops->read);

	SSDFS_DBG("fsi %p, peb_id %llu, bytes_off %u, buf %p, size %zu\n",
		  fsi, peb_id, bytes_off, buf, size);
#endif /* CONFIG_SSDFS_DEBUG */

	sb = fsi->sb;
	pagesize = fsi->pagesize;
	pages_per_peb = fsi->pages_per_peb;
	pages_off = bytes_off / pagesize;

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

	if (pages_off >= pages_per_peb) {
		SSDFS_ERR("pages_off %u >= pages_per_peb %u\n",
			  pages_off, pages_per_peb);
		return -EINVAL;
	}

	if (pages_off >= (U32_MAX / pagesize)) {
		SSDFS_ERR("pages_off %u >= U32_MAX / pagesize %u\n",
			  pages_off, fsi->pagesize);
		return -EINVAL;
	}

	if (size > pagesize) {
		SSDFS_ERR("size %zu > pagesize %u\n",
			  size, fsi->pagesize);
		return -EINVAL;
	}

	offset += bytes_off;

	*read_bytes = ((pages_off + 1) * pagesize) - bytes_off;
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

	err = fsi->devops->read(sb, offset, *read_bytes, buf);
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
				u64 peb_id, u32 bytes_off,
				void *buf, size_t size)
{
	size_t read_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !buf);
	BUG_ON(!fsi->devops->read);

	SSDFS_DBG("fsi %p, peb_id %llu, bytes_off %u, buf %p, size %zu\n",
		  fsi, peb_id, bytes_off, buf, size);
#endif /* CONFIG_SSDFS_DEBUG */

	do {
		size_t iter_size = size - read_bytes;
		size_t iter_read_bytes;

		err = ssdfs_aligned_read_buffer(fsi, peb_id,
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

	if (!fsi->devops->can_write_page)
		return 0;

	cur_peb = sb_log->peb_id;
	page_offset = sb_log->page_offset;
	log_size = sb_log->pages_count;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("cur_peb %llu, page_offset %u, "
		  "log_size %u, pages_per_peb %u\n",
		  cur_peb, page_offset,
		  log_size, fsi->pages_per_peb);

	if (log_size > fsi->pages_per_seg) {
		SSDFS_ERR("log_size value %u is too big\n",
			  log_size);
		return -ERANGE;
	}

	if (cur_peb > div_u64(ULLONG_MAX, fsi->pages_per_seg)) {
		SSDFS_ERR("cur_peb value %llu is too big\n",
			  cur_peb);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	byte_off = cur_peb * fsi->pages_per_peb;

#ifdef CONFIG_SSDFS_DEBUG
	if (byte_off > div_u64(ULLONG_MAX, fsi->pagesize)) {
		SSDFS_ERR("byte_off value %llu is too big\n",
			  byte_off);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	byte_off *= fsi->pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	if ((u64)page_offset > div_u64(ULLONG_MAX, fsi->pagesize)) {
		SSDFS_ERR("page_offset value %u is too big\n",
			  page_offset);
		return -ERANGE;
	}

	if (byte_off > (ULLONG_MAX - ((u64)page_offset * fsi->pagesize))) {
		SSDFS_ERR("byte_off value %llu is too big\n",
			  byte_off);
			return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	byte_off += (u64)page_offset * fsi->pagesize;

	for (i = 0; i < log_size; i++) {
#ifdef CONFIG_SSDFS_DEBUG
		if (byte_off > (ULLONG_MAX - (i * fsi->pagesize))) {
			SSDFS_ERR("offset value %llu is too big\n",
				  byte_off);
			return -ERANGE;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		err = fsi->devops->can_write_page(sb, byte_off, true);
		if (err) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page can't be written: err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		}

		byte_off += fsi->pagesize;
	}

	return 0;
}

int ssdfs_unaligned_read_pagevec(struct pagevec *pvec,
				 u32 offset, u32 size,
				 void *buf)
{
	struct page *page;
	u32 page_off;
	u32 bytes_off;
	size_t read_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec || !buf);

	SSDFS_DBG("pvec %p, offset %u, size %u, buf %p\n",
		  pvec, offset, size, buf);
#endif /* CONFIG_SSDFS_DEBUG */

	do {
		size_t iter_read_bytes;
		size_t cur_off;

		bytes_off = offset + read_bytes;
		page_off = bytes_off / PAGE_SIZE;
		cur_off = bytes_off % PAGE_SIZE;

		iter_read_bytes = min_t(size_t,
					(size_t)(size - read_bytes),
					(size_t)(PAGE_SIZE - cur_off));

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page_off %u, cur_off %zu, "
			  "iter_read_bytes %zu\n",
			  page_off, cur_off,
			  iter_read_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

		if (page_off >= pagevec_count(pvec)) {
			SSDFS_DBG("page out of range: index %u: "
				  "offset %zu, pagevec_count %u\n",
				  page_off, cur_off,
				  pagevec_count(pvec));
			return -E2BIG;
		}

		page = pvec->pages[page_off];

		ssdfs_lock_page(page);
		err = ssdfs_memcpy_from_page(buf, read_bytes, size,
					     page, cur_off, PAGE_SIZE,
					     iter_read_bytes);
		ssdfs_unlock_page(page);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: "
				  "read_bytes %zu, offset %zu, "
				  "iter_read_bytes %zu, err %d\n",
				  read_bytes, cur_off,
				  iter_read_bytes, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
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

int ssdfs_unaligned_read_page_vector(struct ssdfs_page_vector *pvec,
				     u32 offset, u32 size,
				     void *buf)
{
	struct page *page;
	u32 page_off;
	u32 bytes_off;
	size_t read_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec || !buf);

	SSDFS_DBG("pvec %p, offset %u, size %u, buf %p\n",
		  pvec, offset, size, buf);
#endif /* CONFIG_SSDFS_DEBUG */

	do {
		size_t iter_read_bytes;
		size_t cur_off;

		bytes_off = offset + read_bytes;
		page_off = bytes_off / PAGE_SIZE;
		cur_off = bytes_off % PAGE_SIZE;

		iter_read_bytes = min_t(size_t,
					(size_t)(size - read_bytes),
					(size_t)(PAGE_SIZE - cur_off));

		SSDFS_DBG("page_off %u, cur_off %zu, "
			  "iter_read_bytes %zu\n",
			  page_off, cur_off,
			  iter_read_bytes);

		if (page_off >= ssdfs_page_vector_count(pvec)) {
			SSDFS_DBG("page out of range: index %u: "
				  "offset %zu, pagevec_count %u\n",
				  page_off, cur_off,
				  ssdfs_page_vector_count(pvec));
			return -E2BIG;
		}

		page = pvec->pages[page_off];

		ssdfs_lock_page(page);
		err = ssdfs_memcpy_from_page(buf, read_bytes, size,
					     page, cur_off, PAGE_SIZE,
					     iter_read_bytes);
		ssdfs_unlock_page(page);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: "
				  "read_bytes %zu, offset %zu, "
				  "iter_read_bytes %zu, err %d\n",
				  read_bytes, cur_off,
				  iter_read_bytes, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
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

int ssdfs_unaligned_read_folio_vector(struct ssdfs_fs_info *fsi,
				      struct ssdfs_folio_vector *batch,
				      u32 offset, u32 size,
				      void *buf)
{
	struct ssdfs_smart_folio folio;
	u32 bytes_off;
	size_t read_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!batch || !buf);

	SSDFS_DBG("batch %p, offset %u, size %u, buf %p\n",
		  batch, offset, size, buf);
#endif /* CONFIG_SSDFS_DEBUG */

	do {
		size_t iter_read_bytes;

		bytes_off = offset + read_bytes;

		err = SSDFS_OFF2FOLIO(fsi->pagesize, bytes_off, &folio.desc);
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

int ssdfs_unaligned_write_pagevec(struct pagevec *pvec,
				  u32 offset, u32 size,
				  void *buf)
{
	struct page *page;
	u32 page_off;
	u32 bytes_off;
	size_t written_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec || !buf);

	SSDFS_DBG("pvec %p, offset %u, size %u, buf %p\n",
		  pvec, offset, size, buf);
#endif /* CONFIG_SSDFS_DEBUG */

	do {
		size_t iter_write_bytes;
		size_t cur_off;

		bytes_off = offset + written_bytes;
		page_off = bytes_off / PAGE_SIZE;
		cur_off = bytes_off % PAGE_SIZE;

		iter_write_bytes = min_t(size_t,
					(size_t)(size - written_bytes),
					(size_t)(PAGE_SIZE - cur_off));

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("bytes_off %u, page_off %u, "
			  "cur_off %zu, written_bytes %zu, "
			  "iter_write_bytes %zu\n",
			  bytes_off, page_off, cur_off,
			  written_bytes, iter_write_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

		if (page_off >= pagevec_count(pvec)) {
			SSDFS_ERR("invalid page index %u: "
				  "offset %zu, pagevec_count %u\n",
				  page_off, cur_off,
				  pagevec_count(pvec));
			return -EINVAL;
		}

		page = pvec->pages[page_off];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
		WARN_ON(!PageLocked(page));
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_memcpy_to_page(page, cur_off, PAGE_SIZE,
					   buf, written_bytes, size,
					   iter_write_bytes);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: "
				  "written_bytes %zu, offset %zu, "
				  "iter_write_bytes %zu, err %d\n",
				  written_bytes, cur_off,
				  iter_write_bytes, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

		written_bytes += iter_write_bytes;
	} while (written_bytes < size);

	return 0;
}

int ssdfs_unaligned_write_folio_batch(struct ssdfs_fs_info *fsi,
				      struct folio_batch *batch,
				      u32 offset, u32 size,
				      void *buf)
{
	struct ssdfs_smart_folio folio;
	u32 bytes_off;
	size_t written_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !batch || !buf);

	SSDFS_DBG("batch %p, offset %u, size %u, buf %p\n",
		  batch, offset, size, buf);
#endif /* CONFIG_SSDFS_DEBUG */

	do {
		size_t iter_write_bytes;

		bytes_off = offset + written_bytes;

		err = SSDFS_OFF2FOLIO(fsi->pagesize, bytes_off, &folio.desc);
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

int ssdfs_unaligned_write_page_vector(struct ssdfs_page_vector *pvec,
					u32 offset, u32 size,
					void *buf)
{
	struct page *page;
	u32 page_off;
	u32 bytes_off;
	size_t written_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec || !buf);

	SSDFS_DBG("pvec %p, offset %u, size %u, buf %p\n",
		  pvec, offset, size, buf);
#endif /* CONFIG_SSDFS_DEBUG */

	do {
		size_t iter_write_bytes;
		size_t cur_off;

		bytes_off = offset + written_bytes;
		page_off = bytes_off / PAGE_SIZE;
		cur_off = bytes_off % PAGE_SIZE;

		iter_write_bytes = min_t(size_t,
					(size_t)(size - written_bytes),
					(size_t)(PAGE_SIZE - cur_off));

		SSDFS_DBG("bytes_off %u, page_off %u, "
			  "cur_off %zu, written_bytes %zu, "
			  "iter_write_bytes %zu\n",
			  bytes_off, page_off, cur_off,
			  written_bytes, iter_write_bytes);

		if (page_off >= ssdfs_page_vector_count(pvec)) {
			SSDFS_ERR("invalid page index %u: "
				  "offset %zu, pagevec_count %u\n",
				  page_off, cur_off,
				  ssdfs_page_vector_count(pvec));
			return -EINVAL;
		}

		page = pvec->pages[page_off];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
		WARN_ON(!PageLocked(page));
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_memcpy_to_page(page, cur_off, PAGE_SIZE,
					   buf, written_bytes, size,
					   iter_write_bytes);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: "
				  "written_bytes %zu, offset %zu, "
				  "iter_write_bytes %zu, err %d\n",
				  written_bytes, cur_off,
				  iter_write_bytes, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

		written_bytes += iter_write_bytes;
	} while (written_bytes < size);

	return 0;
}
