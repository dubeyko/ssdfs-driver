//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/readwrite.c - read/write primitive operations.
 *
 * Copyright (c) 2014-2020 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2020, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
 */

#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, peb_id %llu, bytes_off %u, page %p\n",
		  fsi, peb_id, bytes_off, page);

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
			SSDFS_DBG("offset %llu is in bad PEB: err %d\n",
				  (unsigned long long)offset, err);
			return -EIO;
		}
	}

	err = fsi->devops->readpage(sb, page, offset);
	if (unlikely(err)) {
		SSDFS_DBG("fail to read page: offset %llu, err %d\n",
			  (unsigned long long)offset, err);
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, peb_id %llu, bytes_off %u, buf %p, size %zu\n",
		  fsi, peb_id, bytes_off, buf, size);

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
			SSDFS_DBG("offset %llu is in bad PEB: err %d\n",
				  (unsigned long long)offset, err);
			return -EIO;
		}
	}

	err = fsi->devops->read(sb, offset, *read_bytes, buf);
	if (unlikely(err)) {
		SSDFS_DBG("fail to read from offset %llu, size %zu, err %d\n",
			  (unsigned long long)offset, *read_bytes, err);
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, peb_id %llu, bytes_off %u, buf %p, size %zu\n",
		  fsi, peb_id, bytes_off, buf, size);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("leb_id %llu, peb_id %llu, "
		  "page_offset %u, pages_count %u\n",
		  sb_log->leb_id, sb_log->peb_id,
		  sb_log->page_offset, sb_log->pages_count);

	fsi = SSDFS_FS_I(sb);

	if (!fsi->devops->can_write_page)
		return 0;

	cur_peb = sb_log->peb_id;
	page_offset = sb_log->page_offset;
	log_size = sb_log->pages_count;

#ifdef CONFIG_SSDFS_DEBUG
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
			SSDFS_DBG("page can't be written: err %d\n", err);
			return err;
		}

		byte_off += fsi->pagesize;
	}

	return 0;
}
