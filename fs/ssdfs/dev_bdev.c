// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dev_bdev.c - Block device access code.
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

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "page_vector.h"
#include "folio_vector.h"
#include "ssdfs.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_dev_bdev_page_leaks;
atomic64_t ssdfs_dev_bdev_folio_leaks;
atomic64_t ssdfs_dev_bdev_memory_leaks;
atomic64_t ssdfs_dev_bdev_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_dev_bdev_cache_leaks_increment(void *kaddr)
 * void ssdfs_dev_bdev_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_dev_bdev_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_dev_bdev_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_dev_bdev_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_dev_bdev_kfree(void *kaddr)
 * struct page *ssdfs_dev_bdev_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_dev_bdev_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_dev_bdev_free_page(struct page *page)
 * void ssdfs_dev_bdev_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(dev_bdev)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(dev_bdev)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_dev_bdev_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_dev_bdev_page_leaks, 0);
	atomic64_set(&ssdfs_dev_bdev_folio_leaks, 0);
	atomic64_set(&ssdfs_dev_bdev_memory_leaks, 0);
	atomic64_set(&ssdfs_dev_bdev_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_dev_bdev_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_dev_bdev_page_leaks) != 0) {
		SSDFS_ERR("BLOCK DEV: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_dev_bdev_page_leaks));
	}

	if (atomic64_read(&ssdfs_dev_bdev_folio_leaks) != 0) {
		SSDFS_ERR("BLOCK DEV: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_dev_bdev_folio_leaks));
	}

	if (atomic64_read(&ssdfs_dev_bdev_memory_leaks) != 0) {
		SSDFS_ERR("BLOCK DEV: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_dev_bdev_memory_leaks));
	}

	if (atomic64_read(&ssdfs_dev_bdev_cache_leaks) != 0) {
		SSDFS_ERR("BLOCK DEV: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_dev_bdev_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static DECLARE_WAIT_QUEUE_HEAD(wq);

/*
 * ssdfs_bdev_device_name() - get device name
 * @sb: superblock object
 */
static const char *ssdfs_bdev_device_name(struct super_block *sb)
{
	return sb->s_id;
}

/*
 * ssdfs_bdev_device_size() - get partition size in bytes
 * @sb: superblock object
 */
static __u64 ssdfs_bdev_device_size(struct super_block *sb)
{
	return i_size_read(sb->s_bdev->bd_inode);
}

static int ssdfs_bdev_open_zone(struct super_block *sb, loff_t offset)
{
	return -EOPNOTSUPP;
}

static int ssdfs_bdev_reopen_zone(struct super_block *sb, loff_t offset)
{
	return -EOPNOTSUPP;
}

static int ssdfs_bdev_close_zone(struct super_block *sb, loff_t offset)
{
	return -EOPNOTSUPP;
}

/*
 * ssdfs_bdev_bio_alloc() - allocate bio object
 * @bdev: block device
 * @nr_iovecs: number of items in biovec
 * @op: direction of I/O
 * @gfp_mask: mask of creation flags
 */
struct bio *ssdfs_bdev_bio_alloc(struct block_device *bdev,
				 unsigned int nr_iovecs,
				 unsigned int op,
				 gfp_t gfp_mask)
{
	struct bio *bio;

	bio = bio_alloc(bdev, nr_iovecs, op, gfp_mask);
	if (!bio) {
		SSDFS_ERR("fail to allocate bio\n");
		return ERR_PTR(-ENOMEM);
	}

	return bio;
}

/*
 * ssdfs_bdev_bio_put() - free bio object
 */
void ssdfs_bdev_bio_put(struct bio *bio)
{
	if (!bio)
		return;

	bio_put(bio);
}

/*
 * ssdfs_bdev_bio_add_page() - add page into bio
 * @bio: pointer on bio object
 * @page: memory page
 * @len: size of data into memory page
 * @offset: vec entry offset
 */
int ssdfs_bdev_bio_add_page(struct bio *bio, struct page *page,
			    unsigned int len, unsigned int offset)
{
	int res;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bio || !page);

	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	res = bio_add_page(bio, page, len, offset);
	if (res != len) {
		SSDFS_ERR("res %d != len %u\n",
			  res, len);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_bdev_bio_add_folio() - add folio into bio
 * @bio: pointer on bio object
 * @folio: memory folio
 * @offset: vec entry offset
 */
int ssdfs_bdev_bio_add_folio(struct bio *bio, struct folio *folio,
			     unsigned int offset)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bio || !folio);

	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	if (!bio_add_folio(bio, folio, folio_size(folio), offset)) {
		SSDFS_ERR("fail to add folio: "
			  "offset %u, size %zu\n",
			  offset, folio_size(folio));
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_bdev_sync_page_request() - submit page request
 * @sb: superblock object
 * @page: memory page
 * @offset: offset in bytes from partition's begin
 * @op: direction of I/O
 * @op_flags: request op flags
 */
static int ssdfs_bdev_sync_page_request(struct super_block *sb,
					struct page *page,
					loff_t offset,
					unsigned int op, int op_flags)
{
	struct bio *bio;
	pgoff_t index = (pgoff_t)(offset >> PAGE_SHIFT);
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

	bio = ssdfs_bdev_bio_alloc(sb->s_bdev, 1, op, GFP_NOIO);
	if (IS_ERR_OR_NULL(bio)) {
		err = !bio ? -ERANGE : PTR_ERR(bio);
		SSDFS_ERR("fail to allocate bio: err %d\n",
			  err);
		return err;
	}

	bio->bi_iter.bi_sector = index * (PAGE_SIZE >> 9);
	bio_set_dev(bio, sb->s_bdev);
	bio->bi_opf = op | op_flags;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_bdev_bio_add_page(bio, page, PAGE_SIZE, 0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add page into bio: "
			  "err %d\n",
			  err);
		goto finish_sync_page_request;
	}

	err = submit_bio_wait(bio);
	if (unlikely(err)) {
		SSDFS_ERR("fail to process request: "
			  "err %d\n",
			  err);
		goto finish_sync_page_request;
	}

finish_sync_page_request:
	ssdfs_bdev_bio_put(bio);

	return err;
}

/*
 * ssdfs_bdev_sync_folio_request() - submit folio request
 * @sb: superblock object
 * @folio: memory folio
 * @offset: offset in bytes from partition's begin
 * @op: direction of I/O
 * @op_flags: request op flags
 */
static int ssdfs_bdev_sync_folio_request(struct super_block *sb,
					 struct folio *folio,
					 loff_t offset,
					 unsigned int op, int op_flags)
{
	struct bio *bio;
	sector_t sector = (pgoff_t)(offset >> SECTOR_SHIFT);
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	bio = ssdfs_bdev_bio_alloc(sb->s_bdev, 1, op, GFP_NOIO);
	if (IS_ERR_OR_NULL(bio)) {
		err = !bio ? -ERANGE : PTR_ERR(bio);
		SSDFS_ERR("fail to allocate bio: err %d\n",
			  err);
		return err;
	}

	bio->bi_iter.bi_sector = sector;
	bio_set_dev(bio, sb->s_bdev);
	bio->bi_opf = op | op_flags;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_bdev_bio_add_folio(bio, folio, 0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add folio into bio: "
			  "err %d\n",
			  err);
		goto finish_sync_folio_request;
	}

	err = submit_bio_wait(bio);
	if (unlikely(err)) {
		SSDFS_ERR("fail to process request: "
			  "err %d\n",
			  err);
		goto finish_sync_folio_request;
	}

finish_sync_folio_request:
	ssdfs_bdev_bio_put(bio);

	return err;
}

/*
 * ssdfs_bdev_sync_pvec_request() - submit pagevec request
 * @sb: superblock object
 * @pvec: pagevec
 * @offset: offset in bytes from partition's begin
 * @op: direction of I/O
 * @op_flags: request op flags
 */
static int ssdfs_bdev_sync_pvec_request(struct super_block *sb,
					struct pagevec *pvec,
					loff_t offset,
					unsigned int op, int op_flags)
{
	struct bio *bio;
	pgoff_t index = (pgoff_t)(offset >> PAGE_SHIFT);
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec);

	SSDFS_DBG("offset %llu, op %#x, op_flags %#x\n",
		  offset, op, op_flags);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pagevec_count(pvec) == 0) {
		SSDFS_WARN("empty page vector\n");
		return 0;
	}

	bio = ssdfs_bdev_bio_alloc(sb->s_bdev, pagevec_count(pvec),
				   op, GFP_NOIO);
	if (IS_ERR_OR_NULL(bio)) {
		err = !bio ? -ERANGE : PTR_ERR(bio);
		SSDFS_ERR("fail to allocate bio: err %d\n",
			  err);
		return err;
	}

	bio->bi_iter.bi_sector = index * (PAGE_SIZE >> 9);
	bio_set_dev(bio, sb->s_bdev);
	bio->bi_opf = op | op_flags;

	for (i = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);

		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_bdev_bio_add_page(bio, page,
					      PAGE_SIZE,
					      0);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add page %d into bio: "
				  "err %d\n",
				  i, err);
			goto finish_sync_pvec_request;
		}
	}

	err = submit_bio_wait(bio);
	if (unlikely(err)) {
		SSDFS_ERR("fail to process request: "
			  "err %d\n",
			  err);
		goto finish_sync_pvec_request;
	}

finish_sync_pvec_request:
	ssdfs_bdev_bio_put(bio);

	return err;
}

/*
 * ssdfs_bdev_readpage() - read page from the volume
 * @sb: superblock object
 * @page: memory page
 * @offset: offset in bytes from partition's begin
 *
 * This function tries to read data on @offset
 * from partition's begin in memory page.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO         - I/O error.
 */
int ssdfs_bdev_readpage(struct super_block *sb, struct page *page,
			loff_t offset)
{
	int err;

	err = ssdfs_bdev_sync_page_request(sb, page, offset,
					   REQ_OP_READ, REQ_SYNC);
	if (err) {
		ClearPageUptodate(page);
		ssdfs_clear_page_private(page, 0);
		SetPageError(page);
	} else {
		SetPageUptodate(page);
		ClearPageError(page);
		flush_dcache_page(page);
	}

	ssdfs_unlock_page(page);

	return err;
}

/*
 * ssdfs_bdev_readpages() - read pages from the volume
 * @sb: superblock object
 * @pvec: pagevec
 * @offset: offset in bytes from partition's begin
 *
 * This function tries to read data on @offset
 * from partition's begin in memory page.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO         - I/O error.
 */
int ssdfs_bdev_readpages(struct super_block *sb, struct pagevec *pvec,
			 loff_t offset)
{
	int i;
	int err = 0;

	err = ssdfs_bdev_sync_pvec_request(sb, pvec, offset,
					   REQ_OP_READ, REQ_RAHEAD);

	for (i = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		if (err) {
			ClearPageUptodate(page);
			ssdfs_clear_page_private(page, 0);
			SetPageError(page);
		} else {
			SetPageUptodate(page);
			ClearPageError(page);
			flush_dcache_page(page);
		}

		ssdfs_unlock_page(page);
	}

	return err;
}

/*
 * ssdfs_bdev_read_pvec() - read from volume into buffer
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 * @len: size of buffer in bytes
 * @buf: buffer
 * @read_bytes: pointer on read bytes [out]
 *
 * This function tries to read data on @offset
 * from partition's begin with @len bytes in size
 * from the volume into @buf.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO         - I/O error.
 */
static int ssdfs_bdev_read_pvec(struct super_block *sb,
				loff_t offset, size_t len,
				void *buf, size_t *read_bytes)
{
	struct pagevec pvec;
	struct page *page;
	loff_t page_start, page_end;
	u32 pages_count;
	u32 read_len;
	loff_t cur_offset = offset;
	u32 page_off;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu, len %zu, buf %p\n",
		  sb, (unsigned long long)offset, len, buf);
#endif /* CONFIG_SSDFS_DEBUG */

	*read_bytes = 0;

	page_start = offset >> PAGE_SHIFT;
	page_end = (offset + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	pages_count = (u32)(page_end - page_start);

	if (pages_count > PAGEVEC_SIZE) {
		SSDFS_ERR("pages_count %u > pvec_capacity %u\n",
			  pages_count, PAGEVEC_SIZE);
		return -ERANGE;
	}

	pagevec_init(&pvec);

	for (i = 0; i < pages_count; i++) {
		page = ssdfs_dev_bdev_alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (IS_ERR_OR_NULL(page)) {
			err = (page == NULL ? -ENOMEM : PTR_ERR(page));
			SSDFS_ERR("unable to allocate memory page\n");
			goto finish_bdev_read_pvec;
		}

		ssdfs_get_page(page);
		ssdfs_lock_page(page);
		pagevec_add(&pvec, page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
	}

	err = ssdfs_bdev_sync_pvec_request(sb, &pvec, offset,
					   REQ_OP_READ, REQ_SYNC);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read pagevec: err %d\n",
			  err);
		goto finish_bdev_read_pvec;
	}

	for (i = 0; i < pagevec_count(&pvec); i++) {
		page = pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		if (*read_bytes >= len) {
			err = -ERANGE;
			SSDFS_ERR("read_bytes %zu >= len %zu\n",
				  *read_bytes, len);
			goto finish_bdev_read_pvec;
		}

		div_u64_rem(cur_offset, PAGE_SIZE, &page_off);
		read_len = min_t(size_t, (size_t)(PAGE_SIZE - page_off),
					  (size_t)(len - *read_bytes));

		err = ssdfs_memcpy_from_page(buf, *read_bytes, len,
					     page, page_off, PAGE_SIZE,
					     read_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: err %d\n", err);
			goto finish_bdev_read_pvec;
		}

		*read_bytes += read_len;
		cur_offset += read_len;
	}

finish_bdev_read_pvec:
	for (i = pagevec_count(&pvec) - 1; i >= 0; i--) {
		page = pvec.pages[i];

		if (page) {
			ssdfs_unlock_page(page);
			ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_dev_bdev_free_page(page);
			pvec.pages[i] = NULL;
		}
	}

	pagevec_reinit(&pvec);

	if (*read_bytes != len) {
		err = -EIO;
		SSDFS_ERR("read_bytes (%zu) != len (%zu)\n",
			  *read_bytes, len);
	}

	return err;
}

/*
 * ssdfs_bdev_read() - read from volume into buffer
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 * @len: size of buffer in bytes
 * @buf: buffer
 *
 * This function tries to read data on @offset
 * from partition's begin with @len bytes in size
 * from the volume into @buf.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO         - I/O error.
 */
int ssdfs_bdev_read(struct super_block *sb, loff_t offset,
		    size_t len, void *buf)
{
	size_t read_bytes = 0;
	loff_t cur_offset = offset;
	u8 *ptr = (u8 *)buf;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu, len %zu, buf %p\n",
		  sb, (unsigned long long)offset, len, buf);
#endif /* CONFIG_SSDFS_DEBUG */

	if (len == 0) {
		SSDFS_WARN("len is zero\n");
		return 0;
	}

	while (read_bytes < len) {
		size_t iter_read;

		err = ssdfs_bdev_read_pvec(sb, cur_offset,
					   len - read_bytes,
					   ptr,
					   &iter_read);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read pvec: "
				  "cur_offset %llu, read_bytes %zu, "
				  "err %d\n",
				  cur_offset, read_bytes, err);
			return err;
		}

		cur_offset += iter_read;
		ptr += iter_read;
		read_bytes += iter_read;
	}

	return 0;
}

/*
 * ssdfs_bdev_can_write_page() - check that page can be written
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 * @need_check: make check or not?
 *
 * This function checks that page can be written.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EROFS       - file system in RO mode.
 * %-ENOMEM      - fail to allocate memory.
 * %-EIO         - I/O error.
 */
int ssdfs_bdev_can_write_page(struct super_block *sb, loff_t offset,
			      bool need_check)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	void *buf;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu, need_check %d\n",
		  sb, (unsigned long long)offset, (int)need_check);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!need_check)
		return 0;

	buf = ssdfs_dev_bdev_kzalloc(fsi->pagesize, GFP_KERNEL);
	if (!buf) {
		SSDFS_ERR("unable to allocate %d bytes\n", fsi->pagesize);
		return -ENOMEM;
	}

	err = ssdfs_bdev_read(sb, offset, fsi->pagesize, buf);
	if (err)
		goto free_buf;

	if (memchr_inv(buf, 0xff, fsi->pagesize)) {
		if (memchr_inv(buf, 0x00, fsi->pagesize)) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("area with offset %llu contains data\n",
				  (unsigned long long)offset);

			SSDFS_DBG("PAGE DUMP:\n");
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     buf,
					     PAGE_SIZE);
			SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */
			err = -EIO;
		}
	}

free_buf:
	ssdfs_dev_bdev_kfree(buf);
	return err;
}

/*
 * ssdfs_bdev_writepage() - write memory page on volume
 * @sb: superblock object
 * @to_off: offset in bytes from partition's begin
 * @page: memory page
 * @from_off: offset in bytes from page's begin
 * @len: size of data in bytes
 *
 * This function tries to write from @page data of @len size
 * on @offset from partition's begin in memory page.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EROFS       - file system in RO mode.
 * %-EIO         - I/O error.
 */
int ssdfs_bdev_writepage(struct super_block *sb, loff_t to_off,
			 struct page *page, u32 from_off, size_t len)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
#ifdef CONFIG_SSDFS_DEBUG
	u32 remainder;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, to_off %llu, page %p, from_off %u, len %zu\n",
		  sb, to_off, page, from_off, len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (sb->s_flags & SB_RDONLY) {
		SSDFS_WARN("unable to write on RO file system\n");
		return -EROFS;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page);
	BUG_ON((to_off >= ssdfs_bdev_device_size(sb)) ||
		(len > (ssdfs_bdev_device_size(sb) - to_off)));
	BUG_ON(len == 0);
	div_u64_rem((u64)to_off, (u64)fsi->pagesize, &remainder);
	BUG_ON(remainder);
	BUG_ON((from_off + len) > PAGE_SIZE);
	BUG_ON(!PageDirty(page));
	BUG_ON(PageLocked(page));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_lock_page(page);
	atomic_inc(&fsi->pending_bios);

	err = ssdfs_bdev_sync_page_request(sb, page, to_off,
					   REQ_OP_WRITE, REQ_SYNC);
	if (err) {
		SetPageError(page);
		SSDFS_ERR("failed to write (err %d): offset %llu\n",
			  err, (unsigned long long)to_off);
	} else {
		ssdfs_clear_dirty_page(page);
		SetPageUptodate(page);
		ClearPageError(page);
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	if (atomic_dec_and_test(&fsi->pending_bios))
		wake_up_all(&wq);

	return err;
}

/*
 * ssdfs_bdev_write_folio() - write memory folio on volume
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 * @folio: memory folio
 *
 * This function tries to write from @folio data
 * on @offset from partition's begin.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EROFS       - file system in RO mode.
 * %-EIO         - I/O error.
 */
int ssdfs_bdev_write_folio(struct super_block *sb, loff_t offset,
			   struct folio *folio)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
#ifdef CONFIG_SSDFS_DEBUG
	u32 remainder;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu, folio %p\n",
		  sb, offset, folio);
#endif /* CONFIG_SSDFS_DEBUG */

	if (sb->s_flags & SB_RDONLY) {
		SSDFS_WARN("unable to write on RO file system\n");
		return -EROFS;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
	BUG_ON((offset >= ssdfs_bdev_device_size(sb)) ||
		(folio_size(folio) > (ssdfs_bdev_device_size(sb) - offset)));
	div_u64_rem((u64)offset, (u64)fsi->pagesize, &remainder);
	BUG_ON(remainder);
	BUG_ON(!folio_test_dirty(folio));
	BUG_ON(folio_test_locked(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_folio_lock(folio);
	atomic_inc(&fsi->pending_bios);

	err = ssdfs_bdev_sync_folio_request(sb, folio, offset,
					    REQ_OP_WRITE, REQ_SYNC);
	if (err) {
		folio_set_error(folio);
		SSDFS_ERR("failed to write (err %d): offset %llu\n",
			  err, (unsigned long long)offset);
	} else {
		ssdfs_clear_dirty_folio(folio);
		folio_mark_uptodate(folio);
		folio_clear_error(folio);
	}

	ssdfs_folio_unlock(folio);
	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	if (atomic_dec_and_test(&fsi->pending_bios))
		wake_up_all(&wq);

	return err;
}

/*
 * ssdfs_bdev_writepages() - write pagevec on volume
 * @sb: superblock object
 * @to_off: offset in bytes from partition's begin
 * @pvec: memory pages vector
 * @from_off: offset in bytes from page's begin
 * @len: size of data in bytes
 *
 * This function tries to write from @pvec data of @len size
 * on @offset from partition's begin.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EROFS       - file system in RO mode.
 * %-EIO         - I/O error.
 */
int ssdfs_bdev_writepages(struct super_block *sb, loff_t to_off,
			  struct pagevec *pvec,
			  u32 from_off, size_t len)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	struct page *page;
	int i;
#ifdef CONFIG_SSDFS_DEBUG
	u32 remainder;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, to_off %llu, pvec %p, from_off %u, len %zu\n",
		  sb, to_off, pvec, from_off, len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (sb->s_flags & SB_RDONLY) {
		SSDFS_WARN("unable to write on RO file system\n");
		return -EROFS;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec);
	BUG_ON((to_off >= ssdfs_bdev_device_size(sb)) ||
		(len > (ssdfs_bdev_device_size(sb) - to_off)));
	BUG_ON(len == 0);
	div_u64_rem((u64)to_off, (u64)fsi->pagesize, &remainder);
	BUG_ON(remainder);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pagevec_count(pvec) == 0) {
		SSDFS_WARN("empty pagevec\n");
		return 0;
	}

	for (i = 0; i < pagevec_count(pvec); i++) {
		page = pvec->pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
		BUG_ON(!PageDirty(page));
		BUG_ON(PageLocked(page));
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_lock_page(page);
	}

	atomic_inc(&fsi->pending_bios);

	err = ssdfs_bdev_sync_pvec_request(sb, pvec, to_off,
					   REQ_OP_WRITE, REQ_SYNC);

	for (i = 0; i < pagevec_count(pvec); i++) {
		page = pvec->pages[i];

		if (err) {
			SetPageError(page);
			SSDFS_ERR("failed to write (err %d): "
				  "page_index %llu\n",
				  err,
				  (unsigned long long)page_index(page));
		} else {
			ssdfs_clear_dirty_page(page);
			SetPageUptodate(page);
			ClearPageError(page);
		}

		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
	}

	if (atomic_dec_and_test(&fsi->pending_bios))
		wake_up_all(&wq);

	return err;
}

/*
 * ssdfs_bdev_support_discard() - check that block device supports discard
 */
static inline bool ssdfs_bdev_support_discard(struct block_device *bdev)
{
	return bdev_max_discard_sectors(bdev) ||
		bdev_is_zoned(bdev);
}

/*
 * ssdfs_bdev_trim() - initiate background erase operation
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 * @len: size in bytes
 *
 * This function tries to initiate background erase operation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EROFS       - file system in RO mode.
 * %-EFAULT      - erase operation error.
 */
static int ssdfs_bdev_trim(struct super_block *sb, loff_t offset, size_t len)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	u32 erase_size = fsi->erasesize;
	loff_t page_start, page_end;
	u32 pages_count;
	u32 remainder;
	sector_t start_sector;
	sector_t sectors_count;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu, len %zu\n",
		  sb, (unsigned long long)offset, len);

	div_u64_rem((u64)len, (u64)erase_size, &remainder);
	BUG_ON(remainder);
	div_u64_rem((u64)offset, (u64)erase_size, &remainder);
	BUG_ON(remainder);
#endif /* CONFIG_SSDFS_DEBUG */

	if (sb->s_flags & SB_RDONLY)
		return -EROFS;

	div_u64_rem((u64)len, (u64)erase_size, &remainder);
	if (remainder) {
		SSDFS_WARN("len %llu, erase_size %u, remainder %u\n",
			   (unsigned long long)len,
			   erase_size, remainder);
		return -ERANGE;
	}

	page_start = offset >> PAGE_SHIFT;
	page_end = (offset + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	pages_count = (u32)(page_end - page_start);

	if (pages_count == 0) {
		SSDFS_WARN("pages_count equals to zero\n");
		return -ERANGE;
	}

	start_sector = page_start << (PAGE_SHIFT - SSDFS_SECTOR_SHIFT);
	sectors_count = pages_count << (PAGE_SHIFT - SSDFS_SECTOR_SHIFT);

	if (ssdfs_bdev_support_discard(sb->s_bdev)) {
		err = blkdev_issue_secure_erase(sb->s_bdev,
						start_sector, sectors_count,
						GFP_NOFS);
		if (err)
			goto try_zeroout;
	} else {
try_zeroout:
		err = blkdev_issue_zeroout(sb->s_bdev,
					   start_sector, sectors_count,
					   GFP_NOFS, 0);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to discard: "
			  "start_sector %llu, sectors_count %llu, "
			  "err %d\n",
			  start_sector, sectors_count, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_bdev_erase() - make erase operation
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 * @len: size in bytes
 *
 * This function tries to make erase operation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EROFS       - file system in RO mode.
 * %-EFAULT      - erase operation error.
 */
static int ssdfs_bdev_erase(struct super_block *sb, loff_t offset, size_t len)
{
	return ssdfs_bdev_trim(sb, offset, len);
}

/*
 * ssdfs_bdev_peb_isbad() - check that PEB is bad
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 *
 * This function tries to detect that PEB is bad or not.
 */
static int ssdfs_bdev_peb_isbad(struct super_block *sb, loff_t offset)
{
	/* do nothing */
	return 0;
}

/*
 * ssdfs_bdev_mark_peb_bad() - mark PEB as bad
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 *
 * This function tries to mark PEB as bad.
 */
int ssdfs_bdev_mark_peb_bad(struct super_block *sb, loff_t offset)
{
	/* do nothing */
	return 0;
}

/*
 * ssdfs_bdev_sync() - make sync operation
 * @sb: superblock object
 */
static void ssdfs_bdev_sync(struct super_block *sb)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("device %s\n", sb->s_id);
#endif /* CONFIG_SSDFS_DEBUG */

	wait_event(wq, atomic_read(&fsi->pending_bios) == 0);
}

const struct ssdfs_device_ops ssdfs_bdev_devops = {
	.device_name		= ssdfs_bdev_device_name,
	.device_size		= ssdfs_bdev_device_size,
	.open_zone		= ssdfs_bdev_open_zone,
	.reopen_zone		= ssdfs_bdev_reopen_zone,
	.close_zone		= ssdfs_bdev_close_zone,
	.read			= ssdfs_bdev_read,
	.readpage		= ssdfs_bdev_readpage,
	.readpages		= ssdfs_bdev_readpages,
	.can_write_page		= ssdfs_bdev_can_write_page,
	.writepage		= ssdfs_bdev_writepage,
	.write_folio		= ssdfs_bdev_write_folio,
	.writepages		= ssdfs_bdev_writepages,
	.erase			= ssdfs_bdev_erase,
	.trim			= ssdfs_bdev_trim,
	.peb_isbad		= ssdfs_bdev_peb_isbad,
	.mark_peb_bad		= ssdfs_bdev_mark_peb_bad,
	.sync			= ssdfs_bdev_sync,
};
