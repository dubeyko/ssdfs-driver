// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dev_mtd.c - MTD device access code.
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
#include <linux/mtd/mtd.h>
#include <linux/mtd/super.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_dev_mtd_page_leaks;
atomic64_t ssdfs_dev_mtd_folio_leaks;
atomic64_t ssdfs_dev_mtd_memory_leaks;
atomic64_t ssdfs_dev_mtd_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_dev_mtd_cache_leaks_increment(void *kaddr)
 * void ssdfs_dev_mtd_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_dev_mtd_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_dev_mtd_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_dev_mtd_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_dev_mtd_kfree(void *kaddr)
 * struct page *ssdfs_dev_mtd_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_dev_mtd_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_dev_mtd_free_page(struct page *page)
 * void ssdfs_dev_mtd_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(dev_mtd)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(dev_mtd)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_dev_mtd_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_dev_mtd_page_leaks, 0);
	atomic64_set(&ssdfs_dev_mtd_folio_leaks, 0);
	atomic64_set(&ssdfs_dev_mtd_memory_leaks, 0);
	atomic64_set(&ssdfs_dev_mtd_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_dev_mtd_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_dev_mtd_page_leaks) != 0) {
		SSDFS_ERR("MTD DEV: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_dev_mtd_page_leaks));
	}

	if (atomic64_read(&ssdfs_dev_mtd_folio_leaks) != 0) {
		SSDFS_ERR("MTD DEV: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_dev_mtd_folio_leaks));
	}

	if (atomic64_read(&ssdfs_dev_mtd_memory_leaks) != 0) {
		SSDFS_ERR("MTD DEV: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_dev_mtd_memory_leaks));
	}

	if (atomic64_read(&ssdfs_dev_mtd_cache_leaks) != 0) {
		SSDFS_ERR("MTD DEV: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_dev_mtd_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * ssdfs_mtd_device_name() - get device name
 * @sb: superblock object
 */
static const char *ssdfs_mtd_device_name(struct super_block *sb)
{
	return sb->s_mtd->name;
}

/*
 * ssdfs_mtd_device_size() - get partition size in bytes
 * @sb: superblock object
 */
static __u64 ssdfs_mtd_device_size(struct super_block *sb)
{
	return SSDFS_FS_I(sb)->mtd->size;
}

static int ssdfs_mtd_open_zone(struct super_block *sb, loff_t offset)
{
	return -EOPNOTSUPP;
}

static int ssdfs_mtd_reopen_zone(struct super_block *sb, loff_t offset)
{
	return -EOPNOTSUPP;
}

static int ssdfs_mtd_close_zone(struct super_block *sb, loff_t offset)
{
	return -EOPNOTSUPP;
}

/*
 * ssdfs_mtd_read() - read from volume into buffer
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
static int ssdfs_mtd_read(struct super_block *sb, loff_t offset, size_t len,
			  void *buf)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	struct mtd_info *mtd = fsi->mtd;
	size_t retlen;
	int ret;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu, len %zu, buf %p\n",
		  sb, (unsigned long long)offset, len, buf);
#endif /* CONFIG_SSDFS_DEBUG */

	ret = mtd_read(mtd, offset, len, &retlen, buf);
	if (ret) {
		SSDFS_ERR("failed to read (err %d): offset %llu, len %zu\n",
			  ret, (unsigned long long)offset, len);
		return ret;
	}

	if (retlen != len) {
		SSDFS_ERR("retlen (%zu) != len (%zu)\n", retlen, len);
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_mtd_readpage() - read page from the volume
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
static int ssdfs_mtd_readpage(struct super_block *sb, struct page *page,
				loff_t offset)
{
	void *kaddr;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu, page %p, page_index %llu\n",
		  sb, (unsigned long long)offset, page,
		  (unsigned long long)page_index(page));
#endif /* CONFIG_SSDFS_DEBUG */

	kaddr = kmap_local_page(page);
	err = ssdfs_mtd_read(sb, offset, PAGE_SIZE, kaddr);
	flush_dcache_page(page);
	kunmap_local(kaddr);

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
 * ssdfs_mtd_readpages() - read pages from the volume
 * @sb: superblock object
 * @pvec: vector of memory pages
 * @offset: offset in bytes from partition's begin
 *
 * This function tries to read data on @offset
 * from partition's begin in memory pages.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO         - I/O error.
 */
static int ssdfs_mtd_readpages(struct super_block *sb, struct pagevec *pvec,
				loff_t offset)
{
	struct page *page;
	loff_t cur_offset = offset;
	u32 page_off;
	u32 read_bytes = 0;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu, pvec %p\n",
		  sb, (unsigned long long)offset, pvec);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pagevec_count(pvec) == 0) {
		SSDFS_WARN("empty page vector\n");
		return 0;
	}

	for (i = 0; i < pagevec_count(pvec); i++) {
		page = pvec->pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_mtd_readpage(sb, page, cur_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read page: "
				  "cur_offset %llu, err %d\n",
				  cur_offset, err);
			return err;
		}

		div_u64_rem(cur_offset, PAGE_SIZE, &page_off);
		read_bytes = PAGE_SIZE - page_off;
		cur_offset += read_bytes;
	}

	return 0;
}

/*
 * ssdfs_mtd_can_write_page() - check that page can be written
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
static int ssdfs_mtd_can_write_page(struct super_block *sb, loff_t offset,
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

	buf = ssdfs_dev_mtd_kzalloc(fsi->pagesize, GFP_KERNEL);
	if (!buf) {
		SSDFS_ERR("unable to allocate %d bytes\n", fsi->pagesize);
		return -ENOMEM;
	}

	err = ssdfs_mtd_read(sb, offset, fsi->pagesize, buf);
	if (err)
		goto free_buf;

	if (memchr_inv(buf, 0xff, fsi->pagesize)) {
		SSDFS_ERR("area with offset %llu contains unmatching char\n",
			  (unsigned long long)offset);
		err = -EIO;
	}

free_buf:
	ssdfs_dev_mtd_kfree(buf);
	return err;
}

/*
 * ssdfs_mtd_writepage() - write memory page on volume
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
static int ssdfs_mtd_writepage(struct super_block *sb, loff_t to_off,
				struct page *page, u32 from_off, size_t len)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	struct mtd_info *mtd = fsi->mtd;
	size_t retlen;
	unsigned char *kaddr;
	int ret;
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
	BUG_ON((to_off >= mtd->size) || (len > (mtd->size - to_off)));
	BUG_ON(len == 0);
	div_u64_rem((u64)to_off, (u64)fsi->pagesize, &remainder);
	BUG_ON(remainder);
	BUG_ON((from_off + len) > PAGE_SIZE);
	BUG_ON(!PageDirty(page));
	BUG_ON(PageLocked(page));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_lock_page(page);
	kaddr = kmap_local_page(page);
	ret = mtd_write(mtd, to_off, len, &retlen, kaddr + from_off);
	kunmap_local(kaddr);

	if (ret || (retlen != len)) {
		SetPageError(page);
		SSDFS_ERR("failed to write (err %d): offset %llu, "
			  "len %zu, retlen %zu\n",
			  ret, (unsigned long long)to_off, len, retlen);
		err = -EIO;
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

	return err;
}

/*
 * ssdfs_mtd_write_folio() - write memory folio on volume
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
static int ssdfs_mtd_write_folio(struct super_block *sb, loff_t offset,
				 struct folio *folio)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	struct mtd_info *mtd = fsi->mtd;
	size_t retlen;
	unsigned char *kaddr;
	int ret;
#ifdef CONFIG_SSDFS_DEBUG
	u32 remainder;
#endif /* CONFIG_SSDFS_DEBUG */
	u32 written_bytes = 0;
	int i = 0;
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
	BUG_ON((offset >= mtd->size) ||
		(folio_size(folio) > (mtd->size - to_off)));
	div_u64_rem((u64)offset, (u64)fsi->pagesize, &remainder);
	BUG_ON(remainder);
	BUG_ON(!folio_test_dirty(folio));
	BUG_ON(folio_test_locked(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_folio_lock(folio);

	while (written_bytes < folio_size(folio)) {
		kaddr = kmap_local_folio(folio, i);
		ret = mtd_write(mtd, offset + written_bytes, PAGE_SIZE,
				&retlen, kaddr);
		kunmap_local(kaddr);

		if (ret || (retlen != PAGE_SIZE)) {
			folio_set_error(folio);
			SSDFS_ERR("failed to write (err %d): offset %llu, "
				  "len %zu, retlen %zu\n",
				  ret, (unsigned long long)offset,
				  PAGE_SIZE, retlen);
			err = -EIO;
			break;
		}

		written_bytes += PAGE_SIZE;
		i++;
	}

	if (!err) {
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

	return err;
}

/*
 * ssdfs_mtd_writepages() - write memory pages on volume
 * @sb: superblock object
 * @to_off: offset in bytes from partition's begin
 * @pvec: vector of memory pages
 * @from_off: offset in bytes from page's begin
 * @len: size of data in bytes
 *
 * This function tries to write from @pvec data of @len size
 * on @offset from partition's begin in memory page.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EROFS       - file system in RO mode.
 * %-EIO         - I/O error.
 */
static int ssdfs_mtd_writepages(struct super_block *sb, loff_t to_off,
				struct pagevec *pvec, u32 from_off, size_t len)
{
	struct page *page;
	loff_t cur_to_off = to_off;
	u32 page_off = from_off;
	u32 written_bytes = 0;
	size_t write_len;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, to_off %llu, pvec %p, from_off %u, len %zu\n",
		  sb, to_off, pvec, from_off, len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (sb->s_flags & SB_RDONLY) {
		SSDFS_WARN("unable to write on RO file system\n");
		return -EROFS;
	}

	if (pagevec_count(pvec) == 0) {
		SSDFS_WARN("empty page vector\n");
		return 0;
	}

	for (i = 0; i < pagevec_count(pvec); i++) {
		page = pvec->pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		if (written_bytes >= len) {
			SSDFS_ERR("written_bytes %u >= len %zu\n",
				  written_bytes, len);
			return -ERANGE;
		}

		write_len = min_t(size_t, (size_t)(PAGE_SIZE - page_off),
					  (size_t)(len - written_bytes));

		err = ssdfs_mtd_writepage(sb, cur_to_off, page, page_off, write_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to write page: "
				  "cur_to_off %llu, page_off %u, "
				  "write_len %zu, err %d\n",
				  cur_to_off, page_off, write_len, err);
			return err;
		}

		div_u64_rem(cur_to_off, PAGE_SIZE, &page_off);
		written_bytes += write_len;
		cur_to_off += write_len;
	}

	return 0;
}

static void ssdfs_erase_callback(struct erase_info *ei)
{
	complete((struct completion *)ei->priv);
}

/*
 * ssdfs_mtd_erase() - make erase operation
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
static int ssdfs_mtd_erase(struct super_block *sb, loff_t offset, size_t len)
{
	struct mtd_info *mtd = SSDFS_FS_I(sb)->mtd;
	struct erase_info ei;
	DECLARE_COMPLETION_ONSTACK(complete);
	u32 remainder;
	int ret;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu, len %zu\n",
		  sb, (unsigned long long)offset, len);

	div_u64_rem((u64)len, (u64)mtd->erasesize, &remainder);
	BUG_ON(remainder);
	div_u64_rem((u64)offset, (u64)mtd->erasesize, &remainder);
	BUG_ON(remainder);
#endif /* CONFIG_SSDFS_DEBUG */

	if (sb->s_flags & SB_RDONLY)
		return -EROFS;

	div_u64_rem((u64)len, (u64)mtd->erasesize, &remainder);
	if (remainder) {
		SSDFS_WARN("len %llu, erase_size %u, remainder %u\n",
			   (unsigned long long)len,
			   mtd->erasesize, remainder);
		return -ERANGE;
	}

	memset(&ei, 0, sizeof(ei));
	ei.mtd = mtd;
	ei.addr = offset;
	ei.len = len;
	ei.callback = ssdfs_erase_callback;
	ei.priv = (long)&complete;

	ret = mtd_erase(mtd, &ei);
	if (ret) {
		SSDFS_ERR("failed to erase (err %d): offset %llu, len %zu\n",
			  ret, (unsigned long long)offset, len);
		return ret;
	}

	err = SSDFS_WAIT_COMPLETION(&complete);
	if (unlikely(err)) {
		SSDFS_ERR("timeout is out: "
			  "err %d\n", err);
		return err;
	}

	if (ei.state != MTD_ERASE_DONE) {
		SSDFS_ERR("ei.state %#x, offset %llu, len %zu\n",
			  ei.state, (unsigned long long)offset, len);
		return -EFAULT;
	}

	return 0;
}

/*
 * ssdfs_mtd_trim() - initiate background erase operation
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 * @len: size in bytes
 *
 * This function tries to initiate background erase operation.
 * Currently, it is the same operation as foreground erase.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EROFS       - file system in RO mode.
 * %-EFAULT      - erase operation error.
 */
static int ssdfs_mtd_trim(struct super_block *sb, loff_t offset, size_t len)
{
	return ssdfs_mtd_erase(sb, offset, len);
}

/*
 * ssdfs_mtd_peb_isbad() - check that PEB is bad
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 *
 * This function tries to detect that PEB is bad or not.
 */
static int ssdfs_mtd_peb_isbad(struct super_block *sb, loff_t offset)
{
	return mtd_block_isbad(SSDFS_FS_I(sb)->mtd, offset);
}

/*
 * ssdfs_mtd_mark_peb_bad() - mark PEB as bad
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 *
 * This function tries to mark PEB as bad.
 */
int ssdfs_mtd_mark_peb_bad(struct super_block *sb, loff_t offset)
{
	return mtd_block_markbad(SSDFS_FS_I(sb)->mtd, offset);
}

/*
 * ssdfs_mtd_sync() - make sync operation
 * @sb: superblock object
 */
static void ssdfs_mtd_sync(struct super_block *sb)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("device %d (\"%s\")\n",
		  fsi->mtd->index, fsi->mtd->name);
#endif /* CONFIG_SSDFS_DEBUG */

	mtd_sync(fsi->mtd);
}

const struct ssdfs_device_ops ssdfs_mtd_devops = {
	.device_name		= ssdfs_mtd_device_name,
	.device_size		= ssdfs_mtd_device_size,
	.open_zone		= ssdfs_mtd_open_zone,
	.reopen_zone		= ssdfs_mtd_reopen_zone,
	.close_zone		= ssdfs_mtd_close_zone,
	.read			= ssdfs_mtd_read,
	.readpage		= ssdfs_mtd_readpage,
	.readpages		= ssdfs_mtd_readpages,
	.can_write_page		= ssdfs_mtd_can_write_page,
	.writepage		= ssdfs_mtd_writepage,
	.write_folio		= ssdfs_mtd_write_folio,
	.writepages		= ssdfs_mtd_writepages,
	.erase			= ssdfs_mtd_erase,
	.trim			= ssdfs_mtd_trim,
	.peb_isbad		= ssdfs_mtd_peb_isbad,
	.mark_peb_bad		= ssdfs_mtd_mark_peb_bad,
	.sync			= ssdfs_mtd_sync,
};
