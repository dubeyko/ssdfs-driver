//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dev_mtd.c - MTD device access code.
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

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/super.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"

#include <trace/events/ssdfs.h>

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

	SSDFS_DBG("sb %p, offset %llu, len %zu, buf %p\n",
		  sb, (unsigned long long)offset, len, buf);

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

	SSDFS_DBG("sb %p, offset %llu, page %p, page_index %llu\n",
		  sb, (unsigned long long)offset, page,
		  (unsigned long long)page_index(page));

	kaddr = kmap(page);
	err = ssdfs_mtd_read(sb, offset, PAGE_SIZE, kaddr);
	kunmap(page);

	if (err) {
		ClearPageUptodate(page);
		SetPageError(page);
	} else {
		SetPageUptodate(page);
		ClearPageError(page);
		flush_dcache_page(page);
	}

	unlock_page(page);

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

	SSDFS_DBG("sb %p, offset %llu, pvec %p\n",
		  sb, (unsigned long long)offset, pvec);

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

	SSDFS_DBG("sb %p, offset %llu, need_check %d\n",
		  sb, (unsigned long long)offset, (int)need_check);

	if (!need_check)
		return 0;

	buf = kzalloc(fsi->pagesize, GFP_KERNEL);
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
	kfree(buf);
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

	SSDFS_DBG("sb %p, to_off %llu, page %p, from_off %u, len %zu\n",
		  sb, to_off, page, from_off, len);

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

	lock_page(page);
	kaddr = kmap(page);
	ret = mtd_write(mtd, to_off, len, &retlen, kaddr + from_off);
	kunmap(page);

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

	unlock_page(page);
	put_page(page);
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

	SSDFS_DBG("sb %p, to_off %llu, pvec %p, from_off %u, len %zu\n",
		  sb, to_off, pvec, from_off, len);

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
	unsigned long res;
	int ret;

	SSDFS_DBG("sb %p, offset %llu, len %zu\n",
		  sb, (unsigned long long)offset, len);

#ifdef CONFIG_SSDFS_DEBUG
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

	res = wait_for_completion_timeout(&complete,
					  SSDFS_DEFAULT_TIMEOUT);
	if (res == 0) {
		err = -ERANGE;
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

	SSDFS_DBG("device %d (\"%s\")\n",
		  fsi->mtd->index, fsi->mtd->name);

	mtd_sync(fsi->mtd);
}

const struct ssdfs_device_ops ssdfs_mtd_devops = {
	.device_name = ssdfs_mtd_device_name,
	.device_size = ssdfs_mtd_device_size,
	.read = ssdfs_mtd_read,
	.readpage = ssdfs_mtd_readpage,
	.readpages = ssdfs_mtd_readpages,
	.can_write_page = ssdfs_mtd_can_write_page,
	.writepage = ssdfs_mtd_writepage,
	.writepages = ssdfs_mtd_writepages,
	.erase = ssdfs_mtd_erase,
	.trim = ssdfs_mtd_trim,
	.peb_isbad = ssdfs_mtd_peb_isbad,
	.mark_peb_bad = ssdfs_mtd_mark_peb_bad,
	.sync = ssdfs_mtd_sync,
};
