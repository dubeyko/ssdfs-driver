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
 * struct folio *ssdfs_dev_mtd_alloc_folio(gfp_t gfp_mask,
 *                                         unsigned int order)
 * struct folio *ssdfs_dev_mtd_add_batch_folio(struct folio_batch *batch,
 *                                             unsigned int order)
 * void ssdfs_dev_mtd_free_folio(struct folio *folio)
 * void ssdfs_dev_mtd_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(dev_mtd)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(dev_mtd)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_dev_mtd_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_dev_mtd_folio_leaks, 0);
	atomic64_set(&ssdfs_dev_mtd_memory_leaks, 0);
	atomic64_set(&ssdfs_dev_mtd_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_dev_mtd_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
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
 * @block_size: block size in bytes
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
static int ssdfs_mtd_read(struct super_block *sb, u32 block_size,
			  loff_t offset, size_t len, void *buf)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	struct mtd_info *mtd = fsi->mtd;
	loff_t folio_index;
	size_t retlen;
	int ret;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, block_size %u, offset %llu, len %zu, buf %p\n",
		  sb, block_size, (unsigned long long)offset, len, buf);
#endif /* CONFIG_SSDFS_DEBUG */

	folio_index = div_u64(offset, block_size);
	offset = folio_index * block_size;

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
 * ssdfs_mtd_read_block() - read block from the volume
 * @sb: superblock object
 * @folio: memory folio
 * @offset: offset in bytes from partition's begin
 *
 * This function tries to read data on @offset
 * from partition's begin in memory folio.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO         - I/O error.
 */
static int ssdfs_mtd_read_block(struct super_block *sb, struct folio *folio,
				loff_t offset)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	void *kaddr;
	u32 processed_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu, folio %p, folio_index %llu\n",
		  sb, (unsigned long long)offset, folio,
		  (unsigned long long)folio_index(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	while (processed_bytes < folio_size(folio)) {
		kaddr = kmap_local_folio(folio, processed_bytes);
		err = ssdfs_mtd_read(sb, offset + processed_bytes,
				     PAGE_SIZE, kaddr);
		kunmap_local(kaddr);

		if (err) {
			folio_clear_uptodate(folio);
			ssdfs_clear_folio_private(folio, 0);
			folio_set_error(folio);
			break;
		}

		processed_bytes += PAGE_SIZE;
	};

	if (!err) {
		folio_mark_uptodate(folio);
		folio_clear_error(folio);
		flush_dcache_folio(folio);
	}

	ssdfs_folio_unlock(folio);

	return err;
}

/*
 * ssdfs_mtd_read_blocks() - read logical blocks from the volume
 * @sb: superblock object
 * @batch: memory folios batch
 * @offset: offset in bytes from partition's begin
 *
 * This function tries to read data on @offset
 * from partition's begin in memory folios.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO         - I/O error.
 */
static int ssdfs_mtd_read_blocks(struct super_block *sb,
				 struct folio_batch *batch,
				 loff_t offset)
{
	struct folio *folio;
	loff_t cur_offset = offset;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu, batch %p\n",
		  sb, (unsigned long long)offset, batch);
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio_batch_count(batch) == 0) {
		SSDFS_WARN("empty folio batch\n");
		return 0;
	}

	for (i = 0; i < folio_batch_count(batch); i++) {
		folio = batch->folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_mtd_read_block(sb, folio, cur_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read block: "
				  "cur_offset %llu, err %d\n",
				  cur_offset, err);
			return err;
		}

		cur_offset += folio_size(folio);
	}

	return 0;
}

/*
 * ssdfs_mtd_can_write_block() - check that logical block can be written
 * @sb: superblock object
 * @block_size: block size in bytes
 * @offset: offset in bytes from partition's begin
 * @need_check: make check or not?
 *
 * This function checks that logical block can be written.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EROFS       - file system in RO mode.
 * %-ENOMEM      - fail to allocate memory.
 * %-EIO         - I/O error.
 */
static int ssdfs_mtd_can_write_block(struct super_block *sb, u32 block_size,
				     loff_t offset, bool need_check)
{
	void *buf;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu, block_size %u, need_check %d\n",
		  sb, (unsigned long long)offset,
		  block_size, (int)need_check);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!need_check)
		return 0;

	buf = ssdfs_dev_mtd_kzalloc(block_size, GFP_KERNEL);
	if (!buf) {
		SSDFS_ERR("unable to allocate %d bytes\n", block_size);
		return -ENOMEM;
	}

	err = ssdfs_mtd_read(sb, block_size, offset, block_size, buf);
	if (err)
		goto free_buf;

	if (memchr_inv(buf, 0xff, block_size)) {
		SSDFS_ERR("area with offset %llu contains unmatching char\n",
			  (unsigned long long)offset);
		err = -EIO;
	}

free_buf:
	ssdfs_dev_mtd_kfree(buf);
	return err;
}

/*
 * ssdfs_mtd_write_block() - write logical block to volume
 * @sb: superblock object
 * @offset: offset in bytes from partition's beginning
 * @folio: memory folio
 *
 * This function tries to write from @folio data
 * on @offset from partition's beginning.
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
	div_u64_rem((u64)offset, (u64)folio_size(folio), &remainder);
	BUG_ON(remainder);
	BUG_ON(!folio_test_dirty(folio));
	BUG_ON(folio_test_locked(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_folio_lock(folio);

	while (written_bytes < folio_size(folio)) {
		kaddr = kmap_local_folio(folio, written_bytes);
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
 * ssdfs_mtd_write_blocks() - write logical blocks to volume
 * @sb: superblock object
 * @offset: offset in bytes from partition's beginning
 * @batch: memory folios batch
 *
 * This function tries to write from @batch data
 * to @offset from partition's beginning.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EROFS       - file system in RO mode.
 * %-EIO         - I/O error.
 */
static int ssdfs_mtd_write_blocks(struct super_block *sb, loff_t offset,
				  struct folio_batch *batch)
{
	struct folio *folio;
	loff_t cur_offset = offset;
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

	if (folio_batch_count(batch) == 0) {
		SSDFS_WARN("empty folio batch\n");
		return 0;
	}

	for (i = 0; i < folio_batch_count(batch); i++) {
		folio = batch->folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_mtd_write_block(sb, cur_offset, folio);
		if (unlikely(err)) {
			SSDFS_ERR("fail to write block: "
				  "cur_offset %llu, err %d\n",
				  cur_offset, err);
			return err;
		}

		cur_offset += folio_size(folio);
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
	.read_block		= ssdfs_mtd_read_block,
	.read_blocks		= ssdfs_mtd_read_blocks,
	.can_write_block	= ssdfs_mtd_can_write_block,
	.write_block		= ssdfs_mtd_write_block,
	.write_blocks		= ssdfs_mtd_write_blocks,
	.erase			= ssdfs_mtd_erase,
	.trim			= ssdfs_mtd_trim,
	.peb_isbad		= ssdfs_mtd_peb_isbad,
	.mark_peb_bad		= ssdfs_mtd_mark_peb_bad,
	.sync			= ssdfs_mtd_sync,
};
