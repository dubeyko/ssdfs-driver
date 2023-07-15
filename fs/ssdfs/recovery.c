// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/recovery.c - searching actual state and recovery on mount code.
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

#include <linux/slab.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "page_vector.h"
#include "ssdfs.h"
#include "page_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "segment_bitmap.h"
#include "peb_mapping_table.h"
#include "recovery.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_recovery_page_leaks;
atomic64_t ssdfs_recovery_folio_leaks;
atomic64_t ssdfs_recovery_memory_leaks;
atomic64_t ssdfs_recovery_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_recovery_cache_leaks_increment(void *kaddr)
 * void ssdfs_recovery_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_recovery_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_recovery_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_recovery_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_recovery_kfree(void *kaddr)
 * struct page *ssdfs_recovery_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_recovery_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_recovery_free_page(struct page *page)
 * void ssdfs_recovery_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(recovery)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(recovery)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_recovery_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_recovery_page_leaks, 0);
	atomic64_set(&ssdfs_recovery_folio_leaks, 0);
	atomic64_set(&ssdfs_recovery_memory_leaks, 0);
	atomic64_set(&ssdfs_recovery_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_recovery_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_recovery_page_leaks) != 0) {
		SSDFS_ERR("RECOVERY: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_recovery_page_leaks));
	}

	if (atomic64_read(&ssdfs_recovery_folio_leaks) != 0) {
		SSDFS_ERR("RECOVERY: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_recovery_folio_leaks));
	}

	if (atomic64_read(&ssdfs_recovery_memory_leaks) != 0) {
		SSDFS_ERR("RECOVERY: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_recovery_memory_leaks));
	}

	if (atomic64_read(&ssdfs_recovery_cache_leaks) != 0) {
		SSDFS_ERR("RECOVERY: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_recovery_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

int ssdfs_init_sb_info(struct ssdfs_fs_info *fsi,
			struct ssdfs_sb_info *sbi)
{
	void *vh_buf = NULL;
	void *vs_buf = NULL;
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	size_t footer_size = sizeof(struct ssdfs_log_footer);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sbi %p, hdr_size %zu, footer_size %zu\n",
		  sbi, hdr_size, footer_size);

	BUG_ON(!sbi);
#endif /* CONFIG_SSDFS_DEBUG */

	sbi->vh_buf = NULL;
	sbi->vs_buf = NULL;

	hdr_size = max_t(size_t, hdr_size, (size_t)SSDFS_4KB);
	sbi->vh_buf_size = hdr_size;
	footer_size = max_t(size_t, footer_size, (size_t)SSDFS_4KB);
	sbi->vs_buf_size = footer_size;

	vh_buf = ssdfs_recovery_kzalloc(sbi->vh_buf_size, GFP_KERNEL);
	vs_buf = ssdfs_recovery_kzalloc(sbi->vs_buf_size, GFP_KERNEL);
	if (unlikely(!vh_buf || !vs_buf)) {
		SSDFS_ERR("unable to allocate superblock buffers\n");
		err = -ENOMEM;
		goto free_buf;
	}

	sbi->vh_buf = vh_buf;
	sbi->vs_buf = vs_buf;

	return 0;

free_buf:
	ssdfs_recovery_kfree(vh_buf);
	ssdfs_recovery_kfree(vs_buf);
	return err;
}

void ssdfs_destruct_sb_info(struct ssdfs_sb_info *sbi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sbi);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!sbi->vh_buf || !sbi->vs_buf)
		return;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sbi %p, sbi->vh_buf %p, sbi->vs_buf %p, "
		  "sbi->last_log.leb_id %llu, sbi->last_log.peb_id %llu, "
		  "sbi->last_log.page_offset %u, "
		  "sbi->last_log.pages_count %u\n",
		  sbi, sbi->vh_buf, sbi->vs_buf, sbi->last_log.leb_id,
		  sbi->last_log.peb_id, sbi->last_log.page_offset,
		  sbi->last_log.pages_count);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_recovery_kfree(sbi->vh_buf);
	ssdfs_recovery_kfree(sbi->vs_buf);
	sbi->vh_buf = NULL;
	sbi->vh_buf_size = 0;
	sbi->vs_buf = NULL;
	sbi->vs_buf_size = 0;
	memset(&sbi->last_log, 0, sizeof(struct ssdfs_peb_extent));
}

void ssdfs_backup_sb_info(struct ssdfs_fs_info *fsi)
{
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	size_t footer_size = sizeof(struct ssdfs_log_footer);
	size_t extent_size = sizeof(struct ssdfs_peb_extent);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!fsi->sbi.vh_buf || !fsi->sbi.vs_buf);
	BUG_ON(!fsi->sbi_backup.vh_buf || !fsi->sbi_backup.vs_buf);

	SSDFS_DBG("last_log: leb_id %llu, peb_id %llu, "
		  "page_offset %u, pages_count %u, "
		  "volume state: free_pages %llu, timestamp %#llx, "
		  "cno %#llx, fs_state %#x\n",
		  fsi->sbi.last_log.leb_id,
		  fsi->sbi.last_log.peb_id,
		  fsi->sbi.last_log.page_offset,
		  fsi->sbi.last_log.pages_count,
		  le64_to_cpu(SSDFS_VS(fsi->sbi.vs_buf)->free_pages),
		  le64_to_cpu(SSDFS_VS(fsi->sbi.vs_buf)->timestamp),
		  le64_to_cpu(SSDFS_VS(fsi->sbi.vs_buf)->cno),
		  le16_to_cpu(SSDFS_VS(fsi->sbi.vs_buf)->state));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_memcpy(fsi->sbi_backup.vh_buf, 0, hdr_size,
		     fsi->sbi.vh_buf, 0, hdr_size,
		     hdr_size);
	ssdfs_memcpy(fsi->sbi_backup.vs_buf, 0, footer_size,
		     fsi->sbi.vs_buf, 0, footer_size,
		     footer_size);
	ssdfs_memcpy(&fsi->sbi_backup.last_log, 0, extent_size,
		     &fsi->sbi.last_log, 0, extent_size,
		     extent_size);
}

void ssdfs_copy_sb_info(struct ssdfs_fs_info *fsi,
			struct ssdfs_recovery_env *env)
{
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	size_t vhdr_size = sizeof(struct ssdfs_volume_header);
	size_t footer_size = sizeof(struct ssdfs_log_footer);
	size_t extent_size = sizeof(struct ssdfs_peb_extent);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!fsi->sbi.vh_buf || !fsi->sbi.vs_buf);
	BUG_ON(!fsi->sbi_backup.vh_buf || !fsi->sbi_backup.vs_buf);
	BUG_ON(!env);
	BUG_ON(!env->sbi.vh_buf || !env->sbi.vs_buf);
	BUG_ON(!env->sbi_backup.vh_buf || !env->sbi_backup.vs_buf);

	SSDFS_DBG("last_log: leb_id %llu, peb_id %llu, "
		  "page_offset %u, pages_count %u, "
		  "volume state: free_pages %llu, timestamp %#llx, "
		  "cno %#llx, fs_state %#x\n",
		  env->sbi.last_log.leb_id,
		  env->sbi.last_log.peb_id,
		  env->sbi.last_log.page_offset,
		  env->sbi.last_log.pages_count,
		  le64_to_cpu(SSDFS_VS(env->sbi.vs_buf)->free_pages),
		  le64_to_cpu(SSDFS_VS(env->sbi.vs_buf)->timestamp),
		  le64_to_cpu(SSDFS_VS(env->sbi.vs_buf)->cno),
		  le16_to_cpu(SSDFS_VS(env->sbi.vs_buf)->state));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_memcpy(fsi->sbi.vh_buf, 0, hdr_size,
		     env->sbi.vh_buf, 0, hdr_size,
		     hdr_size);
	ssdfs_memcpy(fsi->sbi.vs_buf, 0, footer_size,
		     env->sbi.vs_buf, 0, footer_size,
		     footer_size);
	ssdfs_memcpy(&fsi->sbi.last_log, 0, extent_size,
		     &env->sbi.last_log, 0, extent_size,
		     extent_size);
	ssdfs_memcpy(fsi->sbi_backup.vh_buf, 0, hdr_size,
		     env->sbi_backup.vh_buf, 0, hdr_size,
		     hdr_size);
	ssdfs_memcpy(fsi->sbi_backup.vs_buf, 0, footer_size,
		     env->sbi_backup.vs_buf, 0, footer_size,
		     footer_size);
	ssdfs_memcpy(&fsi->sbi_backup.last_log, 0, extent_size,
		     &env->sbi_backup.last_log, 0, extent_size,
		     extent_size);
	ssdfs_memcpy(&fsi->last_vh, 0, vhdr_size,
		     &env->last_vh, 0, vhdr_size,
		     vhdr_size);
}

void ssdfs_restore_sb_info(struct ssdfs_fs_info *fsi)
{
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	size_t footer_size = sizeof(struct ssdfs_log_footer);
	size_t extent_size = sizeof(struct ssdfs_peb_extent);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!fsi->sbi.vh_buf || !fsi->sbi.vs_buf);
	BUG_ON(!fsi->sbi_backup.vh_buf || !fsi->sbi_backup.vs_buf);

	SSDFS_DBG("last_log: leb_id %llu, peb_id %llu, "
		  "page_offset %u, pages_count %u, "
		  "volume state: free_pages %llu, timestamp %#llx, "
		  "cno %#llx, fs_state %#x\n",
		  fsi->sbi.last_log.leb_id,
		  fsi->sbi.last_log.peb_id,
		  fsi->sbi.last_log.page_offset,
		  fsi->sbi.last_log.pages_count,
		  le64_to_cpu(SSDFS_VS(fsi->sbi.vs_buf)->free_pages),
		  le64_to_cpu(SSDFS_VS(fsi->sbi.vs_buf)->timestamp),
		  le64_to_cpu(SSDFS_VS(fsi->sbi.vs_buf)->cno),
		  le16_to_cpu(SSDFS_VS(fsi->sbi.vs_buf)->state));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_memcpy(fsi->sbi.vh_buf, 0, hdr_size,
		     fsi->sbi_backup.vh_buf, 0, hdr_size,
		     hdr_size);
	ssdfs_memcpy(fsi->sbi.vs_buf, 0, footer_size,
		     fsi->sbi_backup.vs_buf, 0, footer_size,
		     footer_size);
	ssdfs_memcpy(&fsi->sbi.last_log, 0, extent_size,
		     &fsi->sbi_backup.last_log, 0, extent_size,
		     extent_size);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("last_log: leb_id %llu, peb_id %llu, "
		  "page_offset %u, pages_count %u, "
		  "volume state: free_pages %llu, timestamp %#llx, "
		  "cno %#llx, fs_state %#x\n",
		  fsi->sbi.last_log.leb_id,
		  fsi->sbi.last_log.peb_id,
		  fsi->sbi.last_log.page_offset,
		  fsi->sbi.last_log.pages_count,
		  le64_to_cpu(SSDFS_VS(fsi->sbi.vs_buf)->free_pages),
		  le64_to_cpu(SSDFS_VS(fsi->sbi.vs_buf)->timestamp),
		  le64_to_cpu(SSDFS_VS(fsi->sbi.vs_buf)->cno),
		  le16_to_cpu(SSDFS_VS(fsi->sbi.vs_buf)->state));
#endif /* CONFIG_SSDFS_DEBUG */
}

static int find_seg_with_valid_start_peb(struct ssdfs_fs_info *fsi,
					 size_t seg_size,
					 loff_t *offset,
					 u64 threshold,
					 int silent,
					 int op_type)
{
	struct super_block *sb = fsi->sb;
	loff_t off;
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	struct ssdfs_volume_header *vh;
	bool magic_valid = false;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("fsi %p, seg_size %zu, start_offset %llu, "
		  "threshold %llu, silent %#x, op_type %#x\n",
		  fsi, seg_size, (unsigned long long)*offset,
		  threshold, silent, op_type);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (op_type) {
	case SSDFS_USE_PEB_ISBAD_OP:
		if (!fsi->devops->peb_isbad) {
			SSDFS_ERR("unable to detect bad PEB\n");
			return -EOPNOTSUPP;
		}
		break;

	case SSDFS_USE_READ_OP:
		if (!fsi->devops->read) {
			SSDFS_ERR("unable to read from device\n");
			return -EOPNOTSUPP;
		}
		break;

	default:
		BUG();
	};

	if (*offset != SSDFS_RESERVED_VBR_SIZE)
		off = (*offset / seg_size) * seg_size;
	else
		off = *offset;

	while (off < threshold) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("off %llu\n", (u64)off);
#endif /* CONFIG_SSDFS_DEBUG */

		switch (op_type) {
		case SSDFS_USE_PEB_ISBAD_OP:
			err = fsi->devops->peb_isbad(sb, off);
			magic_valid = true;
			break;

		case SSDFS_USE_READ_OP:
			err = fsi->devops->read(sb, off, hdr_size,
						fsi->sbi.vh_buf);
			vh = SSDFS_VH(fsi->sbi.vh_buf);
			magic_valid = is_ssdfs_magic_valid(&vh->magic);
			break;

		default:
			BUG();
		};

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("HEADER DUMP: magic_valid %#x, err %d\n",
			  magic_valid, err);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     fsi->sbi.vh_buf, hdr_size);
		SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

		if (!err) {
			if (magic_valid) {
				*offset = off;
				return 0;
			}
		} else if (!silent) {
			SSDFS_NOTICE("offset %llu is in bad PEB\n",
					(unsigned long long)off);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("offset %llu is in bad PEB\n",
				  (unsigned long long)off);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		off += 2 * seg_size;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("unable to find valid PEB\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return -ENODATA;
}

static int ssdfs_find_any_valid_volume_header(struct ssdfs_fs_info *fsi,
						loff_t offset,
						int silent)
{
	struct super_block *sb;
	size_t seg_size = SSDFS_128KB;
	loff_t start_offset = offset;
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	u64 dev_size;
	u64 threshold;
	struct ssdfs_volume_header *vh;
	bool magic_valid, crc_valid;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!fsi->sbi.vh_buf);
	BUG_ON(!fsi->devops->read);

	SSDFS_DBG("fsi %p, fsi->sbi.vh_buf %p, silent %#x\n",
		  fsi, fsi->sbi.vh_buf, silent);
#endif /* CONFIG_SSDFS_DEBUG */

	sb = fsi->sb;
	dev_size = fsi->devops->device_size(sb);

try_seg_size:
	threshold = SSDFS_MAPTBL_PROTECTION_STEP;
	threshold *= SSDFS_MAPTBL_PROTECTION_RANGE;
	threshold *= seg_size;
	threshold = min_t(u64, dev_size, threshold + offset);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("offset %llu, dev_size %llu, threshold %llu\n",
		  offset, dev_size, threshold);
#endif /* CONFIG_SSDFS_DEBUG */

	if (fsi->devops->peb_isbad) {
		err = fsi->devops->peb_isbad(sb, offset);
		if (err) {
			if (!silent) {
				SSDFS_NOTICE("offset %llu is in bad PEB\n",
						(unsigned long long)offset);
			} else {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("offset %llu is in bad PEB\n",
					  (unsigned long long)offset);
#endif /* CONFIG_SSDFS_DEBUG */
			}

			offset += seg_size;
			err = find_seg_with_valid_start_peb(fsi, seg_size,
							&offset, threshold,
							silent,
							SSDFS_USE_PEB_ISBAD_OP);
			if (err) {
				switch (seg_size) {
				case SSDFS_128KB:
					offset = start_offset;
					seg_size = SSDFS_256KB;
					goto try_seg_size;

				case SSDFS_256KB:
					offset = start_offset;
					seg_size = SSDFS_512KB;
					goto try_seg_size;

				case SSDFS_512KB:
					offset = start_offset;
					seg_size = SSDFS_2MB;
					goto try_seg_size;

				case SSDFS_2MB:
					offset = start_offset;
					seg_size = SSDFS_8MB;
					goto try_seg_size;

				default:
					/* finish search */
					break;
				}

				SSDFS_NOTICE("unable to find valid start PEB: "
					     "err %d\n", err);
				return err;
			}
		}
	}

	err = find_seg_with_valid_start_peb(fsi, seg_size, &offset,
					    threshold, silent,
					    SSDFS_USE_READ_OP);
	if (unlikely(err)) {
		switch (seg_size) {
		case SSDFS_128KB:
			offset = start_offset;
			seg_size = SSDFS_256KB;
			goto try_seg_size;

		case SSDFS_256KB:
			offset = start_offset;
			seg_size = SSDFS_512KB;
			goto try_seg_size;

		case SSDFS_512KB:
			offset = start_offset;
			seg_size = SSDFS_2MB;
			goto try_seg_size;

		case SSDFS_2MB:
			offset = start_offset;
			seg_size = SSDFS_8MB;
			goto try_seg_size;

		default:
			/* finish search */
			break;
		}

		SSDFS_NOTICE("unable to find valid start PEB\n");
		return err;
	}

	vh = SSDFS_VH(fsi->sbi.vh_buf);

	seg_size = 1 << vh->log_segsize;

	magic_valid = is_ssdfs_magic_valid(&vh->magic);
	crc_valid = is_ssdfs_volume_header_csum_valid(fsi->sbi.vh_buf,
							hdr_size);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("magic_valid %#x, crc_valid %#x\n",
		  magic_valid, crc_valid);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!magic_valid && !crc_valid) {
		if (!silent)
			SSDFS_NOTICE("valid magic is not detected\n");
		else
			SSDFS_DBG("valid magic is not detected\n");
		return -ENOENT;
	} else if ((magic_valid && !crc_valid) || (!magic_valid && crc_valid)) {
		loff_t start_off;

try_again:
		start_off = offset;
		if (offset >= (threshold - seg_size)) {
			if (!silent)
				SSDFS_NOTICE("valid magic is not detected\n");
			else
				SSDFS_DBG("valid magic is not detected\n");
			return -ENOENT;
		}

		if (fsi->devops->peb_isbad) {
			err = find_seg_with_valid_start_peb(fsi, seg_size,
							&offset, threshold,
							silent,
							SSDFS_USE_PEB_ISBAD_OP);
			if (err) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to find valid start PEB: "
					  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
				return err;
			}
		}

		if (start_off == offset)
			offset += seg_size;

		err = find_seg_with_valid_start_peb(fsi, seg_size, &offset,
						    threshold, silent,
						    SSDFS_USE_READ_OP);
		if (unlikely(err)) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find valid start PEB: "
				  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		}

		magic_valid = is_ssdfs_magic_valid(&vh->magic);
		crc_valid = is_ssdfs_volume_header_csum_valid(fsi->sbi.vh_buf,
								hdr_size);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("magic_valid %#x, crc_valid %#x\n",
			  magic_valid, crc_valid);
#endif /* CONFIG_SSDFS_DEBUG */

		if (!(magic_valid && crc_valid)) {
			if (!silent)
				SSDFS_NOTICE("valid magic is not detected\n");
			else
				SSDFS_DBG("valid magic is not detected\n");
			return -ENOENT;
		}
	}

	if (!is_ssdfs_volume_header_consistent(fsi, vh, dev_size))
		goto try_again;

	fsi->pagesize = 1 << vh->log_pagesize;

	if (fsi->is_zns_device) {
		fsi->erasesize = fsi->zone_size;
		fsi->segsize = fsi->erasesize * le16_to_cpu(vh->pebs_per_seg);
	} else {
		fsi->erasesize = 1 << vh->log_erasesize;
		fsi->segsize = 1 << vh->log_segsize;
	}

	fsi->pages_per_seg = fsi->segsize / fsi->pagesize;
	fsi->pages_per_peb = fsi->erasesize / fsi->pagesize;
	fsi->pebs_per_seg = 1 << vh->log_pebs_per_seg;

	return 0;
}

static int ssdfs_read_checked_sb_info(struct ssdfs_fs_info *fsi, u64 peb_id,
				      u32 pages_off, bool silent)
{
	u32 lf_off;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p, peb_id %llu, pages_off %u, silent %#x\n",
		  fsi, peb_id, pages_off, silent);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_read_checked_segment_header(fsi, peb_id, pages_off,
						fsi->sbi.vh_buf, silent);
	if (err) {
		if (!silent) {
			SSDFS_ERR("volume header is corrupted: "
				  "peb_id %llu, offset %d, err %d\n",
				  peb_id, pages_off, err);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("volume header is corrupted: "
				  "peb_id %llu, offset %d, err %d\n",
				  peb_id, pages_off, err);
#endif /* CONFIG_SSDFS_DEBUG */
		}
		return err;
	}

	lf_off = SSDFS_LOG_FOOTER_OFF(fsi->sbi.vh_buf);

	err = ssdfs_read_checked_log_footer(fsi, SSDFS_SEG_HDR(fsi->sbi.vh_buf),
					    peb_id, lf_off, fsi->sbi.vs_buf,
					    silent);
	if (err) {
		if (!silent) {
			SSDFS_ERR("log footer is corrupted: "
				  "peb_id %llu, offset %d, err %d\n",
				  peb_id, lf_off, err);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("log footer is corrupted: "
				  "peb_id %llu, offset %d, err %d\n",
				  peb_id, lf_off, err);
#endif /* CONFIG_SSDFS_DEBUG */
		}
		return err;
	}

	return 0;
}

static int ssdfs_read_checked_sb_info2(struct ssdfs_fs_info *fsi, u64 peb_id,
					u32 pages_off, bool silent,
					u32 *cur_off)
{
	u32 bytes_off;
	u32 log_pages;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p, peb_id %llu, pages_off %u, silent %#x\n",
		  fsi, peb_id, pages_off, silent);
#endif /* CONFIG_SSDFS_DEBUG */

	bytes_off = pages_off * fsi->pagesize;

	err = ssdfs_read_unchecked_log_footer(fsi, peb_id, bytes_off,
					      fsi->sbi.vs_buf, silent,
					      &log_pages);
	if (err) {
		if (!silent) {
			SSDFS_ERR("fail to read the log footer: "
				  "peb_id %llu, offset %u, err %d\n",
				  peb_id, bytes_off, err);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fail to read the log footer: "
				  "peb_id %llu, offset %u, err %d\n",
				  peb_id, bytes_off, err);
#endif /* CONFIG_SSDFS_DEBUG */
		}
		return err;
	}

	if (log_pages == 0 ||
	    log_pages > fsi->pages_per_peb ||
	    pages_off < log_pages) {
		if (!silent) {
			SSDFS_ERR("invalid log_pages %u\n", log_pages);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("invalid log_pages %u\n", log_pages);
#endif /* CONFIG_SSDFS_DEBUG */
		}
		return -ERANGE;
	}

	pages_off -= log_pages - 1;
	*cur_off -= log_pages - 1;

	err = ssdfs_read_checked_segment_header(fsi, peb_id, pages_off,
						fsi->sbi.vh_buf, silent);
	if (err) {
		if (!silent) {
			SSDFS_ERR("volume header is corrupted: "
				  "peb_id %llu, offset %d, err %d\n",
				  peb_id, pages_off, err);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("volume header is corrupted: "
				  "peb_id %llu, offset %d, err %d\n",
				  peb_id, pages_off, err);
#endif /* CONFIG_SSDFS_DEBUG */
		}
		return err;
	}

	err = ssdfs_check_log_footer(fsi,
				     SSDFS_SEG_HDR(fsi->sbi.vh_buf),
				     SSDFS_LF(fsi->sbi.vs_buf),
				     silent);
	if (err) {
		if (!silent) {
			SSDFS_ERR("log footer is corrupted: "
				  "peb_id %llu, bytes_off %u, err %d\n",
				  peb_id, bytes_off, err);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("log footer is corrupted: "
				  "peb_id %llu, bytes_off %u, err %d\n",
				  peb_id, bytes_off, err);
#endif /* CONFIG_SSDFS_DEBUG */
		}
		return err;
	}

	return 0;
}

static int ssdfs_find_any_valid_sb_segment(struct ssdfs_fs_info *fsi,
					   u64 start_peb_id)
{
#ifdef CONFIG_SSDFS_DEBUG
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
#endif /* CONFIG_SSDFS_DEBUG */
	size_t vh_size = sizeof(struct ssdfs_volume_header);
	struct ssdfs_volume_header *vh;
	struct ssdfs_segment_header *seg_hdr;
	u64 dev_size;
	loff_t offset = start_peb_id * fsi->erasesize;
	loff_t step = SSDFS_RESERVED_SB_SEGS * SSDFS_128KB;
	u64 last_cno, cno;
	__le64 peb1, peb2;
	__le64 leb1, leb2;
	u64 checked_pebs[SSDFS_SB_CHAIN_MAX][SSDFS_SB_SEG_COPY_MAX];
	int i, j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!fsi->sbi.vh_buf);
	BUG_ON(!fsi->devops->read);
	BUG_ON(!is_ssdfs_magic_valid(&SSDFS_VH(fsi->sbi.vh_buf)->magic));
	BUG_ON(!is_ssdfs_volume_header_csum_valid(fsi->sbi.vh_buf, hdr_size));

	SSDFS_DBG("fsi %p, fsi->sbi.vh_buf %p, start_peb_id %llu\n",
		  fsi, fsi->sbi.vh_buf, start_peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	i = SSDFS_SB_CHAIN_MAX;
	dev_size = fsi->devops->device_size(fsi->sb);
	memset(checked_pebs, 0xFF,
		(SSDFS_SB_CHAIN_MAX * sizeof(u64)) +
		(SSDFS_SB_SEG_COPY_MAX * sizeof(u64)));

try_next_volume_portion:
	ssdfs_memcpy(&fsi->last_vh, 0, vh_size,
		     fsi->sbi.vh_buf, 0, vh_size,
		     vh_size);
	last_cno = le64_to_cpu(SSDFS_SEG_HDR(fsi->sbi.vh_buf)->cno);

try_again:
	switch (i) {
	case SSDFS_SB_CHAIN_MAX:
		i = SSDFS_CUR_SB_SEG;
		break;

	case SSDFS_CUR_SB_SEG:
		i = SSDFS_NEXT_SB_SEG;
		break;

	case SSDFS_NEXT_SB_SEG:
		i = SSDFS_RESERVED_SB_SEG;
		break;

	default:
		offset += step;

		if (offset >= dev_size)
			goto fail_find_sb_seg;

		err =  ssdfs_find_any_valid_volume_header(fsi, offset, true);
		if (err)
			goto fail_find_sb_seg;
		else {
			i = SSDFS_SB_CHAIN_MAX;
			goto try_next_volume_portion;
		}
		break;
	}

	err = -ENODATA;

	for (j = SSDFS_MAIN_SB_SEG; j < SSDFS_SB_SEG_COPY_MAX; j++) {
		u64 leb_id = le64_to_cpu(fsi->last_vh.sb_pebs[i][j].leb_id);
		u64 peb_id = le64_to_cpu(fsi->last_vh.sb_pebs[i][j].peb_id);
		u16 seg_type;

		if (peb_id == U64_MAX || leb_id == U64_MAX) {
			err = -ERANGE;
			SSDFS_ERR("invalid peb_id %llu, leb_id %llu\n",
				  leb_id, peb_id);
			goto fail_find_sb_seg;
		}

		if (start_peb_id > peb_id)
			continue;

		if (checked_pebs[i][j] == peb_id)
			continue;
		else
			checked_pebs[i][j] = peb_id;

		if ((peb_id * fsi->erasesize) < dev_size)
			offset = peb_id * fsi->erasesize;

		err = ssdfs_read_checked_sb_info(fsi, peb_id,
						 0, true);
		if (err) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("peb_id %llu is corrupted: err %d\n",
				  peb_id, err);
#endif /* CONFIG_SSDFS_DEBUG */
			continue;
		}

		fsi->sbi.last_log.leb_id = leb_id;
		fsi->sbi.last_log.peb_id = peb_id;
		fsi->sbi.last_log.page_offset = 0;
		fsi->sbi.last_log.pages_count =
			SSDFS_LOG_PAGES(fsi->sbi.vh_buf);

		seg_hdr = SSDFS_SEG_HDR(fsi->sbi.vh_buf);
		seg_type = SSDFS_SEG_TYPE(seg_hdr);

		if (seg_type == SSDFS_SB_SEG_TYPE)
			return 0;
		else {
			err = -EIO;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("PEB %llu is not sb segment\n",
				  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		if (!err)
			goto compare_vh_info;
	}

	if (err) {
		ssdfs_memcpy(fsi->sbi.vh_buf, 0, vh_size,
			     &fsi->last_vh, 0, vh_size,
			     vh_size);
		goto try_again;
	}

compare_vh_info:
	vh = SSDFS_VH(fsi->sbi.vh_buf);
	seg_hdr = SSDFS_SEG_HDR(fsi->sbi.vh_buf);
	leb1 = fsi->last_vh.sb_pebs[SSDFS_CUR_SB_SEG][SSDFS_MAIN_SB_SEG].leb_id;
	leb2 = vh->sb_pebs[SSDFS_CUR_SB_SEG][SSDFS_MAIN_SB_SEG].leb_id;
	peb1 = fsi->last_vh.sb_pebs[SSDFS_CUR_SB_SEG][SSDFS_MAIN_SB_SEG].peb_id;
	peb2 = vh->sb_pebs[SSDFS_CUR_SB_SEG][SSDFS_MAIN_SB_SEG].peb_id;
	cno = le64_to_cpu(seg_hdr->cno);

	if (cno > last_cno && (leb1 != leb2 || peb1 != peb2)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cno %llu, last_cno %llu, "
			  "leb1 %llu, leb2 %llu, "
			  "peb1 %llu, peb2 %llu\n",
			  cno, last_cno,
			  le64_to_cpu(leb1), le64_to_cpu(leb2),
			  le64_to_cpu(peb1), le64_to_cpu(peb2));
#endif /* CONFIG_SSDFS_DEBUG */
		goto try_again;
	}

fail_find_sb_seg:
	SSDFS_CRIT("unable to find any valid segment with superblocks chain\n");
	return -EIO;
}

static inline bool is_sb_peb_exhausted2(struct ssdfs_fs_info *fsi,
					u64 leb_id, u64 peb_id)
{
#ifdef CONFIG_SSDFS_DEBUG
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
#endif /* CONFIG_SSDFS_DEBUG */
	struct ssdfs_peb_extent checking_page;
	u64 pages_per_peb;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!fsi->sbi.vh_buf);
	BUG_ON(!fsi->devops->read);
	BUG_ON(!is_ssdfs_magic_valid(&SSDFS_VH(fsi->sbi.vh_buf)->magic));
	BUG_ON(!is_ssdfs_volume_header_csum_valid(fsi->sbi.vh_buf, hdr_size));

	SSDFS_DBG("fsi %p, fsi->sbi.vh_buf %p, "
		  "leb_id %llu, peb_id %llu\n",
		  fsi, fsi->sbi.vh_buf,
		  leb_id, peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!fsi->devops->can_write_page) {
		SSDFS_CRIT("fail to find latest valid sb info: "
			   "can_write_page is not supported\n");
		return true;
	}

	if (leb_id >= U64_MAX || peb_id >= U64_MAX) {
		SSDFS_ERR("invalid leb_id %llu or peb_id %llu\n",
			  leb_id, peb_id);
		return true;
	}

	checking_page.leb_id = leb_id;
	checking_page.peb_id = peb_id;

	if (fsi->is_zns_device) {
		pages_per_peb = div64_u64(fsi->zone_capacity, fsi->pagesize);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(pages_per_peb >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		checking_page.page_offset = (u32)pages_per_peb - 2;
	} else {
		checking_page.page_offset = fsi->pages_per_peb - 2;
	}

	checking_page.pages_count = 1;

	err = ssdfs_can_write_sb_log(fsi->sb, &checking_page);
	if (!err)
		return false;

	return true;
}

static inline bool is_cur_main_sb_peb_exhausted2(struct ssdfs_fs_info *fsi)
{
	u64 leb_id;
	u64 peb_id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!fsi->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	leb_id = SSDFS_MAIN_SB_LEB(SSDFS_VH(fsi->sbi.vh_buf),
				   SSDFS_CUR_SB_SEG);
	peb_id = SSDFS_MAIN_SB_PEB(SSDFS_VH(fsi->sbi.vh_buf),
				   SSDFS_CUR_SB_SEG);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("fsi %p, fsi->sbi.vh_buf %p, "
		  "leb_id %llu, peb_id %llu\n",
		  fsi, fsi->sbi.vh_buf,
		  leb_id, peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	return is_sb_peb_exhausted2(fsi, leb_id, peb_id);
}

static inline bool is_cur_copy_sb_peb_exhausted2(struct ssdfs_fs_info *fsi)
{
	u64 leb_id;
	u64 peb_id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!fsi->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	leb_id = SSDFS_COPY_SB_LEB(SSDFS_VH(fsi->sbi.vh_buf),
				   SSDFS_CUR_SB_SEG);
	peb_id = SSDFS_COPY_SB_PEB(SSDFS_VH(fsi->sbi.vh_buf),
				   SSDFS_CUR_SB_SEG);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("fsi %p, fsi->sbi.vh_buf %p, "
		  "leb_id %llu, peb_id %llu\n",
		  fsi, fsi->sbi.vh_buf,
		  leb_id, peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	return is_sb_peb_exhausted2(fsi, leb_id, peb_id);
}

static int ssdfs_find_latest_valid_sb_segment(struct ssdfs_fs_info *fsi)
{
#ifdef CONFIG_SSDFS_DEBUG
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
#endif /* CONFIG_SSDFS_DEBUG */
	struct ssdfs_volume_header *last_vh;
	u64 cur_main_sb_peb, cur_copy_sb_peb;
	u64 cno1, cno2;
	u64 cur_peb, next_peb, prev_peb;
	u64 cur_leb, next_leb, prev_leb;
	u16 seg_type;
	loff_t offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!fsi->sbi.vh_buf);
	BUG_ON(!fsi->devops->read);
	BUG_ON(!is_ssdfs_magic_valid(&SSDFS_VH(fsi->sbi.vh_buf)->magic));
	BUG_ON(!is_ssdfs_volume_header_csum_valid(fsi->sbi.vh_buf, hdr_size));

	SSDFS_DBG("fsi %p, fsi->sbi.vh_buf %p\n", fsi, fsi->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

try_next_peb:
	last_vh = SSDFS_VH(fsi->sbi.vh_buf);
	cur_main_sb_peb = SSDFS_MAIN_SB_PEB(last_vh, SSDFS_CUR_SB_SEG);
	cur_copy_sb_peb = SSDFS_COPY_SB_PEB(last_vh, SSDFS_CUR_SB_SEG);

	if (cur_main_sb_peb != fsi->sbi.last_log.peb_id &&
	    cur_copy_sb_peb != fsi->sbi.last_log.peb_id) {
		SSDFS_ERR("volume header is corrupted\n");
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cur_main_sb_peb %llu, cur_copy_sb_peb %llu, "
			  "read PEB %llu\n",
			  cur_main_sb_peb, cur_copy_sb_peb,
			  fsi->sbi.last_log.peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		err = -EIO;
		goto end_search;
	}

	if (cur_main_sb_peb == fsi->sbi.last_log.peb_id) {
		if (!is_cur_main_sb_peb_exhausted2(fsi))
			goto end_search;
	} else {
		if (!is_cur_copy_sb_peb_exhausted2(fsi))
			goto end_search;
	}

	ssdfs_backup_sb_info(fsi);

	next_leb = SSDFS_MAIN_SB_LEB(SSDFS_VH(fsi->sbi.vh_buf),
					SSDFS_NEXT_SB_SEG);
	next_peb = SSDFS_MAIN_SB_PEB(SSDFS_VH(fsi->sbi.vh_buf),
					SSDFS_NEXT_SB_SEG);
	if (next_leb == U64_MAX || next_peb == U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid next_leb %llu, next_peb %llu\n",
			  next_leb, next_peb);
		goto end_search;
	}

	err = ssdfs_read_checked_sb_info(fsi, next_peb, 0, true);
	if (!err) {
		fsi->sbi.last_log.leb_id = next_leb;
		fsi->sbi.last_log.peb_id = next_peb;
		fsi->sbi.last_log.page_offset = 0;
		fsi->sbi.last_log.pages_count =
				SSDFS_LOG_PAGES(fsi->sbi.vh_buf);
		goto check_volume_header;
	} else {
		ssdfs_restore_sb_info(fsi);
		err = 0; /* try to read the backup copy */
	}

	next_leb = SSDFS_COPY_SB_LEB(SSDFS_VH(fsi->sbi.vh_buf),
					SSDFS_NEXT_SB_SEG);
	next_peb = SSDFS_COPY_SB_PEB(SSDFS_VH(fsi->sbi.vh_buf),
					SSDFS_NEXT_SB_SEG);
	if (next_leb == U64_MAX || next_peb == U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid next_leb %llu, next_peb %llu\n",
			  next_leb, next_peb);
		goto end_search;
	}

	err = ssdfs_read_checked_sb_info(fsi, next_peb, 0, true);
	if (err) {
		if (err == -EIO) {
			/* next sb segments are corrupted */
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("next sb PEB %llu is corrupted\n",
				  next_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		} else {
			/* next sb segments are invalid */
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("next sb PEB %llu is invalid\n",
				  next_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		ssdfs_restore_sb_info(fsi);

		offset = next_peb * fsi->erasesize;

		err = ssdfs_find_any_valid_volume_header(fsi, offset, true);
		if (err) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find any valid header: "
				  "peb_id %llu\n",
				  next_peb);
#endif /* CONFIG_SSDFS_DEBUG */
			err = 0;
			goto rollback_valid_vh;
		}

		err = ssdfs_find_any_valid_sb_segment(fsi, next_peb);
		if (err) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find any valid sb seg: "
				  "peb_id %llu\n",
				  next_peb);
#endif /* CONFIG_SSDFS_DEBUG */
			err = 0;
			goto rollback_valid_vh;
		} else
			goto try_next_peb;
	}

	fsi->sbi.last_log.leb_id = next_leb;
	fsi->sbi.last_log.peb_id = next_peb;
	fsi->sbi.last_log.page_offset = 0;
	fsi->sbi.last_log.pages_count = SSDFS_LOG_PAGES(fsi->sbi.vh_buf);

check_volume_header:
	seg_type = SSDFS_SEG_TYPE(SSDFS_SEG_HDR(fsi->sbi.vh_buf));
	if (seg_type != SSDFS_SB_SEG_TYPE) {
		SSDFS_DBG("invalid segment type\n");
		err = 0;
		goto mount_fs_read_only;
	}

	cno1 = SSDFS_SEG_CNO(fsi->sbi_backup.vh_buf);
	cno2 = SSDFS_SEG_CNO(fsi->sbi.vh_buf);
	if (cno1 >= cno2) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("last cno %llu is not lesser than read cno %llu\n",
			  cno1, cno2);
#endif /* CONFIG_SSDFS_DEBUG */
		err = 0;
		goto mount_fs_read_only;
	}

	next_peb = SSDFS_MAIN_SB_PEB(SSDFS_VH(fsi->sbi_backup.vh_buf),
					SSDFS_NEXT_SB_SEG);
	cur_peb = SSDFS_MAIN_SB_PEB(SSDFS_VH(fsi->sbi.vh_buf),
					SSDFS_CUR_SB_SEG);
	if (next_peb != cur_peb) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("next_peb %llu doesn't equal to cur_peb %llu\n",
			  next_peb, cur_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		err = 0;
		goto mount_fs_read_only;
	}

	prev_peb = SSDFS_MAIN_SB_PEB(SSDFS_VH(fsi->sbi.vh_buf),
					SSDFS_PREV_SB_SEG);
	cur_peb = SSDFS_MAIN_SB_PEB(SSDFS_VH(fsi->sbi_backup.vh_buf),
					SSDFS_CUR_SB_SEG);
	if (prev_peb != cur_peb) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("prev_peb %llu doesn't equal to cur_peb %llu\n",
			  prev_peb, cur_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		err = 0;
		goto mount_fs_read_only;
	}

	next_leb = SSDFS_MAIN_SB_LEB(SSDFS_VH(fsi->sbi_backup.vh_buf),
					SSDFS_NEXT_SB_SEG);
	cur_leb = SSDFS_MAIN_SB_LEB(SSDFS_VH(fsi->sbi.vh_buf),
					SSDFS_CUR_SB_SEG);
	if (next_leb != cur_leb) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("next_leb %llu doesn't equal to cur_leb %llu\n",
			  next_leb, cur_leb);
#endif /* CONFIG_SSDFS_DEBUG */
		err = 0;
		goto mount_fs_read_only;
	}

	prev_leb = SSDFS_MAIN_SB_LEB(SSDFS_VH(fsi->sbi.vh_buf),
					SSDFS_PREV_SB_SEG);
	cur_leb = SSDFS_MAIN_SB_LEB(SSDFS_VH(fsi->sbi_backup.vh_buf),
					SSDFS_CUR_SB_SEG);
	if (prev_leb != cur_leb) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("prev_leb %llu doesn't equal to cur_leb %llu\n",
			  prev_leb, cur_leb);
#endif /* CONFIG_SSDFS_DEBUG */
		err = 0;
		goto mount_fs_read_only;
	}

	next_peb = SSDFS_COPY_SB_PEB(SSDFS_VH(fsi->sbi_backup.vh_buf),
					SSDFS_NEXT_SB_SEG);
	cur_peb = SSDFS_COPY_SB_PEB(SSDFS_VH(fsi->sbi.vh_buf),
					SSDFS_CUR_SB_SEG);
	if (next_peb != cur_peb) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("next_peb %llu doesn't equal to cur_peb %llu\n",
			  next_peb, cur_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		err = 0;
		goto mount_fs_read_only;
	}

	prev_peb = SSDFS_COPY_SB_PEB(SSDFS_VH(fsi->sbi.vh_buf),
					SSDFS_PREV_SB_SEG);
	cur_peb = SSDFS_COPY_SB_PEB(SSDFS_VH(fsi->sbi_backup.vh_buf),
					SSDFS_CUR_SB_SEG);
	if (prev_peb != cur_peb) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("prev_peb %llu doesn't equal to cur_peb %llu\n",
			  prev_peb, cur_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		err = 0;
		goto mount_fs_read_only;
	}

	next_leb = SSDFS_COPY_SB_LEB(SSDFS_VH(fsi->sbi_backup.vh_buf),
					SSDFS_NEXT_SB_SEG);
	cur_leb = SSDFS_COPY_SB_LEB(SSDFS_VH(fsi->sbi.vh_buf),
					SSDFS_CUR_SB_SEG);
	if (next_leb != cur_leb) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("next_leb %llu doesn't equal to cur_leb %llu\n",
			  next_leb, cur_leb);
#endif /* CONFIG_SSDFS_DEBUG */
		err = 0;
		goto mount_fs_read_only;
	}

	prev_leb = SSDFS_COPY_SB_LEB(SSDFS_VH(fsi->sbi.vh_buf),
					SSDFS_PREV_SB_SEG);
	cur_leb = SSDFS_COPY_SB_LEB(SSDFS_VH(fsi->sbi_backup.vh_buf),
					SSDFS_CUR_SB_SEG);
	if (prev_leb != cur_leb) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("prev_leb %llu doesn't equal to cur_leb %llu\n",
			  prev_leb, cur_leb);
#endif /* CONFIG_SSDFS_DEBUG */
		err = 0;
		goto mount_fs_read_only;
	}

	goto try_next_peb;

mount_fs_read_only:
	SSDFS_NOTICE("unable to mount in RW mode: "
		     "chain of superblock's segments is broken\n");
	fsi->sb->s_flags |= SB_RDONLY;

rollback_valid_vh:
	ssdfs_restore_sb_info(fsi);

end_search:
	return err;
}

static inline
u64 ssdfs_swap_current_sb_peb(struct ssdfs_volume_header *vh, u64 peb)
{
	if (peb == SSDFS_MAIN_SB_PEB(vh, SSDFS_CUR_SB_SEG))
		return SSDFS_COPY_SB_PEB(vh, SSDFS_CUR_SB_SEG);
	else if (peb == SSDFS_COPY_SB_PEB(vh, SSDFS_CUR_SB_SEG))
		return SSDFS_MAIN_SB_PEB(vh, SSDFS_CUR_SB_SEG);

	BUG();
	return ULLONG_MAX;
}

static inline
u64 ssdfs_swap_current_sb_leb(struct ssdfs_volume_header *vh, u64 leb)
{
	if (leb == SSDFS_MAIN_SB_LEB(vh, SSDFS_CUR_SB_SEG))
		return SSDFS_COPY_SB_LEB(vh, SSDFS_CUR_SB_SEG);
	else if (leb == SSDFS_COPY_SB_LEB(vh, SSDFS_CUR_SB_SEG))
		return SSDFS_MAIN_SB_LEB(vh, SSDFS_CUR_SB_SEG);

	BUG();
	return ULLONG_MAX;
}

/*
 * This method expects that first volume header and log footer
 * are checked yet and they are valid.
 */
static int ssdfs_find_latest_valid_sb_info(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_segment_header *last_seg_hdr;
	u64 leb, peb;
	u32 cur_off, low_off, high_off;
	u32 log_pages;
	u64 pages_per_peb;
	int err = 0;
#ifdef CONFIG_SSDFS_DEBUG
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!fsi->sbi.vh_buf);
	BUG_ON(!fsi->devops->read);
	BUG_ON(!is_ssdfs_magic_valid(&SSDFS_VH(fsi->sbi.vh_buf)->magic));
	BUG_ON(!is_ssdfs_volume_header_csum_valid(fsi->sbi.vh_buf, hdr_size));

	SSDFS_DBG("fsi %p, fsi->sbi.vh_buf %p\n", fsi, fsi->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_backup_sb_info(fsi);
	last_seg_hdr = SSDFS_SEG_HDR(fsi->sbi.vh_buf);
	leb = fsi->sbi.last_log.leb_id;
	peb = fsi->sbi.last_log.peb_id;
	log_pages = SSDFS_LOG_PAGES(last_seg_hdr);

	if (fsi->is_zns_device)
		pages_per_peb = div64_u64(fsi->zone_capacity, fsi->pagesize);
	else
		pages_per_peb = fsi->pages_per_peb;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(pages_per_peb >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	low_off = fsi->sbi.last_log.page_offset;
	high_off = (u32)pages_per_peb;
	cur_off = low_off + log_pages;

	do {
		u32 diff_pages, diff_logs;
		u64 cno1, cno2;
		u64 copy_leb, copy_peb;
		u32 peb_pages_off;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(cur_off >= pages_per_peb);
#endif /* CONFIG_SSDFS_DEBUG */

		peb_pages_off = cur_off % (u32)pages_per_peb;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(peb_pages_off > U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		if (leb == U64_MAX || peb == U64_MAX) {
			err = -ENODATA;
			break;
		}

		err = ssdfs_read_checked_sb_info(fsi, peb,
						 peb_pages_off, true);
		cno1 = SSDFS_SEG_CNO(fsi->sbi_backup.vh_buf);
		cno2 = SSDFS_SEG_CNO(fsi->sbi.vh_buf);
		if (err == -EIO || cno1 >= cno2) {
			void *buf = fsi->sbi_backup.vh_buf;

			copy_peb = ssdfs_swap_current_sb_peb(buf, peb);
			copy_leb = ssdfs_swap_current_sb_leb(buf, leb);
			if (copy_leb == U64_MAX || copy_peb == U64_MAX) {
				err = -ERANGE;
				break;
			}

			err = ssdfs_read_checked_sb_info(fsi, copy_peb,
							 peb_pages_off, true);
			cno1 = SSDFS_SEG_CNO(fsi->sbi_backup.vh_buf);
			cno2 = SSDFS_SEG_CNO(fsi->sbi.vh_buf);
			if (!err) {
				peb = copy_peb;
				leb = copy_leb;
				fsi->sbi.last_log.leb_id = leb;
				fsi->sbi.last_log.peb_id = peb;
				fsi->sbi.last_log.page_offset = cur_off;
				fsi->sbi.last_log.pages_count =
					SSDFS_LOG_PAGES(fsi->sbi.vh_buf);
			}
		} else {
			fsi->sbi.last_log.leb_id = leb;
			fsi->sbi.last_log.peb_id = peb;
			fsi->sbi.last_log.page_offset = cur_off;
			fsi->sbi.last_log.pages_count =
				SSDFS_LOG_PAGES(fsi->sbi.vh_buf);
		}

		if (err == -ENODATA || err == -EIO || cno1 >= cno2) {
			err = !err ? -EIO : err;
			high_off = cur_off;
		} else if (err) {
			/* we have internal error */
			break;
		} else {
			ssdfs_backup_sb_info(fsi);
			low_off = cur_off;
		}

		diff_pages = high_off - low_off;
		diff_logs = (diff_pages / log_pages) / 2;
		cur_off = low_off + (diff_logs * log_pages);
	} while (cur_off > low_off && cur_off < high_off);

	if (err) {
		if (err == -ENODATA || err == -EIO) {
			/* previous read log was valid */
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cur_off %u, low_off %u, high_off %u\n",
				  cur_off, low_off, high_off);
#endif /* CONFIG_SSDFS_DEBUG */
		} else {
			SSDFS_ERR("fail to find valid volume header: err %d\n",
				  err);
		}

		ssdfs_restore_sb_info(fsi);
	}

	return err;
}

/*
 * This method expects that first volume header and log footer
 * are checked yet and they are valid.
 */
static int ssdfs_find_latest_valid_sb_info2(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_segment_header *last_seg_hdr;
	struct ssdfs_peb_extent checking_page;
	u64 leb, peb;
	u32 cur_off, low_off, high_off;
	u32 log_pages;
	u32 start_offset;
	u32 found_log_off;
	u64 cno1, cno2;
	u64 copy_leb, copy_peb;
	u32 peb_pages_off;
	u64 pages_per_peb;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!fsi->sbi.vh_buf);

	SSDFS_DBG("fsi %p, fsi->sbi.vh_buf %p\n", fsi, fsi->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!fsi->devops->can_write_page) {
		SSDFS_CRIT("fail to find latest valid sb info: "
			   "can_write_page is not supported\n");
		return -EOPNOTSUPP;
	}

	ssdfs_backup_sb_info(fsi);
	last_seg_hdr = SSDFS_SEG_HDR(fsi->sbi.vh_buf);
	leb = fsi->sbi.last_log.leb_id;
	peb = fsi->sbi.last_log.peb_id;

	if (leb == U64_MAX || peb == U64_MAX) {
		ssdfs_restore_sb_info(fsi);
		SSDFS_ERR("invalid leb_id %llu or peb_id %llu\n",
			  leb, peb);
		return -ERANGE;
	}

	if (fsi->is_zns_device)
		pages_per_peb = div64_u64(fsi->zone_capacity, fsi->pagesize);
	else
		pages_per_peb = fsi->pages_per_peb;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(pages_per_peb >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	log_pages = SSDFS_LOG_PAGES(last_seg_hdr);
	start_offset = fsi->sbi.last_log.page_offset + log_pages;
	low_off = start_offset;
	high_off = (u32)pages_per_peb;
	cur_off = low_off;

	checking_page.leb_id = leb;
	checking_page.peb_id = peb;
	checking_page.page_offset = cur_off;
	checking_page.pages_count = 1;

	err = ssdfs_can_write_sb_log(fsi->sb, &checking_page);
	if (err == -EIO) {
		/* correct low bound */
		err = 0;
		low_off++;
	} else if (err) {
		SSDFS_ERR("fail to check for write PEB %llu\n",
			  peb);
		return err;
	} else {
		ssdfs_restore_sb_info(fsi);

		/* previous read log was valid */
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cur_off %u, low_off %u, high_off %u\n",
			  cur_off, low_off, high_off);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	if (fsi->is_zns_device) {
		loff_t offset;
		u64 zone_wp;

		offset = (loff_t)peb * fsi->zone_size;

		zone_wp = ssdfs_zns_zone_write_pointer(fsi->sb, offset);

		if (zone_wp >= U64_MAX) {
			cur_off = fsi->zone_capacity;
		} else {
			cur_off = (zone_wp - offset) >> PAGE_SHIFT;
		}

		low_off = cur_off - log_pages;

		for (cur_off--; cur_off >= low_off; cur_off--) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("peb %llu, pages_per_peb %llu, "
				  "offset %llu, zone_wp %llu, "
				  "log_pages %u, cur_off %u\n",
				  peb, pages_per_peb,
				  offset, zone_wp,
				  log_pages, cur_off);
#endif /* CONFIG_SSDFS_DEBUG */

			checking_page.leb_id = leb;
			checking_page.peb_id = peb;
			checking_page.page_offset = cur_off;
			checking_page.pages_count = 1;

			err = ssdfs_can_write_sb_log(fsi->sb, &checking_page);
			if (err == -EIO) {
				/* log footer has been found */
				break;
			} else if (err) {
				SSDFS_ERR("fail to check for write PEB %llu\n",
					  peb);
				return err;
			}
		}
	} else {
		cur_off = high_off - 1;

		do {
			u32 diff_pages;

			checking_page.leb_id = leb;
			checking_page.peb_id = peb;
			checking_page.page_offset = cur_off;
			checking_page.pages_count = 1;

			err = ssdfs_can_write_sb_log(fsi->sb, &checking_page);
			if (err == -EIO) {
				/* correct low bound */
				err = 0;
				low_off = cur_off;
			} else if (err) {
				SSDFS_ERR("fail to check for write PEB %llu\n",
					  peb);
				return err;
			} else {
				/* correct upper bound */
				high_off = cur_off;
			}

			diff_pages = (high_off - low_off) / 2;
			cur_off = low_off + diff_pages;
		} while (cur_off > low_off && cur_off < high_off);
	}

	peb_pages_off = cur_off % (u32)pages_per_peb;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(peb_pages_off >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	found_log_off = cur_off;
	err = ssdfs_read_checked_sb_info2(fsi, peb, peb_pages_off, true,
					  &found_log_off);
	cno1 = SSDFS_SEG_CNO(fsi->sbi_backup.vh_buf);
	cno2 = SSDFS_SEG_CNO(fsi->sbi.vh_buf);

	if (err == -EIO || cno1 >= cno2) {
		void *buf = fsi->sbi_backup.vh_buf;

		copy_peb = ssdfs_swap_current_sb_peb(buf, peb);
		copy_leb = ssdfs_swap_current_sb_leb(buf, leb);
		if (copy_leb == U64_MAX || copy_peb == U64_MAX) {
			err = -ERANGE;
			goto finish_find_latest_sb_info;
		}

		found_log_off = cur_off;
		err = ssdfs_read_checked_sb_info2(fsi, copy_peb,
						  peb_pages_off, true,
						  &found_log_off);
		cno1 = SSDFS_SEG_CNO(fsi->sbi_backup.vh_buf);
		cno2 = SSDFS_SEG_CNO(fsi->sbi.vh_buf);
		if (!err) {
			peb = copy_peb;
			leb = copy_leb;
			fsi->sbi.last_log.leb_id = leb;
			fsi->sbi.last_log.peb_id = peb;
			fsi->sbi.last_log.page_offset = found_log_off;
			fsi->sbi.last_log.pages_count =
				SSDFS_LOG_PAGES(fsi->sbi.vh_buf);
		}
	} else {
		fsi->sbi.last_log.leb_id = leb;
		fsi->sbi.last_log.peb_id = peb;
		fsi->sbi.last_log.page_offset = found_log_off;
		fsi->sbi.last_log.pages_count =
			SSDFS_LOG_PAGES(fsi->sbi.vh_buf);
	}

finish_find_latest_sb_info:
	if (err) {
		if (err == -ENODATA || err == -EIO) {
			/* previous read log was valid */
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cur_off %u, low_off %u, high_off %u\n",
				  cur_off, low_off, high_off);
#endif /* CONFIG_SSDFS_DEBUG */
		} else {
			SSDFS_ERR("fail to find valid volume header: err %d\n",
				  err);
		}

		ssdfs_restore_sb_info(fsi);
	}

	return err;
}

static int ssdfs_check_fs_state(struct ssdfs_fs_info *fsi)
{
	if (fsi->sb->s_flags & SB_RDONLY)
		return 0;

	switch (fsi->fs_state) {
	case SSDFS_MOUNTED_FS:
		SSDFS_NOTICE("unable to mount in RW mode: "
			     "file system didn't unmounted cleanly: "
			     "Please, run fsck utility\n");
		fsi->sb->s_flags |= SB_RDONLY;
		return -EROFS;

	case SSDFS_ERROR_FS:
		if (!ssdfs_test_opt(fsi->mount_opts, IGNORE_FS_STATE)) {
			SSDFS_NOTICE("unable to mount in RW mode: "
				     "file system contains errors: "
				     "Please, run fsck utility\n");
			fsi->sb->s_flags |= SB_RDONLY;
			return -EROFS;
		}
		break;
	};

	return 0;
}

static int ssdfs_check_feature_compatibility(struct ssdfs_fs_info *fsi)
{
	u64 features;

	features = fsi->fs_feature_incompat & ~SSDFS_FEATURE_INCOMPAT_SUPP;
	if (features) {
		SSDFS_NOTICE("unable to mount: "
			     "unsupported incompatible features %llu\n",
			     features);
		return -EOPNOTSUPP;
	}

	features = fsi->fs_feature_compat_ro & ~SSDFS_FEATURE_COMPAT_RO_SUPP;
	if (!(fsi->sb->s_flags & SB_RDONLY) && features) {
		SSDFS_NOTICE("unable to mount in RW mode: "
			     "unsupported RO compatible features %llu\n",
			     features);
		fsi->sb->s_flags |= SB_RDONLY;
		return -EROFS;
	}

	features = fsi->fs_feature_compat & ~SSDFS_FEATURE_COMPAT_SUPP;
	if (features)
		SSDFS_WARN("unknown compatible features %llu\n", features);

	return 0;
}

static inline void ssdfs_init_sb_segs_array(struct ssdfs_fs_info *fsi)
{
	int i, j;

	for (i = SSDFS_CUR_SB_SEG; i < SSDFS_SB_CHAIN_MAX; i++) {
		for (j = SSDFS_MAIN_SB_SEG; j < SSDFS_SB_SEG_COPY_MAX; j++) {
			fsi->sb_lebs[i][j] =
				le64_to_cpu(fsi->vh->sb_pebs[i][j].leb_id);
			fsi->sb_pebs[i][j] =
				le64_to_cpu(fsi->vh->sb_pebs[i][j].peb_id);
		}
	}
}

static int ssdfs_initialize_fs_info(struct ssdfs_fs_info *fsi)
{
	int err;

	init_rwsem(&fsi->volume_sem);

	fsi->vh = SSDFS_VH(fsi->sbi.vh_buf);
	fsi->vs = SSDFS_VS(fsi->sbi.vs_buf);

	fsi->sb_seg_log_pages = le16_to_cpu(fsi->vh->sb_seg_log_pages);
	fsi->segbmap_log_pages = le16_to_cpu(fsi->vh->segbmap_log_pages);
	fsi->maptbl_log_pages = le16_to_cpu(fsi->vh->maptbl_log_pages);
	fsi->lnodes_seg_log_pages = le16_to_cpu(fsi->vh->lnodes_seg_log_pages);
	fsi->hnodes_seg_log_pages = le16_to_cpu(fsi->vh->hnodes_seg_log_pages);
	fsi->inodes_seg_log_pages = le16_to_cpu(fsi->vh->inodes_seg_log_pages);
	fsi->user_data_log_pages = le16_to_cpu(fsi->vh->user_data_log_pages);

	/* Static volume information */
	fsi->log_pagesize = fsi->vh->log_pagesize;
	fsi->pagesize = 1 << fsi->vh->log_pagesize;
	fsi->log_erasesize = fsi->vh->log_erasesize;
	fsi->log_segsize = fsi->vh->log_segsize;
	fsi->segsize = 1 << fsi->vh->log_segsize;
	fsi->log_pebs_per_seg = fsi->vh->log_pebs_per_seg;
	fsi->pebs_per_seg = 1 << fsi->vh->log_pebs_per_seg;
	fsi->pages_per_peb = fsi->erasesize / fsi->pagesize;
	fsi->pages_per_seg = fsi->segsize / fsi->pagesize;
	fsi->lebs_per_peb_index = le32_to_cpu(fsi->vh->lebs_per_peb_index);

	if (fsi->is_zns_device) {
		u64 peb_pages_capacity =
			fsi->zone_capacity >> fsi->vh->log_pagesize;

		fsi->erasesize = fsi->zone_size;
		fsi->segsize = fsi->erasesize *
				le16_to_cpu(fsi->vh->pebs_per_seg);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(peb_pages_capacity >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		fsi->peb_pages_capacity = (u32)peb_pages_capacity;
		atomic_set(&fsi->open_zones, le32_to_cpu(fsi->vs->open_zones));

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("open_zones %d\n",
			  atomic_read(&fsi->open_zones));
#endif /* CONFIG_SSDFS_DEBUG */
	} else {
		fsi->erasesize = 1 << fsi->vh->log_erasesize;
		fsi->segsize = 1 << fsi->vh->log_segsize;
		fsi->peb_pages_capacity = fsi->pages_per_peb;
	}

	if (fsi->pages_per_peb > U16_MAX)
		fsi->leb_pages_capacity = U16_MAX;
	else
		fsi->leb_pages_capacity = fsi->pages_per_peb;

	fsi->fs_ctime = le64_to_cpu(fsi->vh->create_time);
	fsi->fs_cno = le64_to_cpu(fsi->vh->create_cno);
	fsi->raw_inode_size = le16_to_cpu(fsi->vs->inodes_btree.desc.item_size);
	fsi->create_threads_per_seg =
				le16_to_cpu(fsi->vh->create_threads_per_seg);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("STATIC VOLUME INFO:\n");
	SSDFS_DBG("pagesize %u, erasesize %u, segsize %u\n",
		  fsi->pagesize, fsi->erasesize, fsi->segsize);
	SSDFS_DBG("pebs_per_seg %u, pages_per_peb %u, "
		  "pages_per_seg %u, lebs_per_peb_index %u\n",
		  fsi->pebs_per_seg, fsi->pages_per_peb,
		  fsi->pages_per_seg, fsi->lebs_per_peb_index);
	SSDFS_DBG("zone_size %llu, zone_capacity %llu, "
		  "leb_pages_capacity %u, peb_pages_capacity %u, "
		  "open_zones %d\n",
		  fsi->zone_size, fsi->zone_capacity,
		  fsi->leb_pages_capacity, fsi->peb_pages_capacity,
		  atomic_read(&fsi->open_zones));
	SSDFS_DBG("fs_ctime %llu, fs_cno %llu, "
		  "raw_inode_size %u, create_threads_per_seg %u\n",
		  (u64)fsi->fs_ctime, (u64)fsi->fs_cno,
		  fsi->raw_inode_size,
		  fsi->create_threads_per_seg);
#endif /* CONFIG_SSDFS_DEBUG */

	/* Mutable volume info */
	init_rwsem(&fsi->sb_segs_sem);
	ssdfs_init_sb_segs_array(fsi);

	mutex_init(&fsi->resize_mutex);
	fsi->nsegs = le64_to_cpu(fsi->vs->nsegs);

	spin_lock_init(&fsi->volume_state_lock);

	fsi->free_pages = 0;
	fsi->reserved_new_user_data_pages = 0;
	fsi->updated_user_data_pages = 0;
	fsi->flushing_user_data_requests = 0;
	fsi->fs_mount_time = ssdfs_current_timestamp();
	fsi->fs_mod_time = le64_to_cpu(fsi->vs->timestamp);
	ssdfs_init_boot_vs_mount_timediff(fsi);
	fsi->fs_mount_cno = le64_to_cpu(fsi->vs->cno);
	fsi->fs_flags = le32_to_cpu(fsi->vs->flags);
	fsi->fs_state = le16_to_cpu(fsi->vs->state);

	fsi->fs_errors = le16_to_cpu(fsi->vs->errors);
	ssdfs_initialize_fs_errors_option(fsi);

	fsi->fs_feature_compat = le64_to_cpu(fsi->vs->feature_compat);
	fsi->fs_feature_compat_ro = le64_to_cpu(fsi->vs->feature_compat_ro);
	fsi->fs_feature_incompat = le64_to_cpu(fsi->vs->feature_incompat);

	ssdfs_memcpy(fsi->fs_uuid, 0, SSDFS_UUID_SIZE,
		     fsi->vs->uuid, 0, SSDFS_UUID_SIZE,
		     SSDFS_UUID_SIZE);
	ssdfs_memcpy(fsi->fs_label, 0, SSDFS_VOLUME_LABEL_MAX,
		     fsi->vs->label, 0, SSDFS_VOLUME_LABEL_MAX,
		     SSDFS_VOLUME_LABEL_MAX);

	fsi->metadata_options.blk_bmap.flags =
				le16_to_cpu(fsi->vs->blkbmap.flags);
	fsi->metadata_options.blk_bmap.compression =
					fsi->vs->blkbmap.compression;
	fsi->metadata_options.blk2off_tbl.flags =
				le16_to_cpu(fsi->vs->blk2off_tbl.flags);
	fsi->metadata_options.blk2off_tbl.compression =
					fsi->vs->blk2off_tbl.compression;
	fsi->metadata_options.user_data.flags =
				le16_to_cpu(fsi->vs->user_data.flags);
	fsi->metadata_options.user_data.compression =
					fsi->vs->user_data.compression;
	fsi->metadata_options.user_data.migration_threshold =
			le16_to_cpu(fsi->vs->user_data.migration_threshold);

	fsi->migration_threshold = le16_to_cpu(fsi->vs->migration_threshold);
	if (fsi->migration_threshold == 0 ||
	    fsi->migration_threshold >= U16_MAX) {
		/* use default value */
		fsi->migration_threshold = fsi->pebs_per_seg;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("MUTABLE VOLUME INFO:\n");
	SSDFS_DBG("sb_lebs[CUR][MAIN] %llu, sb_pebs[CUR][MAIN] %llu\n",
		  fsi->sb_lebs[SSDFS_CUR_SB_SEG][SSDFS_MAIN_SB_SEG],
		  fsi->sb_pebs[SSDFS_CUR_SB_SEG][SSDFS_MAIN_SB_SEG]);
	SSDFS_DBG("sb_lebs[CUR][COPY] %llu, sb_pebs[CUR][COPY] %llu\n",
		  fsi->sb_lebs[SSDFS_CUR_SB_SEG][SSDFS_COPY_SB_SEG],
		  fsi->sb_pebs[SSDFS_CUR_SB_SEG][SSDFS_COPY_SB_SEG]);
	SSDFS_DBG("sb_lebs[NEXT][MAIN] %llu, sb_pebs[NEXT][MAIN] %llu\n",
		  fsi->sb_lebs[SSDFS_NEXT_SB_SEG][SSDFS_MAIN_SB_SEG],
		  fsi->sb_pebs[SSDFS_NEXT_SB_SEG][SSDFS_MAIN_SB_SEG]);
	SSDFS_DBG("sb_lebs[NEXT][COPY] %llu, sb_pebs[NEXT][COPY] %llu\n",
		  fsi->sb_lebs[SSDFS_NEXT_SB_SEG][SSDFS_COPY_SB_SEG],
		  fsi->sb_pebs[SSDFS_NEXT_SB_SEG][SSDFS_COPY_SB_SEG]);
	SSDFS_DBG("sb_lebs[RESERVED][MAIN] %llu, sb_pebs[RESERVED][MAIN] %llu\n",
		  fsi->sb_lebs[SSDFS_RESERVED_SB_SEG][SSDFS_MAIN_SB_SEG],
		  fsi->sb_pebs[SSDFS_RESERVED_SB_SEG][SSDFS_MAIN_SB_SEG]);
	SSDFS_DBG("sb_lebs[RESERVED][COPY] %llu, sb_pebs[RESERVED][COPY] %llu\n",
		  fsi->sb_lebs[SSDFS_RESERVED_SB_SEG][SSDFS_COPY_SB_SEG],
		  fsi->sb_pebs[SSDFS_RESERVED_SB_SEG][SSDFS_COPY_SB_SEG]);
	SSDFS_DBG("sb_lebs[PREV][MAIN] %llu, sb_pebs[PREV][MAIN] %llu\n",
		  fsi->sb_lebs[SSDFS_PREV_SB_SEG][SSDFS_MAIN_SB_SEG],
		  fsi->sb_pebs[SSDFS_PREV_SB_SEG][SSDFS_MAIN_SB_SEG]);
	SSDFS_DBG("sb_lebs[PREV][COPY] %llu, sb_pebs[PREV][COPY] %llu\n",
		  fsi->sb_lebs[SSDFS_PREV_SB_SEG][SSDFS_COPY_SB_SEG],
		  fsi->sb_pebs[SSDFS_PREV_SB_SEG][SSDFS_COPY_SB_SEG]);
	SSDFS_DBG("nsegs %llu, free_pages %llu\n",
		  fsi->nsegs, fsi->free_pages);
	SSDFS_DBG("fs_mount_time %llu, fs_mod_time %llu, fs_mount_cno %llu\n",
		  fsi->fs_mount_time, fsi->fs_mod_time, fsi->fs_mount_cno);
	SSDFS_DBG("fs_flags %#x, fs_state %#x, fs_errors %#x\n",
		  fsi->fs_flags, fsi->fs_state, fsi->fs_errors);
	SSDFS_DBG("fs_feature_compat %llu, fs_feature_compat_ro %llu, "
		  "fs_feature_incompat %llu\n",
		  fsi->fs_feature_compat, fsi->fs_feature_compat_ro,
		  fsi->fs_feature_incompat);
	SSDFS_DBG("migration_threshold %u\n",
		  fsi->migration_threshold);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi->sb->s_blocksize = fsi->pagesize;
	fsi->sb->s_blocksize_bits = blksize_bits(fsi->pagesize);

	ssdfs_maptbl_cache_init(&fsi->maptbl_cache);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("VOLUME HEADER DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     fsi->vh, fsi->pagesize);
	SSDFS_DBG("END\n");

	SSDFS_DBG("VOLUME STATE DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     fsi->vs, fsi->pagesize);
	SSDFS_DBG("END\n");
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_check_fs_state(fsi);
	if (err && err != -EROFS)
		return err;

	err = ssdfs_check_feature_compatibility(fsi);
	if (err)
		return err;

	if (fsi->leb_pages_capacity >= U16_MAX) {
#ifdef CONFIG_SSDFS_TESTING
		SSDFS_DBG("Continue in testing mode: "
			  "leb_pages_capacity %u, peb_pages_capacity %u\n",
			  fsi->leb_pages_capacity,
			  fsi->peb_pages_capacity);
		return 0;
#else
		SSDFS_NOTICE("unable to mount in RW mode: "
			     "Please, format volume with bigger logical block size.\n");
		SSDFS_NOTICE("STATIC VOLUME INFO:\n");
		SSDFS_NOTICE("pagesize %u, erasesize %u, segsize %u\n",
			     fsi->pagesize, fsi->erasesize, fsi->segsize);
		SSDFS_NOTICE("pebs_per_seg %u, pages_per_peb %u, "
			     "pages_per_seg %u\n",
			     fsi->pebs_per_seg, fsi->pages_per_peb,
			     fsi->pages_per_seg);
		SSDFS_NOTICE("zone_size %llu, zone_capacity %llu, "
			     "leb_pages_capacity %u, peb_pages_capacity %u\n",
			     fsi->zone_size, fsi->zone_capacity,
			     fsi->leb_pages_capacity, fsi->peb_pages_capacity);

		fsi->sb->s_flags |= SB_RDONLY;
		return -EROFS;
#endif /* CONFIG_SSDFS_TESTING */
	}

	return 0;
}

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
	    (prev_end_leb != U64_MAX && prev_end_leb >= start_leb)) {
		SSDFS_ERR("invalid LEB range: start_leb %llu, "
			  "end_leb %llu, prev_end_leb %llu\n",
			  start_leb, end_leb, prev_end_leb);
		return -EIO;
	}

	return 0;
}

static int ssdfs_read_maptbl_cache(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_segment_header *seg_hdr;
	struct ssdfs_metadata_descriptor *meta_desc;
	struct ssdfs_maptbl_cache_header *maptbl_cache_hdr;
	u32 read_off;
	u32 read_bytes = 0;
	u32 bytes_count;
	u32 pages_count;
	u64 peb_id;
	struct page *page;
	void *kaddr;
	u64 prev_end_leb;
	u32 csum = ~0;
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

	meta_desc = &seg_hdr->desc_array[SSDFS_MAPTBL_CACHE_INDEX];
	read_off = le32_to_cpu(meta_desc->offset);
	bytes_count = le32_to_cpu(meta_desc->size);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(bytes_count >= INT_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	peb_id = fsi->sbi.last_log.peb_id;

	pages_count = (bytes_count + PAGE_SIZE - 1) >> PAGE_SHIFT;

	for (i = 0; i < pages_count; i++) {
		struct ssdfs_maptbl_cache *cache = &fsi->maptbl_cache;
		size_t size;

		size = min_t(size_t, (size_t)PAGE_SIZE,
				(size_t)(bytes_count - read_bytes));

		page = ssdfs_maptbl_cache_add_pagevec_page(cache);
		if (unlikely(IS_ERR_OR_NULL(page))) {
			err = !page ? -ENOMEM : PTR_ERR(page);
			SSDFS_ERR("fail to add pagevec page: err %d\n",
				  err);
			goto finish_read_maptbl_cache;
		}

		ssdfs_lock_page(page);

		kaddr = kmap_local_page(page);
		err = ssdfs_unaligned_read_buffer(fsi, peb_id,
						  read_off, kaddr, size);
		flush_dcache_page(page);
		kunmap_local(kaddr);

		if (unlikely(err)) {
			ssdfs_unlock_page(page);
			SSDFS_ERR("fail to read page: "
				  "peb %llu, offset %u, size %zu, err %d\n",
				  peb_id, read_off, size, err);
			goto finish_read_maptbl_cache;
		}

		ssdfs_unlock_page(page);

		read_off += size;
		read_bytes += size;
	}

	prev_end_leb = U64_MAX;

	for (i = 0; i < pages_count; i++) {
		page = fsi->maptbl_cache.pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(i >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_lock_page(page);
		kaddr = kmap_local_page(page);

		maptbl_cache_hdr = SSDFS_MAPTBL_CACHE_HDR(kaddr);

		err = ssdfs_check_maptbl_cache_header(maptbl_cache_hdr,
						      (u16)i,
						      prev_end_leb);
		if (unlikely(err)) {
			SSDFS_ERR("invalid maptbl cache header: "
				  "page_index %d, err %d\n",
				  i, err);
			goto unlock_cur_page;
		}

		prev_end_leb = le64_to_cpu(maptbl_cache_hdr->end_leb);

		csum = crc32(csum, kaddr,
			     le16_to_cpu(maptbl_cache_hdr->bytes_count));

unlock_cur_page:
		kunmap_local(kaddr);
		ssdfs_unlock_page(page);

		if (unlikely(err))
			goto finish_read_maptbl_cache;
	}

	if (csum != le32_to_cpu(meta_desc->check.csum)) {
		err = -EIO;
		SSDFS_ERR("invalid checksum\n");
		goto finish_read_maptbl_cache;
	}

	if (bytes_count < PAGE_SIZE)
		bytes_count = PAGE_SIZE;

	atomic_set(&fsi->maptbl_cache.bytes_count, (int)bytes_count);

finish_read_maptbl_cache:
	up_write(&fsi->maptbl_cache.lock);

	return err;
}

static inline bool is_ssdfs_snapshot_rules_exist(struct ssdfs_fs_info *fsi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	return ssdfs_log_footer_has_snapshot_rules(SSDFS_LF(fsi->vs));
}

static inline
int ssdfs_check_snapshot_rules_header(struct ssdfs_snapshot_rules_header *hdr)
{
	size_t item_size = sizeof(struct ssdfs_snapshot_rule_info);
	u16 items_count;
	u16 items_capacity;
	u32 area_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	if (le32_to_cpu(hdr->magic) != SSDFS_SNAPSHOT_RULES_MAGIC) {
		SSDFS_ERR("invalid snapshot rules magic %#x\n",
			  le32_to_cpu(hdr->magic));
		return -EIO;
	}

	if (le16_to_cpu(hdr->item_size) != item_size) {
		SSDFS_ERR("invalid item size %u\n",
			  le16_to_cpu(hdr->item_size));
		return -EIO;
	}

	items_count = le16_to_cpu(hdr->items_count);
	items_capacity = le16_to_cpu(hdr->items_capacity);

	if (items_count > items_capacity) {
		SSDFS_ERR("corrupted header: "
			  "items_count %u > items_capacity %u\n",
			  items_count, items_capacity);
		return -EIO;
	}

	area_size = le32_to_cpu(hdr->area_size);

	if (area_size != ((u32)items_capacity * item_size)) {
		SSDFS_ERR("corrupted header: "
			  "area_size %u, items_capacity %u, "
			  "item_size %zu\n",
			  area_size, items_capacity, item_size);
		return -EIO;
	}

	return 0;
}

static inline int ssdfs_read_snapshot_rules(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_log_footer *footer;
	struct ssdfs_snapshot_rules_list *rules_list;
	struct ssdfs_metadata_descriptor *meta_desc;
	struct ssdfs_snapshot_rules_header snap_rules_hdr;
	size_t sr_hdr_size = sizeof(struct ssdfs_snapshot_rules_header);
	struct ssdfs_snapshot_rule_info info;
	size_t rule_size = sizeof(struct ssdfs_snapshot_rule_info);
	struct pagevec pvec;
	u32 read_off;
	u32 read_bytes = 0;
	u32 bytes_count;
	u32 pages_count;
	u64 peb_id;
	struct page *page;
	void *kaddr;
	u32 csum = ~0;
	u16 items_count;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!fsi->devops->read);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	footer = SSDFS_LF(fsi->sbi.vs_buf);
	rules_list = &fsi->snapshots.rules_list;

	if (!ssdfs_log_footer_has_snapshot_rules(footer)) {
		SSDFS_ERR("footer hasn't snapshot rules table\n");
		return -EIO;
	}

	meta_desc = &footer->desc_array[SSDFS_SNAPSHOT_RULES_AREA_INDEX];
	read_off = le32_to_cpu(meta_desc->offset);
	bytes_count = le32_to_cpu(meta_desc->size);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(bytes_count >= INT_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	peb_id = fsi->sbi.last_log.peb_id;

	pages_count = (bytes_count + PAGE_SIZE - 1) >> PAGE_SHIFT;
	pagevec_init(&pvec);

	for (i = 0; i < pages_count; i++) {
		size_t size;

		size = min_t(size_t, (size_t)PAGE_SIZE,
				(size_t)(bytes_count - read_bytes));

		page = ssdfs_snapshot_rules_add_pagevec_page(&pvec);
		if (unlikely(IS_ERR_OR_NULL(page))) {
			err = !page ? -ENOMEM : PTR_ERR(page);
			SSDFS_ERR("fail to add pagevec page: err %d\n",
				  err);
			goto finish_read_snapshot_rules;
		}

		ssdfs_lock_page(page);

		kaddr = kmap_local_page(page);
		err = ssdfs_unaligned_read_buffer(fsi, peb_id,
						  read_off, kaddr, size);
		flush_dcache_page(page);
		kunmap_local(kaddr);

		if (unlikely(err)) {
			ssdfs_unlock_page(page);
			SSDFS_ERR("fail to read page: "
				  "peb %llu, offset %u, size %zu, err %d\n",
				  peb_id, read_off, size, err);
			goto finish_read_snapshot_rules;
		}

		ssdfs_unlock_page(page);

		read_off += size;
		read_bytes += size;
	}

	page = pvec.pages[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_lock_page(page);
	ssdfs_memcpy_from_page(&snap_rules_hdr, 0, sr_hdr_size,
				page, 0, PAGE_SIZE,
				sr_hdr_size);
	ssdfs_unlock_page(page);

	err = ssdfs_check_snapshot_rules_header(&snap_rules_hdr);
	if (unlikely(err)) {
		SSDFS_ERR("invalid snapshot rules header: "
			  "err %d\n", err);
		goto finish_read_snapshot_rules;
	}

	for (i = 0; i < pages_count; i++) {
		page = pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(i >= U16_MAX);
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_lock_page(page);
		kaddr = kmap_local_page(page);
		csum = crc32(csum, kaddr, le16_to_cpu(meta_desc->check.bytes));
		kunmap_local(kaddr);
		ssdfs_unlock_page(page);
	}

	if (csum != le32_to_cpu(meta_desc->check.csum)) {
		err = -EIO;
		SSDFS_ERR("invalid checksum\n");
		goto finish_read_snapshot_rules;
	}

	items_count = le16_to_cpu(snap_rules_hdr.items_count);
	read_off = sr_hdr_size;

	for (i = 0; i < items_count; i++) {
		struct ssdfs_snapshot_rule_item *ptr;

		err = ssdfs_unaligned_read_pagevec(&pvec, read_off,
						   rule_size, &info);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read a snapshot rule: "
				  "read_off %u, index %d, err %d\n",
				  read_off, i, err);
			goto finish_read_snapshot_rules;
		}

		ptr = ssdfs_snapshot_rule_alloc();
		if (!ptr) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate rule item\n");
			goto finish_read_snapshot_rules;
		}

		ssdfs_memcpy(&ptr->rule, 0, rule_size,
			     &info, 0, rule_size,
			     rule_size);

		ssdfs_snapshot_rules_list_add_tail(rules_list, ptr);

		read_off += rule_size;
	}

finish_read_snapshot_rules:
	ssdfs_snapshot_rules_pagevec_release(&pvec);
	return err;
}

static int ssdfs_init_recovery_environment(struct ssdfs_fs_info *fsi,
					   struct ssdfs_volume_header *vh,
					   u64 pebs_per_volume,
					   struct ssdfs_recovery_env *env)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !vh || !env);

	SSDFS_DBG("fsi %p, vh %p, env %p\n", fsi, vh, env);
#endif /* CONFIG_SSDFS_DEBUG */

	env->found = NULL;
	env->err = 0;
	env->fsi = fsi;
	env->pebs_per_volume = pebs_per_volume;

	atomic_set(&env->state, SSDFS_RECOVERY_UNKNOWN_STATE);

	err = ssdfs_init_sb_info(fsi, &env->sbi);
	if (likely(!err))
		err = ssdfs_init_sb_info(fsi, &env->sbi_backup);

	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare sb info: err %d\n", err);
		return err;
	}

	return 0;
}

static inline bool has_thread_finished(struct ssdfs_recovery_env *env)
{
	switch (atomic_read(&env->state)) {
	case SSDFS_RECOVERY_FAILED:
	case SSDFS_RECOVERY_FINISHED:
		return true;

	case SSDFS_START_RECOVERY:
		return false;
	}

	return true;
}

static inline u16 ssdfs_get_pebs_per_stripe(u64 pebs_per_volume,
					    u64 processed_pebs,
					    u32 fragments_count,
					    u16 pebs_per_fragment,
					    u16 stripes_per_fragment,
					    u16 pebs_per_stripe)
{
	u64 fragment_index;
	u64 pebs_per_aligned_fragments;
	u64 pebs_per_last_fragment;
	u64 calculated = U16_MAX;
	u32 remainder;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pebs_per_volume %llu, processed_pebs %llu, "
		  "fragments_count %u, pebs_per_fragment %u, "
		  "stripes_per_fragment %u, pebs_per_stripe %u\n",
		  pebs_per_volume, processed_pebs,
		  fragments_count, pebs_per_fragment,
		  stripes_per_fragment, pebs_per_stripe);
#endif /* CONFIG_SSDFS_DEBUG */

	if (fragments_count == 0) {
		SSDFS_WARN("invalid fragments_count %u\n",
			   fragments_count);
		return pebs_per_stripe;
	}

	fragment_index = processed_pebs / pebs_per_fragment;

	if (fragment_index >= fragments_count) {
		SSDFS_WARN("fragment_index %llu >= fragments_count %u\n",
			   fragment_index, fragments_count);
		return pebs_per_stripe;
	}

	if ((fragment_index + 1) < fragments_count)
		calculated = pebs_per_stripe;
	else {
		pebs_per_aligned_fragments = fragments_count - 1;
		pebs_per_aligned_fragments *= pebs_per_fragment;

		if (pebs_per_aligned_fragments >= pebs_per_volume) {
			SSDFS_WARN("calculated %llu >= pebs_per_volume %llu\n",
				   pebs_per_aligned_fragments,
				   pebs_per_volume);
			return 0;
		}

		pebs_per_last_fragment = pebs_per_volume -
						pebs_per_aligned_fragments;
		calculated = pebs_per_last_fragment / stripes_per_fragment;

		div_u64_rem(pebs_per_last_fragment,
			    (u64)stripes_per_fragment, &remainder);

		if (remainder != 0)
			calculated++;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("calculated: fragment_index %llu, pebs_per_stripe %llu\n",
		  fragment_index, calculated);

	BUG_ON(calculated > pebs_per_stripe);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u16)calculated;
}

static inline
void ssdfs_init_found_pebs_details(struct ssdfs_found_protected_pebs *ptr)
{
	int i, j;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);

	SSDFS_DBG("ptr %p\n", ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr->start_peb = U64_MAX;
	ptr->pebs_count = U32_MAX;
	ptr->lower_offset = U64_MAX;
	ptr->middle_offset = U64_MAX;
	ptr->upper_offset = U64_MAX;
	ptr->current_offset = U64_MAX;
	ptr->search_phase = SSDFS_RECOVERY_NO_SEARCH;

	for (i = 0; i < SSDFS_PROTECTED_PEB_CHAIN_MAX; i++) {
		struct ssdfs_found_protected_peb *cur_peb;

		cur_peb = &ptr->array[i];

		cur_peb->peb.peb_id = U64_MAX;
		cur_peb->peb.is_superblock_peb = false;
		cur_peb->peb.state = SSDFS_PEB_NOT_CHECKED;

		for (j = 0; j < SSDFS_SB_CHAIN_MAX; j++) {
			struct ssdfs_superblock_pebs_pair *cur_pair;
			struct ssdfs_found_peb *cur_sb_peb;

			cur_pair = &cur_peb->found.sb_pebs[j];

			cur_sb_peb = &cur_pair->pair[SSDFS_MAIN_SB_SEG];
			cur_sb_peb->peb_id = U64_MAX;
			cur_sb_peb->is_superblock_peb = false;
			cur_sb_peb->state = SSDFS_PEB_NOT_CHECKED;

			cur_sb_peb = &cur_pair->pair[SSDFS_COPY_SB_SEG];
			cur_sb_peb->peb_id = U64_MAX;
			cur_sb_peb->is_superblock_peb = false;
			cur_sb_peb->state = SSDFS_PEB_NOT_CHECKED;
		}
	}
}

static inline
int ssdfs_start_recovery_thread_activity(struct ssdfs_recovery_env *env,
				struct ssdfs_found_protected_pebs *found,
				u64 start_peb, u32 pebs_count, int search_phase)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || env->found || !found);

	SSDFS_DBG("env %p, found %p, start_peb %llu, "
		  "pebs_count %u, search_phase %#x\n",
		  env, found, start_peb,
		  pebs_count, search_phase);
#endif /* CONFIG_SSDFS_DEBUG */

	env->found = found;
	env->err = 0;

	if (search_phase == SSDFS_RECOVERY_FAST_SEARCH) {
		env->found->start_peb = start_peb;
		env->found->pebs_count = pebs_count;
	} else if (search_phase == SSDFS_RECOVERY_SLOW_SEARCH) {
		struct ssdfs_found_protected_peb *protected;
		u64 lower_peb_id;
		u64 upper_peb_id;
		u64 last_cno_peb_id;

		if (env->found->start_peb != start_peb ||
		    env->found->pebs_count != pebs_count) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("ignore search in fragment: "
				  "found (start_peb %llu, pebs_count %u), "
				  "start_peb %llu, pebs_count %u\n",
				  env->found->start_peb,
				  env->found->pebs_count,
				  start_peb, pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */
			env->err = -ENODATA;
			atomic_set(&env->state, SSDFS_RECOVERY_FAILED);
			return -ENODATA;
		}

		protected = &env->found->array[SSDFS_LOWER_PEB_INDEX];
		lower_peb_id = protected->peb.peb_id;

		protected = &env->found->array[SSDFS_UPPER_PEB_INDEX];
		upper_peb_id = protected->peb.peb_id;

		protected = &env->found->array[SSDFS_LAST_CNO_PEB_INDEX];
		last_cno_peb_id = protected->peb.peb_id;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("protected PEBs: "
			  "lower %llu, upper %llu, last_cno_peb %llu\n",
			  lower_peb_id, upper_peb_id, last_cno_peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

		if (lower_peb_id >= U64_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("ignore search in fragment: "
				  "found (start_peb %llu, pebs_count %u), "
				  "start_peb %llu, pebs_count %u, "
				  "lower %llu, upper %llu, "
				  "last_cno_peb %llu\n",
				  env->found->start_peb,
				  env->found->pebs_count,
				  start_peb, pebs_count,
				  lower_peb_id, upper_peb_id,
				  last_cno_peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			env->err = -ENODATA;
			atomic_set(&env->state, SSDFS_RECOVERY_FAILED);
			return -ENODATA;
		} else if (lower_peb_id == env->found->start_peb &&
			   upper_peb_id >= U64_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("ignore search in fragment: "
				  "found (start_peb %llu, pebs_count %u), "
				  "start_peb %llu, pebs_count %u, "
				  "lower %llu, upper %llu, "
				  "last_cno_peb %llu\n",
				  env->found->start_peb,
				  env->found->pebs_count,
				  start_peb, pebs_count,
				  lower_peb_id, upper_peb_id,
				  last_cno_peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			env->err = -ENODATA;
			atomic_set(&env->state, SSDFS_RECOVERY_FAILED);
			return -ENODATA;
		}
	} else {
		SSDFS_ERR("unexpected search phase %#x\n",
			  search_phase);
		return -ERANGE;
	}

	env->found->search_phase = search_phase;
	atomic_set(&env->state, SSDFS_START_RECOVERY);
	wake_up(&env->request_wait_queue);

	return 0;
}

static inline
int ssdfs_wait_recovery_thread_finish(struct ssdfs_fs_info *fsi,
				       struct ssdfs_recovery_env *env,
				       u32 stripe_id,
				       bool *has_sb_peb_found)
{
	struct ssdfs_segment_header *seg_hdr;
	wait_queue_head_t *wq;
	u64 cno1, cno2;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !has_sb_peb_found);

	SSDFS_DBG("env %p, has_sb_peb_found %p, stripe_id %u\n",
		  env, has_sb_peb_found, stripe_id);
#endif /* CONFIG_SSDFS_DEBUG */

	/*
	 * Do not change has_sb_peb_found
	 * if nothing has been found!!!!
	 */

	wq = &env->result_wait_queue;

	wait_event_interruptible_timeout(*wq,
			has_thread_finished(env),
			SSDFS_DEFAULT_TIMEOUT);

	switch (atomic_read(&env->state)) {
	case SSDFS_RECOVERY_FINISHED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("stripe %u has SB segment\n",
			  stripe_id);
#endif /* CONFIG_SSDFS_DEBUG */

		seg_hdr = SSDFS_SEG_HDR(fsi->sbi.vh_buf);
		cno1 = le64_to_cpu(seg_hdr->cno);
		seg_hdr = SSDFS_SEG_HDR(env->sbi.vh_buf);
		cno2 = le64_to_cpu(seg_hdr->cno);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cno1 %llu, cno2 %llu\n",
			  cno1, cno2);
#endif /* CONFIG_SSDFS_DEBUG */

		if (cno1 <= cno2) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("copy sb info: "
				  "stripe_id %u\n",
				  stripe_id);
#endif /* CONFIG_SSDFS_DEBUG */
			ssdfs_copy_sb_info(fsi, env);
			*has_sb_peb_found = true;
		}
		break;

	case SSDFS_RECOVERY_FAILED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("stripe %u has nothing\n",
			  stripe_id);
#endif /* CONFIG_SSDFS_DEBUG */
		break;

	case SSDFS_START_RECOVERY:
		err = -ERANGE;
		SSDFS_WARN("thread is working too long: "
			   "stripe %u\n",
			   stripe_id);
		atomic_set(&env->state, SSDFS_RECOVERY_FAILED);
		break;

	default:
		BUG();
	}

	env->found = NULL;
	return err;
}

int ssdfs_gather_superblock_info(struct ssdfs_fs_info *fsi, int silent)
{
	struct ssdfs_volume_header *vh;
	struct ssdfs_recovery_env *array = NULL;
	struct ssdfs_found_protected_pebs *found_pebs = NULL;
	u64 dev_size;
	u32 erasesize;
	u64 pebs_per_volume;
	u32 fragments_count = 0;
	u16 pebs_per_fragment = 0;
	u16 stripes_per_fragment = 0;
	u16 pebs_per_stripe = 0;
	u32 stripes_count = 0;
	u32 threads_count;
	u32 jobs_count;
	u32 processed_stripes = 0;
	u64 processed_pebs = 0;
	bool has_sb_peb_found1, has_sb_peb_found2;
	bool has_iteration_succeeded;
	u16 calculated;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("fsi %p, silent %#x\n", fsi, silent);
#else
	SSDFS_DBG("fsi %p, silent %#x\n", fsi, silent);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	err = ssdfs_init_sb_info(fsi, &fsi->sbi);
	if (likely(!err)) {
		err = ssdfs_init_sb_info(fsi, &fsi->sbi_backup);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare sb info: err %d\n", err);
		goto free_buf;
	}

	err = ssdfs_find_any_valid_volume_header(fsi,
						 SSDFS_RESERVED_VBR_SIZE,
						 silent);
	if (err)
		goto forget_buf;

	vh = SSDFS_VH(fsi->sbi.vh_buf);
	fragments_count = le32_to_cpu(vh->maptbl.fragments_count);
	pebs_per_fragment = le16_to_cpu(vh->maptbl.pebs_per_fragment);
	pebs_per_stripe = le16_to_cpu(vh->maptbl.pebs_per_stripe);
	stripes_per_fragment = le16_to_cpu(vh->maptbl.stripes_per_fragment);

	dev_size = fsi->devops->device_size(fsi->sb);
	erasesize = 1 << vh->log_erasesize;
	pebs_per_volume = div_u64(dev_size, erasesize);

	stripes_count = fragments_count * stripes_per_fragment;
	threads_count = min_t(u32, SSDFS_RECOVERY_THREADS, stripes_count);

	has_sb_peb_found1 = false;
	has_sb_peb_found2 = false;

	found_pebs = ssdfs_recovery_kcalloc(stripes_count,
				sizeof(struct ssdfs_found_protected_pebs),
				GFP_KERNEL);
	if (!found_pebs) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate the PEBs details array\n");
		goto free_environment;
	}

	for (i = 0; i < stripes_count; i++) {
		ssdfs_init_found_pebs_details(&found_pebs[i]);
	}

	array = ssdfs_recovery_kcalloc(threads_count,
				sizeof(struct ssdfs_recovery_env),
				GFP_KERNEL);
	if (!array) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate the environment\n");
		goto free_environment;
	}

	for (i = 0; i < threads_count; i++) {
		err = ssdfs_init_recovery_environment(fsi, vh,
					pebs_per_volume, &array[i]);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare sb info: err %d\n", err);

			for (; i >= 0; i--) {
				ssdfs_destruct_sb_info(&array[i].sbi);
				ssdfs_destruct_sb_info(&array[i].sbi_backup);
			}

			goto free_environment;
		}
	}

	for (i = 0; i < threads_count; i++) {
		err = ssdfs_recovery_start_thread(&array[i], i);
		if (unlikely(err)) {
			if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
			} else {
				SSDFS_ERR("fail to start thread: "
					  "id %u, err %d\n",
					  i, err);
			}

			for (; i >= 0; i--)
				ssdfs_recovery_stop_thread(&array[i]);

			goto destruct_sb_info;
		}
	}

	jobs_count = 1;

	processed_stripes = 0;
	processed_pebs = 0;

	while (processed_pebs < pebs_per_volume) {
		/* Fast search phase */
		has_iteration_succeeded = false;

		if (processed_stripes >= stripes_count) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("processed_stripes %u >= stripes_count %u\n",
				  processed_stripes, stripes_count);
#endif /* CONFIG_SSDFS_DEBUG */
			goto try_slow_search;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("FAST_SEARCH: jobs_count %u\n", jobs_count);
#endif /* CONFIG_SSDFS_DEBUG */

		for (i = 0; i < jobs_count; i++) {
			calculated =
				ssdfs_get_pebs_per_stripe(pebs_per_volume,
							  processed_pebs,
							  fragments_count,
							  pebs_per_fragment,
							  stripes_per_fragment,
							  pebs_per_stripe);

			if ((processed_pebs + calculated) > pebs_per_volume)
				calculated = pebs_per_volume - processed_pebs;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("i %d, start_peb %llu, pebs_count %u\n",
				  i, processed_pebs, calculated);
			SSDFS_DBG("pebs_per_volume %llu, processed_pebs %llu\n",
				  pebs_per_volume, processed_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

			err = ssdfs_start_recovery_thread_activity(&array[i],
					&found_pebs[processed_stripes + i],
					processed_pebs, calculated,
					SSDFS_RECOVERY_FAST_SEARCH);
			if (err) {
				SSDFS_ERR("fail to start thread's activity: "
					  "err %d\n", err);
				goto finish_sb_peb_search;
			}

			processed_pebs += calculated;
		}

		for (i = 0; i < jobs_count; i++) {
			err = ssdfs_wait_recovery_thread_finish(fsi,
						&array[i],
						processed_stripes + i,
						&has_iteration_succeeded);
			if (unlikely(err)) {
				has_sb_peb_found1 = false;
				goto finish_sb_peb_search;
			}

			switch (array[i].err) {
			case 0:
				/* SB PEB has been found */
				/* continue logic */
				break;

			case -ENODATA:
			case -ENOENT:
			case -EAGAIN:
			case -E2BIG:
				/* SB PEB has not been found */
				/* continue logic */
				break;

			default:
				/* Something is going wrong */
				/* stop execution */
				err = array[i].err;
				has_sb_peb_found1 = false;
				SSDFS_ERR("fail to find valid SB PEB: "
					  "err %d\n", err);
				goto finish_sb_peb_search;
			}
		}

		if (has_iteration_succeeded) {
			has_sb_peb_found1 = true;
			goto finish_sb_peb_search;
		}

		processed_stripes += jobs_count;

		jobs_count <<= 1;
		jobs_count = min_t(u32, jobs_count, threads_count);
		jobs_count = min_t(u32, jobs_count,
				   stripes_count - processed_stripes);
	};

try_slow_search:
	jobs_count = 1;

	processed_stripes = 0;
	processed_pebs = 0;

	while (processed_pebs < pebs_per_volume) {
		/* Slow search phase */
		has_iteration_succeeded = false;

		if (processed_stripes >= stripes_count) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("processed_stripes %u >= stripes_count %u\n",
				  processed_stripes, stripes_count);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_sb_peb_search;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("SLOW_SEARCH: jobs_count %u\n", jobs_count);
#endif /* CONFIG_SSDFS_DEBUG */

		for (i = 0; i < jobs_count; i++) {
			calculated =
				ssdfs_get_pebs_per_stripe(pebs_per_volume,
							  processed_pebs,
							  fragments_count,
							  pebs_per_fragment,
							  stripes_per_fragment,
							  pebs_per_stripe);

			if ((processed_pebs + calculated) > pebs_per_volume)
				calculated = pebs_per_volume - processed_pebs;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("i %d, start_peb %llu, pebs_count %u\n",
				  i, processed_pebs, calculated);
			SSDFS_DBG("pebs_per_volume %llu, processed_pebs %llu\n",
				  pebs_per_volume, processed_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

			err = ssdfs_start_recovery_thread_activity(&array[i],
					&found_pebs[processed_stripes + i],
					processed_pebs, calculated,
					SSDFS_RECOVERY_SLOW_SEARCH);
			if (err == -ENODATA) {
				/* thread continues to sleep */
				/* continue logic */
			} else if (err) {
				SSDFS_ERR("fail to start thread's activity: "
					  "err %d\n", err);
				goto finish_sb_peb_search;
			}

			processed_pebs += calculated;
		}

		for (i = 0; i < jobs_count; i++) {
			err = ssdfs_wait_recovery_thread_finish(fsi,
						&array[i],
						processed_stripes + i,
						&has_iteration_succeeded);
			if (unlikely(err)) {
				has_sb_peb_found2 = false;
				goto finish_sb_peb_search;
			}

			switch (array[i].err) {
			case 0:
				/* SB PEB has been found */
				/* continue logic */
				break;

			case -ENODATA:
			case -ENOENT:
			case -EAGAIN:
			case -E2BIG:
				/* SB PEB has not been found */
				/* continue logic */
				break;

			default:
				/* Something is going wrong */
				/* stop execution */
				err = array[i].err;
				has_sb_peb_found2 = false;
				SSDFS_ERR("fail to find valid SB PEB: "
					  "err %d\n", err);
				goto finish_sb_peb_search;
			}
		}

		if (has_iteration_succeeded) {
			has_sb_peb_found2 = true;
			goto finish_sb_peb_search;
		}

		processed_stripes += jobs_count;

		jobs_count <<= 1;
		jobs_count = min_t(u32, jobs_count, threads_count);
		jobs_count = min_t(u32, jobs_count,
				   stripes_count - processed_stripes);
	};

finish_sb_peb_search:
	for (i = 0; i < threads_count; i++)
		ssdfs_recovery_stop_thread(&array[i]);

destruct_sb_info:
	for (i = 0; i < threads_count; i++) {
		ssdfs_destruct_sb_info(&array[i].sbi);
		ssdfs_destruct_sb_info(&array[i].sbi_backup);
	}

free_environment:
	if (found_pebs) {
		ssdfs_recovery_kfree(found_pebs);
		found_pebs = NULL;
	}

	if (array) {
		ssdfs_recovery_kfree(array);
		array = NULL;
	}

	switch (err) {
	case 0:
		/* SB PEB has been found */
		/* continue logic */
		break;

	case -ENODATA:
	case -ENOENT:
	case -EAGAIN:
	case -E2BIG:
		/* SB PEB has not been found */
		/* continue logic */
		break;

	default:
		/* Something is going wrong */
		/* stop execution */
		SSDFS_ERR("fail to find valid SB PEB: err %d\n", err);
		goto forget_buf;
	}

	if (has_sb_peb_found1)
		SSDFS_DBG("FAST_SEARCH: found SB seg\n");
	else if (has_sb_peb_found2)
		SSDFS_DBG("SLOW_SEARCH: found SB seg\n");

	if (!has_sb_peb_found1 && !has_sb_peb_found2) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_ERR("unable to find latest valid sb segment: "
			  "trying old algorithm!!!\n");
		BUG();
#else
		SSDFS_ERR("unable to find latest valid sb segment: "
			  "trying old algorithm!!!\n");
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_find_any_valid_sb_segment(fsi, 0);
		if (err)
			goto forget_buf;

		err = ssdfs_find_latest_valid_sb_segment(fsi);
		if (err)
			goto forget_buf;
	}

	err = ssdfs_find_latest_valid_sb_info2(fsi);
	if (err) {
		SSDFS_ERR("unable to find latest valid sb info: "
			  "trying old algorithm!!!\n");

		err = ssdfs_find_latest_valid_sb_info(fsi);
		if (err)
			goto forget_buf;
	}

	err = ssdfs_initialize_fs_info(fsi);
	if (err && err != -EROFS)
		goto forget_buf;

	err = ssdfs_read_maptbl_cache(fsi);
	if (err)
		goto forget_buf;

	if (is_ssdfs_snapshot_rules_exist(fsi)) {
		err = ssdfs_read_snapshot_rules(fsi);
		if (err)
			goto forget_buf;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("DONE: gather superblock info\n");
#else
	SSDFS_DBG("DONE: gather superblock info\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;

forget_buf:
	fsi->vh = NULL;
	fsi->vs = NULL;

free_buf:
	ssdfs_destruct_sb_info(&fsi->sbi);
	ssdfs_destruct_sb_info(&fsi->sbi_backup);
	return err;
}
