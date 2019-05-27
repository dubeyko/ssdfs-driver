//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/volume_header.c - operations with volume header.
 *
 * Copyright (c) 2014-2018 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2009-2018, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <Vyacheslav.Dubeyko@wdc.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
 */

#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/pagevec.h>

#include "peb_mapping_table_cache.h"
#include "ssdfs.h"

#include <trace/events/ssdfs.h>

/*
 * is_ssdfs_segment_header_magic_valid() - check segment header's magic
 * @hdr: segment header
 */
bool is_ssdfs_segment_header_magic_valid(struct ssdfs_segment_header *hdr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	return SSDFS_SEG_HDR_MAGIC(hdr) == SSDFS_SEGMENT_HDR_MAGIC;
}

/*
 * is_ssdfs_volume_header_csum_valid() - check volume header checksum
 * @vh_buf: volume header buffer
 * @buf_size: size of buffer in bytes
 */
bool is_ssdfs_volume_header_csum_valid(void *vh_buf, size_t buf_size)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	return is_csum_valid(&SSDFS_VH(vh_buf)->check, vh_buf, buf_size);
}

/*
 * is_ssdfs_volume_header_consistent() - check volume header consistency
 * @vh: volume header
 * @dev_size: partition size in bytes
 *
 * RETURN:
 * [true]  - volume header is consistent.
 * [false] - volume header is corrupted.
 */
bool is_ssdfs_volume_header_consistent(struct ssdfs_volume_header *vh,
					u64 dev_size)
{
	u32 page_size;
	u32 erase_size;
	u32 seg_size;
	u32 pebs_per_seg;
	u64 leb_array[SSDFS_SB_CHAIN_MAX * SSDFS_SB_SEG_COPY_MAX] = {0};
	u64 peb_array[SSDFS_SB_CHAIN_MAX * SSDFS_SB_SEG_COPY_MAX] = {0};
	int array_index = 0;
	int i, j, k;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!vh);
#endif /* CONFIG_SSDFS_DEBUG */

	page_size = 1 << vh->log_pagesize;
	erase_size = 1 << vh->log_erasesize;
	seg_size = 1 << vh->log_segsize;
	pebs_per_seg = 1 << vh->log_pebs_per_seg;

	if (page_size >= erase_size) {
		SSDFS_DBG("page_size %u >= erase_size %u\n",
			  page_size, erase_size);
		return false;
	}

	switch (page_size) {
	case SSDFS_512B:
	case SSDFS_2KB:
	case SSDFS_4KB:
	case SSDFS_8KB:
	case SSDFS_16KB:
		/* do nothing */
		break;

	default:
		SSDFS_DBG("unexpected page_size %u\n", page_size);
		return false;
	}

	switch (erase_size) {
	case SSDFS_128KB:
	case SSDFS_256KB:
	case SSDFS_512KB:
	case SSDFS_2MB:
	case SSDFS_8MB:
		/* do nothing */
		break;

	default:
		SSDFS_DBG("unexpected erase_size %u\n", erase_size);
		return false;
	};

	if (seg_size < erase_size) {
		SSDFS_DBG("seg_size %u < erase_size %u\n",
			  seg_size, erase_size);
		return false;
	}

	if (pebs_per_seg != (seg_size >> vh->log_erasesize)) {
		SSDFS_DBG("pebs_per_seg %u != (seg_size %u / erase_size %u)\n",
			  pebs_per_seg, seg_size, erase_size);
		return false;
	}

	if (seg_size >= dev_size) {
		SSDFS_DBG("seg_size %u >= dev_size %llu\n",
			  seg_size, dev_size);
		return false;
	}

	for (i = 0; i < SSDFS_SB_CHAIN_MAX; i++) {
		for (j = 0; j < SSDFS_SB_SEG_COPY_MAX; j++) {
			u64 leb_id = le64_to_cpu(vh->sb_pebs[i][j].leb_id);
			u64 peb_id = le64_to_cpu(vh->sb_pebs[i][j].peb_id);

			for (k = 0; k < array_index; k++) {
				if (leb_id == leb_array[k]) {
					SSDFS_DBG("corrupted LEB number %llu\n",
						  leb_id);
					return false;
				}

				if (peb_id == peb_array[k]) {
					SSDFS_DBG("corrupted PEB number %llu\n",
						  peb_id);
					return false;
				}
			}

			if (i == SSDFS_PREV_SB_SEG &&
			    leb_id == U64_MAX && peb_id == U64_MAX) {
				/* prev id is U64_MAX after volume creation */
				continue;
			}

			if (leb_id >= (dev_size >> vh->log_erasesize)) {
				SSDFS_DBG("corrupted LEB number %llu\n",
					  leb_id);
				return false;
			}

			leb_array[array_index] = leb_id;
			peb_array[array_index] = peb_id;

			array_index++;
		}
	}

	return true;
}

/*
 * ssdfs_check_segment_header() - check segment header consistency
 * @fsi: pointer on shared file system object
 * @hdr: segment header
 * @silent: show error or not?
 *
 * This function checks consistency of segment header.
 *
 * RETURN:
 * [success] - segment header is consistent.
 * [failure] - error code:
 *
 * %-ENODATA     - valid magic doesn't detected.
 * %-EIO         - segment header is corrupted.
 */
static
int ssdfs_check_segment_header(struct ssdfs_fs_info *fsi,
				struct ssdfs_segment_header *hdr,
				bool silent)
{
	struct ssdfs_volume_header *vh;
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	bool major_magic_valid, minor_magic_valid;
	u64 dev_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, hdr %p, silent %#x\n", fsi, hdr, silent);

	vh = SSDFS_VH(hdr);

	major_magic_valid = is_ssdfs_magic_valid(&vh->magic);
	minor_magic_valid = is_ssdfs_segment_header_magic_valid(hdr);

	if (!major_magic_valid && !minor_magic_valid) {
		if (!silent)
			SSDFS_ERR("valid magic doesn't detected\n");
		else
			SSDFS_DBG("valid magic doesn't detected\n");
		return -ENODATA;
	} else if (!major_magic_valid) {
		if (!silent)
			SSDFS_ERR("invalid SSDFS magic signature\n");
		else
			SSDFS_DBG("invalid SSDFS magic signature\n");
		return -EIO;
	} else if (!minor_magic_valid) {
		if (!silent)
			SSDFS_ERR("invalid segment header magic signature\n");
		else
			SSDFS_DBG("invalid segment header magic signature\n");
		return -EIO;
	}

	if (!is_ssdfs_volume_header_csum_valid(hdr, hdr_size)) {
		if (!silent)
			SSDFS_ERR("invalid checksum of volume header\n");
		else
			SSDFS_DBG("invalid checksum of volume header\n");
		return -EIO;
	}

	dev_size = fsi->devops->device_size(fsi->sb);
	if (!is_ssdfs_volume_header_consistent(vh, dev_size)) {
		if (!silent)
			SSDFS_ERR("volume header is corrupted\n");
		else
			SSDFS_DBG("volume header is corrupted\n");
		return -EIO;
	}

	if (SSDFS_VH_CNO(vh) > SSDFS_SEG_CNO(hdr)) {
		if (!silent)
			SSDFS_ERR("invalid checkpoint/timestamp\n");
		else
			SSDFS_DBG("invalid checkpoint/timestamp\n");
		return -EIO;
	}

	if (le16_to_cpu(hdr->log_pages) > fsi->pages_per_peb) {
		if (!silent) {
			SSDFS_ERR("log_pages %u > pages_per_peb %u\n",
				  le16_to_cpu(hdr->log_pages),
				  fsi->pages_per_peb);
		} else {
			SSDFS_DBG("log_pages %u > pages_per_peb %u\n",
				  le16_to_cpu(hdr->log_pages),
				  fsi->pages_per_peb);
		}
		return -EIO;
	}

	if (le16_to_cpu(hdr->seg_type) > SSDFS_LAST_KNOWN_SEG_TYPE) {
		if (!silent) {
			SSDFS_ERR("unknown seg_type %#x\n",
				  le16_to_cpu(hdr->seg_type));
		} else {
			SSDFS_DBG("unknown seg_type %#x\n",
				  le16_to_cpu(hdr->seg_type));
		}
		return -EIO;
	}

	if (le32_to_cpu(hdr->seg_flags) & ~SSDFS_SEG_HDR_FLAG_MASK) {
		if (!silent) {
			SSDFS_ERR("corrupted seg_flags %#x\n",
				  le32_to_cpu(hdr->seg_flags));
		} else {
			SSDFS_DBG("corrupted seg_flags %#x\n",
				  le32_to_cpu(hdr->seg_flags));
		}
		return -EIO;
	}

	return 0;
}

/* TODO: fsi->sbi.vh_buf -> ssdfs_read_checked_volume_header */

/*
 * ssdfs_read_checked_segment_header() - read and check segment header
 * @fsi: pointer on shared file system object
 * @peb_id: PEB identification number
 * @pages_off: offset from PEB's begin in pages
 * @buf: buffer
 * @silent: show error or not?
 *
 * This function reads and checks consistency of segment header.
 *
 * RETURN:
 * [success] - segment header is consistent.
 * [failure] - error code:
 *
 * %-ENODATA     - valid magic doesn't detected.
 * %-EIO         - segment header is corrupted.
 */
int ssdfs_read_checked_segment_header(struct ssdfs_fs_info *fsi,
					u64 peb_id, u32 pages_off,
					void *buf, bool silent)
{
	struct ssdfs_segment_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	size_t read_bytes;
	int err;

	SSDFS_DBG("peb_id %llu, pages_off %u, buf %p, silent %#x\n",
		  peb_id, pages_off, buf, silent);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!fsi->devops->read);
	BUG_ON(!buf);
	BUG_ON(pages_off >= fsi->pages_per_peb);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_aligned_read_buffer(fsi, peb_id,
					pages_off * fsi->pagesize,
					buf, hdr_size,
					&read_bytes);
	if (unlikely(err)) {
		if (!silent) {
			SSDFS_ERR("fail to read segment header: "
				  "peb_id %llu, pages_off %u, err %d\n",
				  peb_id, pages_off, err);
		} else {
			SSDFS_DBG("fail to read segment header: "
				  "peb_id %llu, pages_off %u, err %d\n",
				  peb_id, pages_off, err);
		}
		return err;
	}

	if (unlikely(read_bytes != hdr_size)) {
		if (!silent) {
			SSDFS_ERR("fail to read segment header: "
				  "peb_id %llu, pages_off %u: "
				  "read_bytes %zu != hdr_size %zu\n",
				  peb_id, pages_off, read_bytes, hdr_size);
		} else {
			SSDFS_DBG("fail to read segment header: "
				  "peb_id %llu, pages_off %u: "
				  "read_bytes %zu != hdr_size %zu\n",
				  peb_id, pages_off, read_bytes, hdr_size);
		}
		return -ERANGE;
	}

	hdr = SSDFS_SEG_HDR(buf);

	err = ssdfs_check_segment_header(fsi, hdr, silent);
	if (err) {
		if (!silent) {
			SSDFS_ERR("segment header is corrupted: "
				  "peb_id %llu, pages_off %u, err %d\n",
				  peb_id, pages_off, err);
		} else {
			SSDFS_DBG("segment header is corrupted: "
				  "peb_id %llu, pages_off %u, err %d\n",
				  peb_id, pages_off, err);
		}
		return err;
	}

	return 0;
}

/*
 * ssdfs_create_volume_header() - initialize volume header from the scratch
 * @fsi: pointer on shared file system object
 * @vh: volume header
 */
void ssdfs_create_volume_header(struct ssdfs_fs_info *fsi,
				struct ssdfs_volume_header *vh)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !vh);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, vh %p\n", fsi, vh);

	vh->magic.common = cpu_to_le32(SSDFS_SUPER_MAGIC);
	vh->magic.key = cpu_to_le16(SSDFS_SEGMENT_HDR_MAGIC);
	vh->magic.version.major = SSDFS_MAJOR_REVISION;
	vh->magic.version.minor = SSDFS_MINOR_REVISION;

	vh->log_pagesize = fsi->log_pagesize;
	vh->log_erasesize = fsi->log_erasesize;
	vh->log_segsize = fsi->log_segsize;
	vh->log_pebs_per_seg = fsi->log_pebs_per_seg;

	vh->create_time = cpu_to_le64(fsi->fs_ctime);
	vh->create_cno = cpu_to_le64(fsi->fs_cno);
}

/*
 * ssdfs_store_sb_segs_array() - store sb segments array
 * @fsi: pointer on shared file system object
 * @vh: volume header
 */
static inline
void ssdfs_store_sb_segs_array(struct ssdfs_fs_info *fsi,
				struct ssdfs_volume_header *vh)
{
	int i, j;

	SSDFS_DBG("fsi %p, vh %p\n", fsi, vh);

	down_read(&fsi->sb_segs_sem);

	for (i = SSDFS_CUR_SB_SEG; i < SSDFS_SB_CHAIN_MAX; i++) {
		for (j = SSDFS_MAIN_SB_SEG; j < SSDFS_SB_SEG_COPY_MAX; j++) {
			vh->sb_pebs[i][j].leb_id =
				cpu_to_le64(fsi->sb_lebs[i][j]);
			vh->sb_pebs[i][j].peb_id =
				cpu_to_le64(fsi->sb_pebs[i][j]);
		}
	}

	up_read(&fsi->sb_segs_sem);
}

/*
 * ssdfs_prepare_volume_header_for_commit() - prepare volume header for commit
 * @fsi: pointer on shared file system object
 * @vh: volume header
 */
int ssdfs_prepare_volume_header_for_commit(struct ssdfs_fs_info *fsi,
					   struct ssdfs_volume_header *vh)
{
#ifdef CONFIG_SSDFS_DEBUG
	struct super_block *sb = fsi->sb;
	u64 dev_size;
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, vh %p\n", fsi, vh);

	ssdfs_store_sb_segs_array(fsi, vh);

#ifdef CONFIG_SSDFS_DEBUG
	dev_size = fsi->devops->device_size(sb);
	if (!is_ssdfs_volume_header_consistent(vh, dev_size)) {
		SSDFS_ERR("volume header is inconsistent\n");
		return -EIO;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_prepare_segment_header_for_commit() - prepare segment header
 * @fsi: pointer on shared file system object
 * @log_pages: full log pages count
 * @seg_type: segment type
 * @seg_flags: segment flags
 * @hdr: segment header [out]
 */
int ssdfs_prepare_segment_header_for_commit(struct ssdfs_fs_info *fsi,
					    u32 log_pages,
					    u16 seg_type,
					    u32 seg_flags,
					    struct ssdfs_segment_header *hdr)
{
	u16 data_size = sizeof(struct ssdfs_segment_header);
	int err;

	SSDFS_DBG("fsi %p, hdr %p, "
		  "log_pages %u, seg_type %#x, seg_flags %#x\n",
		  fsi, hdr, log_pages, seg_type, seg_flags);

	hdr->timestamp = fsi->vs->timestamp;
	hdr->cno = fsi->vs->cno;

	if (log_pages > fsi->pages_per_seg || log_pages > U16_MAX) {
		SSDFS_ERR("invalid value of log_pages %u\n", log_pages);
		return -EINVAL;
	}

	hdr->log_pages = cpu_to_le16((u16)log_pages);

	if (seg_type == SSDFS_UNKNOWN_SEG_TYPE ||
	    seg_type > SSDFS_LAST_KNOWN_SEG_TYPE) {
		SSDFS_ERR("invalid value of seg_type %#x\n", seg_type);
		return -EINVAL;
	}

	hdr->seg_type = cpu_to_le16(seg_type);
	hdr->seg_flags = cpu_to_le32(seg_flags);

	hdr->volume_hdr.check.bytes = cpu_to_le16(data_size);
	hdr->volume_hdr.check.flags = cpu_to_le16(SSDFS_CRC32);

	err = ssdfs_calculate_csum(&hdr->volume_hdr.check,
				   hdr, data_size);
	if (unlikely(err)) {
		SSDFS_ERR("unable to calculate checksum: err %d\n", err);
		return err;
	}

	return 0;
}
