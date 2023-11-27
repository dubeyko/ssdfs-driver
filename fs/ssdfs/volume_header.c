// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/volume_header.c - operations with volume header.
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
 * __is_ssdfs_segment_header_magic_valid() - check segment header's magic
 * @magic: pointer on magic value
 */
bool __is_ssdfs_segment_header_magic_valid(struct ssdfs_signature *magic)
{
	return le16_to_cpu(magic->key) == SSDFS_SEGMENT_HDR_MAGIC;
}

/*
 * is_ssdfs_segment_header_magic_valid() - check segment header's magic
 * @hdr: segment header
 */
bool is_ssdfs_segment_header_magic_valid(struct ssdfs_segment_header *hdr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	return __is_ssdfs_segment_header_magic_valid(&hdr->volume_hdr.magic);
}

/*
 * is_ssdfs_partial_log_header_magic_valid() - check partial log header's magic
 * @magic: pointer on magic value
 */
bool is_ssdfs_partial_log_header_magic_valid(struct ssdfs_signature *magic)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!magic);
#endif /* CONFIG_SSDFS_DEBUG */

	return le16_to_cpu(magic->key) == SSDFS_PARTIAL_LOG_HDR_MAGIC;
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
 * is_ssdfs_partial_log_header_csum_valid() - check partial log header checksum
 * @plh_buf: partial log header buffer
 * @buf_size: size of buffer in bytes
 */
bool is_ssdfs_partial_log_header_csum_valid(void *plh_buf, size_t buf_size)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!plh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	return is_csum_valid(&SSDFS_PLH(plh_buf)->check, plh_buf, buf_size);
}

static inline
void ssdfs_show_volume_header(struct ssdfs_volume_header *hdr)
{
	SSDFS_ERR("MAGIC: common %#x, key %#x, "
		  "version (major %u, minor %u)\n",
		  le32_to_cpu(hdr->magic.common),
		  le16_to_cpu(hdr->magic.key),
		  hdr->magic.version.major,
		  hdr->magic.version.minor);
	SSDFS_ERR("CHECK: bytes %u, flags %#x, csum %#x\n",
		  le16_to_cpu(hdr->check.bytes),
		  le16_to_cpu(hdr->check.flags),
		  le32_to_cpu(hdr->check.csum));
	SSDFS_ERR("KEY VALUES: log_pagesize %u, log_erasesize %u, "
		  "log_segsize %u, log_pebs_per_seg %u, "
		  "megabytes_per_peb %u, pebs_per_seg %u, "
		  "create_time %llu, create_cno %llu, flags %#x\n",
		  hdr->log_pagesize,
		  hdr->log_erasesize,
		  hdr->log_segsize,
		  hdr->log_pebs_per_seg,
		  le16_to_cpu(hdr->megabytes_per_peb),
		  le16_to_cpu(hdr->pebs_per_seg),
		  le64_to_cpu(hdr->create_time),
		  le64_to_cpu(hdr->create_cno),
		  le32_to_cpu(hdr->flags));
}

/*
 * is_ssdfs_volume_header_consistent() - check volume header consistency
 * @fsi: pointer on shared file system object
 * @vh: volume header
 * @dev_size: partition size in bytes
 *
 * RETURN:
 * [true]  - volume header is consistent.
 * [false] - volume header is corrupted.
 */
bool is_ssdfs_volume_header_consistent(struct ssdfs_fs_info *fsi,
					struct ssdfs_volume_header *vh,
					u64 dev_size)
{
	u32 page_size;
	u64 erase_size;
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
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page_size %u >= erase_size %llu\n",
			  page_size, erase_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	switch (page_size) {
	case SSDFS_4KB:
	case SSDFS_8KB:
	case SSDFS_16KB:
	case SSDFS_32KB:
		/* do nothing */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unexpected page_size %u\n", page_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	switch (erase_size) {
	case SSDFS_128KB:
	case SSDFS_256KB:
	case SSDFS_512KB:
	case SSDFS_2MB:
	case SSDFS_8MB:
	case SSDFS_16MB:
	case SSDFS_32MB:
	case SSDFS_64MB:
	case SSDFS_128MB:
	case SSDFS_256MB:
	case SSDFS_512MB:
	case SSDFS_1GB:
	case SSDFS_2GB:
	case SSDFS_8GB:
	case SSDFS_16GB:
	case SSDFS_32GB:
	case SSDFS_64GB:
		/* do nothing */
		break;

	default:
		if (fsi->is_zns_device) {
			u64 zone_size = le16_to_cpu(vh->megabytes_per_peb);

			zone_size *= SSDFS_1MB;

			if (fsi->zone_size != zone_size) {
				SSDFS_ERR("invalid zone size: "
					  "size1 %llu != size2 %llu\n",
					  fsi->zone_size, zone_size);
				return -ERANGE;
			}

			erase_size = zone_size;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unexpected erase_size %llu\n", erase_size);
#endif /* CONFIG_SSDFS_DEBUG */
			return false;
		}
	};

	if (seg_size < erase_size) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg_size %u < erase_size %llu\n",
			  seg_size, erase_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	if (pebs_per_seg != (seg_size >> vh->log_erasesize)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("pebs_per_seg %u != (seg_size %u / erase_size %llu)\n",
			  pebs_per_seg, seg_size, erase_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	if (seg_size >= dev_size) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg_size %u >= dev_size %llu\n",
			  seg_size, dev_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	for (i = 0; i < SSDFS_SB_CHAIN_MAX; i++) {
		for (j = 0; j < SSDFS_SB_SEG_COPY_MAX; j++) {
			u64 leb_id = le64_to_cpu(vh->sb_pebs[i][j].leb_id);
			u64 peb_id = le64_to_cpu(vh->sb_pebs[i][j].peb_id);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("i %d, j %d, LEB %llu, PEB %llu\n",
				  i, j, leb_id, peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

			for (k = 0; k < array_index; k++) {
				if (leb_id == leb_array[k]) {
#ifdef CONFIG_SSDFS_DEBUG
					SSDFS_DBG("corrupted LEB number: "
						  "leb_id %llu, "
						  "leb_array[%d] %llu\n",
						  leb_id, k,
						  leb_array[k]);
#endif /* CONFIG_SSDFS_DEBUG */
					return false;
				}

				if (peb_id == peb_array[k]) {
#ifdef CONFIG_SSDFS_DEBUG
					SSDFS_DBG("corrupted PEB number: "
						  "peb_id %llu, "
						  "peb_array[%d] %llu\n",
						  peb_id, k,
						  peb_array[k]);
#endif /* CONFIG_SSDFS_DEBUG */
					return false;
				}
			}

			if (i == SSDFS_PREV_SB_SEG &&
			    leb_id == U64_MAX && peb_id == U64_MAX) {
				/* prev id is U64_MAX after volume creation */
				continue;
			}

			if (i == SSDFS_RESERVED_SB_SEG &&
			    leb_id == U64_MAX && peb_id == U64_MAX) {
				/*
				 * The reserved seg could be U64_MAX
				 * if there is no clean segment.
				 */
				continue;
			}

			if (leb_id >= (dev_size >> vh->log_erasesize)) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("corrupted LEB number %llu\n",
					  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
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

	SSDFS_DBG("fsi %p, hdr %p, silent %#x\n", fsi, hdr, silent);
#endif /* CONFIG_SSDFS_DEBUG */

	vh = SSDFS_VH(hdr);

	major_magic_valid = is_ssdfs_magic_valid(&vh->magic);
	minor_magic_valid = is_ssdfs_segment_header_magic_valid(hdr);

	if (!major_magic_valid && !minor_magic_valid) {
		if (!silent) {
			SSDFS_ERR("valid magic doesn't detected\n");
			ssdfs_show_volume_header(vh);
		} else
			SSDFS_DBG("valid magic doesn't detected\n");
		return -ENODATA;
	} else if (!major_magic_valid) {
		if (!silent) {
			SSDFS_ERR("invalid SSDFS magic signature\n");
			ssdfs_show_volume_header(vh);
		} else
			SSDFS_DBG("invalid SSDFS magic signature\n");
		return -EIO;
	} else if (!minor_magic_valid) {
		if (!silent) {
			SSDFS_ERR("invalid segment header magic signature\n");
			ssdfs_show_volume_header(vh);
		} else
			SSDFS_DBG("invalid segment header magic signature\n");
		return -EIO;
	}

	if (!is_ssdfs_volume_header_csum_valid(hdr, hdr_size)) {
		if (!silent) {
			SSDFS_ERR("invalid checksum of volume header\n");
			ssdfs_show_volume_header(vh);
		} else
			SSDFS_DBG("invalid checksum of volume header\n");
		return -EIO;
	}

	dev_size = fsi->devops->device_size(fsi->sb);
	if (!is_ssdfs_volume_header_consistent(fsi, vh, dev_size)) {
		if (!silent) {
			SSDFS_ERR("volume header is corrupted\n");
			ssdfs_show_volume_header(vh);
		} else
			SSDFS_DBG("volume header is corrupted\n");
		return -EIO;
	}

	if (SSDFS_VH_CNO(vh) > SSDFS_SEG_CNO(hdr)) {
		if (!silent) {
			SSDFS_ERR("invalid checkpoint/timestamp\n");
			ssdfs_show_volume_header(vh);
		} else
			SSDFS_DBG("invalid checkpoint/timestamp\n");
		return -EIO;
	}

	if (le16_to_cpu(hdr->log_pages) > fsi->pages_per_peb) {
		if (!silent) {
			SSDFS_ERR("log_pages %u > pages_per_peb %u\n",
				  le16_to_cpu(hdr->log_pages),
				  fsi->pages_per_peb);
			ssdfs_show_volume_header(vh);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("log_pages %u > pages_per_peb %u\n",
				  le16_to_cpu(hdr->log_pages),
				  fsi->pages_per_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		}
		return -EIO;
	}

	if (le16_to_cpu(hdr->seg_type) > SSDFS_LAST_KNOWN_SEG_TYPE) {
		if (!silent) {
			SSDFS_ERR("unknown seg_type %#x\n",
				  le16_to_cpu(hdr->seg_type));
			ssdfs_show_volume_header(vh);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unknown seg_type %#x\n",
				  le16_to_cpu(hdr->seg_type));
#endif /* CONFIG_SSDFS_DEBUG */
		}
		return -EIO;
	}

	if (le32_to_cpu(hdr->seg_flags) & ~SSDFS_SEG_HDR_FLAG_MASK) {
		if (!silent) {
			SSDFS_ERR("corrupted seg_flags %#x\n",
				  le32_to_cpu(hdr->seg_flags));
			ssdfs_show_volume_header(vh);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("corrupted seg_flags %#x\n",
				  le32_to_cpu(hdr->seg_flags));
#endif /* CONFIG_SSDFS_DEBUG */
		}
		return -EIO;
	}

	return 0;
}

/*
 * is_ssdfs_partial_log_header_consistent() - check partial header consistency
 * @fsi: pointer on shared file system object
 * @ph: partial log header
 * @dev_size: partition size in bytes
 *
 * RETURN:
 * [true]  - partial log header is consistent.
 * [false] - partial log header is corrupted.
 */
bool is_ssdfs_partial_log_header_consistent(struct ssdfs_fs_info *fsi,
					    struct ssdfs_partial_log_header *ph,
					    u64 dev_size)
{
	u32 page_size;
	u64 erase_size;
	u32 seg_size;
	u32 pebs_per_seg;
	u64 nsegs;
	u64 free_pages;
	u64 pages_count;
	u32 remainder;
	u32 pages_per_seg;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ph);
#endif /* CONFIG_SSDFS_DEBUG */

	page_size = 1 << ph->log_pagesize;
	erase_size = 1 << ph->log_erasesize;
	seg_size = 1 << ph->log_segsize;
	pebs_per_seg = 1 << ph->log_pebs_per_seg;

	if (page_size >= erase_size) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page_size %u >= erase_size %llu\n",
			  page_size, erase_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	switch (page_size) {
	case SSDFS_4KB:
	case SSDFS_8KB:
	case SSDFS_16KB:
	case SSDFS_32KB:
		/* do nothing */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unexpected page_size %u\n", page_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	switch (erase_size) {
	case SSDFS_128KB:
	case SSDFS_256KB:
	case SSDFS_512KB:
	case SSDFS_2MB:
	case SSDFS_8MB:
	case SSDFS_16MB:
	case SSDFS_32MB:
	case SSDFS_64MB:
	case SSDFS_128MB:
	case SSDFS_256MB:
	case SSDFS_512MB:
	case SSDFS_1GB:
	case SSDFS_2GB:
	case SSDFS_8GB:
	case SSDFS_16GB:
	case SSDFS_32GB:
	case SSDFS_64GB:
		/* do nothing */
		break;

	default:
		if (fsi->is_zns_device) {
			u64 zone_size = le16_to_cpu(fsi->vh->megabytes_per_peb);

			zone_size *= SSDFS_1MB;

			if (fsi->zone_size != zone_size) {
				SSDFS_ERR("invalid zone size: "
					  "size1 %llu != size2 %llu\n",
					  fsi->zone_size, zone_size);
				return -ERANGE;
			}

			erase_size = (u32)zone_size;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unexpected erase_size %llu\n", erase_size);
#endif /* CONFIG_SSDFS_DEBUG */
			return false;
		}
	};

	if (seg_size < erase_size) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg_size %u < erase_size %llu\n",
			  seg_size, erase_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	if (pebs_per_seg != (seg_size >> ph->log_erasesize)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("pebs_per_seg %u != (seg_size %u / erase_size %llu)\n",
			  pebs_per_seg, seg_size, erase_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	if (seg_size >= dev_size) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg_size %u >= dev_size %llu\n",
			  seg_size, dev_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	nsegs = le64_to_cpu(ph->nsegs);

	if (nsegs == 0 || nsegs > (dev_size >> ph->log_segsize)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("invalid nsegs %llu, dev_size %llu, seg_size) %u\n",
			  nsegs, dev_size, seg_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	free_pages = le64_to_cpu(ph->free_pages);

	pages_count = div_u64_rem(dev_size, page_size, &remainder);
	if (remainder) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("dev_size %llu is unaligned on page_size %u\n",
			  dev_size, page_size);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	if (free_pages > pages_count) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("free_pages %llu is greater than pages_count %llu\n",
			  free_pages, pages_count);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	pages_per_seg = seg_size / page_size;
	if (nsegs <= div_u64(free_pages, pages_per_seg)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("invalid nsegs %llu, free_pages %llu, "
			  "pages_per_seg %u\n",
			  nsegs, free_pages, pages_per_seg);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	return true;
}

/*
 * ssdfs_check_partial_log_header() - check partial log header consistency
 * @fsi: pointer on shared file system object
 * @hdr: partial log header
 * @silent: show error or not?
 *
 * This function checks consistency of partial log header.
 *
 * RETURN:
 * [success] - partial log header is consistent.
 * [failure] - error code:
 *
 * %-ENODATA     - valid magic doesn't detected.
 * %-EIO         - partial log header is corrupted.
 */
int ssdfs_check_partial_log_header(struct ssdfs_fs_info *fsi,
				   struct ssdfs_partial_log_header *hdr,
				   bool silent)
{
	size_t hdr_size = sizeof(struct ssdfs_partial_log_header);
	bool major_magic_valid, minor_magic_valid;
	u64 dev_size;
	u32 log_bytes;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !hdr);

	SSDFS_DBG("fsi %p, hdr %p, silent %#x\n", fsi, hdr, silent);
#endif /* CONFIG_SSDFS_DEBUG */

	major_magic_valid = is_ssdfs_magic_valid(&hdr->magic);
	minor_magic_valid =
		is_ssdfs_partial_log_header_magic_valid(&hdr->magic);

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
			SSDFS_ERR("invalid partial log header magic\n");
		else
			SSDFS_DBG("invalid partial log header magic\n");
		return -EIO;
	}

	if (!is_ssdfs_partial_log_header_csum_valid(hdr, hdr_size)) {
		if (!silent)
			SSDFS_ERR("invalid checksum of partial log header\n");
		else
			SSDFS_DBG("invalid checksum of partial log header\n");
		return -EIO;
	}

	dev_size = fsi->devops->device_size(fsi->sb);
	if (!is_ssdfs_partial_log_header_consistent(fsi, hdr, dev_size)) {
		if (!silent)
			SSDFS_ERR("partial log header is corrupted\n");
		else
			SSDFS_DBG("partial log header is corrupted\n");
		return -EIO;
	}

	if (le16_to_cpu(hdr->log_pages) > fsi->pages_per_peb) {
		if (!silent) {
			SSDFS_ERR("log_pages %u > pages_per_peb %u\n",
				  le16_to_cpu(hdr->log_pages),
				  fsi->pages_per_peb);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("log_pages %u > pages_per_peb %u\n",
				  le16_to_cpu(hdr->log_pages),
				  fsi->pages_per_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		}
		return -EIO;
	}

	log_bytes = (u32)le16_to_cpu(hdr->log_pages) * fsi->pagesize;
	if (le32_to_cpu(hdr->log_bytes) > log_bytes) {
		if (!silent) {
			SSDFS_ERR("calculated log_bytes %u < log_bytes %u\n",
				  log_bytes,
				  le32_to_cpu(hdr->log_bytes));
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("calculated log_bytes %u < log_bytes %u\n",
				  log_bytes,
				  le32_to_cpu(hdr->log_bytes));
#endif /* CONFIG_SSDFS_DEBUG */
		}
		return -EIO;
	}

	if (le16_to_cpu(hdr->seg_type) > SSDFS_LAST_KNOWN_SEG_TYPE) {
		if (!silent) {
			SSDFS_ERR("unknown seg_type %#x\n",
				  le16_to_cpu(hdr->seg_type));
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unknown seg_type %#x\n",
				  le16_to_cpu(hdr->seg_type));
#endif /* CONFIG_SSDFS_DEBUG */
		}
		return -EIO;
	}

	if (le32_to_cpu(hdr->pl_flags) & ~SSDFS_SEG_HDR_FLAG_MASK) {
		if (!silent) {
			SSDFS_ERR("corrupted pl_flags %#x\n",
				  le32_to_cpu(hdr->pl_flags));
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("corrupted pl_flags %#x\n",
				  le32_to_cpu(hdr->pl_flags));
#endif /* CONFIG_SSDFS_DEBUG */
		}
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_read_checked_segment_header() - read and check segment header
 * @fsi: pointer on shared file system object
 * @peb_id: PEB identification number
 * @block_size: block size in bytes
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
					u64 peb_id, u32 block_size,
					u32 pages_off,
					void *buf, bool silent)
{
	struct ssdfs_signature *magic;
	struct ssdfs_segment_header *hdr;
	struct ssdfs_partial_log_header *pl_hdr;
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	u64 offset = 0;
	size_t read_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_id %llu, block_size %u, "
		  "pages_off %u, buf %p, silent %#x\n",
		  peb_id, block_size, pages_off, buf, silent);

	BUG_ON(!fsi);
	BUG_ON(!fsi->devops->read);
	BUG_ON(!buf);
	BUG_ON(pages_off >= (fsi->erasesize / block_size));
#endif /* CONFIG_SSDFS_DEBUG */

	if (peb_id == 0 && pages_off == 0)
		offset = SSDFS_RESERVED_VBR_SIZE;
	else
		offset = (u64)pages_off * block_size;

	err = ssdfs_aligned_read_buffer(fsi, peb_id,
					block_size, offset,
					buf, hdr_size,
					&read_bytes);
	if (unlikely(err)) {
		if (!silent) {
			SSDFS_ERR("fail to read segment header: "
				  "peb_id %llu, block_size %u, "
				  "pages_off %u, err %d\n",
				  peb_id, block_size, pages_off, err);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fail to read segment header: "
				  "peb_id %llu, block_size %u, "
				  "pages_off %u, err %d\n",
				  peb_id, block_size, pages_off, err);
#endif /* CONFIG_SSDFS_DEBUG */
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
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fail to read segment header: "
				  "peb_id %llu, pages_off %u: "
				  "read_bytes %zu != hdr_size %zu\n",
				  peb_id, pages_off, read_bytes, hdr_size);
#endif /* CONFIG_SSDFS_DEBUG */
		}
		return -ERANGE;
	}

	magic = (struct ssdfs_signature *)buf;

	if (!is_ssdfs_magic_valid(magic)) {
		if (!silent)
			SSDFS_ERR("valid magic is not detected\n");
		else
			SSDFS_DBG("valid magic is not detected\n");

		return -ENODATA;
	}

	if (__is_ssdfs_segment_header_magic_valid(magic)) {
		hdr = SSDFS_SEG_HDR(buf);

		err = ssdfs_check_segment_header(fsi, hdr, silent);
		if (unlikely(err)) {
			if (!silent) {
				SSDFS_ERR("segment header is corrupted: "
					  "peb_id %llu, pages_off %u, err %d\n",
					  peb_id, pages_off, err);
			} else {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("segment header is corrupted: "
					  "peb_id %llu, pages_off %u, err %d\n",
					  peb_id, pages_off, err);
#endif /* CONFIG_SSDFS_DEBUG */
			}

			return err;
		}
	} else if (is_ssdfs_partial_log_header_magic_valid(magic)) {
		pl_hdr = SSDFS_PLH(buf);

		err = ssdfs_check_partial_log_header(fsi, pl_hdr, silent);
		if (unlikely(err)) {
			if (!silent) {
				SSDFS_ERR("partial log header is corrupted: "
					  "peb_id %llu, pages_off %u\n",
					  peb_id, pages_off);
			} else {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("partial log header is corrupted: "
					  "peb_id %llu, pages_off %u\n",
					  peb_id, pages_off);
#endif /* CONFIG_SSDFS_DEBUG */
			}

			return err;
		}
	} else {
		if (!silent) {
			SSDFS_ERR("log header is corrupted: "
				  "peb_id %llu, pages_off %u\n",
				  peb_id, pages_off);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("log header is corrupted: "
				  "peb_id %llu, pages_off %u\n",
				  peb_id, pages_off);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		return -EIO;
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
	u64 erase_size;
	u32 megabytes_per_peb;
	u32 flags;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !vh);

	SSDFS_DBG("fsi %p, vh %p\n", fsi, vh);
	SSDFS_DBG("fsi->log_pagesize %u, fsi->log_erasesize %u, "
		  "fsi->log_segsize %u, fsi->log_pebs_per_seg %u\n",
		  fsi->log_pagesize,
		  fsi->log_erasesize,
		  fsi->log_segsize,
		  fsi->log_pebs_per_seg);
#endif /* CONFIG_SSDFS_DEBUG */

	vh->magic.common = cpu_to_le32(SSDFS_SUPER_MAGIC);
	vh->magic.key = cpu_to_le16(SSDFS_SEGMENT_HDR_MAGIC);
	vh->magic.version.major = SSDFS_MAJOR_REVISION;
	vh->magic.version.minor = SSDFS_MINOR_REVISION;

	vh->log_pagesize = fsi->log_pagesize;
	vh->log_erasesize = fsi->log_erasesize;
	vh->log_segsize = fsi->log_segsize;
	vh->log_pebs_per_seg = fsi->log_pebs_per_seg;

	megabytes_per_peb = fsi->erasesize / SSDFS_1MB;
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(megabytes_per_peb >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	vh->megabytes_per_peb = cpu_to_le16((u16)megabytes_per_peb);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(fsi->pebs_per_seg >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	vh->pebs_per_seg = cpu_to_le16((u16)fsi->pebs_per_seg);

	vh->create_time = cpu_to_le64(fsi->fs_ctime);
	vh->create_cno = cpu_to_le64(fsi->fs_cno);

	vh->lebs_per_peb_index = cpu_to_le32(fsi->lebs_per_peb_index);
	vh->create_threads_per_seg = cpu_to_le16(fsi->create_threads_per_seg);

	vh->flags = cpu_to_le32(0);

	if (fsi->is_zns_device) {
		flags = le32_to_cpu(vh->flags);
		flags |= SSDFS_VH_ZNS_BASED_VOLUME;

		erase_size = 1 << fsi->log_erasesize;
		if (erase_size != fsi->zone_size)
			flags |= SSDFS_VH_UNALIGNED_ZONE;

		vh->flags = cpu_to_le32(flags);
	}

	vh->sb_seg_log_pages = cpu_to_le16(fsi->sb_seg_log_pages);
	vh->segbmap_log_pages = cpu_to_le16(fsi->segbmap_log_pages);
	vh->maptbl_log_pages = cpu_to_le16(fsi->maptbl_log_pages);
	vh->lnodes_seg_log_pages = cpu_to_le16(fsi->lnodes_seg_log_pages);
	vh->hnodes_seg_log_pages = cpu_to_le16(fsi->hnodes_seg_log_pages);
	vh->inodes_seg_log_pages = cpu_to_le16(fsi->inodes_seg_log_pages);
	vh->user_data_log_pages = cpu_to_le16(fsi->user_data_log_pages);

	ssdfs_memcpy(&vh->segbmap,
		     0, sizeof(struct ssdfs_segbmap_sb_header),
		     &fsi->vh->segbmap,
		     0, sizeof(struct ssdfs_segbmap_sb_header),
		     sizeof(struct ssdfs_segbmap_sb_header));
	ssdfs_memcpy(&vh->maptbl,
		     0, sizeof(struct ssdfs_maptbl_sb_header),
		     &fsi->vh->maptbl,
		     0, sizeof(struct ssdfs_maptbl_sb_header),
		     sizeof(struct ssdfs_maptbl_sb_header));
	ssdfs_memcpy(&vh->dentries_btree,
		     0, sizeof(struct ssdfs_dentries_btree_descriptor),
		     &fsi->vh->dentries_btree,
		     0, sizeof(struct ssdfs_dentries_btree_descriptor),
		     sizeof(struct ssdfs_dentries_btree_descriptor));
	ssdfs_memcpy(&vh->extents_btree,
		     0, sizeof(struct ssdfs_extents_btree_descriptor),
		     &fsi->vh->extents_btree,
		     0, sizeof(struct ssdfs_extents_btree_descriptor),
		     sizeof(struct ssdfs_extents_btree_descriptor));
	ssdfs_memcpy(&vh->xattr_btree,
		     0, sizeof(struct ssdfs_xattr_btree_descriptor),
		     &fsi->vh->xattr_btree,
		     0, sizeof(struct ssdfs_xattr_btree_descriptor),
		     sizeof(struct ssdfs_xattr_btree_descriptor));
	ssdfs_memcpy(&vh->invextree,
		     0, sizeof(struct ssdfs_invalidated_extents_btree),
		     &fsi->vh->invextree,
		     0, sizeof(struct ssdfs_invalidated_extents_btree),
		     sizeof(struct ssdfs_invalidated_extents_btree));
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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("fsi %p, vh %p\n", fsi, vh);
#endif /* CONFIG_SSDFS_DEBUG */

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

#ifdef CONFIG_SSDFS_DEBUG
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
#endif /* CONFIG_SSDFS_DEBUG */
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

	SSDFS_DBG("fsi %p, vh %p\n", fsi, vh);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_store_sb_segs_array(fsi, vh);

#ifdef CONFIG_SSDFS_DEBUG
	dev_size = fsi->devops->device_size(sb);
	if (!is_ssdfs_volume_header_consistent(fsi, vh, dev_size)) {
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
 * @last_log_time: log creation time
 * @last_log_cno: log checkpoint
 * @hdr: segment header [out]
 */
int ssdfs_prepare_segment_header_for_commit(struct ssdfs_fs_info *fsi,
					    u32 log_pages,
					    u16 seg_type,
					    u32 seg_flags,
					    u64 last_log_time,
					    u64 last_log_cno,
					    struct ssdfs_segment_header *hdr)
{
	u16 data_size = sizeof(struct ssdfs_segment_header);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("fsi %p, hdr %p, "
		  "log_pages %u, seg_type %#x, seg_flags %#x\n",
		  fsi, hdr, log_pages, seg_type, seg_flags);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr->timestamp = cpu_to_le64(last_log_time);
	hdr->cno = cpu_to_le64(last_log_cno);

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

/*
 * ssdfs_prepare_partial_log_header_for_commit() - prepare partial log header
 * @fsi: pointer on shared file system object
 * @sequence_id: sequence ID of the partial log inside the full log
 * @log_pages: log pages count
 * @seg_type: segment type
 * @pl_flags: partial log's flags
 * @last_log_time: log creation time
 * @last_log_cno: log checkpoint
 * @hdr: partial log's header [out]
 */
int ssdfs_prepare_partial_log_header_for_commit(struct ssdfs_fs_info *fsi,
					int sequence_id,
					u32 log_pages,
					u16 seg_type,
					u32 pl_flags,
					u64 last_log_time,
					u64 last_log_cno,
					struct ssdfs_partial_log_header *hdr)
{
	u16 data_size = sizeof(struct ssdfs_partial_log_header);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("fsi %p, hdr %p, sequence_id %d, "
		  "log_pages %u, seg_type %#x, pl_flags %#x\n",
		  fsi, hdr, sequence_id, log_pages, seg_type, pl_flags);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr->magic.common = cpu_to_le32(SSDFS_SUPER_MAGIC);
	hdr->magic.key = cpu_to_le16(SSDFS_PARTIAL_LOG_HDR_MAGIC);
	hdr->magic.version.major = SSDFS_MAJOR_REVISION;
	hdr->magic.version.minor = SSDFS_MINOR_REVISION;

	hdr->timestamp = cpu_to_le64(last_log_time);
	hdr->cno = cpu_to_le64(last_log_cno);

	if (log_pages > fsi->pages_per_seg || log_pages > U16_MAX) {
		SSDFS_ERR("invalid value of log_pages %u\n", log_pages);
		return -EINVAL;
	}

	hdr->log_pages = cpu_to_le16((u16)log_pages);
	hdr->log_bytes = cpu_to_le32(log_pages << fsi->log_pagesize);

	if (seg_type == SSDFS_UNKNOWN_SEG_TYPE ||
	    seg_type > SSDFS_LAST_KNOWN_SEG_TYPE) {
		SSDFS_ERR("invalid value of seg_type %#x\n", seg_type);
		return -EINVAL;
	}

	hdr->seg_type = cpu_to_le16(seg_type);
	hdr->pl_flags = cpu_to_le32(pl_flags);

	spin_lock(&fsi->volume_state_lock);
	hdr->free_pages = cpu_to_le64(fsi->free_pages);
	hdr->flags = cpu_to_le32(fsi->fs_flags);
	spin_unlock(&fsi->volume_state_lock);

	mutex_lock(&fsi->resize_mutex);
	hdr->nsegs = cpu_to_le64(fsi->nsegs);
	mutex_unlock(&fsi->resize_mutex);

	ssdfs_memcpy(&hdr->root_folder,
		     0, sizeof(struct ssdfs_inode),
		     &fsi->vs->root_folder,
		     0, sizeof(struct ssdfs_inode),
		     sizeof(struct ssdfs_inode));

	ssdfs_memcpy(&hdr->inodes_btree,
		     0, sizeof(struct ssdfs_inodes_btree),
		     &fsi->vs->inodes_btree,
		     0, sizeof(struct ssdfs_inodes_btree),
		     sizeof(struct ssdfs_inodes_btree));
	ssdfs_memcpy(&hdr->shared_extents_btree,
		     0, sizeof(struct ssdfs_shared_extents_btree),
		     &fsi->vs->shared_extents_btree,
		     0, sizeof(struct ssdfs_shared_extents_btree),
		     sizeof(struct ssdfs_shared_extents_btree));
	ssdfs_memcpy(&hdr->shared_dict_btree,
		     0, sizeof(struct ssdfs_shared_dictionary_btree),
		     &fsi->vs->shared_dict_btree,
		     0, sizeof(struct ssdfs_shared_dictionary_btree),
		     sizeof(struct ssdfs_shared_dictionary_btree));
	ssdfs_memcpy(&hdr->snapshots_btree,
		     0, sizeof(struct ssdfs_snapshots_btree),
		     &fsi->vs->snapshots_btree,
		     0, sizeof(struct ssdfs_snapshots_btree),
		     sizeof(struct ssdfs_snapshots_btree));
	ssdfs_memcpy(&hdr->invextree,
		     0, sizeof(struct ssdfs_invalidated_extents_btree),
		     &fsi->vh->invextree,
		     0, sizeof(struct ssdfs_invalidated_extents_btree),
		     sizeof(struct ssdfs_invalidated_extents_btree));

	hdr->sequence_id = cpu_to_le32(sequence_id);

	hdr->log_pagesize = fsi->log_pagesize;
	hdr->log_erasesize = fsi->log_erasesize;
	hdr->log_segsize = fsi->log_segsize;
	hdr->log_pebs_per_seg = fsi->log_pebs_per_seg;
	hdr->lebs_per_peb_index = cpu_to_le32(fsi->lebs_per_peb_index);
	hdr->create_threads_per_seg = cpu_to_le16(fsi->create_threads_per_seg);

	hdr->open_zones = cpu_to_le32(atomic_read(&fsi->open_zones));

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("open_zones %d\n",
		  atomic_read(&fsi->open_zones));
#endif /* CONFIG_SSDFS_DEBUG */

	hdr->check.bytes = cpu_to_le16(data_size);
	hdr->check.flags = cpu_to_le16(SSDFS_CRC32);

	err = ssdfs_calculate_csum(&hdr->check,
				   hdr, data_size);
	if (unlikely(err)) {
		SSDFS_ERR("unable to calculate checksum: err %d\n", err);
		return err;
	}

	return 0;
}
