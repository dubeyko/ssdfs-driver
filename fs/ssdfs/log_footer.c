//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/log_footer.c - operations with log footer.
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
#include "segment_bitmap.h"
#include "page_array.h"
#include "segment.h"
#include "current_segment.h"

#include <trace/events/ssdfs.h>

/*
 * __is_ssdfs_log_footer_magic_valid() - check log footer's magic
 * @magic: pointer on magic value
 */
bool __is_ssdfs_log_footer_magic_valid(struct ssdfs_signature *magic)
{
	return le16_to_cpu(magic->key) == SSDFS_LOG_FOOTER_MAGIC;
}

/*
 * is_ssdfs_log_footer_magic_valid() - check log footer's magic
 * @footer: log footer
 */
bool is_ssdfs_log_footer_magic_valid(struct ssdfs_log_footer *footer)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!footer);
#endif /* CONFIG_SSDFS_DEBUG */

	return __is_ssdfs_log_footer_magic_valid(&footer->volume_state.magic);
}

/*
 * is_ssdfs_log_footer_csum_valid() - check log footer's checksum
 * @buf: buffer with log footer
 * @size: size of buffer in bytes
 */
bool is_ssdfs_log_footer_csum_valid(void *buf, size_t buf_size)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!buf);
#endif /* CONFIG_SSDFS_DEBUG */

	return is_csum_valid(&SSDFS_LF(buf)->volume_state.check, buf, buf_size);
}

/*
 * is_ssdfs_volume_state_info_consistent() - check volume state consistency
 * @fsi: pointer on shared file system object
 * @buf: log header
 * @footer: log footer
 * @dev_size: partition size in bytes
 *
 * RETURN:
 * [true]  - volume state metadata is consistent.
 * [false] - volume state metadata is corrupted.
 */
bool is_ssdfs_volume_state_info_consistent(struct ssdfs_fs_info *fsi,
					   void *buf,
					   struct ssdfs_log_footer *footer,
					   u64 dev_size)
{
	struct ssdfs_signature *magic;
	u64 nsegs;
	u64 free_pages;
	u8 log_segsize = U8_MAX;
	u32 seg_size = U32_MAX;
	u32 page_size = U32_MAX;
	u64 cno = U64_MAX;
	u16 log_pages = U16_MAX;
	u32 log_bytes = U32_MAX;
	u64 pages_count;
	u32 pages_per_seg;
	u32 remainder;
	u16 fs_state;
	u16 fs_errors;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!buf || !footer);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("buf %p, footer %p, dev_size %llu\n",
		  buf, footer, dev_size);

	magic = (struct ssdfs_signature *)buf;

	if (!is_ssdfs_magic_valid(magic)) {
		SSDFS_DBG("valid magic is not detected\n");
		return -ERANGE;
	}

	if (__is_ssdfs_segment_header_magic_valid(magic)) {
		struct ssdfs_segment_header *hdr;
		struct ssdfs_volume_header *vh;

		hdr = SSDFS_SEG_HDR(buf);
		vh = SSDFS_VH(buf);

		log_segsize = vh->log_segsize;
		seg_size = 1 << vh->log_segsize;
		page_size = 1 << vh->log_pagesize;
		cno = le64_to_cpu(hdr->cno);
		log_pages = le16_to_cpu(hdr->log_pages);
	} else if (is_ssdfs_partial_log_header_magic_valid(magic)) {
		struct ssdfs_partial_log_header *pl_hdr;

		pl_hdr = SSDFS_PLH(buf);

		log_segsize = pl_hdr->log_segsize;
		seg_size = 1 << pl_hdr->log_segsize;
		page_size = 1 << pl_hdr->log_pagesize;
		cno = le64_to_cpu(pl_hdr->cno);
		log_pages = le16_to_cpu(pl_hdr->log_pages);
	} else {
		SSDFS_DBG("log header is corrupted\n");
		return -EIO;
	}

	nsegs = le64_to_cpu(footer->volume_state.nsegs);

	if (nsegs == 0 || nsegs > (dev_size >> log_segsize)) {
		SSDFS_DBG("invalid nsegs %llu, dev_size %llu, seg_size) %u\n",
			  nsegs, dev_size, seg_size);
		return false;
	}

	free_pages = le64_to_cpu(footer->volume_state.free_pages);

	pages_count = div_u64_rem(dev_size, page_size, &remainder);
	if (remainder) {
		SSDFS_DBG("dev_size %llu is unaligned on page_size %u\n",
			  dev_size, page_size);
		return false;
	}

	if (free_pages > pages_count) {
		SSDFS_DBG("free_pages %llu is greater than pages_count %llu\n",
			  free_pages, pages_count);
		return false;
	}

	pages_per_seg = seg_size / page_size;
	if (nsegs <= div_u64(free_pages, pages_per_seg)) {
		SSDFS_DBG("invalid nsegs %llu, free_pages %llu, "
			  "pages_per_seg %u\n",
			  nsegs, free_pages, pages_per_seg);
		return false;
	}

	if (cno > le64_to_cpu(footer->cno)) {
		SSDFS_DBG("create_cno %llu is greater than write_cno %llu\n",
			  cno, le64_to_cpu(footer->cno));
		return false;
	}

	log_bytes = (u32)log_pages * fsi->pagesize;
	if (le32_to_cpu(footer->log_bytes) > log_bytes) {
		SSDFS_DBG("hdr log_bytes %u > footer log_bytes %u\n",
			  log_bytes,
			  le32_to_cpu(footer->log_bytes));
		return -EIO;
	}

	fs_state = le16_to_cpu(footer->volume_state.state);
	if (fs_state > SSDFS_LAST_KNOWN_FS_STATE) {
		SSDFS_DBG("unknown FS state %#x\n",
			  fs_state);
		return false;
	}

	fs_errors = le16_to_cpu(footer->volume_state.errors);
	if (fs_errors > SSDFS_LAST_KNOWN_FS_ERROR) {
		SSDFS_DBG("unknown FS error %#x\n",
			  fs_errors);
		return false;
	}

	return true;
}

/*
 * ssdfs_check_log_footer() - check log footer consistency
 * @fsi: pointer on shared file system object
 * @buf: log header
 * @footer: log footer
 * @silent: show error or not?
 *
 * This function checks consistency of log footer.
 *
 * RETURN:
 * [success] - log footer is consistent.
 * [failure] - error code:
 *
 * %-ENODATA     - valid magic doesn't detected.
 * %-EIO         - log footer is corrupted.
 */
int ssdfs_check_log_footer(struct ssdfs_fs_info *fsi,
			   void *buf,
			   struct ssdfs_log_footer *footer,
			   bool silent)
{
	struct ssdfs_volume_state *vs;
	size_t footer_size = sizeof(struct ssdfs_log_footer);
	u64 dev_size;
	bool major_magic_valid, minor_magic_valid;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !buf || !footer);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, buf %p, footer %p, silent %#x\n",
		  fsi, buf, footer, silent);

	vs = SSDFS_VS(footer);

	major_magic_valid = is_ssdfs_magic_valid(&vs->magic);
	minor_magic_valid = is_ssdfs_log_footer_magic_valid(footer);

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
			SSDFS_ERR("invalid log footer magic signature\n");
		else
			SSDFS_DBG("invalid log footer magic signature\n");
		return -EIO;
	}

	if (!is_ssdfs_log_footer_csum_valid(footer, footer_size)) {
		if (!silent)
			SSDFS_ERR("invalid checksum of log footer\n");
		else
			SSDFS_DBG("invalid checksum of log footer\n");
		return -EIO;
	}

	dev_size = fsi->devops->device_size(fsi->sb);
	if (!is_ssdfs_volume_state_info_consistent(fsi, buf,
						   footer, dev_size)) {
		if (!silent)
			SSDFS_ERR("log footer is corrupted\n");
		else
			SSDFS_DBG("log footer is corrupted\n");
		return -EIO;
	}

	if (le32_to_cpu(footer->log_flags) & ~SSDFS_LOG_FOOTER_FLAG_MASK) {
		if (!silent) {
			SSDFS_ERR("corrupted log_flags %#x\n",
				  le32_to_cpu(footer->log_flags));
		} else {
			SSDFS_DBG("corrupted log_flags %#x\n",
				  le32_to_cpu(footer->log_flags));
		}
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_read_unchecked_log_footer() - read log footer without check
 * @fsi: pointer on shared file system object
 * @peb_id: PEB identification number
 * @bytes_off: offset inside PEB in bytes
 * @buf: buffer for log footer
 * @silent: show error or not?
 * @log_pages: number of pages in the log
 *
 * This function reads log footer without
 * the consistency check.
 *
 * RETURN:
 * [success] - log footer is consistent.
 * [failure] - error code:
 *
 * %-ENODATA     - valid magic doesn't detected.
 * %-EIO         - log footer is corrupted.
 */
int ssdfs_read_unchecked_log_footer(struct ssdfs_fs_info *fsi,
				    u64 peb_id, u32 bytes_off,
				    void *buf, bool silent,
				    u32 *log_pages)
{
	struct ssdfs_log_footer *footer;
	struct ssdfs_volume_state *vs;
	size_t footer_size = sizeof(struct ssdfs_log_footer);
	bool major_magic_valid, minor_magic_valid;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->devops->read);
	BUG_ON(!buf || !log_pages);
	BUG_ON(bytes_off >= (fsi->pages_per_peb * fsi->pagesize));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_id %llu, bytes_off %u, buf %p\n",
		  peb_id, bytes_off, buf);

	*log_pages = U32_MAX;

	err = ssdfs_unaligned_read_buffer(fsi, peb_id, bytes_off,
					  buf, footer_size);
	if (unlikely(err)) {
		if (!silent) {
			SSDFS_ERR("fail to read log footer: "
				  "peb_id %llu, bytes_off %u, err %d\n",
				  peb_id, bytes_off, err);
		} else {
			SSDFS_DBG("fail to read log footer: "
				  "peb_id %llu, bytes_off %u, err %d\n",
				  peb_id, bytes_off, err);
		}
		return err;
	}

	footer = SSDFS_LF(buf);
	vs = SSDFS_VS(footer);

	major_magic_valid = is_ssdfs_magic_valid(&vs->magic);
	minor_magic_valid = is_ssdfs_log_footer_magic_valid(footer);

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
			SSDFS_ERR("invalid log footer magic signature\n");
		else
			SSDFS_DBG("invalid log footer magic signature\n");
		return -EIO;
	}

	if (!is_ssdfs_log_footer_csum_valid(footer, footer_size)) {
		if (!silent)
			SSDFS_ERR("invalid checksum of log footer\n");
		else
			SSDFS_DBG("invalid checksum of log footer\n");
		return -EIO;
	}

	*log_pages = le32_to_cpu(footer->log_bytes);
	*log_pages /= fsi->pagesize;

	if (*log_pages == 0 || *log_pages >= fsi->pages_per_peb) {
		if (!silent)
			SSDFS_ERR("invalid log pages %u\n", *log_pages);
		else
			SSDFS_DBG("invalid log pages %u\n", *log_pages);
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_read_checked_log_footer() - read and check log footer
 * @fsi: pointer on shared file system object
 * @log_hdr: log header
 * @peb_id: PEB identification number
 * @bytes_off: offset inside PEB in bytes
 * @buf: buffer for log footer
 * @silent: show error or not?
 *
 * This function reads and checks consistency of log footer.
 *
 * RETURN:
 * [success] - log footer is consistent.
 * [failure] - error code:
 *
 * %-ENODATA     - valid magic doesn't detected.
 * %-EIO         - log footer is corrupted.
 */
int ssdfs_read_checked_log_footer(struct ssdfs_fs_info *fsi, void *log_hdr,
				  u64 peb_id, u32 bytes_off, void *buf,
				  bool silent)
{
	struct ssdfs_log_footer *footer;
	size_t footer_size = sizeof(struct ssdfs_log_footer);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->devops->read);
	BUG_ON(!log_hdr || !buf);
	BUG_ON(bytes_off >= (fsi->pages_per_peb * fsi->pagesize));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_id %llu, bytes_off %u, buf %p\n",
		  peb_id, bytes_off, buf);

	err = ssdfs_unaligned_read_buffer(fsi, peb_id, bytes_off,
					  buf, footer_size);
	if (unlikely(err)) {
		if (!silent) {
			SSDFS_ERR("fail to read log footer: "
				  "peb_id %llu, bytes_off %u, err %d\n",
				  peb_id, bytes_off, err);
		} else {
			SSDFS_DBG("fail to read log footer: "
				  "peb_id %llu, bytes_off %u, err %d\n",
				  peb_id, bytes_off, err);
		}
		return err;
	}

	footer = SSDFS_LF(buf);

	err = ssdfs_check_log_footer(fsi, log_hdr, footer, silent);
	if (err) {
		if (!silent) {
			SSDFS_ERR("log footer is corrupted: "
				  "peb_id %llu, bytes_off %u, err %d\n",
				  peb_id, bytes_off, err);
		} else {
			SSDFS_DBG("log footer is corrupted: "
				  "peb_id %llu, bytes_off %u, err %d\n",
				  peb_id, bytes_off, err);
		}
		return err;
	}

	return 0;
}

/*
 * ssdfs_store_nsegs() - store volume's segments number in volume state
 * @fsi: pointer on shared file system object
 * @vs: volume state [out]
 *
 * This function stores volume's segments number in volume state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOLCK     - volume is under resize.
 */
static inline
int ssdfs_store_nsegs(struct ssdfs_fs_info *fsi,
			struct ssdfs_volume_state *vs)
{
	mutex_lock(&fsi->resize_mutex);
	vs->nsegs = cpu_to_le64(fsi->nsegs);
	mutex_unlock(&fsi->resize_mutex);

	return 0;
}

/*
 * ssdfs_prepare_current_segment_ids() - prepare current segment IDs
 * @fsi: pointer on shared file system object
 * @array: pointer on array of IDs [out]
 * @size: size the array in bytes
 *
 * This function prepares the current segment IDs.
 *
 * RETURN:
 * [success]
 * [failure] - error code.
 */
int ssdfs_prepare_current_segment_ids(struct ssdfs_fs_info *fsi,
					__le64 *array,
					size_t size)
{
	size_t count = size / sizeof(__le64);
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, array %p, size %zu\n",
		  fsi, array, size);

	if (size != (sizeof(__le64) * SSDFS_CUR_SEGS_COUNT)) {
		SSDFS_ERR("invalid array size %zu\n",
			  size);
		return -EINVAL;
	}

	memset(array, 0xFF, size);

	if (fsi->cur_segs) {
		down_read(&fsi->cur_segs->lock);
		for (i = 0; i < count; i++) {
			struct ssdfs_segment_info *real_seg;
			u64 seg;

			if (!fsi->cur_segs->objects[i])
				continue;

			ssdfs_current_segment_lock(fsi->cur_segs->objects[i]);

			real_seg = fsi->cur_segs->objects[i]->real_seg;
			if (real_seg) {
				seg = real_seg->seg_id;
				array[i] = cpu_to_le64(seg);
			} else
				array[i] = cpu_to_le64(U64_MAX);

			ssdfs_current_segment_unlock(fsi->cur_segs->objects[i]);
		}
		up_read(&fsi->cur_segs->lock);
	}

	return 0;
}

/*
 * ssdfs_prepare_volume_state_info_for_commit() - prepare volume state
 * @fsi: pointer on shared file system object
 * @fs_state: file system state
 * @array: pointer on array of IDs
 * @size: size the array in bytes
 * @vs: volume state [out]
 *
 * This function prepares volume state info for commit.
 *
 * RETURN:
 * [success]
 * [failure] - error code.
 */
int ssdfs_prepare_volume_state_info_for_commit(struct ssdfs_fs_info *fsi,
						u16 fs_state,
						__le64 *cur_segs,
						size_t size,
						struct ssdfs_volume_state *vs)
{
	struct super_block *sb = fsi->sb;
	u64 timestamp = ssdfs_current_timestamp();
	u64 cno = ssdfs_current_cno(sb);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !vs);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, fs_state %#x\n", fsi, fs_state);

	if (size != (sizeof(__le64) * SSDFS_CUR_SEGS_COUNT)) {
		SSDFS_ERR("invalid array size %zu\n",
			  size);
		return -EINVAL;
	}

	err = ssdfs_store_nsegs(fsi, vs);
	if (err) {
		SSDFS_DBG("unable to store segments number: err %d\n", err);
		return err;
	}

	vs->magic.common = cpu_to_le32(SSDFS_SUPER_MAGIC);
	vs->magic.version.major = SSDFS_MAJOR_REVISION;
	vs->magic.version.minor = SSDFS_MINOR_REVISION;

	spin_lock(&fsi->volume_state_lock);

	fsi->fs_mod_time = timestamp;
	fsi->fs_state = fs_state;

	vs->free_pages = cpu_to_le64(fsi->free_pages);
	vs->timestamp = cpu_to_le64(timestamp);
	vs->cno = cpu_to_le64(cno);
	vs->flags = cpu_to_le32(fsi->fs_flags);
	vs->state = cpu_to_le16(fs_state);
	vs->errors = cpu_to_le16(fsi->fs_errors);
	vs->feature_compat = cpu_to_le64(fsi->fs_feature_compat);
	vs->feature_compat_ro = cpu_to_le64(fsi->fs_feature_compat_ro);
	vs->feature_incompat = cpu_to_le64(fsi->fs_feature_incompat);

	memcpy(vs->uuid, fsi->vs->uuid, SSDFS_UUID_SIZE);
	memcpy(vs->label, fsi->vs->label, SSDFS_VOLUME_LABEL_MAX);
	memcpy(vs->cur_segs, cur_segs, size);

	vs->migration_threshold = cpu_to_le16(fsi->migration_threshold);

	spin_unlock(&fsi->volume_state_lock);

	memcpy(&vs->blkbmap, &fsi->vs->blkbmap,
		sizeof(struct ssdfs_blk_bmap_options));
	memcpy(&vs->blk2off_tbl, &fsi->vs->blk2off_tbl,
		sizeof(struct ssdfs_blk2off_tbl_options));
	memcpy(&vs->user_data, &fsi->vs->user_data,
		sizeof(struct ssdfs_user_data_options));

	memcpy(&vs->root_folder, &fsi->vs->root_folder,
		sizeof(struct ssdfs_inode));

	memcpy(&vs->inodes_btree, &fsi->vs->inodes_btree,
		sizeof(struct ssdfs_inodes_btree));
	memcpy(&vs->shared_extents_btree, &fsi->vs->shared_extents_btree,
		sizeof(struct ssdfs_shared_extents_btree));
	memcpy(&vs->shared_dict_btree, &fsi->vs->shared_dict_btree,
		sizeof(struct ssdfs_shared_dictionary_btree));

	return 0;
}

/*
 * ssdfs_prepare_log_footer_for_commit() - prepare log footer for commit
 * @fsi: pointer on shared file system object
 * @log_pages: count of pages in the log
 * @log_flags: log's flags
 * @footer: log footer [out]
 *
 * This function prepares log footer for commit.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input values.
 */
int ssdfs_prepare_log_footer_for_commit(struct ssdfs_fs_info *fsi,
					u32 log_pages,
					u32 log_flags,
					struct ssdfs_log_footer *footer)
{
	u16 data_size = sizeof(struct ssdfs_log_footer);
	int err;

	SSDFS_DBG("fsi %p, log_pages %u, log_flags %#x, footer %p\n",
		  fsi, log_pages, log_flags, footer);

	footer->volume_state.magic.key = cpu_to_le16(SSDFS_LOG_FOOTER_MAGIC);

	footer->timestamp = footer->volume_state.timestamp;
	footer->cno = footer->volume_state.cno;

	if (log_pages >= (U32_MAX >> fsi->log_pagesize)) {
		SSDFS_ERR("invalid value of log_pages %u\n", log_pages);
		return -EINVAL;
	}

	footer->log_bytes = cpu_to_le32(log_pages << fsi->log_pagesize);

	if (log_flags & ~SSDFS_LOG_FOOTER_FLAG_MASK) {
		SSDFS_ERR("unknow log flags %#x\n", log_flags);
		return -EINVAL;
	}

	footer->log_flags = cpu_to_le32(log_flags);

	footer->volume_state.check.bytes = cpu_to_le16(data_size);
	footer->volume_state.check.flags = cpu_to_le16(SSDFS_CRC32);

	err = ssdfs_calculate_csum(&footer->volume_state.check,
				   footer, data_size);
	if (unlikely(err)) {
		SSDFS_ERR("unable to calculate checksum: err %d\n", err);
		return err;
	}

	return 0;
}
