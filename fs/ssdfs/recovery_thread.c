//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/recovery_thread.c - recovery thread's logic.
 *
 * Copyright (c) 2019-2020 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "page_array.h"
#include "peb.h"
#include "segment_bitmap.h"
#include "peb_mapping_table.h"
#include "recovery.h"

#include <trace/events/ssdfs.h>

void ssdfs_backup_sb_info2(struct ssdfs_recovery_env *env)
{
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	size_t footer_size = sizeof(struct ssdfs_log_footer);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env);
	BUG_ON(!env->sbi.vh_buf || !env->sbi.vs_buf);
	BUG_ON(!env->sbi_backup.vh_buf || !env->sbi_backup.vs_buf);
#endif /* CONFIG_SSDFS_DEBUG */

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

	memcpy(env->sbi_backup.vh_buf, env->sbi.vh_buf, hdr_size);
	memcpy(env->sbi_backup.vs_buf, env->sbi.vs_buf, footer_size);
	memcpy(&env->sbi_backup.last_log, &env->sbi.last_log,
		sizeof(struct ssdfs_peb_extent));

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
}

void ssdfs_restore_sb_info2(struct ssdfs_recovery_env *env)
{
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	size_t footer_size = sizeof(struct ssdfs_log_footer);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env);
	BUG_ON(!env->sbi.vh_buf || !env->sbi.vs_buf);
	BUG_ON(!env->sbi_backup.vh_buf || !env->sbi_backup.vs_buf);
#endif /* CONFIG_SSDFS_DEBUG */

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

	memcpy(env->sbi.vh_buf, env->sbi_backup.vh_buf, hdr_size);
	memcpy(env->sbi.vs_buf, env->sbi_backup.vs_buf, footer_size);
	memcpy(&env->sbi.last_log, &env->sbi_backup.last_log,
		sizeof(struct ssdfs_peb_extent));

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
}

int ssdfs_read_checked_sb_info3(struct ssdfs_recovery_env *env,
				u64 peb_id, u32 pages_off)
{
	u32 lf_off;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("env %p, peb_id %llu, pages_off %u\n",
		  env, peb_id, pages_off);

	err = ssdfs_read_checked_segment_header(env->fsi, peb_id, pages_off,
						env->sbi.vh_buf, true);
	if (err) {
		SSDFS_DBG("volume header is corrupted: "
			  "peb_id %llu, offset %d, err %d\n",
			  peb_id, pages_off, err);
		return err;
	}

	lf_off = SSDFS_LOG_FOOTER_OFF(env->sbi.vh_buf);

	err = ssdfs_read_checked_log_footer(env->fsi,
					    SSDFS_SEG_HDR(env->sbi.vh_buf),
					    peb_id, lf_off, env->sbi.vs_buf,
					    true);
	if (err) {
		SSDFS_DBG("log footer is corrupted: "
			  "peb_id %llu, offset %d, err %d\n",
			  peb_id, lf_off, err);
		return err;
	}

	return 0;
}

static inline
int ssdfs_read_and_check_volume_header(struct ssdfs_recovery_env *env,
					u64 offset)
{
	struct super_block *sb;
	struct ssdfs_volume_header *vh;
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	u64 dev_size;
	bool magic_valid, crc_valid, hdr_consistent;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi);
	BUG_ON(!env->fsi->devops->read);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("env %p, offset %llu\n",
		  env, offset);

	sb = env->fsi->sb;
	dev_size = env->fsi->devops->device_size(sb);

	err = env->fsi->devops->read(sb, offset, hdr_size,
				     env->sbi.vh_buf);
	if (err)
		goto found_corrupted_peb;

	err = -ENODATA;

	vh = SSDFS_VH(env->sbi.vh_buf);
	magic_valid = is_ssdfs_magic_valid(&vh->magic);
	if (magic_valid) {
		crc_valid = is_ssdfs_volume_header_csum_valid(env->sbi.vh_buf,
								hdr_size);
		hdr_consistent = is_ssdfs_volume_header_consistent(vh,
								dev_size);

		if (crc_valid && hdr_consistent) {
			SSDFS_DBG("found offset %llu\n",
				  offset);
			return 0;
		}
	}

found_corrupted_peb:
	SSDFS_DBG("peb %llu (offset %llu) is corrupted\n",
		  offset / env->fsi->erasesize, offset);

	return err;
}

int __ssdfs_find_any_valid_volume_header2(struct ssdfs_recovery_env *env,
					  u64 start_offset,
					  u64 end_offset,
					  u64 step)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi);
	BUG_ON(!env->fsi->devops->read);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("env %p, start_offset %llu, "
		  "end_offset %llu, step %llu\n",
		  env, start_offset, end_offset, step);

	if (start_offset >= end_offset)
		return -E2BIG;

	*SSDFS_RECOVERY_CUR_OFF_PTR(env) = start_offset;

	while (*SSDFS_RECOVERY_CUR_OFF_PTR(env) < end_offset) {
		if (kthread_should_stop())
			return -ENOENT;

		err = ssdfs_read_and_check_volume_header(env,
					*SSDFS_RECOVERY_CUR_OFF_PTR(env));
		if (!err) {
			SSDFS_DBG("found offset %llu\n",
				  *SSDFS_RECOVERY_CUR_OFF_PTR(env));
			return 0;
		}

		*SSDFS_RECOVERY_CUR_OFF_PTR(env) += step;
	}

	return -E2BIG;
}

int ssdfs_find_any_valid_sb_segment2(struct ssdfs_recovery_env *env,
				     u64 threshold_peb)
{
	size_t vh_size = sizeof(struct ssdfs_volume_header);
	struct ssdfs_volume_header *vh;
	struct ssdfs_segment_header *seg_hdr;
	u64 dev_size;
	u64 start_peb;
	loff_t start_offset, next_offset;
	u64 last_cno, cno;
	__le64 peb1, peb2;
	__le64 leb1, leb2;
	u64 checked_pebs[SSDFS_SB_CHAIN_MAX][SSDFS_SB_SEG_COPY_MAX];
	u64 step;
	int i, j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->found || !env->fsi);
	BUG_ON(!env->fsi->devops->read);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("env %p, start_peb %llu, "
		  "pebs_count %u, threshold_peb %llu\n",
		  env, env->found->start_peb,
		  env->found->pebs_count, threshold_peb);

	dev_size = env->fsi->devops->device_size(env->fsi->sb);
	step = (u64)2 * env->fsi->erasesize;

	start_peb = max_t(u64,
			*SSDFS_RECOVERY_CUR_OFF_PTR(env) / env->fsi->erasesize,
			threshold_peb);
	start_offset = start_peb * env->fsi->erasesize;

	SSDFS_DBG("start_peb %llu, start_offset %llu, "
		  "end_offset %llu\n",
		  start_peb, start_offset,
		  SSDFS_RECOVERY_UPPER_OFF(env));

	if (start_offset >= SSDFS_RECOVERY_UPPER_OFF(env)) {
		SSDFS_DBG("start_offset %llu >= end_offset %llu\n",
			  start_offset, SSDFS_RECOVERY_UPPER_OFF(env));
		return -E2BIG;
	}

	i = SSDFS_SB_CHAIN_MAX;
	memset(checked_pebs, 0xFF,
		(SSDFS_SB_CHAIN_MAX * sizeof(u64)) +
		(SSDFS_SB_SEG_COPY_MAX * sizeof(u64)));

try_next_volume_portion:
	memcpy(&env->last_vh, env->sbi.vh_buf, vh_size);
	last_cno = le64_to_cpu(SSDFS_SEG_HDR(env->sbi.vh_buf)->cno);

try_again:
	if (kthread_should_stop())
		return -ENODATA;

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
		start_offset = (threshold_peb * env->fsi->erasesize) + step;
		start_offset = max_t(u64, start_offset,
				     *SSDFS_RECOVERY_CUR_OFF_PTR(env) + step);
		err = __ssdfs_find_any_valid_volume_header2(env, start_offset,
					SSDFS_RECOVERY_UPPER_OFF(env), step);
		if (!err) {
			i = SSDFS_SB_CHAIN_MAX;
			threshold_peb = *SSDFS_RECOVERY_CUR_OFF_PTR(env);
			threshold_peb /= env->fsi->erasesize;
			goto try_next_volume_portion;
		}

		/* the fragment is checked completely */
		return err;
	}

	err = -ENODATA;

	for (j = SSDFS_MAIN_SB_SEG; j < SSDFS_SB_SEG_COPY_MAX; j++) {
		u64 leb_id = le64_to_cpu(env->last_vh.sb_pebs[i][j].leb_id);
		u64 peb_id = le64_to_cpu(env->last_vh.sb_pebs[i][j].peb_id);
		u16 seg_type;
		u32 erasesize = env->fsi->erasesize;

		if (kthread_should_stop())
			return -ENODATA;

		if (peb_id == U64_MAX || leb_id == U64_MAX) {
			err = -ERANGE;
			SSDFS_ERR("invalid peb_id %llu, leb_id %llu\n",
				  leb_id, peb_id);
			goto fail_find_sb_seg;
		}

		SSDFS_DBG("leb_id %llu, peb_id %llu, "
			  "checked_peb %llu, threshold_peb %llu\n",
			  leb_id, peb_id,
			  checked_pebs[i][j],
			  threshold_peb);

		if (checked_pebs[i][j] == peb_id)
			continue;
		else
			checked_pebs[i][j] = peb_id;

		next_offset = peb_id * erasesize;

		SSDFS_DBG("peb_id %llu, next_offset %llu, "
			  "cur_offset %llu, end_offset %llu\n",
			  peb_id, next_offset,
			  *SSDFS_RECOVERY_CUR_OFF_PTR(env),
			  SSDFS_RECOVERY_UPPER_OFF(env));

		if (next_offset >= SSDFS_RECOVERY_UPPER_OFF(env)) {
			SSDFS_DBG("unable to find valid SB segment: "
				  "next_offset %llu >= end_offset %llu\n",
				  next_offset,
				  SSDFS_RECOVERY_UPPER_OFF(env));
			continue;
		}

		if ((env->found->start_peb * erasesize) > next_offset) {
			SSDFS_DBG("unable to find valid SB segment: "
				  "next_offset %llu >= start_offset %llu\n",
				  next_offset,
				  env->found->start_peb * erasesize);
			continue;
		}

		if (*SSDFS_RECOVERY_CUR_OFF_PTR(env) <= next_offset)
			*SSDFS_RECOVERY_CUR_OFF_PTR(env) = next_offset;

		err = ssdfs_read_checked_sb_info3(env, peb_id, 0);
		if (err) {
			SSDFS_DBG("peb_id %llu is corrupted: err %d\n",
				  peb_id, err);
			continue;
		}

		env->sbi.last_log.leb_id = leb_id;
		env->sbi.last_log.peb_id = peb_id;
		env->sbi.last_log.page_offset = 0;
		env->sbi.last_log.pages_count =
			SSDFS_LOG_PAGES(env->sbi.vh_buf);

		seg_hdr = SSDFS_SEG_HDR(env->sbi.vh_buf);
		seg_type = SSDFS_SEG_TYPE(seg_hdr);

		if (seg_type == SSDFS_SB_SEG_TYPE) {
			SSDFS_DBG("PEB %llu has been found\n",
				  peb_id);
			return 0;
		} else {
			err = -EIO;
			SSDFS_DBG("PEB %llu is not sb segment\n",
				  peb_id);
		}

		if (!err)
			goto compare_vh_info;
	}

	if (err) {
		memcpy(env->sbi.vh_buf, &env->last_vh, vh_size);
		goto try_again;
	}

compare_vh_info:
	vh = SSDFS_VH(env->sbi.vh_buf);
	seg_hdr = SSDFS_SEG_HDR(env->sbi.vh_buf);
	leb1 = env->last_vh.sb_pebs[SSDFS_CUR_SB_SEG][SSDFS_MAIN_SB_SEG].leb_id;
	leb2 = vh->sb_pebs[SSDFS_CUR_SB_SEG][SSDFS_MAIN_SB_SEG].leb_id;
	peb1 = env->last_vh.sb_pebs[SSDFS_CUR_SB_SEG][SSDFS_MAIN_SB_SEG].peb_id;
	peb2 = vh->sb_pebs[SSDFS_CUR_SB_SEG][SSDFS_MAIN_SB_SEG].peb_id;
	cno = le64_to_cpu(seg_hdr->cno);

	if (cno > last_cno && (leb1 != leb2 || peb1 != peb2)) {
		SSDFS_DBG("cno %llu, last_cno %llu, "
			  "leb1 %llu, leb2 %llu, "
			  "peb1 %llu, peb2 %llu\n",
			  cno, last_cno,
			  le64_to_cpu(leb1), le64_to_cpu(leb2),
			  le64_to_cpu(peb1), le64_to_cpu(peb2));
		goto try_again;
	}

fail_find_sb_seg:
	SSDFS_DBG("unable to find any valid segment with superblocks chain\n");
	return err;
}

static inline
bool is_sb_peb_exhausted(struct ssdfs_recovery_env *env,
			 u64 leb_id, u64 peb_id)
{
#ifdef CONFIG_SSDFS_DEBUG
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
#endif /* CONFIG_SSDFS_DEBUG */
	struct ssdfs_peb_extent checking_page;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi);
	BUG_ON(!env->sbi.vh_buf);
	BUG_ON(!env->fsi->devops->read);
	BUG_ON(!is_ssdfs_magic_valid(&SSDFS_VH(env->sbi.vh_buf)->magic));
	BUG_ON(!is_ssdfs_volume_header_csum_valid(env->sbi.vh_buf, hdr_size));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("env %p, env->sbi.vh_buf %p, "
		  "leb_id %llu, peb_id %llu\n",
		  env, env->sbi.vh_buf,
		  leb_id, peb_id);

	if (!env->fsi->devops->can_write_page) {
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
	checking_page.page_offset = env->fsi->pages_per_peb - 2;
	checking_page.pages_count = 1;

	err = ssdfs_can_write_sb_log(env->fsi->sb, &checking_page);
	if (!err)
		return false;

	return true;
}

bool is_cur_main_sb_peb_exhausted(struct ssdfs_recovery_env *env)
{
	u64 leb_id;
	u64 peb_id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi);
	BUG_ON(!env->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	leb_id = SSDFS_MAIN_SB_LEB(SSDFS_VH(env->sbi.vh_buf),
				   SSDFS_CUR_SB_SEG);
	peb_id = SSDFS_MAIN_SB_PEB(SSDFS_VH(env->sbi.vh_buf),
				   SSDFS_CUR_SB_SEG);

	SSDFS_DBG("env %p, env->sbi.vh_buf %p, "
		  "leb_id %llu, peb_id %llu\n",
		  env, env->sbi.vh_buf,
		  leb_id, peb_id);

	return is_sb_peb_exhausted(env, leb_id, peb_id);
}

bool is_cur_copy_sb_peb_exhausted(struct ssdfs_recovery_env *env)
{
	u64 leb_id;
	u64 peb_id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi);
	BUG_ON(!env->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	leb_id = SSDFS_COPY_SB_LEB(SSDFS_VH(env->sbi.vh_buf),
				   SSDFS_CUR_SB_SEG);
	peb_id = SSDFS_COPY_SB_PEB(SSDFS_VH(env->sbi.vh_buf),
				   SSDFS_CUR_SB_SEG);

	SSDFS_DBG("env %p, env->sbi.vh_buf %p, "
		  "leb_id %llu, peb_id %llu\n",
		  env, env->sbi.vh_buf,
		  leb_id, peb_id);

	return is_sb_peb_exhausted(env, leb_id, peb_id);
}

static
int ssdfs_check_sb_segs_sequence(struct ssdfs_recovery_env *env)
{
	u16 seg_type;
	u64 cno1, cno2;
	u64 cur_peb, next_peb, prev_peb;
	u64 cur_leb, next_leb, prev_leb;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi);
	BUG_ON(!env->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("env %p, env->sbi.vh_buf %p\n", env, env->sbi.vh_buf);

	seg_type = SSDFS_SEG_TYPE(SSDFS_SEG_HDR(env->sbi.vh_buf));
	if (seg_type != SSDFS_SB_SEG_TYPE) {
		SSDFS_DBG("invalid segment type\n");
		return -ENODATA;
	}

	cno1 = SSDFS_SEG_CNO(env->sbi_backup.vh_buf);
	cno2 = SSDFS_SEG_CNO(env->sbi.vh_buf);
	if (cno1 >= cno2) {
		SSDFS_DBG("last cno %llu is not lesser than read cno %llu\n",
			  cno1, cno2);
		return -ENODATA;
	}

	next_peb = SSDFS_MAIN_SB_PEB(SSDFS_VH(env->sbi_backup.vh_buf),
					SSDFS_NEXT_SB_SEG);
	cur_peb = SSDFS_MAIN_SB_PEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_CUR_SB_SEG);
	if (next_peb != cur_peb) {
		SSDFS_DBG("next_peb %llu doesn't equal to cur_peb %llu\n",
			  next_peb, cur_peb);
		return -ENODATA;
	}

	prev_peb = SSDFS_MAIN_SB_PEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_PREV_SB_SEG);
	cur_peb = SSDFS_MAIN_SB_PEB(SSDFS_VH(env->sbi_backup.vh_buf),
					SSDFS_CUR_SB_SEG);
	if (prev_peb != cur_peb) {
		SSDFS_DBG("prev_peb %llu doesn't equal to cur_peb %llu\n",
			  prev_peb, cur_peb);
		return -ENODATA;
	}

	next_leb = SSDFS_MAIN_SB_LEB(SSDFS_VH(env->sbi_backup.vh_buf),
					SSDFS_NEXT_SB_SEG);
	cur_leb = SSDFS_MAIN_SB_LEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_CUR_SB_SEG);
	if (next_leb != cur_leb) {
		SSDFS_DBG("next_leb %llu doesn't equal to cur_leb %llu\n",
			  next_leb, cur_leb);
		return -ENODATA;
	}

	prev_leb = SSDFS_MAIN_SB_LEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_PREV_SB_SEG);
	cur_leb = SSDFS_MAIN_SB_LEB(SSDFS_VH(env->sbi_backup.vh_buf),
					SSDFS_CUR_SB_SEG);
	if (prev_leb != cur_leb) {
		SSDFS_DBG("prev_leb %llu doesn't equal to cur_leb %llu\n",
			  prev_leb, cur_leb);
		return -ENODATA;
	}

	next_peb = SSDFS_COPY_SB_PEB(SSDFS_VH(env->sbi_backup.vh_buf),
					SSDFS_NEXT_SB_SEG);
	cur_peb = SSDFS_COPY_SB_PEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_CUR_SB_SEG);
	if (next_peb != cur_peb) {
		SSDFS_DBG("next_peb %llu doesn't equal to cur_peb %llu\n",
			  next_peb, cur_peb);
		return -ENODATA;
	}

	prev_peb = SSDFS_COPY_SB_PEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_PREV_SB_SEG);
	cur_peb = SSDFS_COPY_SB_PEB(SSDFS_VH(env->sbi_backup.vh_buf),
					SSDFS_CUR_SB_SEG);
	if (prev_peb != cur_peb) {
		SSDFS_DBG("prev_peb %llu doesn't equal to cur_peb %llu\n",
			  prev_peb, cur_peb);
		return -ENODATA;
	}

	next_leb = SSDFS_COPY_SB_LEB(SSDFS_VH(env->sbi_backup.vh_buf),
					SSDFS_NEXT_SB_SEG);
	cur_leb = SSDFS_COPY_SB_LEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_CUR_SB_SEG);
	if (next_leb != cur_leb) {
		SSDFS_DBG("next_leb %llu doesn't equal to cur_leb %llu\n",
			  next_leb, cur_leb);
		return -ENODATA;
	}

	prev_leb = SSDFS_COPY_SB_LEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_PREV_SB_SEG);
	cur_leb = SSDFS_COPY_SB_LEB(SSDFS_VH(env->sbi_backup.vh_buf),
					SSDFS_CUR_SB_SEG);
	if (prev_leb != cur_leb) {
		SSDFS_DBG("prev_leb %llu doesn't equal to cur_leb %llu\n",
			  prev_leb, cur_leb);
		return -ENODATA;
	}

	return 0;
}

int ssdfs_check_next_sb_pebs_pair(struct ssdfs_recovery_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
#endif /* CONFIG_SSDFS_DEBUG */
	u64 next_leb;
	u64 next_peb;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->found || !env->fsi);
	BUG_ON(!env->sbi.vh_buf);
	BUG_ON(!is_ssdfs_magic_valid(&SSDFS_VH(env->sbi.vh_buf)->magic));
	BUG_ON(!is_ssdfs_volume_header_csum_valid(env->sbi.vh_buf, hdr_size));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("env %p, env->sbi.vh_buf %p, "
		  "env->start_peb %llu, env->pebs_count %u\n",
		  env, env->sbi.vh_buf,
		  env->found->start_peb, env->found->pebs_count);

	next_leb = SSDFS_MAIN_SB_LEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_NEXT_SB_SEG);
	next_peb = SSDFS_MAIN_SB_PEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_NEXT_SB_SEG);
	if (next_leb == U64_MAX || next_peb == U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid next_leb %llu, next_peb %llu\n",
			  next_leb, next_peb);
		goto end_next_peb_check;
	}

	SSDFS_DBG("MAIN: next_leb %llu, next_peb %llu\n",
		  next_leb, next_peb);

	if (next_peb >= (env->found->start_peb + env->found->pebs_count)) {
		err = -E2BIG;
		SSDFS_DBG("next_peb %llu, start_peb %llu, pebs_count %u\n",
			  next_peb,
			  env->found->start_peb,
			  env->found->pebs_count);
		goto end_next_peb_check;
	}

	ssdfs_backup_sb_info2(env);

	err = ssdfs_read_checked_sb_info3(env, next_peb, 0);
	if (!err) {
		env->sbi.last_log.leb_id = next_leb;
		env->sbi.last_log.peb_id = next_peb;
		env->sbi.last_log.page_offset = 0;
		env->sbi.last_log.pages_count =
				SSDFS_LOG_PAGES(env->sbi.vh_buf);

		err = ssdfs_check_sb_segs_sequence(env);
		if (!err)
			goto end_next_peb_check;
	}

	ssdfs_restore_sb_info2(env);
	err = 0; /* try to read the backup copy */

	next_leb = SSDFS_COPY_SB_LEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_NEXT_SB_SEG);
	next_peb = SSDFS_COPY_SB_PEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_NEXT_SB_SEG);
	if (next_leb >= U64_MAX || next_peb >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid next_leb %llu, next_peb %llu\n",
			  next_leb, next_peb);
		goto end_next_peb_check;
	}

	SSDFS_DBG("COPY: next_leb %llu, next_peb %llu\n",
		  next_leb, next_peb);

	if (next_peb >= (env->found->start_peb + env->found->pebs_count)) {
		err = -E2BIG;
		SSDFS_DBG("next_peb %llu, start_peb %llu, pebs_count %u\n",
			  next_peb,
			  env->found->start_peb,
			  env->found->pebs_count);
		goto end_next_peb_check;
	}

	err = ssdfs_read_checked_sb_info3(env, next_peb, 0);
	if (!err) {
		env->sbi.last_log.leb_id = next_leb;
		env->sbi.last_log.peb_id = next_peb;
		env->sbi.last_log.page_offset = 0;
		env->sbi.last_log.pages_count =
				SSDFS_LOG_PAGES(env->sbi.vh_buf);

		err = ssdfs_check_sb_segs_sequence(env);
		if (!err)
			goto end_next_peb_check;
	}

	ssdfs_restore_sb_info2(env);

end_next_peb_check:
	return err;
}

int ssdfs_check_reserved_sb_pebs_pair(struct ssdfs_recovery_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
#endif /* CONFIG_SSDFS_DEBUG */
	u64 reserved_leb;
	u64 reserved_peb;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->found || !env->fsi);
	BUG_ON(!env->sbi.vh_buf);
	BUG_ON(!is_ssdfs_magic_valid(&SSDFS_VH(env->sbi.vh_buf)->magic));
	BUG_ON(!is_ssdfs_volume_header_csum_valid(env->sbi.vh_buf, hdr_size));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("env %p, env->sbi.vh_buf %p, "
		  "start_peb %llu, pebs_count %u\n",
		  env, env->sbi.vh_buf,
		  env->found->start_peb,
		  env->found->pebs_count);

	reserved_leb = SSDFS_MAIN_SB_LEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_RESERVED_SB_SEG);
	reserved_peb = SSDFS_MAIN_SB_PEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_RESERVED_SB_SEG);
	if (reserved_leb >= U64_MAX || reserved_peb >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid reserved_leb %llu, reserved_peb %llu\n",
			  reserved_leb, reserved_peb);
		goto end_reserved_peb_check;
	}

	SSDFS_DBG("MAIN: reserved_leb %llu, reserved_peb %llu\n",
		  reserved_leb, reserved_peb);

	if (reserved_peb >= (env->found->start_peb + env->found->pebs_count)) {
		err = -E2BIG;
		SSDFS_DBG("reserved_peb %llu, start_peb %llu, pebs_count %u\n",
			  reserved_peb,
			  env->found->start_peb,
			  env->found->pebs_count);
		goto end_reserved_peb_check;
	}

	ssdfs_backup_sb_info2(env);

	err = ssdfs_read_checked_sb_info3(env, reserved_peb, 0);
	if (!err) {
		env->sbi.last_log.leb_id = reserved_leb;
		env->sbi.last_log.peb_id = reserved_peb;
		env->sbi.last_log.page_offset = 0;
		env->sbi.last_log.pages_count =
				SSDFS_LOG_PAGES(env->sbi.vh_buf);
		goto end_reserved_peb_check;
	}

	ssdfs_restore_sb_info2(env);
	err = 0; /* try to read the backup copy */

	reserved_leb = SSDFS_COPY_SB_LEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_RESERVED_SB_SEG);
	reserved_peb = SSDFS_COPY_SB_PEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_RESERVED_SB_SEG);
	if (reserved_leb >= U64_MAX || reserved_peb >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid reserved_leb %llu, reserved_peb %llu\n",
			  reserved_leb, reserved_peb);
		goto end_reserved_peb_check;
	}

	SSDFS_DBG("COPY: reserved_leb %llu, reserved_peb %llu\n",
		  reserved_leb, reserved_peb);

	if (reserved_peb >= (env->found->start_peb + env->found->pebs_count)) {
		err = -E2BIG;
		SSDFS_DBG("reserved_peb %llu, start_peb %llu, pebs_count %u\n",
			  reserved_peb,
			  env->found->start_peb,
			  env->found->pebs_count);
		goto end_reserved_peb_check;
	}

	err = ssdfs_read_checked_sb_info3(env, reserved_peb, 0);
	if (!err) {
		env->sbi.last_log.leb_id = reserved_leb;
		env->sbi.last_log.peb_id = reserved_peb;
		env->sbi.last_log.page_offset = 0;
		env->sbi.last_log.pages_count =
				SSDFS_LOG_PAGES(env->sbi.vh_buf);
		goto end_reserved_peb_check;
	}

	ssdfs_restore_sb_info2(env);

end_reserved_peb_check:
	return err;
}

static inline
bool has_recovery_job(struct ssdfs_recovery_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env);
#endif /* CONFIG_SSDFS_DEBUG */

	return atomic_read(&env->state) == SSDFS_START_RECOVERY;
}

int ssdfs_recovery_thread_func(void *data);

static
struct ssdfs_thread_descriptor recovery_thread = {
	.threadfn = ssdfs_recovery_thread_func,
	.fmt = "ssdfs-recovery-%u",
};

#define RECOVERY_THREAD_WAKE_CONDITION(env) \
	(kthread_should_stop() || has_recovery_job(env))

/*
 * ssdfs_recovery_thread_func() - main fuction of recovery thread
 * @data: pointer on data object
 *
 * This function is main fuction of recovery thread.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
int ssdfs_recovery_thread_func(void *data)
{
	struct ssdfs_recovery_env *env = data;
	wait_queue_head_t *wait_queue;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!env) {
		SSDFS_ERR("pointer on environment is NULL\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("recovery thread: env %p\n", env);

	wait_queue = &env->request_wait_queue;

repeat:
	if (kthread_should_stop()) {
		SSDFS_DBG("stop recovery thread: env %p\n", env);
		complete_all(&env->thread.full_stop);
		return 0;
	}

	if (atomic_read(&env->state) != SSDFS_START_RECOVERY)
		goto sleep_recovery_thread;

	if (env->found->start_peb >= U64_MAX ||
	    env->found->pebs_count >= U32_MAX) {
		err = -EINVAL;
		SSDFS_DBG("invalid input: "
			  "start_peb %llu, pebs_count %u\n",
			  env->found->start_peb,
			  env->found->pebs_count);
		goto finish_recovery;
	}

	SSDFS_DBG("start_peb %llu, pebs_count %u\n",
		  env->found->start_peb,
		  env->found->pebs_count);
	SSDFS_DBG("search_phase %#x\n",
		  env->found->search_phase);

	switch (env->found->search_phase) {
	case SSDFS_RECOVERY_FAST_SEARCH:
		err = ssdfs_recovery_try_fast_search(env);
		if (err) {
			if (kthread_should_stop()) {
				err = -ENOENT;
				goto finish_recovery;
			}
		}
		break;

	case SSDFS_RECOVERY_SLOW_SEARCH:
		err = ssdfs_recovery_try_slow_search(env);
		if (err) {
			if (kthread_should_stop()) {
				err = -ENOENT;
				goto finish_recovery;
			}
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("search has not been requested: "
			  "search_phase %#x\n",
			  env->found->search_phase);
		goto finish_recovery;
	}

finish_recovery:
	env->err = err;

	if (env->err)
		atomic_set(&env->state, SSDFS_RECOVERY_FAILED);
	else
		atomic_set(&env->state, SSDFS_RECOVERY_FINISHED);

	wake_up_all(&env->result_wait_queue);

sleep_recovery_thread:
	wait_event_interruptible(*wait_queue,
				 RECOVERY_THREAD_WAKE_CONDITION(env));
	goto repeat;
}

/*
 * ssdfs_recovery_start_thread() - start recovery's thread
 * @env: recovery environment
 * @id: thread's ID
 */
int ssdfs_recovery_start_thread(struct ssdfs_recovery_env *env,
				u32 id)
{
	ssdfs_threadfn threadfn;
	const char *fmt;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("env %p, id %u\n", env, id);

	threadfn = recovery_thread.threadfn;
	fmt = recovery_thread.fmt;

	env->thread.task = kthread_create(threadfn, env, fmt, id);
	if (IS_ERR_OR_NULL(env->thread.task)) {
		err = PTR_ERR(env->thread.task);
		SSDFS_ERR("fail to start recovery thread: "
			  "id %u, err %d\n", id, err);
		return err;
	}

	init_waitqueue_head(&env->request_wait_queue);
	init_waitqueue_entry(&env->thread.wait, env->thread.task);
	add_wait_queue(&env->request_wait_queue, &env->thread.wait);
	init_waitqueue_head(&env->result_wait_queue);
	init_completion(&env->thread.full_stop);

	wake_up_process(env->thread.task);

	return 0;
}

/*
 * ssdfs_recovery_stop_thread() - stop recovery thread
 * @env: recovery environment
 */
int ssdfs_recovery_stop_thread(struct ssdfs_recovery_env *env)
{
	unsigned long res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("env %p\n", env);

	if (!env->thread.task)
		return 0;

	err = kthread_stop(env->thread.task);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 * The wake_up_process() was never called.
		 */
		return 0;
	} else if (unlikely(err)) {
		SSDFS_WARN("thread function had some issue: err %d\n",
			    err);
		return err;
	}

	finish_wait(&env->request_wait_queue, &env->thread.wait);
	env->thread.task = NULL;

	res = wait_for_completion_timeout(&env->thread.full_stop,
					SSDFS_DEFAULT_TIMEOUT);
	if (res == 0) {
		err = -ERANGE;
		SSDFS_ERR("stop thread fails: err %d\n", err);
		return err;
	}

	return 0;
}
