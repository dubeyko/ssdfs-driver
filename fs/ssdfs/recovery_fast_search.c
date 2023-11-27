// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/recovery_fast_search.c - fast superblock search.
 *
 * Copyright (c) 2020-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
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
#include "folio_vector.h"
#include "ssdfs.h"
#include "folio_array.h"
#include "peb.h"
#include "segment_bitmap.h"
#include "peb_mapping_table.h"
#include "recovery.h"

#include <trace/events/ssdfs.h>

static inline
bool IS_SB_PEB(struct ssdfs_recovery_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
#endif /* CONFIG_SSDFS_DEBUG */
	int type;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env);
	BUG_ON(!env->sbi.vh_buf);
	BUG_ON(!is_ssdfs_magic_valid(&SSDFS_VH(env->sbi.vh_buf)->magic));
	BUG_ON(!is_ssdfs_volume_header_csum_valid(env->sbi.vh_buf, hdr_size));
#endif /* CONFIG_SSDFS_DEBUG */

	type = le16_to_cpu(SSDFS_SEG_HDR(env->sbi.vh_buf)->seg_type);

	if (type == SSDFS_SB_SEG_TYPE)
		return true;

	return false;
}

static inline
void STORE_PEB_INFO(struct ssdfs_found_peb *peb,
		    u64 peb_id, u64 cno,
		    int type, int state)
{
	peb->peb_id = peb_id;
	peb->cno = cno;
	if (type == SSDFS_SB_SEG_TYPE)
		peb->is_superblock_peb = true;
	else
		peb->is_superblock_peb = false;
	peb->state = state;
}

static inline
void STORE_SB_PEB_INFO(struct ssdfs_found_peb *peb,
		       u64 peb_id)
{
	STORE_PEB_INFO(peb, peb_id, U64_MAX,
			SSDFS_UNKNOWN_SEG_TYPE,
			SSDFS_PEB_NOT_CHECKED);
}

static inline
void STORE_MAIN_SB_PEB_INFO(struct ssdfs_recovery_env *env,
			    struct ssdfs_found_protected_peb *ptr,
			    int sb_seg_index)
{
	struct ssdfs_superblock_pebs_pair *pair;
	struct ssdfs_found_peb *sb_peb;
	u64 peb_id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);
	BUG_ON(sb_seg_index < SSDFS_CUR_SB_SEG ||
		sb_seg_index >= SSDFS_SB_CHAIN_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	pair = &ptr->found.sb_pebs[sb_seg_index];
	sb_peb = &pair->pair[SSDFS_MAIN_SB_SEG];
	peb_id = SSDFS_MAIN_SB_PEB(SSDFS_VH(env->sbi.vh_buf), sb_seg_index);

	STORE_SB_PEB_INFO(sb_peb, peb_id);
}

static inline
void STORE_COPY_SB_PEB_INFO(struct ssdfs_recovery_env *env,
			    struct ssdfs_found_protected_peb *ptr,
			    int sb_seg_index)
{
	struct ssdfs_superblock_pebs_pair *pair;
	struct ssdfs_found_peb *sb_peb;
	u64 peb_id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);
	BUG_ON(sb_seg_index < SSDFS_CUR_SB_SEG ||
		sb_seg_index >= SSDFS_SB_CHAIN_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	pair = &ptr->found.sb_pebs[sb_seg_index];
	sb_peb = &pair->pair[SSDFS_COPY_SB_SEG];
	peb_id = SSDFS_COPY_SB_PEB(SSDFS_VH(env->sbi.vh_buf), sb_seg_index);

	STORE_SB_PEB_INFO(sb_peb, peb_id);
}

static inline
void ssdfs_store_superblock_pebs_info(struct ssdfs_recovery_env *env,
				      int peb_index)
{
	struct ssdfs_found_protected_peb *ptr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->found);
	BUG_ON(!env->sbi.vh_buf);
	BUG_ON(peb_index < SSDFS_LOWER_PEB_INDEX ||
		peb_index >= SSDFS_PROTECTED_PEB_CHAIN_MAX);

	SSDFS_DBG("env %p, peb_index %d\n",
		  env, peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr = &env->found->array[peb_index];

	STORE_MAIN_SB_PEB_INFO(env, ptr, SSDFS_CUR_SB_SEG);
	STORE_COPY_SB_PEB_INFO(env, ptr, SSDFS_CUR_SB_SEG);

	STORE_MAIN_SB_PEB_INFO(env, ptr, SSDFS_NEXT_SB_SEG);
	STORE_COPY_SB_PEB_INFO(env, ptr, SSDFS_NEXT_SB_SEG);

	STORE_MAIN_SB_PEB_INFO(env, ptr, SSDFS_RESERVED_SB_SEG);
	STORE_COPY_SB_PEB_INFO(env, ptr, SSDFS_RESERVED_SB_SEG);

	STORE_MAIN_SB_PEB_INFO(env, ptr, SSDFS_PREV_SB_SEG);
	STORE_COPY_SB_PEB_INFO(env, ptr, SSDFS_PREV_SB_SEG);
}

static inline
void ssdfs_store_protected_peb_info(struct ssdfs_recovery_env *env,
				    int peb_index,
				    u64 peb_id)
{
#ifdef CONFIG_SSDFS_DEBUG
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
#endif /* CONFIG_SSDFS_DEBUG */
	struct ssdfs_found_protected_peb *ptr;
	u64 cno;
	int type;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->found);
	BUG_ON(!env->sbi.vh_buf);
	BUG_ON(peb_index < SSDFS_LOWER_PEB_INDEX ||
		peb_index >= SSDFS_PROTECTED_PEB_CHAIN_MAX);
	BUG_ON(!is_ssdfs_magic_valid(&SSDFS_VH(env->sbi.vh_buf)->magic));
	BUG_ON(!is_ssdfs_volume_header_csum_valid(env->sbi.vh_buf, hdr_size));

	SSDFS_DBG("env %p, peb_index %d, peb_id %llu\n",
		  env, peb_index, peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	cno = le64_to_cpu(SSDFS_SEG_HDR(env->sbi.vh_buf)->cno);
	type = le16_to_cpu(SSDFS_SEG_HDR(env->sbi.vh_buf)->seg_type);

	ptr = &env->found->array[peb_index];
	STORE_PEB_INFO(&ptr->peb, peb_id, cno, type, SSDFS_FOUND_PEB_VALID);
	ssdfs_store_superblock_pebs_info(env, peb_index);
}

static
int ssdfs_calculate_recovery_search_bounds(struct ssdfs_recovery_env *env,
					   u64 dev_size,
					   u64 *lower_peb, loff_t *lower_off,
					   u64 *upper_peb, loff_t *upper_off)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->found || !env->fsi);
	BUG_ON(!lower_peb || !lower_off);
	BUG_ON(!upper_peb || !upper_off);

	SSDFS_DBG("env %p, start_peb %llu, "
		  "pebs_count %u, dev_size %llu\n",
		  env, env->found->start_peb,
		  env->found->pebs_count, dev_size);
#endif /* CONFIG_SSDFS_DEBUG */

	*lower_peb = env->found->start_peb;
	if (*lower_peb == 0)
		*lower_off = SSDFS_RESERVED_VBR_SIZE;
	else
		*lower_off = *lower_peb * env->fsi->erasesize;

	if (*lower_off >= dev_size) {
		SSDFS_ERR("invalid offset: lower_off %llu, "
			  "dev_size %llu\n",
			  (unsigned long long)*lower_off,
			  dev_size);
		return -ERANGE;
	}

	*upper_peb = env->found->pebs_count - 1;
	*upper_peb /= SSDFS_MAPTBL_PROTECTION_STEP;
	*upper_peb *= SSDFS_MAPTBL_PROTECTION_STEP;
	*upper_peb += env->found->start_peb;
	*upper_off = *upper_peb * env->fsi->erasesize;

	if (*upper_off >= dev_size) {
		*upper_off = min_t(u64, *upper_off,
				   dev_size - env->fsi->erasesize);
		*upper_peb = *upper_off / env->fsi->erasesize;
		*upper_peb -= env->found->start_peb;
		*upper_peb /= SSDFS_MAPTBL_PROTECTION_STEP;
		*upper_peb *= SSDFS_MAPTBL_PROTECTION_STEP;
		*upper_peb += env->found->start_peb;
		*upper_off = *upper_peb * env->fsi->erasesize;
	}

	return 0;
}

static
int ssdfs_find_valid_protected_pebs(struct ssdfs_recovery_env *env)
{
	struct super_block *sb = env->fsi->sb;
	u64 dev_size = env->fsi->devops->device_size(sb);
	u64 lower_peb, upper_peb;
	loff_t lower_off, upper_off;
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	size_t vh_size = sizeof(struct ssdfs_volume_header);
	struct ssdfs_volume_header *vh;
	struct ssdfs_found_protected_peb *found;
	bool magic_valid = false;
	u64 cno = U64_MAX, last_cno = U64_MAX;
	int err;

	if (!env->found) {
		SSDFS_ERR("unable to find protected PEBs\n");
		return -EOPNOTSUPP;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("env %p, start_peb %llu, pebs_count %u\n",
		  env, env->found->start_peb,
		  env->found->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!env->fsi->devops->read) {
		SSDFS_ERR("unable to read from device\n");
		return -EOPNOTSUPP;
	}

	env->found->lower_offset = dev_size;
	env->found->middle_offset = dev_size;
	env->found->upper_offset = dev_size;

	err = ssdfs_calculate_recovery_search_bounds(env, dev_size,
						     &lower_peb, &lower_off,
						     &upper_peb, &upper_off);
	if (unlikely(err)) {
		SSDFS_ERR("fail to calculate search bounds: "
			  "err %d\n", err);
		return err;
	}

	env->found->lower_offset = lower_off;
	env->found->middle_offset = lower_off;
	env->found->upper_offset = upper_off;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("lower_peb %llu, upper_peb %llu\n",
		  lower_peb, upper_peb);
#endif /* CONFIG_SSDFS_DEBUG */

	while (lower_peb <= upper_peb) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("lower_peb %llu, lower_off %llu\n",
			  lower_peb, (u64)lower_off);
		SSDFS_DBG("upper_peb %llu, upper_off %llu\n",
			  upper_peb, (u64)upper_off);
#endif /* CONFIG_SSDFS_DEBUG */

		err = env->fsi->devops->read(sb,
					     env->fsi->pagesize,
					     lower_off,
					     hdr_size,
					     env->sbi.vh_buf);
		vh = SSDFS_VH(env->sbi.vh_buf);
		magic_valid = is_ssdfs_magic_valid(&vh->magic);
		cno = le64_to_cpu(SSDFS_SEG_HDR(env->sbi.vh_buf)->cno);

		if (!err && magic_valid) {
			found = &env->found->array[SSDFS_LOWER_PEB_INDEX];

			if (found->peb.peb_id >= U64_MAX) {
				ssdfs_store_protected_peb_info(env,
						SSDFS_LOWER_PEB_INDEX,
						lower_peb);

				env->found->lower_offset = lower_off;

				ssdfs_memcpy(&env->last_vh, 0, vh_size,
					     env->sbi.vh_buf, 0, vh_size,
					     vh_size);
				ssdfs_backup_sb_info2(env);

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("FOUND: lower_peb %llu, "
					  "lower_bound %llu\n",
					  lower_peb, lower_off);
#endif /* CONFIG_SSDFS_DEBUG */

				goto define_last_cno_peb;
			}

			ssdfs_store_protected_peb_info(env,
						SSDFS_UPPER_PEB_INDEX,
						lower_peb);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("FOUND: lower_peb %llu, "
				  "lower_bound %llu\n",
				  lower_peb, lower_off);
#endif /* CONFIG_SSDFS_DEBUG */

define_last_cno_peb:
			if (last_cno >= U64_MAX) {
				env->found->middle_offset = lower_off;
				ssdfs_store_protected_peb_info(env,
						SSDFS_LAST_CNO_PEB_INDEX,
						lower_peb);
				ssdfs_memcpy(&env->last_vh, 0, vh_size,
					     env->sbi.vh_buf, 0, vh_size,
					     vh_size);
				ssdfs_backup_sb_info2(env);
				last_cno = cno;

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("FOUND: lower_peb %llu, "
					  "middle_offset %llu, "
					  "cno %llu\n",
					  lower_peb, lower_off, cno);
#endif /* CONFIG_SSDFS_DEBUG */
			} else if (cno > last_cno) {
				env->found->middle_offset = lower_off;
				ssdfs_store_protected_peb_info(env,
						SSDFS_LAST_CNO_PEB_INDEX,
						lower_peb);
				ssdfs_memcpy(&env->last_vh, 0, vh_size,
					     env->sbi.vh_buf, 0, vh_size,
					     vh_size);
				ssdfs_backup_sb_info2(env);
				last_cno = cno;

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("FOUND: lower_peb %llu, "
					  "middle_offset %llu, "
					  "cno %llu\n",
					  lower_peb, lower_off, cno);
#endif /* CONFIG_SSDFS_DEBUG */
			} else {
				ssdfs_restore_sb_info2(env);
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("ignore valid PEB: "
					  "lower_peb %llu, lower_off %llu, "
					  "cno %llu, last_cno %llu\n",
					  lower_peb, lower_off,
					  cno, last_cno);
#endif /* CONFIG_SSDFS_DEBUG */
			}
		} else {
			ssdfs_restore_sb_info2(env);
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("peb %llu (offset %llu) is corrupted\n",
				  lower_peb,
				  (unsigned long long)lower_off);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		lower_peb += SSDFS_MAPTBL_PROTECTION_STEP;
		lower_off = lower_peb * env->fsi->erasesize;

		if (kthread_should_stop())
			goto finish_search;
	}

	found = &env->found->array[SSDFS_UPPER_PEB_INDEX];

	if (found->peb.peb_id >= U64_MAX)
		goto finish_search;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("env->lower_offset %llu, "
		  "env->middle_offset %llu, "
		  "env->upper_offset %llu\n",
		  env->found->lower_offset,
		  env->found->middle_offset,
		  env->found->upper_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_RECOVERY_SET_FAST_SEARCH_TRY(env);

	return 0;

finish_search:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("unable to find valid PEB\n");
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_RECOVERY_SET_FAST_SEARCH_TRY(env);

	return -ENODATA;
}

static inline
int ssdfs_read_sb_peb_checked(struct ssdfs_recovery_env *env,
			      u64 peb_id)
{
	struct ssdfs_volume_header *vh;
	size_t vh_size = sizeof(struct ssdfs_volume_header);
	bool magic_valid = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi || !env->fsi->sb);
	BUG_ON(!env->sbi.vh_buf);

	SSDFS_DBG("peb_id %llu\n", peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_read_checked_sb_info3(env, peb_id, 0);
	vh = SSDFS_VH(env->sbi.vh_buf);
	magic_valid = is_ssdfs_magic_valid(&vh->magic);

	if (err || !magic_valid) {
		err = -ENODATA;
		ssdfs_restore_sb_info2(env);
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("peb %llu is corrupted\n",
			  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_check;
	} else {
		ssdfs_memcpy(&env->last_vh, 0, vh_size,
			     env->sbi.vh_buf, 0, vh_size,
			     vh_size);
		ssdfs_backup_sb_info2(env);
		goto finish_check;
	}

finish_check:
	return err;
}

int ssdfs_find_last_sb_seg_outside_fragment(struct ssdfs_recovery_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
#endif /* CONFIG_SSDFS_DEBUG */
	struct super_block *sb;
	struct ssdfs_volume_header *vh;
	u64 leb_id;
	u64 peb_id;
	bool magic_valid = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi || !env->fsi->sb);
	BUG_ON(!env->sbi.vh_buf);
	BUG_ON(!is_ssdfs_magic_valid(&SSDFS_VH(env->sbi.vh_buf)->magic));
	BUG_ON(!is_ssdfs_volume_header_csum_valid(env->sbi.vh_buf, hdr_size));

	SSDFS_DBG("env %p, env->sbi.vh_buf %p\n", env, env->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	sb = env->fsi->sb;
	err = -ENODATA;

	leb_id = SSDFS_MAIN_SB_LEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_CUR_SB_SEG);
	peb_id = SSDFS_MAIN_SB_PEB(SSDFS_VH(env->sbi.vh_buf),
					SSDFS_CUR_SB_SEG);

	do {
		err = ssdfs_read_sb_peb_checked(env, peb_id);
		vh = SSDFS_VH(env->sbi.vh_buf);
		magic_valid = is_ssdfs_magic_valid(&vh->magic);

		if (err == -ENODATA)
			goto finish_search;
		else if (err) {
			SSDFS_ERR("fail to read peb %llu\n",
				  peb_id);
			goto finish_search;
		} else {
			u64 new_leb_id;
			u64 new_peb_id;

			new_leb_id =
				SSDFS_MAIN_SB_LEB(SSDFS_VH(env->sbi.vh_buf),
						  SSDFS_CUR_SB_SEG);
			new_peb_id =
				SSDFS_MAIN_SB_PEB(SSDFS_VH(env->sbi.vh_buf),
						  SSDFS_CUR_SB_SEG);

			if (new_leb_id != leb_id || new_peb_id != peb_id) {
				err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("SB segment not found: "
					  "peb %llu\n",
					  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_search;
			}

			env->sbi.last_log.leb_id = leb_id;
			env->sbi.last_log.peb_id = peb_id;
			env->sbi.last_log.page_offset = 0;
			env->sbi.last_log.pages_count =
				SSDFS_LOG_PAGES(env->sbi.vh_buf);

			if (IS_SB_PEB(env)) {
				if (is_cur_main_sb_peb_exhausted(env)) {
					err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
					SSDFS_DBG("peb %llu is exhausted\n",
						  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
					goto try_next_sb_peb;
				} else {
					err = 0;
					goto finish_search;
				}
			} else {
				err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("SB segment not found: "
					  "peb %llu\n",
					  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_search;
			}
		}

try_next_sb_peb:
		if (kthread_should_stop()) {
			err = -ENODATA;
			goto finish_search;
		}

		leb_id = SSDFS_MAIN_SB_LEB(SSDFS_VH(env->sbi_backup.vh_buf),
						SSDFS_NEXT_SB_SEG);
		peb_id = SSDFS_MAIN_SB_PEB(SSDFS_VH(env->sbi_backup.vh_buf),
						SSDFS_NEXT_SB_SEG);
	} while (magic_valid);

finish_search:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("search outside fragment is finished: "
		  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

static
int ssdfs_check_cur_main_sb_peb(struct ssdfs_recovery_env *env)
{
	struct ssdfs_volume_header *vh;
	u64 leb_id;
	u64 peb_id;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env);
	BUG_ON(!env->sbi.vh_buf);

	SSDFS_DBG("env %p, env->sbi.vh_buf %p\n", env, env->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	vh = SSDFS_VH(env->sbi.vh_buf);
	leb_id = SSDFS_MAIN_SB_LEB(vh, SSDFS_CUR_SB_SEG);
	peb_id = SSDFS_MAIN_SB_PEB(vh, SSDFS_CUR_SB_SEG);

	ssdfs_backup_sb_info2(env);

	err = ssdfs_read_sb_peb_checked(env, peb_id);
	if (err == -ENODATA)
		goto finish_check;
	else if (err) {
		SSDFS_ERR("fail to read peb %llu\n",
			  peb_id);
		goto finish_check;
	} else {
		u64 new_leb_id;
		u64 new_peb_id;

		vh = SSDFS_VH(env->sbi.vh_buf);
		new_leb_id = SSDFS_MAIN_SB_LEB(vh, SSDFS_CUR_SB_SEG);
		new_peb_id = SSDFS_MAIN_SB_PEB(vh, SSDFS_CUR_SB_SEG);

		if (new_leb_id != leb_id || new_peb_id != peb_id) {
			err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("SB segment not found: "
				  "peb %llu\n",
				  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_check;
		}

		env->sbi.last_log.leb_id = leb_id;
		env->sbi.last_log.peb_id = peb_id;
		env->sbi.last_log.page_offset = 0;
		env->sbi.last_log.pages_count =
			SSDFS_LOG_PAGES(env->sbi.vh_buf);

		if (IS_SB_PEB(env)) {
			if (is_cur_main_sb_peb_exhausted(env)) {
				err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("peb %llu is exhausted\n",
					  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_check;
			} else {
				err = 0;
				goto finish_check;
			}
		} else {
			err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("SB segment not found: "
				  "peb %llu\n",
				  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_check;
		}
	}

finish_check:
	return err;
}

static
int ssdfs_check_cur_copy_sb_peb(struct ssdfs_recovery_env *env)
{
	struct ssdfs_volume_header *vh;
	u64 leb_id;
	u64 peb_id;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env);
	BUG_ON(!env->sbi.vh_buf);

	SSDFS_DBG("env %p, env->sbi.vh_buf %p\n", env, env->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	vh = SSDFS_VH(env->sbi.vh_buf);
	leb_id = SSDFS_COPY_SB_LEB(vh, SSDFS_CUR_SB_SEG);
	peb_id = SSDFS_COPY_SB_PEB(vh, SSDFS_CUR_SB_SEG);

	ssdfs_backup_sb_info2(env);

	err = ssdfs_read_sb_peb_checked(env, peb_id);
	if (err == -ENODATA)
		goto finish_check;
	else if (err) {
		SSDFS_ERR("fail to read peb %llu\n",
			  peb_id);
		goto finish_check;
	} else {
		u64 new_leb_id;
		u64 new_peb_id;

		vh = SSDFS_VH(env->sbi.vh_buf);
		new_leb_id = SSDFS_COPY_SB_LEB(vh, SSDFS_CUR_SB_SEG);
		new_peb_id = SSDFS_COPY_SB_PEB(vh, SSDFS_CUR_SB_SEG);

		if (new_leb_id != leb_id || new_peb_id != peb_id) {
			err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("SB segment not found: "
				  "peb %llu\n",
				  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_check;
		}

		env->sbi.last_log.leb_id = leb_id;
		env->sbi.last_log.peb_id = peb_id;
		env->sbi.last_log.page_offset = 0;
		env->sbi.last_log.pages_count =
			SSDFS_LOG_PAGES(env->sbi.vh_buf);

		if (IS_SB_PEB(env)) {
			if (is_cur_copy_sb_peb_exhausted(env)) {
				err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("peb %llu is exhausted\n",
					  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_check;
			} else {
				err = 0;
				goto finish_check;
			}
		} else {
			err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("SB segment not found: "
				  "peb %llu\n",
				  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_check;
		}
	}

finish_check:
	return err;
}

static
int ssdfs_find_last_sb_seg_inside_fragment(struct ssdfs_recovery_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi || !env->fsi->sb);
	BUG_ON(!env->sbi.vh_buf);
	BUG_ON(!is_ssdfs_magic_valid(&SSDFS_VH(env->sbi.vh_buf)->magic));
	BUG_ON(!is_ssdfs_volume_header_csum_valid(env->sbi.vh_buf, hdr_size));

	SSDFS_DBG("env %p, env->sbi.vh_buf %p\n", env, env->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

try_next_peb:
	if (kthread_should_stop()) {
		err = -ENODATA;
		goto finish_search;
	}

	err = ssdfs_check_cur_main_sb_peb(env);
	if (err == -ENODATA)
		goto try_cur_copy_sb_peb;
	else if (err == -ENOENT)
		goto check_next_sb_pebs_pair;
	else if (err)
		goto finish_search;
	else
		goto finish_search;

try_cur_copy_sb_peb:
	if (kthread_should_stop()) {
		err = -ENODATA;
		goto finish_search;
	}

	err = ssdfs_check_cur_copy_sb_peb(env);
	if (err == -ENODATA || err == -ENOENT)
		goto check_next_sb_pebs_pair;
	else if (err)
		goto finish_search;
	else
		goto finish_search;

check_next_sb_pebs_pair:
	if (kthread_should_stop()) {
		err = -ENODATA;
		goto finish_search;
	}

	err = ssdfs_check_next_sb_pebs_pair(env);
	if (err == -E2BIG) {
		err = ssdfs_find_last_sb_seg_outside_fragment(env);
		if (err == -ENODATA || err == -ENOENT) {
			/* unable to find anything */
			goto check_reserved_sb_pebs_pair;
		} else if (err) {
			SSDFS_ERR("search outside fragment has failed: "
				  "err %d\n", err);
			goto finish_search;
		} else
			goto finish_search;
	} else if (!err)
		goto try_next_peb;

check_reserved_sb_pebs_pair:
	if (kthread_should_stop()) {
		err = -ENODATA;
		goto finish_search;
	}

	err = ssdfs_check_reserved_sb_pebs_pair(env);
	if (err == -E2BIG) {
		err = ssdfs_find_last_sb_seg_outside_fragment(env);
		if (err == -ENODATA || err == -ENOENT) {
			/* unable to find anything */
			goto finish_search;
		} else if (err) {
			SSDFS_ERR("search outside fragment has failed: "
				  "err %d\n", err);
			goto finish_search;
		} else
			goto finish_search;
	} else if (!err)
		goto try_next_peb;

finish_search:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("search inside fragment is finished: "
		  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

static
int ssdfs_find_last_sb_seg_starting_from_peb(struct ssdfs_recovery_env *env,
					     struct ssdfs_found_peb *ptr)
{
	struct super_block *sb;
	struct ssdfs_volume_header *vh;
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	size_t vh_size = sizeof(struct ssdfs_volume_header);
	u64 offset;
	u64 threshold_peb;
	u64 peb_id;
	u64 cno = U64_MAX;
	bool magic_valid = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->found || !env->fsi || !env->fsi->sb);
	BUG_ON(!env->sbi.vh_buf);
	BUG_ON(!env->fsi->devops->read);
	BUG_ON(!ptr);
	BUG_ON(ptr->peb_id >= U64_MAX);

	SSDFS_DBG("peb_id %llu, start_peb %llu, pebs_count %u\n",
		  ptr->peb_id,
		  env->found->start_peb,
		  env->found->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	sb = env->fsi->sb;
	threshold_peb = env->found->start_peb + env->found->pebs_count;
	peb_id = ptr->peb_id;
	offset = peb_id * env->fsi->erasesize;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_id %llu, offset %llu\n",
		  peb_id, offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = env->fsi->devops->read(sb, env->fsi->pagesize,
				     offset, hdr_size,
				     env->sbi.vh_buf);
	vh = SSDFS_VH(env->sbi.vh_buf);
	magic_valid = is_ssdfs_magic_valid(&vh->magic);

	if (err || !magic_valid) {
		ssdfs_restore_sb_info2(env);
		ptr->state = SSDFS_FOUND_PEB_INVALID;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("peb %llu is corrupted\n",
			  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		if (ptr->peb_id >= env->found->start_peb &&
		    ptr->peb_id < threshold_peb) {
			/* try again */
			return -EAGAIN;
		} else {
			/* PEB is out of range */
			return -E2BIG;
		}
	} else {
		ssdfs_memcpy(&env->last_vh, 0, vh_size,
			     env->sbi.vh_buf, 0, vh_size,
			     vh_size);
		ssdfs_backup_sb_info2(env);
		cno = le64_to_cpu(SSDFS_SEG_HDR(env->sbi.vh_buf)->cno);
		ptr->cno = cno;
		ptr->is_superblock_peb = IS_SB_PEB(env);
		ptr->state = SSDFS_FOUND_PEB_VALID;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("peb_id %llu, cno %llu, is_superblock_peb %#x\n",
			  peb_id, cno, ptr->is_superblock_peb);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	if (ptr->peb_id >= env->found->start_peb &&
	    ptr->peb_id < threshold_peb) {
		err = ssdfs_find_last_sb_seg_inside_fragment(env);
		if (err == -ENODATA || err == -ENOENT) {
			ssdfs_restore_sb_info2(env);
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("nothing has been found inside fragment: "
				  "peb_id %llu\n",
				  ptr->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return -EAGAIN;
		} else if (err) {
			SSDFS_ERR("search inside fragment has failed: "
				  "err %d\n", err);
			return err;
		}
	} else {
		err = ssdfs_find_last_sb_seg_outside_fragment(env);
		if (err == -ENODATA || err == -ENOENT) {
			ssdfs_restore_sb_info2(env);
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("nothing has been found outside fragment: "
				  "peb_id %llu\n",
				  ptr->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return -E2BIG;
		} else if (err) {
			SSDFS_ERR("search outside fragment has failed: "
				  "err %d\n", err);
			return err;
		}
	}

	return 0;
}

static
int ssdfs_find_last_sb_seg_for_protected_peb(struct ssdfs_recovery_env *env)
{
	struct super_block *sb;
	struct ssdfs_found_protected_peb *protected_peb;
	struct ssdfs_found_peb *cur_peb;
	u64 dev_size;
	u64 threshold_peb;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->found || !env->fsi || !env->fsi->sb);
	BUG_ON(!env->sbi.vh_buf);
	BUG_ON(!env->fsi->devops->read);

	SSDFS_DBG("env %p, env->sbi.vh_buf %p\n", env, env->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	sb = env->fsi->sb;
	dev_size = env->fsi->devops->device_size(env->fsi->sb);
	threshold_peb = env->found->start_peb + env->found->pebs_count;

	protected_peb = &env->found->array[SSDFS_LAST_CNO_PEB_INDEX];

	if (protected_peb->peb.peb_id >= U64_MAX) {
		SSDFS_ERR("protected hasn't been found\n");
		return -ERANGE;
	}

	cur_peb = CUR_MAIN_SB_PEB(&protected_peb->found);
	if (cur_peb->peb_id >= U64_MAX) {
		SSDFS_ERR("peb_id is invalid\n");
		return -ERANGE;
	}

	err = ssdfs_find_last_sb_seg_starting_from_peb(env, cur_peb);
	if (err == -EAGAIN || err == -E2BIG) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("nothing was found for peb %llu\n",
			  cur_peb->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		/* continue search */
	} else if (err) {
		SSDFS_ERR("fail to find last superblock segment: "
			  "err %d\n", err);
		goto finish_search;
	} else
		goto finish_search;

	cur_peb = CUR_COPY_SB_PEB(&protected_peb->found);
	if (cur_peb->peb_id >= U64_MAX) {
		SSDFS_ERR("peb_id is invalid\n");
		return -ERANGE;
	}

	err = ssdfs_find_last_sb_seg_starting_from_peb(env, cur_peb);
	if (err == -EAGAIN || err == -E2BIG) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("nothing was found for peb %llu\n",
			  cur_peb->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		/* continue search */
	} else if (err) {
		SSDFS_ERR("fail to find last superblock segment: "
			  "err %d\n", err);
		goto finish_search;
	} else
		goto finish_search;

	cur_peb = NEXT_MAIN_SB_PEB(&protected_peb->found);
	if (cur_peb->peb_id >= U64_MAX) {
		SSDFS_ERR("peb_id is invalid\n");
		return -ERANGE;
	}

	err = ssdfs_find_last_sb_seg_starting_from_peb(env, cur_peb);
	if (err == -EAGAIN || err == -E2BIG) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("nothing was found for peb %llu\n",
			  cur_peb->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		/* continue search */
	} else if (err) {
		SSDFS_ERR("fail to find last superblock segment: "
			  "err %d\n", err);
		goto finish_search;
	} else
		goto finish_search;

	cur_peb = NEXT_COPY_SB_PEB(&protected_peb->found);
	if (cur_peb->peb_id >= U64_MAX) {
		SSDFS_ERR("peb_id is invalid\n");
		return -ERANGE;
	}

	err = ssdfs_find_last_sb_seg_starting_from_peb(env, cur_peb);
	if (err == -EAGAIN || err == -E2BIG) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("nothing was found for peb %llu\n",
			  cur_peb->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		/* continue search */
	} else if (err) {
		SSDFS_ERR("fail to find last superblock segment: "
			  "err %d\n", err);
		goto finish_search;
	} else
		goto finish_search;

	cur_peb = RESERVED_MAIN_SB_PEB(&protected_peb->found);
	if (cur_peb->peb_id >= U64_MAX) {
		SSDFS_ERR("peb_id is invalid\n");
		return -ERANGE;
	}

	err = ssdfs_find_last_sb_seg_starting_from_peb(env, cur_peb);
	if (err == -EAGAIN || err == -E2BIG) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("nothing was found for peb %llu\n",
			  cur_peb->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		/* continue search */
	} else if (err) {
		SSDFS_ERR("fail to find last superblock segment: "
			  "err %d\n", err);
		goto finish_search;
	} else
		goto finish_search;

	cur_peb = RESERVED_COPY_SB_PEB(&protected_peb->found);
	if (cur_peb->peb_id >= U64_MAX) {
		SSDFS_ERR("peb_id is invalid\n");
		return -ERANGE;
	}

	err = ssdfs_find_last_sb_seg_starting_from_peb(env, cur_peb);
	if (err == -EAGAIN || err == -E2BIG) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("nothing was found for peb %llu\n",
			  cur_peb->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_search;
	} else if (err) {
		SSDFS_ERR("fail to find last superblock segment: "
			  "err %d\n", err);
		goto finish_search;
	} else
		goto finish_search;

finish_search:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("search is finished: "
		  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

static
int ssdfs_recovery_protected_section_fast_search(struct ssdfs_recovery_env *env)
{
	u64 threshold_peb;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi);
	BUG_ON(!env->sbi.vh_buf);

	SSDFS_DBG("env %p, env->sbi.vh_buf %p\n", env, env->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	threshold_peb = *SSDFS_RECOVERY_CUR_OFF_PTR(env) / env->fsi->erasesize;

	err = ssdfs_find_any_valid_sb_segment2(env, threshold_peb);
	if (err)
		return err;

	if (kthread_should_stop())
		return -ENOENT;

	err = ssdfs_find_latest_valid_sb_segment2(env);
	if (err)
		return err;

	return 0;
}

int ssdfs_recovery_try_fast_search(struct ssdfs_recovery_env *env)
{
	struct ssdfs_found_protected_peb *found;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->found);
	BUG_ON(!env->sbi.vh_buf);

	SSDFS_DBG("env %p, start_peb %llu, pebs_count %u\n",
		  env, env->found->start_peb,
		  env->found->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_find_valid_protected_pebs(env);
	if (err == -ENODATA) {
		found = &env->found->array[SSDFS_LOWER_PEB_INDEX];

		if (found->peb.peb_id >= U64_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("no valid protected PEBs in fragment: "
				  "start_peb %llu, pebs_count %u\n",
				  env->found->start_peb,
				  env->found->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_fast_search;
		} else {
			/* search only in the last valid section */
			err = ssdfs_recovery_protected_section_fast_search(env);
			goto finish_fast_search;
		}
	} else if (err) {
		SSDFS_ERR("fail to find protected PEBs: "
			  "start_peb %llu, pebs_count %u, err %d\n",
			  env->found->start_peb,
			  env->found->pebs_count, err);
		goto finish_fast_search;
	}

	err = ssdfs_find_last_sb_seg_for_protected_peb(env);
	if (err == -EAGAIN) {
		*SSDFS_RECOVERY_CUR_OFF_PTR(env) = env->found->middle_offset;
		err = ssdfs_recovery_protected_section_fast_search(env);
		if (err == -ENODATA || err == -E2BIG) {
			SSDFS_DBG("SEARCH FINISHED: "
				  "nothing was found\n");
			goto finish_fast_search;
		} else if (err) {
			SSDFS_ERR("fail to find last SB segment: "
				  "err %d\n", err);
			goto finish_fast_search;
		}
	} else if (err == -ENODATA || err == -E2BIG) {
			SSDFS_DBG("SEARCH FINISHED: "
				  "nothing was found\n");
			goto finish_fast_search;
	} else if (err) {
		SSDFS_ERR("fail to find last SB segment: "
			  "err %d\n", err);
		goto finish_fast_search;
	}

finish_fast_search:
	return err;
}
