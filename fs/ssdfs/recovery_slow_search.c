//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/recovery_slow_search.c - slow superblock search.
 *
 * Copyright (c) 2020 Viacheslav Dubeyko <slava@dubeyko.com>
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

int ssdfs_find_latest_valid_sb_segment2(struct ssdfs_recovery_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
#endif /* CONFIG_SSDFS_DEBUG */
	struct ssdfs_volume_header *last_vh;
	u64 dev_size;
	u64 cur_main_sb_peb, cur_copy_sb_peb;
	u64 start_peb, next_peb;
	u64 start_offset;
	u64 step;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi);
	BUG_ON(!env->sbi.vh_buf);
	BUG_ON(!env->fsi->devops->read);
	BUG_ON(!is_ssdfs_magic_valid(&SSDFS_VH(env->sbi.vh_buf)->magic));
	BUG_ON(!is_ssdfs_volume_header_csum_valid(env->sbi.vh_buf, hdr_size));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("env %p, env->sbi.vh_buf %p\n", env, env->sbi.vh_buf);

	dev_size = env->fsi->devops->device_size(env->fsi->sb);
	step = (u64)2 * env->fsi->erasesize;

try_next_peb:
	if (kthread_should_stop()) {
		err = -ENODATA;
		goto rollback_valid_vh;
	}

	last_vh = SSDFS_VH(env->sbi.vh_buf);
	cur_main_sb_peb = SSDFS_MAIN_SB_PEB(last_vh, SSDFS_CUR_SB_SEG);
	cur_copy_sb_peb = SSDFS_COPY_SB_PEB(last_vh, SSDFS_CUR_SB_SEG);

	if (cur_main_sb_peb != env->sbi.last_log.peb_id &&
	    cur_copy_sb_peb != env->sbi.last_log.peb_id) {
		SSDFS_ERR("volume header is corrupted\n");
		SSDFS_DBG("cur_main_sb_peb %llu, cur_copy_sb_peb %llu, "
			  "read PEB %llu\n",
			  cur_main_sb_peb, cur_copy_sb_peb,
			  env->sbi.last_log.peb_id);
		err = -EIO;
		goto end_search;
	}

	if (cur_main_sb_peb == env->sbi.last_log.peb_id) {
		if (!is_cur_main_sb_peb_exhausted(env))
			goto end_search;
	} else {
		if (!is_cur_copy_sb_peb_exhausted(env))
			goto end_search;
	}

	err = ssdfs_check_next_sb_pebs_pair(env);
	if (err == -E2BIG)
		goto continue_search;
	else if (!err)
		goto try_next_peb;

	if (kthread_should_stop()) {
		err = -ENODATA;
		goto rollback_valid_vh;
	}

	err = ssdfs_check_reserved_sb_pebs_pair(env);
	if (err == -E2BIG)
		goto continue_search;
	else if (!err)
		goto try_next_peb;

continue_search:
	if (kthread_should_stop()) {
		err = -ENODATA;
		goto rollback_valid_vh;
	}

	start_offset = *SSDFS_RECOVERY_CUR_OFF_PTR(env) + env->fsi->erasesize;
	start_peb = start_offset / env->fsi->erasesize;

	SSDFS_DBG("start_peb %llu, start_offset %llu, "
		  "end_offset %llu\n",
		  start_peb, start_offset,
		  SSDFS_RECOVERY_UPPER_OFF(env));

	err = __ssdfs_find_any_valid_volume_header2(env,
						    start_offset,
						    SSDFS_RECOVERY_UPPER_OFF(env),
						    step);
	if (err == -E2BIG) {
		SSDFS_DBG("unable to find any valid header: "
			  "peb_id %llu\n",
			  start_peb);
		goto end_search;
	} else if (err) {
		SSDFS_DBG("unable to find any valid header: "
			  "peb_id %llu\n",
			  start_peb);
		goto rollback_valid_vh;
	}

	if (kthread_should_stop()) {
		err = -ENODATA;
		goto rollback_valid_vh;
	}

	if (*SSDFS_RECOVERY_CUR_OFF_PTR(env) >= U64_MAX) {
		err = -ENODATA;
		goto rollback_valid_vh;
	}

	next_peb = *SSDFS_RECOVERY_CUR_OFF_PTR(env) / env->fsi->erasesize;

	err = ssdfs_find_any_valid_sb_segment2(env, next_peb);
	if (err == -E2BIG) {
		SSDFS_DBG("unable to find any valid header: "
			  "peb_id %llu\n",
			  start_peb);
		goto end_search;
	} else if (err) {
		SSDFS_DBG("unable to find any valid sb seg: "
			  "peb_id %llu\n",
			  next_peb);
		goto rollback_valid_vh;
	} else
		goto try_next_peb;

rollback_valid_vh:
	ssdfs_restore_sb_info2(env);

end_search:
	return err;
}

static
int ssdfs_recovery_first_phase_slow_search(struct ssdfs_recovery_env *env)
{
	u64 threshold_peb;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi);
	BUG_ON(!env->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("env %p, env->sbi.vh_buf %p\n", env, env->sbi.vh_buf);

	threshold_peb = *SSDFS_RECOVERY_CUR_OFF_PTR(env) / env->fsi->erasesize;

	err = ssdfs_find_any_valid_sb_segment2(env, threshold_peb);
	if (err == -E2BIG) {
		ssdfs_restore_sb_info2(env);
		err = ssdfs_find_last_sb_seg_outside_fragment(env);
		goto finish_first_phase;
	} else if (err) {
		err = -EAGAIN;
		goto finish_first_phase;
	}

	if (kthread_should_stop()) {
		err = -ENOENT;
		goto finish_first_phase;
	}

	err = ssdfs_find_latest_valid_sb_segment2(env);

finish_first_phase:
	return err;
}

static
int ssdfs_recovery_second_phase_slow_search(struct ssdfs_recovery_env *env)
{
	u64 threshold_peb;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi);
	BUG_ON(!env->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("env %p, env->sbi.vh_buf %p\n", env, env->sbi.vh_buf);

	if (!is_second_slow_try_possible(env)) {
		SSDFS_DBG("there is no room for second slow try\n");
		return -EAGAIN;
	}

	SSDFS_RECOVERY_SET_SECOND_SLOW_TRY(env);

	err = __ssdfs_find_any_valid_volume_header2(env,
					*SSDFS_RECOVERY_CUR_OFF_PTR(env),
					SSDFS_RECOVERY_UPPER_OFF(env),
					env->fsi->erasesize);
	if (err) {
		SSDFS_DBG("valid magic is not detected\n");
		return err;
	}

	if (kthread_should_stop())
		return -ENOENT;

	threshold_peb = *SSDFS_RECOVERY_CUR_OFF_PTR(env) / env->fsi->erasesize;

	err = ssdfs_find_any_valid_sb_segment2(env, threshold_peb);
	if (err == -E2BIG) {
		ssdfs_restore_sb_info2(env);
		err = ssdfs_find_last_sb_seg_outside_fragment(env);
		goto finish_second_phase;
	} else if (err) {
		err = -EAGAIN;
		goto finish_second_phase;
	}

	if (kthread_should_stop()) {
		err = -ENOENT;
		goto finish_second_phase;
	}

	err = ssdfs_find_latest_valid_sb_segment2(env);

finish_second_phase:
	return err;
}

static
int ssdfs_recovery_third_phase_slow_search(struct ssdfs_recovery_env *env)
{
	u64 threshold_peb;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi);
	BUG_ON(!env->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("env %p, env->sbi.vh_buf %p\n", env, env->sbi.vh_buf);

	if (!is_third_slow_try_possible(env)) {
		SSDFS_DBG("there is no room for third slow try\n");
		return -ENODATA;
	}

	SSDFS_RECOVERY_SET_THIRD_SLOW_TRY(env);

	err = __ssdfs_find_any_valid_volume_header2(env,
					*SSDFS_RECOVERY_CUR_OFF_PTR(env),
					SSDFS_RECOVERY_UPPER_OFF(env),
					env->fsi->erasesize);
	if (err) {
		SSDFS_DBG("valid magic is not detected\n");
		return err;
	}

	if (kthread_should_stop())
		return -ENOENT;

	threshold_peb = *SSDFS_RECOVERY_CUR_OFF_PTR(env) / env->fsi->erasesize;

	err = ssdfs_find_any_valid_sb_segment2(env, threshold_peb);
	if (err == -E2BIG) {
		ssdfs_restore_sb_info2(env);
		err = ssdfs_find_last_sb_seg_outside_fragment(env);
		goto finish_third_phase;
	} else if (err)
		goto finish_third_phase;

	if (kthread_should_stop()) {
		err = -ENOENT;
		goto finish_third_phase;
	}

	err = ssdfs_find_latest_valid_sb_segment2(env);

finish_third_phase:
	return err;
}

int ssdfs_recovery_try_slow_search(struct ssdfs_recovery_env *env)
{
	struct ssdfs_found_protected_peb *protected_peb;
	struct ssdfs_volume_header *vh;
	size_t vh_size = sizeof(struct ssdfs_volume_header);
	bool magic_valid = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->found);
	BUG_ON(!env->sbi.vh_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("env %p, start_peb %llu, pebs_count %u\n",
		  env, env->found->start_peb, env->found->pebs_count);

	SSDFS_DBG("env->lower_offset %llu, env->upper_offset %llu\n",
		  env->found->lower_offset, env->found->upper_offset);

	protected_peb = &env->found->array[SSDFS_LAST_CNO_PEB_INDEX];

	if (protected_peb->peb.peb_id >= U64_MAX) {
		SSDFS_DBG("fragment is empty\n");
		return -ENODATA;
	}

	err = ssdfs_read_checked_sb_info3(env, protected_peb->peb.peb_id, 0);
	vh = SSDFS_VH(env->sbi.vh_buf);
	magic_valid = is_ssdfs_magic_valid(&vh->magic);

	if (err || !magic_valid) {
		err = -ENODATA;
		SSDFS_DBG("peb %llu is corrupted\n",
			  protected_peb->peb.peb_id);
		goto finish_search;
	} else {
		memcpy(&env->last_vh, env->sbi.vh_buf, vh_size);
		ssdfs_backup_sb_info2(env);
	}

	SSDFS_RECOVERY_SET_FIRST_SLOW_TRY(env);

	err = ssdfs_recovery_first_phase_slow_search(env);
	if (err == -EAGAIN || err == -E2BIG ||
	    err == -ENODATA || err == -ENOENT) {
		if (kthread_should_stop()) {
			err = -ENOENT;
			goto finish_search;
		}

		err = ssdfs_recovery_second_phase_slow_search(env);
		if (err == -EAGAIN || err == -E2BIG ||
		    err == -ENODATA || err == -ENOENT) {
			if (kthread_should_stop()) {
				err = -ENOENT;
				goto finish_search;
			}

			err = ssdfs_recovery_third_phase_slow_search(env);
		}
	}

finish_search:
	return err;
}
