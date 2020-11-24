//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/recovery.h - recovery logic declarations.
 *
 * Copyright (c) 2019-2020 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_RECOVERY_H
#define _SSDFS_RECOVERY_H

#define SSDFS_RESERVED_SB_SEGS		(6)
#define SSDFS_RECOVERY_THREADS		(12)

/*
 * struct ssdfs_found_peb - found PEB details
 * @peb_id: PEB's ID
 * @cno: PEB's starting checkpoint
 * @is_superblock_peb: has superblock PEB been found?
 * @state: PEB's state
 */
struct ssdfs_found_peb {
	u64 peb_id;
	u64 cno;
	bool is_superblock_peb;
	int state;
};

/*
 * States of found PEB
 */
enum {
	SSDFS_PEB_NOT_CHECKED,
	SSDFS_FOUND_PEB_VALID,
	SSDFS_FOUND_PEB_INVALID,
	SSDFS_FOUND_PEB_STATE_MAX
};

/*
 * struct ssdfs_superblock_pebs_pair - pair of superblock PEBs
 * @pair: main and copy superblock PEBs
 */
struct ssdfs_superblock_pebs_pair {
	struct ssdfs_found_peb pair[SSDFS_SB_SEG_COPY_MAX];
};

/*
 * struct ssdfs_found_superblock_pebs - found superblock PEBs
 * sb_pebs: array of superblock PEBs details
 */
struct ssdfs_found_superblock_pebs {
	struct ssdfs_superblock_pebs_pair sb_pebs[SSDFS_SB_CHAIN_MAX];
};

/*
 * struct ssdfs_found_protected_peb - protected PEB details
 * @peb: protected PEB details
 * @found: superblock PEBs details
 */
struct ssdfs_found_protected_peb {
	struct ssdfs_found_peb peb;
	struct ssdfs_found_superblock_pebs found;
};

/*
 * struct ssdfs_found_protected_pebs - found protected PEBs
 * @start_peb: starting PEB ID in fragment
 * @pebs_count: PEBs count in fragment
 * @lower_offset: lower offset bound
 * @middle_offset: middle offset
 * @upper_offset: upper offset bound
 * @current_offset: current position of the search
 * @search_phase: current search phase
 * array: array of protected PEBs details
 */
struct ssdfs_found_protected_pebs {
	u64 start_peb;
	u32 pebs_count;

	u64 lower_offset;
	u64 middle_offset;
	u64 upper_offset;
	u64 current_offset;
	int search_phase;

#define SSDFS_LOWER_PEB_INDEX			(0)
#define SSDFS_UPPER_PEB_INDEX			(1)
#define SSDFS_LAST_CNO_PEB_INDEX		(2)
#define SSDFS_PROTECTED_PEB_CHAIN_MAX		(3)
	struct ssdfs_found_protected_peb array[SSDFS_PROTECTED_PEB_CHAIN_MAX];
};

/*
 * struct ssdfs_recovery_env - recovery environment
 * @found: found PEBs' details
 * @err: result of the search
 * @state: recovery thread's state
 * @last_vh: buffer for last valid volume header
 * @sbi: superblock info
 * @sbi_backup: backup copy of superblock info
 * @request_wait_queue: request wait queue of recovery thread
 * @result_wait_queue: result wait queue of recovery thread
 * @thread: descriptor of recovery thread
 * @fsi: file system info object
 */
struct ssdfs_recovery_env {
	struct ssdfs_found_protected_pebs *found;

	int err;
	atomic_t state;

	struct ssdfs_volume_header last_vh;
	struct ssdfs_sb_info sbi;
	struct ssdfs_sb_info sbi_backup;

	wait_queue_head_t request_wait_queue;
	wait_queue_head_t result_wait_queue;
	struct ssdfs_thread_info thread;
	struct ssdfs_fs_info *fsi;
};

/*
 * Search phases
 */
enum {
	SSDFS_RECOVERY_NO_SEARCH,
	SSDFS_RECOVERY_FAST_SEARCH,
	SSDFS_RECOVERY_SLOW_SEARCH,
	SSDFS_RECOVERY_FIRST_SLOW_TRY,
	SSDFS_RECOVERY_SECOND_SLOW_TRY,
	SSDFS_RECOVERY_THIRD_SLOW_TRY,
	SSDFS_RECOVERY_SEARCH_PHASES_MAX
};

/*
 * Recovery thread's state
 */
enum {
	SSDFS_RECOVERY_UNKNOWN_STATE,
	SSDFS_START_RECOVERY,
	SSDFS_RECOVERY_FAILED,
	SSDFS_RECOVERY_FINISHED,
	SSDFS_RECOVERY_STATE_MAX
};

/*
 * Operation types
 */
enum {
	SSDFS_USE_PEB_ISBAD_OP,
	SSDFS_USE_READ_OP,
};

/*
 * Inline functions
 */

static inline
struct ssdfs_found_peb *
CUR_MAIN_SB_PEB(struct ssdfs_found_superblock_pebs *ptr)
{
	return &ptr->sb_pebs[SSDFS_CUR_SB_SEG].pair[SSDFS_MAIN_SB_SEG];
}

static inline
struct ssdfs_found_peb *
CUR_COPY_SB_PEB(struct ssdfs_found_superblock_pebs *ptr)
{
	return &ptr->sb_pebs[SSDFS_CUR_SB_SEG].pair[SSDFS_COPY_SB_SEG];
}

static inline
struct ssdfs_found_peb *
NEXT_MAIN_SB_PEB(struct ssdfs_found_superblock_pebs *ptr)
{
	return &ptr->sb_pebs[SSDFS_NEXT_SB_SEG].pair[SSDFS_MAIN_SB_SEG];
}

static inline
struct ssdfs_found_peb *
NEXT_COPY_SB_PEB(struct ssdfs_found_superblock_pebs *ptr)
{
	return &ptr->sb_pebs[SSDFS_NEXT_SB_SEG].pair[SSDFS_COPY_SB_SEG];
}

static inline
struct ssdfs_found_peb *
RESERVED_MAIN_SB_PEB(struct ssdfs_found_superblock_pebs *ptr)
{
	return &ptr->sb_pebs[SSDFS_RESERVED_SB_SEG].pair[SSDFS_MAIN_SB_SEG];
}

static inline
struct ssdfs_found_peb *
RESERVED_COPY_SB_PEB(struct ssdfs_found_superblock_pebs *ptr)
{
	return &ptr->sb_pebs[SSDFS_RESERVED_SB_SEG].pair[SSDFS_COPY_SB_SEG];
}

static inline
struct ssdfs_found_peb *
PREV_MAIN_SB_PEB(struct ssdfs_found_superblock_pebs *ptr)
{
	return &ptr->sb_pebs[SSDFS_PREV_SB_SEG].pair[SSDFS_MAIN_SB_SEG];
}

static inline
struct ssdfs_found_peb *
PREV_COPY_SB_PEB(struct ssdfs_found_superblock_pebs *ptr)
{
	return &ptr->sb_pebs[SSDFS_PREV_SB_SEG].pair[SSDFS_COPY_SB_SEG];
}

static inline
bool IS_INSIDE_STRIPE(struct ssdfs_found_protected_pebs *ptr,
		      struct ssdfs_found_peb *found)
{
	return found->peb_id >= ptr->start_peb &&
		found->peb_id < (ptr->start_peb + ptr->pebs_count);
}

static inline
u64 SSDFS_RECOVERY_LOW_OFF(struct ssdfs_recovery_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi || !env->found);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (env->found->search_phase) {
	case SSDFS_RECOVERY_FAST_SEARCH:
		return env->found->lower_offset;

	case SSDFS_RECOVERY_SLOW_SEARCH:
	case SSDFS_RECOVERY_FIRST_SLOW_TRY:
		return env->found->middle_offset;

	case SSDFS_RECOVERY_SECOND_SLOW_TRY:
		return env->found->lower_offset;

	case SSDFS_RECOVERY_THIRD_SLOW_TRY:
		if (env->found->start_peb == 0)
			return SSDFS_RESERVED_VBR_SIZE;
		else
			return env->found->start_peb * env->fsi->erasesize;
	}

	return U64_MAX;
}

static inline
u64 SSDFS_RECOVERY_UPPER_OFF(struct ssdfs_recovery_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi || !env->found);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (env->found->search_phase) {
	case SSDFS_RECOVERY_FAST_SEARCH:
		return env->found->middle_offset +
			    ((SSDFS_MAPTBL_PROTECTION_STEP - 1) *
				env->fsi->erasesize);

	case SSDFS_RECOVERY_SLOW_SEARCH:
	case SSDFS_RECOVERY_FIRST_SLOW_TRY:
		return env->found->upper_offset;

	case SSDFS_RECOVERY_SECOND_SLOW_TRY:
		return env->found->middle_offset;

	case SSDFS_RECOVERY_THIRD_SLOW_TRY:
		return env->found->lower_offset;
	}

	return U64_MAX;
}

static inline
u64 *SSDFS_RECOVERY_CUR_OFF_PTR(struct ssdfs_recovery_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->found);
#endif /* CONFIG_SSDFS_DEBUG */

	return &env->found->current_offset;
}

static inline
void SSDFS_RECOVERY_SET_FAST_SEARCH_TRY(struct ssdfs_recovery_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->found);
#endif /* CONFIG_SSDFS_DEBUG */

	*SSDFS_RECOVERY_CUR_OFF_PTR(env) = env->found->lower_offset;
	env->found->search_phase = SSDFS_RECOVERY_FAST_SEARCH;

	SSDFS_DBG("lower_offset %llu, "
		  "middle_offset %llu, "
		  "upper_offset %llu, "
		  "current_offset %llu, "
		  "search_phase %#x\n",
		  env->found->lower_offset,
		  env->found->middle_offset,
		  env->found->upper_offset,
		  env->found->current_offset,
		  env->found->search_phase);
}

static inline
void SSDFS_RECOVERY_SET_FIRST_SLOW_TRY(struct ssdfs_recovery_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->found);
#endif /* CONFIG_SSDFS_DEBUG */

	*SSDFS_RECOVERY_CUR_OFF_PTR(env) = env->found->middle_offset;
	env->found->search_phase = SSDFS_RECOVERY_FIRST_SLOW_TRY;

	SSDFS_DBG("lower_offset %llu, "
		  "middle_offset %llu, "
		  "upper_offset %llu, "
		  "current_offset %llu, "
		  "search_phase %#x\n",
		  env->found->lower_offset,
		  env->found->middle_offset,
		  env->found->upper_offset,
		  env->found->current_offset,
		  env->found->search_phase);
}

static inline
bool is_second_slow_try_possible(struct ssdfs_recovery_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->found);
#endif /* CONFIG_SSDFS_DEBUG */

	return env->found->lower_offset < env->found->middle_offset;
}

static inline
void SSDFS_RECOVERY_SET_SECOND_SLOW_TRY(struct ssdfs_recovery_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->found);
#endif /* CONFIG_SSDFS_DEBUG */

	*SSDFS_RECOVERY_CUR_OFF_PTR(env) = env->found->lower_offset;
	env->found->search_phase = SSDFS_RECOVERY_SECOND_SLOW_TRY;

	SSDFS_DBG("lower_offset %llu, "
		  "middle_offset %llu, "
		  "upper_offset %llu, "
		  "current_offset %llu, "
		  "search_phase %#x\n",
		  env->found->lower_offset,
		  env->found->middle_offset,
		  env->found->upper_offset,
		  env->found->current_offset,
		  env->found->search_phase);
}

static inline
bool is_third_slow_try_possible(struct ssdfs_recovery_env *env)
{
	u64 offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi || !env->found);
#endif /* CONFIG_SSDFS_DEBUG */

	offset = env->found->start_peb * env->fsi->erasesize;
	return offset < env->found->lower_offset;
}

static inline
void SSDFS_RECOVERY_SET_THIRD_SLOW_TRY(struct ssdfs_recovery_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->fsi || !env->found);
#endif /* CONFIG_SSDFS_DEBUG */

	*SSDFS_RECOVERY_CUR_OFF_PTR(env) = env->found->lower_offset;
	env->found->search_phase = SSDFS_RECOVERY_THIRD_SLOW_TRY;

	SSDFS_DBG("lower_offset %llu, "
		  "middle_offset %llu, "
		  "upper_offset %llu, "
		  "current_offset %llu, "
		  "search_phase %#x\n",
		  env->found->lower_offset,
		  env->found->middle_offset,
		  env->found->upper_offset,
		  env->found->current_offset,
		  env->found->search_phase);
}

/*
 * Recovery API
 */
int ssdfs_recovery_start_thread(struct ssdfs_recovery_env *env,
				u32 id);
int ssdfs_recovery_stop_thread(struct ssdfs_recovery_env *env);
void ssdfs_backup_sb_info2(struct ssdfs_recovery_env *env);
void ssdfs_restore_sb_info2(struct ssdfs_recovery_env *env);
int ssdfs_read_checked_sb_info3(struct ssdfs_recovery_env *env,
				u64 peb_id, u32 pages_off);
int __ssdfs_find_any_valid_volume_header2(struct ssdfs_recovery_env *env,
					  u64 start_offset,
					  u64 end_offset,
					  u64 step);
int ssdfs_find_any_valid_sb_segment2(struct ssdfs_recovery_env *env,
				     u64 threshold_peb);
bool is_cur_main_sb_peb_exhausted(struct ssdfs_recovery_env *env);
bool is_cur_copy_sb_peb_exhausted(struct ssdfs_recovery_env *env);
int ssdfs_check_next_sb_pebs_pair(struct ssdfs_recovery_env *env);
int ssdfs_check_reserved_sb_pebs_pair(struct ssdfs_recovery_env *env);
int ssdfs_find_latest_valid_sb_segment2(struct ssdfs_recovery_env *env);
int ssdfs_find_last_sb_seg_outside_fragment(struct ssdfs_recovery_env *env);
int ssdfs_recovery_try_fast_search(struct ssdfs_recovery_env *env);
int ssdfs_recovery_try_slow_search(struct ssdfs_recovery_env *env);

#endif /* _SSDFS_RECOVERY_H */
