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
 * struct ssdfs_recovery_env - recovery environment
 * @pagesize: page size in bytes
 * @erasesize: physical erase block size in bytes
 * @segsize: segment size in bytes
 * @pebs_per_seg: physical erase blocks per segment
 * @pages_per_peb: pages per physical erase block
 * @pages_per_seg: pages per segment
 * @start_peb: starting PEB ID in fragment
 * @pebs_count: PEBs count in fragment
 * @lower_offset: lower offset bound
 * @middle_offset: middle offset
 * @upper_offset: upper offset bound
 * @current_offset: current position of the search
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
	u32 pagesize;
	u32 erasesize;
	u32 segsize;
	u32 pebs_per_seg;
	u32 pages_per_peb;
	u32 pages_per_seg;

	u64 start_peb;
	u32 pebs_count;

	u64 lower_offset;
	u64 middle_offset;
	u64 upper_offset;
	u64 current_offset;
	int search_phase;

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
	SSDFS_RECOVERY_LAST_TRY_SEARCH,
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
u64 SSDFS_RECOVERY_LOW_OFF(struct ssdfs_recovery_env *env)
{
	switch (env->search_phase) {
	case SSDFS_RECOVERY_FAST_SEARCH:
		return env->middle_offset;

	case SSDFS_RECOVERY_SLOW_SEARCH:
		return env->lower_offset;

	case SSDFS_RECOVERY_LAST_TRY_SEARCH:
		return env->start_peb * env->erasesize;
	}

	return U64_MAX;
}

static inline
u64 SSDFS_RECOVERY_UPPER_OFF(struct ssdfs_recovery_env *env)
{
	switch (env->search_phase) {
	case SSDFS_RECOVERY_FAST_SEARCH:
		return env->upper_offset;

	case SSDFS_RECOVERY_SLOW_SEARCH:
		return env->middle_offset;

	case SSDFS_RECOVERY_LAST_TRY_SEARCH:
		return env->lower_offset;
	}

	return U64_MAX;
}

static inline
u64 *SSDFS_RECOVERY_CUR_OFF_PTR(struct ssdfs_recovery_env *env)
{
	return &env->current_offset;
}

static inline
void SSDFS_RECOVERY_SET_MIDDLE_OFF(struct ssdfs_recovery_env *env)
{
	u64 range_bytes;

	if (env->lower_offset == env->upper_offset) {
		SSDFS_WARN("lower_offset %llu == upper_offset %llu\n",
			   env->lower_offset,
			   env->upper_offset);
		return;
	}

	range_bytes = (u64)SSDFS_MAPTBL_PROTECTION_STEP * env->erasesize;

	env->middle_offset =
		max_t(u64, env->lower_offset, env->upper_offset - range_bytes);
}

static inline
void SSDFS_RECOVERY_SET_FAST_SEARCH(struct ssdfs_recovery_env *env)
{
	*SSDFS_RECOVERY_CUR_OFF_PTR(env) = env->middle_offset;
	env->search_phase = SSDFS_RECOVERY_FAST_SEARCH;

	SSDFS_DBG("env->lower_offset %llu, "
		  "env->middle_offset %llu, "
		  "env->upper_offset %llu, "
		  "env->current_offset %llu, "
		  "env->search_phase %#x\n",
		  env->lower_offset,
		  env->middle_offset,
		  env->upper_offset,
		  env->current_offset,
		  env->search_phase);
}

static inline
bool is_slow_search_possible(struct ssdfs_recovery_env *env)
{
	return env->lower_offset < env->middle_offset;
}

static inline
void SSDFS_RECOVERY_SET_SLOW_SEARCH(struct ssdfs_recovery_env *env)
{
	*SSDFS_RECOVERY_CUR_OFF_PTR(env) = env->lower_offset;
	env->search_phase = SSDFS_RECOVERY_SLOW_SEARCH;

	SSDFS_DBG("env->lower_offset %llu, "
		  "env->middle_offset %llu, "
		  "env->upper_offset %llu, "
		  "env->current_offset %llu, "
		  "env->search_phase %#x\n",
		  env->lower_offset,
		  env->middle_offset,
		  env->upper_offset,
		  env->current_offset,
		  env->search_phase);
}

static inline
bool is_last_try_search_possible(struct ssdfs_recovery_env *env)
{
	return (env->start_peb * env->erasesize) < env->lower_offset;
}

static inline
void SSDFS_RECOVERY_SET_LAST_TRY_SEARCH(struct ssdfs_recovery_env *env)
{
	*SSDFS_RECOVERY_CUR_OFF_PTR(env) = env->start_peb * env->erasesize;
	env->search_phase = SSDFS_RECOVERY_LAST_TRY_SEARCH;

	SSDFS_DBG("env->lower_offset %llu, "
		  "env->middle_offset %llu, "
		  "env->upper_offset %llu, "
		  "env->current_offset %llu, "
		  "env->search_phase %#x\n",
		  env->lower_offset,
		  env->middle_offset,
		  env->upper_offset,
		  env->current_offset,
		  env->search_phase);
}

/*
 * Recovery API
 */
int ssdfs_recovery_start_thread(struct ssdfs_recovery_env *env,
				u32 id);
int ssdfs_recovery_stop_thread(struct ssdfs_recovery_env *env);

#endif /* _SSDFS_RECOVERY_H */
