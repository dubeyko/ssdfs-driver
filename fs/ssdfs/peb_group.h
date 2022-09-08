//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_group.h - PEBs group's declarations.
 *
 * Copyright (c) 2021-2022 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_PEB_GROUP_H
#define _SSDFS_PEB_GROUP_H

/*
 * struct ssdfs_peb_group - PEBs group declaration
 * @start_leb: starting LEB id in the group
 * @lebs_count: number of LEBs in the group
 * @fsi: pointer on shared file system object
 * @thread: pool of threads in the group
 * @wait_queue: threads' wait queues
 * @reqs_counter: request counters array
 * @create_rq_state: create queue state
 * @group_lock: lock of the group
 * @active_pebs: number of active PEB containers in array
 * @pebs: array of pointers on PEB containers
 */
struct ssdfs_peb_group {
	/* Static data */
	u64 start_leb;
	u32 lebs_count;

	struct ssdfs_fs_info *fsi;

	/* PEBs group's threads */
	struct ssdfs_thread_info thread[SSDFS_PEB_THREAD_TYPE_MAX];

	/* Threads' wait queues */
	wait_queue_head_t wait_queue[SSDFS_PEB_THREAD_TYPE_MAX];

	/* Requests counter */
	atomic64_t reqs_counter[SSDFS_PEB_THREAD_TYPE_MAX];

	/* Create queue state */
	atomic_t create_rq_state;

	spinlock_t group_lock;
	u32 active_pebs;
	struct ssdfs_peb_container *pebs[SSDFS_DEFAULT_PEBS_PER_GROUP];
};

/* Possible states of create queue */
enum {
	SSDFS_CREATE_RQ_EMPTY,
	SSDFS_PLEASE_CHECK_CREATE_RQ_EMPTYNESS,
};

/*
 * Inline methods
 */
static inline
u64 SSDFS_LEB2GROUP_ID(struct ssdfs_fs_info *fsi,
			u64 leb_id)
{
	return div64_u64(leb_id, fsi->pebs_per_group);
}

static inline
u64 SSDFS_GROUP2LEB_ID(struct ssdfs_fs_info *fsi,
			u64 group_id)
{
	return group_id * fsi->pebs_per_group;
}

static inline
void SSDFS_GROUP_REQS_INC(struct ssdfs_peb_group *group,
			  int thread_type)
{
	atomic64_inc(&group->reqs_counter[thread_type]);
}

static inline
void SSDFS_GROUP_REQS_DEC(struct ssdfs_peb_group *group,
			  int thread_type)
{
	s64 count;

	count = atomic64_dec_return(&group->reqs_counter[thread_type]);
	if (count < 0) {
		SSDFS_WARN("invalid count %lld\n", count);
	}
}

static inline
s64 SSDFS_GROUP_READ_REQS(struct ssdfs_peb_group *group,
			  int thread_type)
{
	return atomic64_read(&group->reqs_counter[thread_type]);
}

static inline
bool IS_SSDFS_GROUP_RQ_EMPTY(struct ssdfs_peb_group *group,
			     int thread_type)
{
	return SSDFS_GROUP_READ_REQS(group, thread_type) <= 0;
}

static inline
void SSDFS_SET_CREATE_RQ_EMPTY(struct ssdfs_peb_group *group)
{
	atomic_set(&group->create_rq_state, SSDFS_CREATE_RQ_EMPTY);
}

static inline
void SSDFS_PLEASE_CHECK_CREATE_RQ(struct ssdfs_peb_group *group)
{
	atomic_set(&group->create_rq_state,
			SSDFS_PLEASE_CHECK_CREATE_RQ_EMPTYNESS);
}

static inline
bool IS_SSDFS_CREATE_RQ_EMPTY(struct ssdfs_peb_group *group)
{
	return atomic_read(&group->create_rq_state) == SSDFS_CREATE_RQ_EMPTY;
}

/*
 * PEBs group's API
 */
int ssdfs_peb_group_create(struct ssdfs_fs_info *fsi,
			   struct ssdfs_peb_group *group,
			   u64 group_id);
void ssdfs_peb_group_destroy(struct ssdfs_peb_group *group);
int ssdfs_peb_group_add_peb(struct ssdfs_peb_group *group,
			     struct ssdfs_peb_container *pebc);
int ssdfs_peb_group_remove_peb(struct ssdfs_peb_group *group,
				struct ssdfs_peb_container *pebc);

u64 SSDFS_SEG2LEB(struct ssdfs_peb_container *pebc);
u16 SSDFS_LEB2INDEX(struct ssdfs_peb_group *group,
		    struct ssdfs_peb_container *pebc);

#endif /* _SSDFS_PEB_GROUP_H */
