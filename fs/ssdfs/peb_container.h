//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_container.h - PEB container declarations.
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

#ifndef _SSDFS_PEB_CONTAINER_H
#define _SSDFS_PEB_CONTAINER_H

#include "block_bitmap.h"
#include "peb.h"

/* PEB container's array indexes */
enum {
	SSDFS_SEG_PEB1,
	SSDFS_SEG_PEB2,
	SSDFS_SEG_PEB_ITEMS_MAX
};

/* PEB container possible states */
enum {
	SSDFS_PEB_CONTAINER_EMPTY,
	SSDFS_PEB1_SRC_CONTAINER,
	SSDFS_PEB1_DST_CONTAINER,
	SSDFS_PEB1_SRC_PEB2_DST_CONTAINER,
	SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER,
	SSDFS_PEB2_SRC_CONTAINER,
	SSDFS_PEB2_DST_CONTAINER,
	SSDFS_PEB2_SRC_PEB1_DST_CONTAINER,
	SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER,
	SSDFS_PEB_CONTAINER_STATE_MAX
};

/*
 * PEB migration state
 */
enum {
	SSDFS_PEB_UNKNOWN_MIGRATION_STATE,
	SSDFS_PEB_NOT_MIGRATING,
	SSDFS_PEB_MIGRATION_PREPARATION,
	SSDFS_PEB_RELATION_PREPARATION,
	SSDFS_PEB_UNDER_MIGRATION,
	SSDFS_PEB_MIGRATION_STATE_MAX
};

/*
 * PEB migration phase
 */
enum {
	SSDFS_PEB_MIGRATION_STATUS_UNKNOWN,
	SSDFS_SRC_PEB_NOT_EXHAUSTED,
	SSDFS_DST_PEB_RECEIVES_DATA,
	SSDFS_PEB_MIGRATION_PHASE_MAX
};

/*
 * struct ssdfs_peb_container - PEB container
 * @peb_type: type of PEB
 * @peb_index: index of PEB in the array
 * @log_pages: count of pages in full log
 * @threads: PEB container's threads array
 * @read_rq: read requests queue
 * @update_rq: update requests queue
 * @crq_ptr_lock: lock of pointer on create requests queue
 * @create_rq: pointer on shared new page requests queue
 * @parent_si: pointer on parent segment object
 * @migration_state: PEB migration state
 * @migration_phase: PEB migration phase
 * @items_state: items array state
 * @shared_free_dst_blks: count of blocks that destination is able to share
 * @lock: container's internals lock
 * @src_peb: pointer on source PEB
 * @dst_peb: pointer on destination PEB
 * @dst_peb_refs: reference counter of destination PEB (sharing counter)
 * @items: buffers for PEB objects
 * @peb_kobj: /sys/fs/ssdfs/<device>/<segN>/<pebN> kernel object
 * @peb_kobj_unregister: completion state for <pebN> kernel object
 */
struct ssdfs_peb_container {
	/* Static data */
	u8 peb_type;
	u16 peb_index;
	u16 log_pages;

	/* PEB container's threads */
	struct ssdfs_thread_info thread[SSDFS_PEB_THREAD_TYPE_MAX];

	/* Read requests queue */
	struct ssdfs_requests_queue read_rq;

	/* Update requests queue */
	struct ssdfs_requests_queue update_rq;

	/* Shared new page requests queue */
	spinlock_t crq_ptr_lock;
	struct ssdfs_requests_queue *create_rq;

	/* Parent segment */
	struct ssdfs_segment_info *parent_si;

	/* Migration info */
	atomic_t migration_state;
	atomic_t migration_phase;
	atomic_t items_state;
	atomic_t shared_free_dst_blks;

	/* PEB objects */
	struct rw_semaphore lock;
	struct ssdfs_peb_info *src_peb;
	struct ssdfs_peb_info *dst_peb;
	atomic_t dst_peb_refs;
	struct ssdfs_peb_info items[SSDFS_SEG_PEB_ITEMS_MAX];

	/* /sys/fs/ssdfs/<device>/<segN>/<pebN> */
	struct kobject peb_kobj;
	struct completion peb_kobj_unregister;
};

/*
 * Inline functions
 */
static inline
bool is_peb_container_empty(struct ssdfs_peb_container *pebc)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);
#endif /* CONFIG_SSDFS_DEBUG */

	return atomic_read(&pebc->items_state) == SSDFS_PEB_CONTAINER_EMPTY;
}

/*
 * PEB container's API
 */
int ssdfs_peb_container_create(struct ssdfs_fs_info *fsi,
				u64 seg, u32 peb_index,
				u8 peb_type,
				u16 log_pages,
				struct ssdfs_segment_info *si);
void ssdfs_peb_container_destroy(struct ssdfs_peb_container *pebc);

int ssdfs_peb_container_invalidate_block(struct ssdfs_peb_container *pebc,
				    struct ssdfs_phys_offset_descriptor *desc);
int ssdfs_peb_get_free_pages(struct ssdfs_peb_container *pebc);
int ssdfs_peb_get_used_data_pages(struct ssdfs_peb_container *pebc);
int ssdfs_peb_get_invalid_pages(struct ssdfs_peb_container *pebc);

int ssdfs_peb_join_create_requests_queue(struct ssdfs_peb_container *pebc,
					 struct ssdfs_requests_queue *create_rq);
void ssdfs_peb_forget_create_requests_queue(struct ssdfs_peb_container *pebc);
bool is_peb_joined_into_create_requests_queue(struct ssdfs_peb_container *pebc);

struct ssdfs_peb_info *
ssdfs_get_current_peb_locked(struct ssdfs_peb_container *pebc);
void ssdfs_unlock_current_peb(struct ssdfs_peb_container *pebc);

int ssdfs_peb_container_create_destination(struct ssdfs_peb_container *ptr);
int ssdfs_peb_container_forget_source(struct ssdfs_peb_container *pebc);
int ssdfs_peb_container_forget_relation(struct ssdfs_peb_container *pebc);
int ssdfs_peb_container_change_state(struct ssdfs_peb_container *pebc);

/*
 * PEB container's private API
 */
int ssdfs_peb_gc_thread_func(void *data);
int ssdfs_peb_read_thread_func(void *data);
int ssdfs_peb_flush_thread_func(void *data);

u16 ssdfs_peb_estimate_reserved_metapages(u32 page_size, u32 pages_per_peb,
					  u16 log_pages, u32 pebs_per_seg,
					  bool is_migrating);
int ssdfs_peb_read_page(struct ssdfs_peb_container *pebc,
			struct ssdfs_segment_request *req,
			struct completion **end);
int ssdfs_peb_readahead_pages(struct ssdfs_peb_container *pebc,
			      struct ssdfs_segment_request *req,
			      struct completion **end);
void ssdfs_peb_mark_request_block_uptodate(struct ssdfs_peb_container *pebc,
					   struct ssdfs_segment_request *req,
					   int blk_index);
int ssdfs_peb_copy_pages_range(struct ssdfs_peb_container *pebc,
				struct ssdfs_block_bmap_range *range,
				struct ssdfs_segment_request *req);
int ssdfs_peb_copy_pre_alloc_page(struct ssdfs_peb_container *pebc,
				  u32 logical_blk,
				  struct ssdfs_segment_request *req);
int __ssdfs_peb_get_block_state_desc(struct ssdfs_peb_info *pebi,
				struct ssdfs_metadata_descriptor *area_desc,
				struct ssdfs_block_state_descriptor *desc,
				u64 *cno, u64 *parent_snapshot);
int ssdfs_peb_read_block_state(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				struct ssdfs_metadata_descriptor *array,
				size_t array_size,
				struct ssdfs_block_descriptor *blk_desc,
				int blk_state_index);

#endif /* _SSDFS_PEB_CONTAINER_H */
