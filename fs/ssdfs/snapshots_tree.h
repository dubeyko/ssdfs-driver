//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/snapshots_tree.h - snapshots btree declarations.
 *
 * Copyright (c) 2021-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_SNAPSHOTS_TREE_H
#define _SSDFS_SNAPSHOTS_TREE_H

/*
 * struct ssdfs_snapshots_btree_queue - snapshot requests queue
 * @queue: snapshot requests queue object
 * @thread: descriptor of queue's thread
 */
struct ssdfs_snapshots_btree_queue {
	struct ssdfs_snapshot_reqs_queue queue;
	struct ssdfs_thread_info thread;
};

/*
 * struct ssdfs_snapshots_btree_info - snapshots btree info
 * @state: snapshots btree state
 * @lock: snapshots btree lock
 * @generic_tree: generic btree description
 * @snapshots_count: count of the snapshots in the whole tree
 * @deleted_snapshots: current number of snapshot delete operations
 * @requests: snapshot requests queue
 * @wait_queue: wait queue of snapshots tree's thread
 * @fsi: pointer on shared file system object
 */
struct ssdfs_snapshots_btree_info {
	atomic_t state;
	struct rw_semaphore lock;
	struct ssdfs_btree generic_tree;

	atomic64_t snapshots_count;
	atomic64_t deleted_snapshots;

	struct ssdfs_snapshots_btree_queue requests;
	wait_queue_head_t wait_queue;

	struct ssdfs_fs_info *fsi;
};

/* Snapshots tree states */
enum {
	SSDFS_SNAPSHOTS_BTREE_UNKNOWN_STATE,
	SSDFS_SNAPSHOTS_BTREE_CREATED,
	SSDFS_SNAPSHOTS_BTREE_INITIALIZED,
	SSDFS_SNAPSHOTS_BTREE_DIRTY,
	SSDFS_SNAPSHOTS_BTREE_CORRUPTED,
	SSDFS_SNAPSHOTS_BTREE_STATE_MAX
};

/*
 * Inline functions
 */

static inline
int check_minute(int minute)
{
	if (minute < 0 || minute > 60) {
		SSDFS_ERR("invalid minute value %d\n",
			  minute);
		return -EINVAL;
	}

	return 0;
}

static inline
int check_hour(int hour)
{
	if (hour < 0 || hour > 24) {
		SSDFS_ERR("invalid hour value %d\n",
			  hour);
		return -EINVAL;
	}

	return 0;
}

static inline
int check_day(int day)
{
	if (day <= 0 || day > 31) {
		SSDFS_ERR("invalid day value %d\n",
			  day);
		return -EINVAL;
	}

	return 0;
}

static inline
int check_month(int month)
{
	if (month <= 0 || month > 12) {
		SSDFS_ERR("invalid month value %d\n",
			  month);
		return -EINVAL;
	}

	return 0;
}

static inline
int check_year(int year)
{
	if (year < 1970) {
		SSDFS_ERR("invalid year value %d\n",
			  year);
		return -EINVAL;
	}

	return 0;
}

static inline
void SHOW_SNAPSHOT_INFO(struct ssdfs_snapshot_request *snr)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("SNAPSHOT INFO: ");
	SSDFS_DBG("name %s, ", snr->info.name);
	SSDFS_DBG("UUID %pUb, ", snr->info.uuid);
	SSDFS_DBG("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, snapshots_threshold %u, "
		  "TIME_RANGE (day %u, month %u, year %u)\n",
		  snr->info.mode, snr->info.type, snr->info.expiration,
		  snr->info.frequency, snr->info.snapshots_threshold,
		  snr->info.time_range.day,
		  snr->info.time_range.month,
		  snr->info.time_range.year);
#endif /* CONFIG_SSDFS_DEBUG */
}

static inline
bool is_item_snapshot(void *kaddr)
{
	struct ssdfs_snapshot *snapshot;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

	snapshot = (struct ssdfs_snapshot *)kaddr;

	return le16_to_cpu(snapshot->magic) == SSDFS_SNAPSHOT_RECORD_MAGIC;
}

static inline
bool is_item_peb2time_record(void *kaddr)
{
	struct ssdfs_peb2time_set *peb2time;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

	peb2time = (struct ssdfs_peb2time_set *)kaddr;

	return le16_to_cpu(peb2time->magic) == SSDFS_PEB2TIME_RECORD_MAGIC;
}

static inline
bool is_peb2time_record_requested(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	return search->request.flags & SSDFS_BTREE_SEARCH_HAS_PEB2TIME_PAIR;
}

/*
 * Snapshots tree API
 */
int ssdfs_snapshots_btree_create(struct ssdfs_fs_info *fsi);
void ssdfs_snapshots_btree_destroy(struct ssdfs_fs_info *fsi);
int ssdfs_snapshots_btree_flush(struct ssdfs_fs_info *fsi);

int ssdfs_snapshots_btree_find(struct ssdfs_snapshots_btree_info *tree,
				struct ssdfs_snapshot_id *id,
				struct ssdfs_btree_search *search);
int ssdfs_snapshots_btree_find_range(struct ssdfs_snapshots_btree_info *tree,
				     struct ssdfs_timestamp_range *range,
				     struct ssdfs_btree_search *search);
int ssdfs_snapshots_btree_check_range(struct ssdfs_snapshots_btree_info *tree,
				      struct ssdfs_timestamp_range *range,
				      struct ssdfs_btree_search *search);
int ssdfs_snapshots_btree_add(struct ssdfs_snapshots_btree_info *tree,
			     struct ssdfs_snapshot_request *snr,
			     struct ssdfs_btree_search *search);
int ssdfs_snapshots_btree_add_peb2time(struct ssdfs_snapshots_btree_info *tree,
					struct ssdfs_peb_timestamps *peb2time,
					struct ssdfs_btree_search *search);
int ssdfs_snapshots_btree_change(struct ssdfs_snapshots_btree_info *tree,
				 struct ssdfs_snapshot_request *snr,
				 struct ssdfs_btree_search *search);
int ssdfs_snapshots_btree_delete(struct ssdfs_snapshots_btree_info *tree,
				 struct ssdfs_snapshot_request *snr,
				 struct ssdfs_btree_search *search);
int ssdfs_snapshots_btree_delete_peb2time(struct ssdfs_snapshots_btree_info *,
					  struct ssdfs_peb_timestamps *peb2time,
					  struct ssdfs_btree_search *search);
int ssdfs_snapshots_btree_delete_all(struct ssdfs_snapshots_btree_info *tree);

/*
 * Internal snapshots tree API
 */
int ssdfs_start_snapshots_btree_thread(struct ssdfs_fs_info *fsi);
int ssdfs_stop_snapshots_btree_thread(struct ssdfs_fs_info *fsi);
int ssdfs_snapshots_tree_find_leaf_node(struct ssdfs_snapshots_btree_info *tree,
					struct ssdfs_timestamp_range *range,
					struct ssdfs_btree_search *search);
int ssdfs_snapshots_tree_get_start_hash(struct ssdfs_snapshots_btree_info *tree,
					u64 *start_hash);
int ssdfs_snapshots_tree_node_hash_range(struct ssdfs_snapshots_btree_info *tree,
					 struct ssdfs_btree_search *search,
					 u64 *start_hash, u64 *end_hash,
					 u16 *items_count);
int ssdfs_snapshots_tree_extract_range(struct ssdfs_snapshots_btree_info *tree,
				       u16 start_index, u16 count,
				       struct ssdfs_btree_search *search);
int ssdfs_snapshots_tree_check_search_result(struct ssdfs_btree_search *search);
int ssdfs_snapshots_tree_get_next_hash(struct ssdfs_snapshots_btree_info *tree,
					struct ssdfs_btree_search *search,
					u64 *next_hash);

void ssdfs_debug_snapshots_btree_object(struct ssdfs_snapshots_btree_info *tree);

/*
 * Snapshots btree specialized operations
 */
extern const struct ssdfs_btree_descriptor_operations
						ssdfs_snapshots_btree_desc_ops;
extern const struct ssdfs_btree_operations ssdfs_snapshots_btree_ops;
extern const struct ssdfs_btree_node_operations ssdfs_snapshots_btree_node_ops;

#endif /* _SSDFS_SNAPSHOTS_TREE_H */
