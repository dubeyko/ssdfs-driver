//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/snapshot_requests_queue.h - snapshot requests queue declarations.
 *
 * Copyright (c) 2021-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_SNAPSHOT_REQUESTS_QUEUE_H
#define _SSDFS_SNAPSHOT_REQUESTS_QUEUE_H

/*
 * struct ssdfs_snapshot_reqs_queue - snapshot requests queue descriptor
 * @lock: snapshot requests queue's lock
 * @list: snapshot requests queue's list
 */
struct ssdfs_snapshot_reqs_queue {
	spinlock_t lock;
	struct list_head list;
};

struct ssdfs_snapshot_request;
struct ssdfs_snapshot_subsystem;
struct ssdfs_fs_info;

/*
 * Snapshot requests queue API
 */
void ssdfs_snapshot_reqs_queue_init(struct ssdfs_snapshot_reqs_queue *rq);
bool is_ssdfs_snapshot_reqs_queue_empty(struct ssdfs_snapshot_reqs_queue *rq);
void ssdfs_snapshot_reqs_queue_add_tail(struct ssdfs_snapshot_reqs_queue *rq,
					struct ssdfs_snapshot_request *snr);
void ssdfs_snapshot_reqs_queue_add_head(struct ssdfs_snapshot_reqs_queue *rq,
					struct ssdfs_snapshot_request *snr);
int ssdfs_snapshot_reqs_queue_remove_first(struct ssdfs_snapshot_reqs_queue *rq,
					   struct ssdfs_snapshot_request **snr);
void ssdfs_snapshot_reqs_queue_remove_all(struct ssdfs_snapshot_reqs_queue *rq);

/*
 * Snapshot request's API
 */
struct ssdfs_snapshot_request *ssdfs_snapshot_request_alloc(void);
void ssdfs_snapshot_request_free(struct ssdfs_snapshot_request *snr);

int ssdfs_execute_create_snapshots(struct ssdfs_fs_info *fsi);
int ssdfs_execute_list_snapshots_request(struct ssdfs_snapshot_subsystem *ptr,
					 struct ssdfs_snapshot_request *snr);
int ssdfs_execute_modify_snapshot_request(struct ssdfs_fs_info *fsi,
					  struct ssdfs_snapshot_request *snr);
int ssdfs_execute_remove_snapshot_request(struct ssdfs_snapshot_subsystem *ptr,
					  struct ssdfs_snapshot_request *snr);
int ssdfs_execute_remove_range_request(struct ssdfs_snapshot_subsystem *ptr,
					struct ssdfs_snapshot_request *snr);
int ssdfs_execute_show_details_request(struct ssdfs_snapshot_subsystem *ptr,
					struct ssdfs_snapshot_request *snr);
int ssdfs_execute_list_snapshot_rules_request(struct ssdfs_fs_info *fsi,
					struct ssdfs_snapshot_request *snr);

#endif /* _SSDFS_SNAPSHOT_REQUESTS_QUEUE_H */
