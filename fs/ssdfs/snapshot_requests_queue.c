//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/snapshot_requests_queue.c - snapshot requests queue implementation.
 *
 * Copyright (c) 2021 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "snapshot_requests_queue.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_snap_reqs_queue_page_leaks;
atomic64_t ssdfs_snap_reqs_queue_memory_leaks;
atomic64_t ssdfs_snap_reqs_queue_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_snap_reqs_queue_cache_leaks_increment(void *kaddr)
 * void ssdfs_snap_reqs_queue_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_snap_reqs_queue_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_snap_reqs_queue_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_snap_reqs_queue_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_snap_reqs_queue_kfree(void *kaddr)
 * struct page *ssdfs_snap_reqs_queue_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_snap_reqs_queue_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_snap_reqs_queue_free_page(struct page *page)
 * void ssdfs_snap_reqs_queue_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(snap_reqs_queue)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(snap_reqs_queue)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_snap_reqs_queue_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_snap_reqs_queue_page_leaks, 0);
	atomic64_set(&ssdfs_snap_reqs_queue_memory_leaks, 0);
	atomic64_set(&ssdfs_snap_reqs_queue_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_snap_reqs_queue_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_snap_reqs_queue_page_leaks) != 0) {
		SSDFS_ERR("SNAPSHOT REQUESTS QUEUE: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_snap_reqs_queue_page_leaks));
	}

	if (atomic64_read(&ssdfs_snap_reqs_queue_memory_leaks) != 0) {
		SSDFS_ERR("SNAPSHOT REQUESTS QUEUE: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_snap_reqs_queue_memory_leaks));
	}

	if (atomic64_read(&ssdfs_snap_reqs_queue_cache_leaks) != 0) {
		SSDFS_ERR("SNAPSHOT REQUESTS QUEUE: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_snap_reqs_queue_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * ssdfs_snapshot_reqs_queue_init() - initialize snapshot requests queue
 * @rq: snapshot requests queue
 */
void ssdfs_snapshot_reqs_queue_init(struct ssdfs_snapshot_reqs_queue *rq)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock_init(&rq->lock);
	INIT_LIST_HEAD(&rq->list);
}

/*
 * is_ssdfs_snapshot_reqs_queue_empty() - check that snap reqs queue is empty
 * @rq: snapshot requests queue
 */
bool is_ssdfs_snapshot_reqs_queue_empty(struct ssdfs_snapshot_reqs_queue *rq)
{
	bool is_empty;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&rq->lock);
	is_empty = list_empty_careful(&rq->list);
	spin_unlock(&rq->lock);

	return is_empty;
}

/*
 * ssdfs_snapshot_reqs_queue_add_head() - add request at the head of queue
 * @rq: snapshot requests queue
 * @snr: snapshot request
 */
void ssdfs_snapshot_reqs_queue_add_head(struct ssdfs_snapshot_reqs_queue *rq,
					struct ssdfs_snapshot_request *snr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rq || !snr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("operation %#x\n",
		  snr->operation);

	spin_lock(&rq->lock);
	list_add(&snr->list, &rq->list);
	spin_unlock(&rq->lock);
}

/*
 * ssdfs_snapshot_reqs_queue_add_tail() - add request at the tail of queue
 * @rq: snapshot requests queue
 * @snr: snapshot request
 */
void ssdfs_snapshot_reqs_queue_add_tail(struct ssdfs_snapshot_reqs_queue *rq,
					struct ssdfs_snapshot_request *snr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rq || !snr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("operation %#x\n",
		  snr->operation);

	spin_lock(&rq->lock);
	list_add_tail(&snr->list, &rq->list);
	spin_unlock(&rq->lock);
}

/*
 * ssdfs_snapshot_reqs_queue_remove_first() - get request and remove from queue
 * @rq: snapshot requests queue
 * @snr: first snapshot request [out]
 *
 * This function get first snapshot request in @rq, remove it from queue
 * and return as @snr.
 *
 * RETURN:
 * [success] - @snr contains pointer on snapshot request.
 * [failure] - error code:
 *
 * %-ENODATA     - queue is empty.
 * %-ENOENT      - first entry is NULL.
 */
int ssdfs_snapshot_reqs_queue_remove_first(struct ssdfs_snapshot_reqs_queue *rq,
					   struct ssdfs_snapshot_request **snr)
{
	bool is_empty;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rq || !snr);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&rq->lock);
	is_empty = list_empty_careful(&rq->list);
	if (!is_empty) {
		*snr = list_first_entry_or_null(&rq->list,
						struct ssdfs_snapshot_request,
						list);
		if (!*snr) {
			SSDFS_WARN("first entry is NULL\n");
			err = -ENOENT;
		} else
			list_del(&(*snr)->list);
	}
	spin_unlock(&rq->lock);

	if (is_empty) {
		SSDFS_WARN("snapshot requests queue is empty\n");
		err = -ENODATA;
	}

	return err;
}

/*
 * ssdfs_snapshot_reqs_queue_remove_all() - remove all requests from queue
 * @rq: snapshot requests queue
 *
 * This function removes all snapshot requests from the queue.
 */
void ssdfs_snapshot_reqs_queue_remove_all(struct ssdfs_snapshot_reqs_queue *rq)
{
	bool is_empty;
	LIST_HEAD(tmp_list);
	struct list_head *this, *next;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&rq->lock);
	is_empty = list_empty_careful(&rq->list);
	if (!is_empty)
		list_replace_init(&rq->list, &tmp_list);
	spin_unlock(&rq->lock);

	if (is_empty)
		return;

	list_for_each_safe(this, next, &tmp_list) {
		struct ssdfs_snapshot_request *snr;

		snr = list_entry(this, struct ssdfs_snapshot_request, list);
		list_del(&snr->list);

		switch (snr->operation) {
		case SSDFS_CREATE_SNAPSHOT:
		case SSDFS_LIST_SNAPSHOTS:
		case SSDFS_MODIFY_SNAPSHOT:
		case SSDFS_REMOVE_SNAPSHOT:
		case SSDFS_REMOVE_RANGE:
		case SSDFS_SHOW_SNAPSHOT_DETAILS:
			SSDFS_WARN("delete snapshot request: "
				   "operation %#x\n",
				   snr->operation);
			break;

		default:
			SSDFS_WARN("invalid snapshot request: "
				   "operation %#x\n",
				   snr->operation);
			break;
		}

		ssdfs_snapshot_request_free(snr);
	}
}

/*
 * ssdfs_snapshot_request_alloc() - allocate memory for snapshot request object
 */
struct ssdfs_snapshot_request *ssdfs_snapshot_request_alloc(void)
{
	struct ssdfs_snapshot_request *snr;
	size_t desc_size = sizeof(struct ssdfs_snapshot_request);

	snr = ssdfs_snap_reqs_queue_kzalloc(desc_size, GFP_KERNEL);
	if (!snr) {
		SSDFS_ERR("fail to allocate memory for snapshot request\n");
		return ERR_PTR(-ENOMEM);
	}

	return snr;
}

/*
 * ssdfs_snapshot_request_free() - free memory of snapshot request object
 */
void ssdfs_snapshot_request_free(struct ssdfs_snapshot_request *snr)
{
	if (!snr)
		return;

	ssdfs_snap_reqs_queue_kfree(snr);
}

/*
 * ssdfs_create_snapshot() - create snapshot
 * @snr: snapshot request
 *
 * This function tries to create a snapshot.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error
 */
static
int ssdfs_create_snapshot(struct ssdfs_snapshot_request *snr)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!snr);
#endif /* CONFIG_SSDFS_DEBUG */

/* TODO: implement */
	err = -EOPNOTSUPP;

	SSDFS_ERR("SNAPSHOT INFO: ");
	SSDFS_ERR("name %s, ", snr->info.name);
	SSDFS_ERR("UUID %pUb, ", snr->info.uuid);
	SSDFS_ERR("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, existing_snapshots %u, "
		  "TIME_RANGE (day %u, month %u, year %u)\n",
		  snr->info.mode, snr->info.type, snr->info.expiration,
		  snr->info.frequency, snr->info.existing_snapshots,
		  snr->info.time_range.day,
		  snr->info.time_range.month,
		  snr->info.time_range.year);

	return err;
}

/*
 * ssdfs_execute_create_snapshots() - process the snapshot requests queue
 * @rq: snapshot requests queue
 *
 * This function tries to process the queue of snapshot requests
 * and to create the snapshots.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error
 */
int ssdfs_execute_create_snapshots(struct ssdfs_snapshot_reqs_queue *rq)
{
	struct ssdfs_snapshot_request *snr = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rq);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("rq %p\n", rq);

	if (is_ssdfs_snapshot_reqs_queue_empty(rq)) {
		SSDFS_DBG("snapshot requests queue is empty\n");
		return 0;
	}

	do {
		err = ssdfs_snapshot_reqs_queue_remove_first(rq, &snr);
		if (err == -ENODATA) {
			/* empty queue */
			err = 0;
			break;
		} else if (err == -ENOENT) {
			SSDFS_WARN("request queue contains NULL request\n");
			err = 0;
			continue;
		} else if (unlikely(err < 0)) {
			SSDFS_CRIT("fail to get request from the queue: "
				   "err %d\n",
				   err);
			return err;
		}

		err = ssdfs_create_snapshot(snr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create snapshot: err %d\n",
				  err);
			ssdfs_snapshot_request_free(snr);
			ssdfs_snapshot_reqs_queue_remove_all(rq);
			return err;
		}

		ssdfs_snapshot_request_free(snr);
	} while (!is_ssdfs_snapshot_reqs_queue_empty(rq));

	return 0;
}

/*
 * ssdfs_execute_list_snapshots_request() - get list of snapshots
 * @snr: snapshot request
 *
 * This function tries to get a list of snapshots.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error
 */
int ssdfs_execute_list_snapshots_request(struct ssdfs_snapshot_request *snr)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!snr);
#endif /* CONFIG_SSDFS_DEBUG */

/* TODO: implement */
	err = -EOPNOTSUPP;

	SSDFS_ERR("SNAPSHOT INFO: ");
	SSDFS_ERR("name %s, ", snr->info.name);
	SSDFS_ERR("UUID %pUb, ", snr->info.uuid);
	SSDFS_ERR("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, existing_snapshots %u, "
		  "TIME_RANGE (day %u, month %u, year %u)\n",
		  snr->info.mode, snr->info.type, snr->info.expiration,
		  snr->info.frequency, snr->info.existing_snapshots,
		  snr->info.time_range.day,
		  snr->info.time_range.month,
		  snr->info.time_range.year);

	return err;
}

/*
 * ssdfs_execute_modify_snapshot_request() - modify snapshot's features
 * @snr: snapshot request
 *
 * This function tries to change a snapshot's features.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error
 */
int ssdfs_execute_modify_snapshot_request(struct ssdfs_snapshot_request *snr)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!snr);
#endif /* CONFIG_SSDFS_DEBUG */

/* TODO: implement */
	err = -EOPNOTSUPP;

	SSDFS_ERR("SNAPSHOT INFO: ");
	SSDFS_ERR("name %s, ", snr->info.name);
	SSDFS_ERR("UUID %pUb, ", snr->info.uuid);
	SSDFS_ERR("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, existing_snapshots %u, "
		  "TIME_RANGE (day %u, month %u, year %u)\n",
		  snr->info.mode, snr->info.type, snr->info.expiration,
		  snr->info.frequency, snr->info.existing_snapshots,
		  snr->info.time_range.day,
		  snr->info.time_range.month,
		  snr->info.time_range.year);

	return err;
}

/*
 * ssdfs_execute_remove_snapshot_request() - remove snapshot
 * @snr: snapshot request
 *
 * This function tries to delete a snapshot.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error
 */
int ssdfs_execute_remove_snapshot_request(struct ssdfs_snapshot_request *snr)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!snr);
#endif /* CONFIG_SSDFS_DEBUG */

/* TODO: implement */
	err = -EOPNOTSUPP;

	SSDFS_ERR("SNAPSHOT INFO: ");
	SSDFS_ERR("name %s, ", snr->info.name);
	SSDFS_ERR("UUID %pUb, ", snr->info.uuid);
	SSDFS_ERR("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, existing_snapshots %u, "
		  "TIME_RANGE (day %u, month %u, year %u)\n",
		  snr->info.mode, snr->info.type, snr->info.expiration,
		  snr->info.frequency, snr->info.existing_snapshots,
		  snr->info.time_range.day,
		  snr->info.time_range.month,
		  snr->info.time_range.year);

	return err;
}

/*
 * ssdfs_execute_remove_range_request() - remove range of snapshots
 * @snr: snapshot request
 *
 * This function tries to delete a range of snapshots.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error
 */
int ssdfs_execute_remove_range_request(struct ssdfs_snapshot_request *snr)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!snr);
#endif /* CONFIG_SSDFS_DEBUG */

/* TODO: implement */
	err = -EOPNOTSUPP;

	SSDFS_ERR("SNAPSHOT INFO: ");
	SSDFS_ERR("name %s, ", snr->info.name);
	SSDFS_ERR("UUID %pUb, ", snr->info.uuid);
	SSDFS_ERR("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, existing_snapshots %u, "
		  "TIME_RANGE (day %u, month %u, year %u)\n",
		  snr->info.mode, snr->info.type, snr->info.expiration,
		  snr->info.frequency, snr->info.existing_snapshots,
		  snr->info.time_range.day,
		  snr->info.time_range.month,
		  snr->info.time_range.year);

	return err;
}

/*
 * ssdfs_execute_show_details_request() - show snapshot's details
 * @snr: snapshot request
 *
 * This function tries to extract a snapshot's details.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error
 */
int ssdfs_execute_show_details_request(struct ssdfs_snapshot_request *snr)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!snr);
#endif /* CONFIG_SSDFS_DEBUG */

/* TODO: implement */
	err = -EOPNOTSUPP;

	SSDFS_ERR("SNAPSHOT INFO: ");
	SSDFS_ERR("name %s, ", snr->info.name);
	SSDFS_ERR("UUID %pUb, ", snr->info.uuid);
	SSDFS_ERR("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, existing_snapshots %u, "
		  "TIME_RANGE (day %u, month %u, year %u)\n",
		  snr->info.mode, snr->info.type, snr->info.expiration,
		  snr->info.frequency, snr->info.existing_snapshots,
		  snr->info.time_range.day,
		  snr->info.time_range.month,
		  snr->info.time_range.year);

	return err;
}
