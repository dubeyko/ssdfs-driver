//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/snapshot_rules.c - snapshot rules implementation.
 *
 * Copyright (c) 2021-2022 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "dentries_tree.h"
#include "shared_dictionary.h"
#include "snapshots_tree.h"
#include "snapshot_rules.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_snap_rules_list_page_leaks;
atomic64_t ssdfs_snap_rules_list_memory_leaks;
atomic64_t ssdfs_snap_rules_list_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_snap_rules_list_cache_leaks_increment(void *kaddr)
 * void ssdfs_snap_rules_list_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_snap_rules_list_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_snap_rules_list_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_snap_rules_list_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_snap_rules_list_kfree(void *kaddr)
 * struct page *ssdfs_snap_rules_list_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_snap_rules_list_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_snap_rules_list_free_page(struct page *page)
 * void ssdfs_snap_rules_list_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(snap_rules_list)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(snap_rules_list)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_snap_rules_list_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_snap_rules_list_page_leaks, 0);
	atomic64_set(&ssdfs_snap_rules_list_memory_leaks, 0);
	atomic64_set(&ssdfs_snap_rules_list_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_snap_rules_list_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_snap_rules_list_page_leaks) != 0) {
		SSDFS_ERR("SNAPSHOT RULES LIST: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_snap_rules_list_page_leaks));
	}

	if (atomic64_read(&ssdfs_snap_rules_list_memory_leaks) != 0) {
		SSDFS_ERR("SNAPSHOT RULES LIST: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_snap_rules_list_memory_leaks));
	}

	if (atomic64_read(&ssdfs_snap_rules_list_cache_leaks) != 0) {
		SSDFS_ERR("SNAPSHOT RULES LIST: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_snap_rules_list_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * ssdfs_snapshot_rules_list_init() - initialize snapshot rules list
 * @rl: snapshot rules list
 */
void ssdfs_snapshot_rules_list_init(struct ssdfs_snapshot_rules_list *rl)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rl);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock_init(&rl->lock);
	INIT_LIST_HEAD(&rl->list);
}

/*
 * is_ssdfs_snapshot_rules_list_empty() - check that snap rules list is empty
 * @rl: snapshot rules_list
 */
bool is_ssdfs_snapshot_rules_list_empty(struct ssdfs_snapshot_rules_list *rl)
{
	bool is_empty;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rl);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&rl->lock);
	is_empty = list_empty_careful(&rl->list);
	spin_unlock(&rl->lock);

	return is_empty;
}

/*
 * ssdfs_snapshot_rules_list_add_head() - add rule at the head of list
 * @rl: snapshot rules list
 * @ri: snapshot rule item
 */
void ssdfs_snapshot_rules_list_add_head(struct ssdfs_snapshot_rules_list *rl,
					struct ssdfs_snapshot_rule_item *ri)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rl || !ri);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("rl %p, ri %p\n",
		  rl, ri);

	spin_lock(&rl->lock);
	list_add(&ri->list, &rl->list);
	spin_unlock(&rl->lock);
}

/*
 * ssdfs_snapshot_rules_list_add_tail() - add rule at the tail of list
 * @rl: snapshot rules list
 * @ri: snapshot rule item
 */
void ssdfs_snapshot_rules_list_add_tail(struct ssdfs_snapshot_rules_list *rl,
					struct ssdfs_snapshot_rule_item *ri)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rl || !ri);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("rl %p, ri %p\n",
		  rl, ri);

	spin_lock(&rl->lock);
	list_add_tail(&ri->list, &rl->list);
	spin_unlock(&rl->lock);
}

/*
 * ssdfs_snapshot_rules_list_remove_all() - remove all rules from list
 * @rl: snapshot rules list
 *
 * This function removes all snapshot rules from the list.
 */
void ssdfs_snapshot_rules_list_remove_all(struct ssdfs_snapshot_rules_list *rl)
{
	bool is_empty;
	LIST_HEAD(tmp_list);
	struct list_head *this, *next;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rl);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&rl->lock);
	is_empty = list_empty_careful(&rl->list);
	if (!is_empty)
		list_replace_init(&rl->list, &tmp_list);
	spin_unlock(&rl->lock);

	if (is_empty)
		return;

	list_for_each_safe(this, next, &tmp_list) {
		struct ssdfs_snapshot_rule_item *ri;

		ri = list_entry(this, struct ssdfs_snapshot_rule_item, list);
		list_del(&ri->list);

		ssdfs_snapshot_rule_free(ri);
	}
}

/*
 * ssdfs_snapshot_rule_alloc() - allocate memory for snapshot rule object
 */
struct ssdfs_snapshot_rule_item *ssdfs_snapshot_rule_alloc(void)
{
	struct ssdfs_snapshot_rule_item *ri;
	size_t desc_size = sizeof(struct ssdfs_snapshot_rule_item);

	ri = ssdfs_snap_rules_list_kzalloc(desc_size, GFP_KERNEL);
	if (!ri) {
		SSDFS_ERR("fail to allocate memory for snapshot rule\n");
		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&ri->list);

	return ri;
}

/*
 * ssdfs_snapshot_rule_free() - free memory of snapshot rule object
 */
void ssdfs_snapshot_rule_free(struct ssdfs_snapshot_rule_item *ri)
{
	if (!ri)
		return;

	ssdfs_snap_rules_list_kfree(ri);
}

struct page *
ssdfs_snapshot_rules_add_pagevec_page(struct pagevec *pvec)
{
	struct page *page;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("pvec %p\n", pvec);

	page = ssdfs_snap_rules_list_add_pagevec_page(pvec);
	if (unlikely(IS_ERR_OR_NULL(page))) {
		err = !page ? -ENOMEM : PTR_ERR(page);
		SSDFS_ERR("fail to add pagevec page: err %d\n",
			  err);
	}

	return page;
}

void ssdfs_snapshot_rules_pagevec_release(struct pagevec *pvec)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("pvec %p\n", pvec);

	ssdfs_snap_rules_list_pagevec_release(pvec);
}

/*
 * is_snapshot_rule_expired() - has snapshot rule being expired
 * @ptr: snapshot rule
 *
 * This function tries to check that snapshot rule has been expired.
 */
static inline
bool is_snapshot_rule_expired(struct ssdfs_snapshot_rule_item *ptr)
{
	u16 snapshots_number;
	u16 snapshots_threshold;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	snapshots_number = le16_to_cpu(ptr->rule.snapshots_number);
	snapshots_threshold = le16_to_cpu(ptr->rule.snapshots_threshold);

	return snapshots_number >= snapshots_threshold;
}

/*
 * is_time_create_snapshot() - is it time to create snapshot
 * @fsi: pointer on shared file system object
 * @ptr: snapshot rule
 *
 * This function tries to check that it's time to create snapshot.
 */
static inline
bool is_time_create_snapshot(struct ssdfs_fs_info *fsi,
			     struct ssdfs_snapshot_rule_info *ptr)
{
	u8 frequency;
	u64 last_snapshot_cno;
	u64 cno;
	u64 diff_cno;
	u64 diff_secs;
	u64 secs_per_day = (u64)SSDFS_HOURS_PER_DAY * SSDFS_SECS_PER_HOUR;
	u64 secs_per_week = secs_per_day * SSDFS_DAYS_PER_WEEK;
	u64 secs_per_month = secs_per_week * SSDFS_WEEKS_PER_MONTH;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	frequency = ptr->frequency;
	last_snapshot_cno = le64_to_cpu(ptr->last_snapshot_cno);

	if (last_snapshot_cno >= SSDFS_INVALID_CNO)
		return true;

	cno = ssdfs_current_cno(fsi->sb);

	if (last_snapshot_cno >= cno) {
		SSDFS_ERR("last_snapshot_cno %llu >= cno %llu\n",
			  last_snapshot_cno, cno);
		return false;
	}

	diff_cno = cno - last_snapshot_cno;
	diff_secs = div64_u64(diff_cno, SSDFS_NANOSECS_PER_SEC);

	switch (frequency) {
	case SSDFS_SYNCFS_FREQUENCY:
		return true;

	case SSDFS_HOUR_FREQUENCY:
		return diff_secs >= SSDFS_SECS_PER_HOUR;

	case SSDFS_DAY_FREQUENCY:
		return diff_secs >= secs_per_day;

	case SSDFS_WEEK_FREQUENCY:
		return diff_secs >= secs_per_week;

	case SSDFS_MONTH_FREQUENCY:
		return diff_secs >= secs_per_month;

	default:
		/* do nothing */
		SSDFS_ERR("unexpected frequency %#x\n",
			  frequency);
	}

	return false;
}

/*
 * ssdfs_create_snapshot() - create snapshot
 * @fsi: pointer on shared file system object
 * @ptr: snapshot rule
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
int ssdfs_create_snapshot(struct ssdfs_fs_info *fsi,
			  struct ssdfs_snapshot_rule_info *ptr)
{
	struct ssdfs_snapshots_btree_info *tree;
	struct ssdfs_snapshot_request *snr = NULL;
	u16 snapshots_threshold;
	u16 snapshots_number;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	snapshots_threshold = le16_to_cpu(ptr->snapshots_threshold);
	snapshots_number = le16_to_cpu(ptr->snapshots_number);

	if (snapshots_threshold == U16_MAX || snapshots_number == U16_MAX) {
		SSDFS_ERR("corrupted rule: "
			  "snapshots_number %u, "
			  "snapshots_threshold %u\n",
			  snapshots_number, snapshots_threshold);
		return -ERANGE;
	}

	if (snapshots_number > snapshots_threshold) {
		SSDFS_ERR("snapshots_number %u > snapshots_threshold %u\n",
			  snapshots_number, snapshots_threshold);
		return -ERANGE;
	}

	if (snapshots_number == snapshots_threshold) {
		SSDFS_DBG("nothing should be done: "
			  "snapshots_number %u, snapshots_threshold %u\n",
			  snapshots_number, snapshots_threshold);
		return 0;
	}

	snr = ssdfs_snapshot_request_alloc();
	if (!snr) {
		SSDFS_ERR("fail to allocate snaphot request\n");
		return -ENOMEM;
	}

	snr->operation = SSDFS_CREATE_SNAPSHOT;
	snr->ino = le64_to_cpu(ptr->ino);

	ssdfs_memcpy(snr->info.uuid, 0, SSDFS_UUID_SIZE,
		     ptr->uuid, 0, SSDFS_UUID_SIZE,
		     SSDFS_UUID_SIZE);
	ssdfs_memcpy(snr->info.name, 0, SSDFS_MAX_SNAPSHOT_NAME_LEN,
		     ptr->name, 0, SSDFS_MAX_SNAP_RULE_NAME_LEN,
		     SSDFS_MAX_SNAPSHOT_NAME_LEN);

	snr->info.mode = ptr->mode;
	snr->info.type = ptr->type;
	snr->info.expiration = ptr->expiration;
	snr->info.frequency = ptr->frequency;
	snr->info.snapshots_threshold = le16_to_cpu(ptr->snapshots_threshold);

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

	tree = fsi->snapshots.tree;
	ssdfs_snapshot_reqs_queue_add_tail(&tree->requests.queue, snr);
	wake_up_all(&tree->wait_queue);

	return 0;
}

/*
 * ssdfs_process_snapshot_rules() - process existing snapshot rules
 * @fsi: pointer on shared file system object
 *
 * This function tries to process the existing snapshot rules
 * and to create snapshots.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
int ssdfs_process_snapshot_rules(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_snapshot_rules_list *rl = NULL;
	struct list_head *this, *next;
	struct ssdfs_snapshot_rule_item *ptr = NULL;
	struct ssdfs_snapshot_rule_info rule;
	size_t rule_size = sizeof(struct ssdfs_snapshot_rule_info);
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p\n", fsi);

	rl = &fsi->snapshots.rules_list;

	if (is_ssdfs_snapshot_rules_list_empty(rl)) {
		SSDFS_DBG("snapshot rules list is empty\n");
		return 0;
	}

	spin_lock(&rl->lock);
	list_for_each_safe(this, next, &rl->list) {
		ptr = list_entry(this, struct ssdfs_snapshot_rule_item, list);

		if (is_snapshot_rule_expired(ptr)) {
			list_del(&ptr->list);
			ssdfs_snapshot_rule_free(ptr);
			continue;
		}

		ssdfs_memcpy(&rule, 0, rule_size,
			     &ptr->rule, 0, rule_size,
			     rule_size);

		spin_unlock(&rl->lock);

		if (rule.type != SSDFS_PERIODIC_SNAPSHOT) {
			err = -ERANGE;
			SSDFS_ERR("invalid rule type %#x\n",
				  rule.type);
			goto try_next_rule;
		}

		if (is_time_create_snapshot(fsi, &rule)) {
			err = ssdfs_create_snapshot(fsi, &rule);
			if (unlikely(err)) {
				SSDFS_ERR("fail to create snapshot: "
					  "UUID %pUb, err %d\n",
					  rule.uuid, err);
			}
		}

try_next_rule:
		spin_lock(&rl->lock);

		if (!err) {
			ptr = list_entry(this, struct ssdfs_snapshot_rule_item,
					 list);
			le16_add_cpu(&ptr->rule.snapshots_number, 1);
			ptr->rule.last_snapshot_cno =
				cpu_to_le64(ssdfs_current_cno(fsi->sb));
		}
	}
	spin_unlock(&rl->lock);

	return err;
}

/*
 * is_name_the_same() - compare the hash of two names
 * @ptr: pointer on snapshot rule item
 * @name_hash: hash of second name
 */
static inline
bool is_name_the_same(struct ssdfs_snapshot_rule_item *ptr,
		      u64 name_hash)
{
	if (name_hash == U64_MAX)
		return true;

	return le64_to_cpu(ptr->rule.name_hash) == name_hash;
}

/*
 * ssdfs_modify_snapshot_rule() - modify existing snapshot rule
 * @fsi: pointer on shared file system object
 * @snr: snapshot request
 *
 * This function tries to modify the existing snapshot rule.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - no such snapshot rule.
 */
int ssdfs_modify_snapshot_rule(struct ssdfs_fs_info *fsi,
				struct ssdfs_snapshot_request *snr)
{
	struct ssdfs_snapshot_rules_list *rl = NULL;
	struct list_head *this, *next;
	struct ssdfs_snapshot_rule_item *ptr = NULL;
	size_t len;
	u64 name_hash = U64_MAX;
	int err = -ENODATA;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !snr);

	SSDFS_DBG("MODIFICATION REQUEST: ");
	SSDFS_DBG("name %s, ", snr->info.name);
	SSDFS_DBG("UUID %pUb, ", snr->info.uuid);
	SSDFS_DBG("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, snapshots_threshold %u\n",
		  snr->info.mode, snr->info.type,
		  snr->info.expiration, snr->info.frequency,
		  snr->info.snapshots_threshold);
#endif /* CONFIG_SSDFS_DEBUG */

	rl = &fsi->snapshots.rules_list;

	if (is_ssdfs_snapshot_rules_list_empty(rl)) {
		SSDFS_DBG("snapshot rules list is empty\n");
		return -ENODATA;
	}

	len = strnlen(snr->info.name, SSDFS_MAX_NAME_LEN);

	if (len != 0) {
		name_hash = __ssdfs_generate_name_hash(snr->info.name, len,
						SSDFS_MAX_SNAP_RULE_NAME_LEN);
		if (name_hash == U64_MAX) {
			SSDFS_ERR("fail to generate name hash\n");
			return -ERANGE;
		}
	}

	spin_lock(&rl->lock);
	list_for_each_safe(this, next, &rl->list) {
		ptr = list_entry(this, struct ssdfs_snapshot_rule_item, list);

		if (!is_uuids_identical(ptr->rule.uuid, snr->info.uuid))
			continue;

		if (!is_name_the_same(ptr, name_hash)) {
			ptr->rule.name_hash = cpu_to_le64(name_hash);

			ssdfs_memcpy(ptr->rule.name, 0,
				     SSDFS_MAX_SNAP_RULE_NAME_LEN,
				     snr->info.name, 0, SSDFS_MAX_NAME_LEN,
				     SSDFS_MAX_SNAP_RULE_NAME_LEN);
		}

		if (is_ssdfs_snapshot_mode_correct(snr->info.mode))
			ptr->rule.mode = (u8)snr->info.mode;

		if (is_ssdfs_snapshot_expiration_correct(snr->info.expiration))
			ptr->rule.expiration = (u8)snr->info.expiration;

		if (is_ssdfs_snapshot_frequency_correct(snr->info.frequency))
			ptr->rule.frequency = (u8)snr->info.frequency;

		if (snr->info.snapshots_threshold < U16_MAX) {
			ptr->rule.snapshots_threshold =
				cpu_to_le16((u16)snr->info.snapshots_threshold);
		}

		err = 0;
		goto finish_process_rules;
	}
finish_process_rules:
	spin_unlock(&rl->lock);

	if (err == -ENODATA)
		goto finish_modify_rule;

	if (len > SSDFS_MAX_SNAP_RULE_NAME_LEN) {
		struct ssdfs_shared_dict_btree_info *dict;
		struct qstr str = QSTR_INIT(snr->info.name, len);

		dict = fsi->shdictree;
		if (!dict) {
			err = -ERANGE;
			SSDFS_ERR("shared dict is absent\n");
			goto finish_modify_rule;
		}

		err = ssdfs_shared_dict_save_name(dict,
						  name_hash,
						  &str);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store name: "
				  "hash %llx, err %d\n",
				  name_hash, err);
			goto finish_modify_rule;
		}
	}

finish_modify_rule:
	return err;
}

/*
 * ssdfs_remove_snapshot_rule() - delete existing snapshot rule
 * @snapshots: snapshots subsystem
 * @snr: snapshot request
 *
 * This function tries to delete the existing snapshot rule.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - no such snapshot rule.
 */
int ssdfs_remove_snapshot_rule(struct ssdfs_snapshot_subsystem *snapshots,
				struct ssdfs_snapshot_request *snr)
{
	struct ssdfs_snapshot_rules_list *rl = NULL;
	struct list_head *this, *next;
	struct ssdfs_snapshot_rule_item *ptr = NULL;
	size_t len;
	u64 name_hash = U64_MAX;
	int err = -ENODATA;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!snapshots || !snr);

	SSDFS_DBG("REMOVE REQUEST: ");
	SSDFS_DBG("name %s, ", snr->info.name);
	SSDFS_DBG("UUID %pUb, ", snr->info.uuid);
	SSDFS_DBG("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, snapshots_threshold %u\n",
		  snr->info.mode, snr->info.type,
		  snr->info.expiration, snr->info.frequency,
		  snr->info.snapshots_threshold);
#endif /* CONFIG_SSDFS_DEBUG */

	rl = &snapshots->rules_list;

	if (is_ssdfs_snapshot_rules_list_empty(rl)) {
		SSDFS_DBG("snapshot rules list is empty\n");
		return -ENODATA;
	}

	len = strnlen(snr->info.name, SSDFS_MAX_NAME_LEN);

	if (len != 0) {
		name_hash = __ssdfs_generate_name_hash(snr->info.name, len,
						SSDFS_MAX_SNAP_RULE_NAME_LEN);
		if (name_hash == U64_MAX) {
			SSDFS_ERR("fail to generate name hash\n");
			return -ERANGE;
		}
	}

	spin_lock(&rl->lock);
	list_for_each_safe(this, next, &rl->list) {
		ptr = list_entry(this, struct ssdfs_snapshot_rule_item, list);

		if (!is_uuids_identical(ptr->rule.uuid, snr->info.uuid))
			continue;

		if (!is_name_the_same(ptr, name_hash))
			continue;

		err = 0;
		list_del(&ptr->list);
		ssdfs_snapshot_rule_free(ptr);
		goto finish_process_rules;
	}
finish_process_rules:
	spin_unlock(&rl->lock);

	return err;
}
