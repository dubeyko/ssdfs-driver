//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_mapping_queue.c - PEB mappings queue implementation.
 *
 * Copyright (c) 2019-2020 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"

static struct kmem_cache *ssdfs_peb_mapping_info_cachep;

static
void ssdfs_init_peb_mapping_info_once(void *obj)
{
	struct ssdfs_peb_mapping_info *pmi_obj = obj;

	memset(pmi_obj, 0, sizeof(struct ssdfs_peb_mapping_info));
}

void ssdfs_destroy_peb_mapping_info_cache(void)
{
	if (ssdfs_peb_mapping_info_cachep)
		kmem_cache_destroy(ssdfs_peb_mapping_info_cachep);
}

int ssdfs_init_peb_mapping_info_cache(void)
{
	ssdfs_peb_mapping_info_cachep =
		kmem_cache_create("ssdfs_peb_mapping_info_cache",
				  sizeof(struct ssdfs_peb_mapping_info), 0,
				  SLAB_RECLAIM_ACCOUNT |
				  SLAB_MEM_SPREAD |
				  SLAB_ACCOUNT,
				  ssdfs_init_peb_mapping_info_once);
	if (!ssdfs_peb_mapping_info_cachep) {
		SSDFS_ERR("unable to create PEB mapping info objects cache\n");
		return -ENOMEM;
	}

	return 0;
}

/*
 * ssdfs_peb_mapping_queue_init() - initialize PEB mappings queue
 * @pmq: initialized PEB mappings queue
 */
void ssdfs_peb_mapping_queue_init(struct ssdfs_peb_mapping_queue *pmq)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pmq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock_init(&pmq->lock);
	INIT_LIST_HEAD(&pmq->list);
}

/*
 * is_ssdfs_peb_mapping_queue_empty() - check that PEB mappings queue is empty
 * @pmq: PEB mappings queue
 */
bool is_ssdfs_peb_mapping_queue_empty(struct ssdfs_peb_mapping_queue *pmq)
{
	bool is_empty;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pmq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&pmq->lock);
	is_empty = list_empty_careful(&pmq->list);
	spin_unlock(&pmq->lock);

	return is_empty;
}

/*
 * ssdfs_peb_mapping_queue_add_head() - add PEB mapping at the head of queue
 * @pmq: PEB mappings queue
 * @pmi: PEB mapping info
 */
void ssdfs_peb_mapping_queue_add_head(struct ssdfs_peb_mapping_queue *pmq,
				      struct ssdfs_peb_mapping_info *pmi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pmq || !pmi);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&pmq->lock);
	list_add(&pmi->list, &pmq->list);
	spin_unlock(&pmq->lock);
}

/*
 * ssdfs_peb_mapping_queue_add_tail() - add PEB mapping at the tail of queue
 * @pmq: PEB mappings queue
 * @pmi: PEB mapping info
 */
void ssdfs_peb_mapping_queue_add_tail(struct ssdfs_peb_mapping_queue *pmq,
				      struct ssdfs_peb_mapping_info *pmi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pmq || !pmi);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&pmq->lock);
	list_add_tail(&pmi->list, &pmq->list);
	spin_unlock(&pmq->lock);
}

/*
 * ssdfs_peb_mapping_queue_remove_first() - get mapping and remove from queue
 * @pmq: PEB mappings queue
 * @pmi: first PEB mapping [out]
 *
 * This function get first PEB mapping in @pmq, remove it from queue
 * and return as @pmi.
 *
 * RETURN:
 * [success] - @pmi contains pointer on PEB mapping.
 * [failure] - error code:
 *
 * %-ENODATA     - queue is empty.
 * %-ENOENT      - first entry is NULL.
 */
int ssdfs_peb_mapping_queue_remove_first(struct ssdfs_peb_mapping_queue *pmq,
					 struct ssdfs_peb_mapping_info **pmi)
{
	bool is_empty;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pmq || !pmi);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&pmq->lock);
	is_empty = list_empty_careful(&pmq->list);
	if (!is_empty) {
		*pmi = list_first_entry_or_null(&pmq->list,
						struct ssdfs_peb_mapping_info,
						list);
		if (!*pmi) {
			SSDFS_WARN("first entry is NULL\n");
			err = -ENOENT;
		} else
			list_del(&(*pmi)->list);
	}
	spin_unlock(&pmq->lock);

	if (is_empty) {
		SSDFS_WARN("PEB mappings queue is empty\n");
		err = -ENODATA;
	}

	return err;
}

/*
 * ssdfs_peb_mapping_queue_remove_all() - remove all PEB mappings from queue
 * @pmq: PEB mappings queue
 *
 * This function removes all PEB mappings from the queue.
 */
void ssdfs_peb_mapping_queue_remove_all(struct ssdfs_peb_mapping_queue *pmq)
{
	bool is_empty;
	LIST_HEAD(tmp_list);
	struct list_head *this, *next;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pmq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&pmq->lock);
	is_empty = list_empty_careful(&pmq->list);
	if (!is_empty)
		list_replace_init(&pmq->list, &tmp_list);
	spin_unlock(&pmq->lock);

	if (is_empty)
		return;

	list_for_each_safe(this, next, &tmp_list) {
		struct ssdfs_peb_mapping_info *pmi;

		pmi = list_entry(this, struct ssdfs_peb_mapping_info, list);
		list_del(&pmi->list);

		SSDFS_DBG("delete PEB mapping: "
			  "leb_id %llu, peb_id %llu, consistency %d\n",
			  pmi->leb_id, pmi->peb_id, pmi->consistency);

		ssdfs_peb_mapping_info_free(pmi);
	}
}

/*
 * ssdfs_peb_mapping_info_alloc() - allocate memory for PEB mapping info object
 */
struct ssdfs_peb_mapping_info *ssdfs_peb_mapping_info_alloc(void)
{
	struct ssdfs_peb_mapping_info *ptr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_peb_mapping_info_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr = kmem_cache_alloc(ssdfs_peb_mapping_info_cachep, GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate memory for PEB mapping\n");
		return ERR_PTR(-ENOMEM);
	}

	return ptr;
}

/*
 * ssdfs_peb_mapping_info_free() - free memory for PEB mapping info object
 */
void ssdfs_peb_mapping_info_free(struct ssdfs_peb_mapping_info *pmi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_peb_mapping_info_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!pmi)
		return;

	kmem_cache_free(ssdfs_peb_mapping_info_cachep, pmi);
}

/*
 * ssdfs_peb_mapping_info_init() - PEB mapping info initialization
 * @leb_id: LEB ID
 * @peb_id: PEB ID
 * @consistency: consistency state in PEB mapping table cache
 * @pmi: PEB mapping info [out]
 */
void ssdfs_peb_mapping_info_init(u64 leb_id, u64 peb_id, int consistency,
				 struct ssdfs_peb_mapping_info *pmi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pmi);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(pmi, 0, sizeof(struct ssdfs_peb_mapping_info));

	INIT_LIST_HEAD(&pmi->list);
	pmi->leb_id = leb_id;
	pmi->peb_id = peb_id;
	pmi->consistency = consistency;
}
