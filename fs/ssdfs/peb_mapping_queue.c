//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_mapping_queue.c - PEB mappings queue implementation.
 *
 * Copyright (c) 2019-2021 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_map_queue_page_leaks;
atomic64_t ssdfs_map_queue_memory_leaks;
atomic64_t ssdfs_map_queue_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_map_queue_cache_leaks_increment(void *kaddr)
 * void ssdfs_map_queue_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_map_queue_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_map_queue_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_map_queue_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_map_queue_kfree(void *kaddr)
 * struct page *ssdfs_map_queue_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_map_queue_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_map_queue_free_page(struct page *page)
 * void ssdfs_map_queue_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(map_queue)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(map_queue)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_map_queue_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_map_queue_page_leaks, 0);
	atomic64_set(&ssdfs_map_queue_memory_leaks, 0);
	atomic64_set(&ssdfs_map_queue_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_map_queue_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_map_queue_page_leaks) != 0) {
		SSDFS_ERR("MAPPING QUEUE: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_map_queue_page_leaks));
	}

	if (atomic64_read(&ssdfs_map_queue_memory_leaks) != 0) {
		SSDFS_ERR("MAPPING QUEUE: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_map_queue_memory_leaks));
	}

	if (atomic64_read(&ssdfs_map_queue_cache_leaks) != 0) {
		SSDFS_ERR("MAPPING QUEUE: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_map_queue_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static struct kmem_cache *ssdfs_peb_mapping_info_cachep;

static
void ssdfs_init_peb_mapping_info_once(void *obj)
{
	struct ssdfs_peb_mapping_info *pmi_obj = obj;

	memset(pmi_obj, 0, sizeof(struct ssdfs_peb_mapping_info));
}

void ssdfs_shrink_peb_mapping_info_cache(void)
{
	if (ssdfs_peb_mapping_info_cachep)
		kmem_cache_shrink(ssdfs_peb_mapping_info_cachep);
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

	ssdfs_map_queue_cache_leaks_increment(ptr);

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

	ssdfs_map_queue_cache_leaks_decrement(pmi);
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
