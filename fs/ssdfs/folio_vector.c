/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/folio_vector.c - folio vector implementation.
 *
 * Copyright (c) 2023-2025 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 *
 */

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_folio_vector_folio_leaks;
atomic64_t ssdfs_folio_vector_memory_leaks;
atomic64_t ssdfs_folio_vector_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_folio_vector_cache_leaks_increment(void *kaddr)
 * void ssdfs_folio_vector_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_folio_vector_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_folio_vector_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_folio_vector_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_folio_vector_kfree(void *kaddr)
 * struct folio *ssdfs_folio_vector_alloc_folio(gfp_t gfp_mask,
 *                                              unsigned int order)
 * struct folio *ssdfs_folio_vector_add_batch_folio(struct folio_batch *batch,
 *                                                  unsigned int order)
 * void ssdfs_folio_vector_free_folio(struct folio *folio)
 * void ssdfs_folio_vector_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(folio_vector)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(folio_vector)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_folio_vector_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_folio_vector_folio_leaks, 0);
	atomic64_set(&ssdfs_folio_vector_memory_leaks, 0);
	atomic64_set(&ssdfs_folio_vector_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_folio_vector_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_folio_vector_folio_leaks) != 0) {
		SSDFS_ERR("FOLIO VECTOR: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_folio_vector_folio_leaks));
	}

	if (atomic64_read(&ssdfs_folio_vector_memory_leaks) != 0) {
		SSDFS_ERR("FOLIO VECTOR: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_folio_vector_memory_leaks));
	}

	if (atomic64_read(&ssdfs_folio_vector_cache_leaks) != 0) {
		SSDFS_ERR("FOLIO VECTOR: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_folio_vector_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * ssdfs_folio_vector_create() - create folio vector
 * @array: pointer on folio vector
 * @order: allocation order of a particular sized block of memory
 * @capacity: max number of memory folios in vector
 */
int ssdfs_folio_vector_create(struct ssdfs_folio_vector *array,
			      unsigned order,
			      u32 capacity)
{
	size_t size = sizeof(struct folio *);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	array->count = 0;
	array->capacity = 0;
	array->order = order;

	size *= capacity;
	array->folios = ssdfs_folio_vector_kzalloc(size, GFP_KERNEL);
	if (!array->folios) {
		SSDFS_ERR("fail to allocate memory: size %zu\n",
			  size);
		return -ENOMEM;
	}

	array->capacity = capacity;

	return 0;
}

/*
 * ssdfs_folio_vector_destroy() - destroy folio vector
 * @array: pointer on folio vector
 */
void ssdfs_folio_vector_destroy(struct ssdfs_folio_vector *array)
{
#ifdef CONFIG_SSDFS_DEBUG
	int i;

	BUG_ON(!array);

	if (array->count > 0) {
		SSDFS_ERR("invalid state: count %u\n",
			  array->count);
	}

	for (i = 0; i < array->capacity; i++) {
		struct folio *folio = array->folios[i];

		if (folio)
			SSDFS_ERR("folio %d is not released\n", i);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	array->count = 0;

	if (array->folios) {
#ifdef CONFIG_SSDFS_DEBUG
		if (array->capacity == 0) {
			SSDFS_ERR("invalid state: capacity %u\n",
				  array->capacity);
		}
#endif /* CONFIG_SSDFS_DEBUG */

		array->capacity = 0;
		ssdfs_folio_vector_kfree(array->folios);
		array->folios = NULL;
	}
}

/*
 * ssdfs_folio_vector_init() - init folio vector
 * @array: pointer on folio vector
 */
int ssdfs_folio_vector_init(struct ssdfs_folio_vector *array)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	if (!array->folios) {
		SSDFS_ERR("fail to init\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	array->count = 0;

	if (array->capacity == 0) {
		SSDFS_ERR("invalid state: capacity %u\n",
			  array->capacity);
		return -ERANGE;
	} else {
		memset(array->folios, 0,
			sizeof(struct folio *) * array->capacity);
	}

	return 0;
}

/*
 * ssdfs_folio_vector_reinit() - reinit folio vector
 * @array: pointer on folio vector
 */
int ssdfs_folio_vector_reinit(struct ssdfs_folio_vector *array)
{
#ifdef CONFIG_SSDFS_DEBUG
	int i;

	BUG_ON(!array);

	if (!array->folios) {
		SSDFS_ERR("fail to reinit\n");
		return -ERANGE;
	}

	for (i = 0; i < array->capacity; i++) {
		struct folio *folio = array->folios[i];

		if (folio)
			SSDFS_WARN("folio %d is not released\n", i);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	array->count = 0;

	if (array->capacity == 0) {
		SSDFS_ERR("invalid state: capacity %u\n",
			  array->capacity);
		return -ERANGE;
	} else {
		memset(array->folios, 0,
			sizeof(struct folio *) * array->capacity);
	}

	return 0;
}

/*
 * ssdfs_folio_vector_count() - count of folios in folio vector
 * @array: pointer on folio vector
 */
u32 ssdfs_folio_vector_count(struct ssdfs_folio_vector *array)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	return array->count;
}

/*
 * ssdfs_folio_vector_space() - free space in folio vector
 * @array: pointer on folio vector
 */
u32 ssdfs_folio_vector_space(struct ssdfs_folio_vector *array)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	if (array->count > array->capacity) {
		SSDFS_ERR("count %u is bigger than max %u\n",
			  array->count, array->capacity);
		return 0;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return array->capacity - array->count;
}

/*
 * ssdfs_folio_vector_capacity() - capacity of folio vector
 * @array: pointer on folio vector
 */
u32 ssdfs_folio_vector_capacity(struct ssdfs_folio_vector *array)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	return array->capacity;
}

/*
 * ssdfs_folio_vector_add() - add folio in folio vector
 * @array: pointer on folio vector
 * @folio: memory folio
 */
int ssdfs_folio_vector_add(struct ssdfs_folio_vector *array,
			  struct folio *folio)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !folio);

	if (array->count >= array->capacity) {
		SSDFS_ERR("array is full: count %u\n",
			  array->count);
		return -ENOSPC;
	}

	if (!array->folios) {
		SSDFS_ERR("fail to add folio: "
			  "count %u, capacity %u\n",
			  array->count, array->capacity);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	array->folios[array->count] = folio;
	array->count++;

	ssdfs_folio_vector_account_folio(folio);

	return 0;
}

/*
 * ssdfs_folio_vector_allocate() - allocate + add folio
 * @array: pointer on folio vector
 */
struct folio *ssdfs_folio_vector_allocate(struct ssdfs_folio_vector *array)
{
	struct folio *folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	if (ssdfs_folio_vector_space(array) == 0) {
		SSDFS_ERR("folio vector hasn't space\n");
		return ERR_PTR(-E2BIG);
	}

	folio = ssdfs_folio_vector_alloc_folio(GFP_KERNEL | __GFP_ZERO,
						array->order);
	if (IS_ERR_OR_NULL(folio)) {
		err = (folio == NULL ? -ENOMEM : PTR_ERR(folio));
		SSDFS_ERR("unable to allocate memory folio\n");
		return ERR_PTR(err);
	}

	ssdfs_folio_get(folio);

	/*
	 * ssdfs_folio_vector_add() accounts folio
	 */
	ssdfs_folio_vector_forget_folio(folio);

	err = ssdfs_folio_vector_add(array, folio);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add folio: err %d\n",
			  err);
		ssdfs_folio_free(folio);
		return ERR_PTR(err);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("array %p, folio vector count %u\n",
		  array->folios, ssdfs_folio_vector_count(array));
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_DBG("folio %p, allocated_folios %lld\n",
		  folio, atomic64_read(&ssdfs_folio_vector_folio_leaks));
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
#endif /* CONFIG_SSDFS_DEBUG */

	return folio;
}

/*
 * ssdfs_folio_vector_remove() - remove folio
 * @array: pointer on folio vector
 * @folio_index: index of the folio
 */
struct folio *ssdfs_folio_vector_remove(struct ssdfs_folio_vector *array,
				      u32 folio_index)
{
	struct folio *folio;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	if (ssdfs_folio_vector_count(array) == 0) {
		SSDFS_ERR("folio vector is empty\n");
		return ERR_PTR(-ENODATA);
	}

	if (array->count > array->capacity) {
		SSDFS_ERR("folio vector is corrupted: "
			  "array->count %u, array->capacity %u\n",
			  array->count, array->capacity);
		return ERR_PTR(-ERANGE);
	}

	if (folio_index >= array->count) {
		SSDFS_ERR("folio index is out of range: "
			  "folio_index %u, array->count %u\n",
			  folio_index, array->count);
		return ERR_PTR(-ENOENT);
	}

	folio = array->folios[folio_index];

	if (!folio) {
		SSDFS_ERR("folio index is absent: "
			  "folio_index %u, array->count %u\n",
			  folio_index, array->count);
		return ERR_PTR(-ENOENT);
	}

	ssdfs_folio_vector_forget_folio(folio);
	array->folios[folio_index] = NULL;

	return folio;
}

/*
 * ssdfs_folio_vector_release() - release folios from folio vector
 * @array: pointer on folio vector
 */
void ssdfs_folio_vector_release(struct ssdfs_folio_vector *array)
{
	struct folio *folio;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	if (!array->folios) {
		SSDFS_ERR("fail to release: "
			  "count %u, capacity %u\n",
			  array->count, array->capacity);
		return;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < ssdfs_folio_vector_count(array); i++) {
		folio = array->folios[i];

		if (!folio)
			continue;

		ssdfs_folio_put(folio);

		ssdfs_folio_vector_free_folio(folio);
		array->folios[i] = NULL;

#ifdef CONFIG_SSDFS_DEBUG
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
		SSDFS_DBG("folio %p, allocated_folios %lld\n",
			  folio,
			  atomic64_read(&ssdfs_folio_vector_folio_leaks));
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
#endif /* CONFIG_SSDFS_DEBUG */
	}

	ssdfs_folio_vector_reinit(array);
}
