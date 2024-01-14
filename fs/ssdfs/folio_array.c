/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/folio_array.c - folio array object's functionality.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2024 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 *
 * (C) Copyright 2014-2019, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot
 *                  Zvonimir Bandic
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "folio_array.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_farray_folio_leaks;
atomic64_t ssdfs_farray_memory_leaks;
atomic64_t ssdfs_farray_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_farray_cache_leaks_increment(void *kaddr)
 * void ssdfs_farray_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_farray_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_farray_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_farray_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_farray_kfree(void *kaddr)
 * struct folio *ssdfs_farray_alloc_folio(gfp_t gfp_mask,
 *                                        unsigned int order)
 * struct folio *ssdfs_farray_add_batch_folio(struct folio_batch *batch,
 *                                            unsigned int order)
 * void ssdfs_farray_free_folio(struct folio *folio)
 * void ssdfs_farray_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(farray)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(farray)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_farray_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_farray_folio_leaks, 0);
	atomic64_set(&ssdfs_farray_memory_leaks, 0);
	atomic64_set(&ssdfs_farray_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_farray_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_farray_folio_leaks) != 0) {
		SSDFS_ERR("FOLIO ARRAY: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_farray_folio_leaks));
	}

	if (atomic64_read(&ssdfs_farray_memory_leaks) != 0) {
		SSDFS_ERR("FOLIO ARRAY: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_farray_memory_leaks));
	}

	if (atomic64_read(&ssdfs_farray_cache_leaks) != 0) {
		SSDFS_ERR("FOLIO ARRAY: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_farray_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * ssdfs_create_folio_array() - create folio array
 * @array: pointer of memory area for the array creation [out]
 * @order: allocation order of a particular sized block of memory
 * @capacity: maximum number of folios in the array
 *
 * This method tries to create the folio array with @capacity
 * of maximum number of folios in the array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 */
int ssdfs_create_folio_array(struct ssdfs_folio_array *array,
			     unsigned order,
			     int capacity)
{
	void *addr[SSDFS_FOLIO_ARRAY_BMAP_COUNT];
	size_t bmap_bytes;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("capacity %d, array %p\n",
		  capacity, array);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(array, 0, sizeof(struct ssdfs_folio_array));
	atomic_set(&array->state, SSDFS_FOLIO_ARRAY_UNKNOWN_STATE);

	if (capacity == 0) {
		SSDFS_ERR("invalid capacity %d\n",
			  capacity);
		return -EINVAL;
	}

	init_rwsem(&array->lock);
	atomic_set(&array->folios_capacity, capacity);
	array->folios_count = 0;
	array->last_folio = SSDFS_FOLIO_ARRAY_INVALID_LAST_FOLIO;
	array->order = order;
	array->folio_size = PAGE_SIZE << order;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folios_count %lu, last_folio %lu, "
		  "order %u, folio_size %zu\n",
		  array->folios_count, array->last_folio,
		  order, array->folio_size);
#endif /* CONFIG_SSDFS_DEBUG */

	array->folios = ssdfs_farray_kcalloc(capacity, sizeof(struct folio *),
					     GFP_KERNEL);
	if (!array->folios) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate memory: capacity %d\n",
			  capacity);
		goto finish_create_folio_array;
	}

	bmap_bytes = capacity + BITS_PER_LONG + (BITS_PER_LONG - 1);
	bmap_bytes /= BITS_PER_BYTE;
	array->bmap_bytes = bmap_bytes;

	for (i = 0; i < SSDFS_FOLIO_ARRAY_BMAP_COUNT; i++) {
		spin_lock_init(&array->bmap[i].lock);
		array->bmap[i].ptr = NULL;
	}

	for (i = 0; i < SSDFS_FOLIO_ARRAY_BMAP_COUNT; i++) {
		addr[i] = ssdfs_farray_kmalloc(bmap_bytes, GFP_KERNEL);

		if (!addr[i]) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate bmap: index %d\n",
				  i);
			for (; i >= 0; i--)
				ssdfs_farray_kfree(addr[i]);
			goto free_folio_array;
		}

		memset(addr[i], 0xFF, bmap_bytes);
	}

	down_write(&array->lock);
	for (i = 0; i < SSDFS_FOLIO_ARRAY_BMAP_COUNT; i++) {
		spin_lock(&array->bmap[i].lock);
		array->bmap[i].ptr = addr[i];
		addr[i] = NULL;
		spin_unlock(&array->bmap[i].lock);
	}
	up_write(&array->lock);

	atomic_set(&array->state, SSDFS_FOLIO_ARRAY_CREATED);

	return 0;

free_folio_array:
	ssdfs_farray_kfree(array->folios);
	array->folios = NULL;

finish_create_folio_array:
	return err;
}

/*
 * ssdfs_destroy_folio_array() - destroy folio array
 * @array: folio array object
 *
 * This method tries to destroy the folio array.
 */
void ssdfs_destroy_folio_array(struct ssdfs_folio_array *array)
{
	int state;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
	BUG_ON(rwsem_is_locked(&array->lock));

	SSDFS_DBG("array %p, state %#x\n",
		  array,
		  atomic_read(&array->state));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_folio_array_release_all_folios(array);

	state = atomic_xchg(&array->state, SSDFS_FOLIO_ARRAY_UNKNOWN_STATE);

	switch (state) {
	case SSDFS_FOLIO_ARRAY_CREATED:
		/* expected state */
		break;

	case SSDFS_FOLIO_ARRAY_DIRTY:
		SSDFS_WARN("folio array is dirty on destruction\n");
		break;

	default:
		SSDFS_WARN("unexpected state %#x of folio array\n",
			  state);
		break;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folios_count %lu, last_folio %lu\n",
		  array->folios_count, array->last_folio);
#endif /* CONFIG_SSDFS_DEBUG */

	atomic_set(&array->folios_capacity, 0);
	array->folios_count = 0;
	array->last_folio = SSDFS_FOLIO_ARRAY_INVALID_LAST_FOLIO;

	if (array->folios)
		ssdfs_farray_kfree(array->folios);

	array->folios = NULL;

	array->bmap_bytes = 0;

	for (i = 0; i < SSDFS_FOLIO_ARRAY_BMAP_COUNT; i++) {
		spin_lock(&array->bmap[i].lock);
		if (array->bmap[i].ptr)
			ssdfs_farray_kfree(array->bmap[i].ptr);
		array->bmap[i].ptr = NULL;
		spin_unlock(&array->bmap[i].lock);
	}
}

/*
 * ssdfs_reinit_folio_array() - change the capacity of the folio array
 * @capacity: new value of the capacity
 * @array: pointer of memory area for the array creation
 *
 * This method tries to change the capacity of the folio array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
int ssdfs_reinit_folio_array(int capacity, struct ssdfs_folio_array *array)
{
	struct folio **folios;
	void *addr[SSDFS_FOLIO_ARRAY_BMAP_COUNT];
	int old_capacity;
	size_t bmap_bytes;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, capacity %d, state %#x\n",
		  array, capacity,
		  atomic_read(&array->state));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&array->state)) {
	case SSDFS_FOLIO_ARRAY_CREATED:
	case SSDFS_FOLIO_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of folio array\n",
			  atomic_read(&array->state));
		return -ERANGE;
	}

	down_write(&array->lock);

	old_capacity = atomic_read(&array->folios_capacity);

	if (capacity < old_capacity) {
		err = -EINVAL;
		SSDFS_ERR("unable to shrink: "
			  "capacity %d, folios_capacity %d\n",
			  capacity,
			  old_capacity);
		goto finish_reinit;
	}

	if (capacity == old_capacity) {
		err = 0;
		SSDFS_WARN("capacity %d == folios_capacity %d\n",
			   capacity,
			   old_capacity);
		goto finish_reinit;
	}

	atomic_set(&array->folios_capacity, capacity);

	folios = ssdfs_farray_kcalloc(capacity, sizeof(struct folio *),
					GFP_KERNEL);
	if (!folios) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate memory: capacity %d\n",
			  capacity);
		goto finish_reinit;
	}

	bmap_bytes = capacity + BITS_PER_LONG + (BITS_PER_LONG - 1);
	bmap_bytes /= BITS_PER_BYTE;

	for (i = 0; i < SSDFS_FOLIO_ARRAY_BMAP_COUNT; i++) {
		addr[i] = ssdfs_farray_kmalloc(bmap_bytes, GFP_KERNEL);

		if (!addr[i]) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate bmap: index %d\n",
				  i);
			for (; i >= 0; i--)
				ssdfs_farray_kfree(addr[i]);
			ssdfs_farray_kfree(folios);
			goto finish_reinit;
		}

		memset(addr[i], 0xFF, bmap_bytes);
	}

	err = ssdfs_memcpy(folios,
			   0, sizeof(struct folio *) * capacity,
			   array->folios,
			   0, sizeof(struct folio *) * old_capacity,
			   sizeof(struct folio *) * old_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		goto finish_reinit;
	}

	ssdfs_farray_kfree(array->folios);
	array->folios = folios;

	for (i = 0; i < SSDFS_FOLIO_ARRAY_BMAP_COUNT; i++) {
		void *tmp_addr = NULL;

		spin_lock(&array->bmap[i].lock);
		ssdfs_memcpy(addr[i], 0, bmap_bytes,
			     array->bmap[i].ptr, 0, array->bmap_bytes,
			     array->bmap_bytes);
		tmp_addr = array->bmap[i].ptr;
		array->bmap[i].ptr = addr[i];
		addr[i] = NULL;
		spin_unlock(&array->bmap[i].lock);

		ssdfs_farray_kfree(tmp_addr);
	}

	array->bmap_bytes = bmap_bytes;

finish_reinit:
	if (unlikely(err))
		atomic_set(&array->folios_capacity, old_capacity);

	up_write(&array->lock);

	return err;
}

/*
 * is_ssdfs_folio_array_empty() - is folio array empty?
 * @array: folio array object
 *
 * This method tries to check that folio array is empty.
 */
bool is_ssdfs_folio_array_empty(struct ssdfs_folio_array *array)
{
	bool is_empty = false;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&array->lock);
	is_empty = array->folios_count == 0;
	up_read(&array->lock);

	return is_empty;
}

/*
 * ssdfs_folio_array_get_last_folio_index() - get latest folio index
 * @array: folio array object
 *
 * This method tries to get latest folio index.
 */
unsigned long
ssdfs_folio_array_get_last_folio_index(struct ssdfs_folio_array *array)
{
	unsigned long index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&array->lock);
	index = array->last_folio;
	up_read(&array->lock);

	return index;
}

/*
 * ssdfs_folio_array_add_folio() - add memory folio into the folio array
 * @array: folio array object
 * @folio: memory folio
 * @folio_index: index of the folio in the folio array
 *
 * This method tries to add a folio into the folio array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - folio array contains the folio for the index.
 */
int ssdfs_folio_array_add_folio(struct ssdfs_folio_array *array,
			      struct folio *folio,
			      unsigned long folio_index)
{
	struct ssdfs_folio_array_bitmap *bmap;
	int capacity;
	unsigned long found;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !folio);

	SSDFS_DBG("array %p, folio %p, folio_index %lu, state %#x\n",
		  array, folio, folio_index,
		  atomic_read(&array->state));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&array->state)) {
	case SSDFS_FOLIO_ARRAY_CREATED:
	case SSDFS_FOLIO_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of folio array\n",
			  atomic_read(&array->state));
		return -ERANGE;
	}

	capacity = atomic_read(&array->folios_capacity);

	if (folio_index >= capacity) {
		SSDFS_ERR("folio_index %lu >= folios_capacity %d\n",
			  folio_index,
			  capacity);
		return -EINVAL;
	}

	down_write(&array->lock);

	capacity = atomic_read(&array->folios_capacity);

	if (array->folios_count > capacity) {
		err = -ERANGE;
		SSDFS_ERR("corrupted folio array: "
			  "folios_count %lu, folios_capacity %d\n",
			  array->folios_count,
			  capacity);
		goto finish_add_folio;
	}

	if (array->folios_count == capacity) {
		err = -EEXIST;
		SSDFS_ERR("folio %lu is allocated already\n",
			  folio_index);
		goto finish_add_folio;
	}

	bmap = &array->bmap[SSDFS_FOLIO_ARRAY_ALLOC_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("bitmap is empty\n");
		goto finish_add_folio;
	}

	spin_lock(&bmap->lock);
	found = bitmap_find_next_zero_area(bmap->ptr, capacity,
					   folio_index, 1, 0);
	if (found == folio_index) {
		/* folio is allocated already */
		err = -EEXIST;
	} else
		bitmap_clear(bmap->ptr, folio_index, 1);
	spin_unlock(&bmap->lock);

	if (err) {
		SSDFS_ERR("folio %lu is allocated already\n",
			  folio_index);
		goto finish_add_folio;
	}

	if (array->folios[folio_index]) {
		err = -ERANGE;
		SSDFS_WARN("position %lu contains folio pointer\n",
			   folio_index);
		goto finish_add_folio;
	} else {
		ssdfs_folio_get(folio);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

		array->folios[folio_index] = folio;
		folio->index = folio_index;
	}

	ssdfs_farray_account_folio(folio);
	array->folios_count++;

	if (array->last_folio >= SSDFS_FOLIO_ARRAY_INVALID_LAST_FOLIO)
		array->last_folio = folio_index;
	else if (array->last_folio < folio_index)
		array->last_folio = folio_index;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folios_count %lu, last_folio %lu\n",
		  array->folios_count, array->last_folio);
#endif /* CONFIG_SSDFS_DEBUG */

finish_add_folio:
	up_write(&array->lock);

	return err;
}

/*
 * ssdfs_folio_array_allocate_folio_locked() - allocate and add folio
 * @array: folio array object
 * @folio_index: index of the folio in the folio array
 *
 * This method tries to allocate, to add into the folio array and
 * to lock folio.
 *
 * RETURN:
 * [success] - pointer on allocated and locked folio.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - unable to allocate memory folio.
 * %-EEXIST     - folio array contains the folio for the index.
 */
struct folio *
ssdfs_folio_array_allocate_folio_locked(struct ssdfs_folio_array *array,
					unsigned long folio_index)
{
	struct folio *folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, folio_index %lu, state %#x\n",
		  array, folio_index,
		  atomic_read(&array->state));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&array->state)) {
	case SSDFS_FOLIO_ARRAY_CREATED:
	case SSDFS_FOLIO_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of folio array\n",
			  atomic_read(&array->state));
		return ERR_PTR(-ERANGE);
	}

	folio = ssdfs_farray_alloc_folio(GFP_KERNEL | __GFP_ZERO,
					 array->order);
	if (IS_ERR_OR_NULL(folio)) {
		err = (folio == NULL ? -ENOMEM : PTR_ERR(folio));
		SSDFS_ERR("unable to allocate memory folio\n");
		return ERR_PTR(err);
	}

	/*
	 * The ssdfs_folio_array_add_folio() calls
	 * ssdfs_farray_account_folio(). It needs to exclude
	 * the improper leaks accounting.
	 */
	ssdfs_farray_forget_folio(folio);

	err = ssdfs_folio_array_add_folio(array, folio, folio_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add folio: "
			  "folio_index %lu, err %d\n",
			  folio_index, err);
		ssdfs_farray_free_folio(folio);
		return ERR_PTR(err);
	}

	ssdfs_folio_lock(folio);
	return folio;
}

/*
 * ssdfs_folio_array_get_folio() - get folio unlocked
 * @array: folio array object
 * @folio_index: index of the folio in the folio array
 *
 * This method tries to find a folio into the folio array.
 *
 * RETURN:
 * [success] - pointer on folio.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - no allocated folio for the requested index.
 */
struct folio *ssdfs_folio_array_get_folio(struct ssdfs_folio_array *array,
					  unsigned long folio_index)
{
	struct folio *folio;
	struct ssdfs_folio_array_bitmap *bmap;
	int capacity;
	unsigned long found;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, folio_index %lu, state %#x\n",
		  array, folio_index,
		  atomic_read(&array->state));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&array->state)) {
	case SSDFS_FOLIO_ARRAY_CREATED:
	case SSDFS_FOLIO_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of folio array\n",
			  atomic_read(&array->state));
		return ERR_PTR(-ERANGE);
	}

	capacity = atomic_read(&array->folios_capacity);

	if (folio_index >= capacity) {
		SSDFS_ERR("folio_index %lu >= folios_capacity %d\n",
			  folio_index,
			  capacity);
		return ERR_PTR(-EINVAL);
	}

	down_read(&array->lock);

	bmap = &array->bmap[SSDFS_FOLIO_ARRAY_ALLOC_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("bitmap is empty\n");
		goto finish_get_folio;
	}

	spin_lock(&bmap->lock);
	found = bitmap_find_next_zero_area(bmap->ptr, capacity,
					   folio_index, 1, 0);
	if (found != folio_index) {
		/* folio is not allocated yet */
		err = -ENOENT;
	}
	spin_unlock(&bmap->lock);

	if (err) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %lu is not allocated yet\n",
			  folio_index);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_get_folio;
	}

	folio = array->folios[folio_index];

	if (!folio) {
		err = -ERANGE;
		SSDFS_ERR("folio pointer is NULL\n");
		goto finish_get_folio;
	}

finish_get_folio:
	up_read(&array->lock);

	if (unlikely(err))
		return ERR_PTR(err);

	ssdfs_folio_get(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	return folio;
}

/*
 * ssdfs_folio_array_get_folio_locked() - get folio locked
 * @array: folio array object
 * @folio_index: index of the folio in the folio array
 *
 * This method tries to find and to lock a folio into the
 * folio array.
 *
 * RETURN:
 * [success] - pointer on locked folio.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - no allocated folio for the requested index.
 */
struct folio *ssdfs_folio_array_get_folio_locked(struct ssdfs_folio_array *array,
						 unsigned long folio_index)
{
	struct folio *folio;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, folio_index %lu, state %#x\n",
		  array, folio_index,
		  atomic_read(&array->state));
#endif /* CONFIG_SSDFS_DEBUG */

	folio = ssdfs_folio_array_get_folio(array, folio_index);
	if (PTR_ERR(folio) == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %lu is not allocated yet\n",
			  folio_index);
#endif /* CONFIG_SSDFS_DEBUG */
	} else if (IS_ERR_OR_NULL(folio)) {
		SSDFS_ERR("fail to get the folio: "
			  "folio_index %lu, err %d\n",
			  folio_index, (int)PTR_ERR(folio));
	} else
		ssdfs_folio_lock(folio);

	return folio;
}

/*
 * ssdfs_folio_array_grab_folio() - get or add folio locked
 * @array: folio array object
 * @folio_index: index of the folio in the folio array
 *
 * This method tries to find and to lock a folio into the
 * folio array. If no such folio then to add and to lock
 * the folio.
 *
 * RETURN:
 * [success] - pointer on locked folio.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to add the folio.
 */
struct folio *ssdfs_folio_array_grab_folio(struct ssdfs_folio_array *array,
					   unsigned long folio_index)
{
	struct folio *folio = ERR_PTR(-ENOMEM);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, folio_index %lu, state %#x\n",
		  array, folio_index,
		  atomic_read(&array->state));
#endif /* CONFIG_SSDFS_DEBUG */

	folio = ssdfs_folio_array_get_folio_locked(array, folio_index);
	if (PTR_ERR(folio) == -ENOENT) {
		folio = ssdfs_folio_array_allocate_folio_locked(array,
								folio_index);
		if (IS_ERR_OR_NULL(folio)) {
			if (!folio)
				folio = ERR_PTR(-ENOMEM);

			SSDFS_ERR("fail to allocate the folio: "
				  "folio_index %lu, err %d\n",
				  folio_index, (int)PTR_ERR(folio));
		} else {
			ssdfs_folio_get(folio);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, count %d\n",
				  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */
		}
	} else if (IS_ERR_OR_NULL(folio)) {
		if (!folio)
			folio = ERR_PTR(-ENOMEM);

		SSDFS_ERR("fail to get folio: "
			  "folio_index %lu, err %d\n",
			  folio_index, (int)PTR_ERR(folio));
	}

	return folio;
}

/*
 * ssdfs_folio_array_set_folio_dirty() - set folio dirty
 * @array: folio array object
 * @folio_index: index of the folio in the folio array
 *
 * This method tries to set folio as dirty in the folio array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - no allocated folio for the requested index.
 */
int ssdfs_folio_array_set_folio_dirty(struct ssdfs_folio_array *array,
				      unsigned long folio_index)
{
	struct folio *folio;
	struct ssdfs_folio_array_bitmap *bmap;
	int capacity;
	unsigned long found;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, folio_index %lu, state %#x\n",
		  array, folio_index,
		  atomic_read(&array->state));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&array->state)) {
	case SSDFS_FOLIO_ARRAY_CREATED:
	case SSDFS_FOLIO_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of folio array\n",
			  atomic_read(&array->state));
		return -ERANGE;
	}

	capacity = atomic_read(&array->folios_capacity);

	if (folio_index >= capacity) {
		SSDFS_ERR("folio_index %lu >= folios_capacity %d\n",
			  folio_index,
			  capacity);
		return -EINVAL;
	}

	down_read(&array->lock);

	bmap = &array->bmap[SSDFS_FOLIO_ARRAY_ALLOC_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("allocation bitmap is empty\n");
		goto finish_set_folio_dirty;
	}

	spin_lock(&bmap->lock);
	found = bitmap_find_next_zero_area(bmap->ptr, capacity,
					   folio_index, 1, 0);
	if (found != folio_index) {
		/* folio is not allocated yet */
		err = -ENOENT;
	}
	spin_unlock(&bmap->lock);

	if (err) {
		SSDFS_ERR("folio %lu is not allocated yet\n",
			  folio_index);
		goto finish_set_folio_dirty;
	}

	bmap = &array->bmap[SSDFS_FOLIO_ARRAY_DIRTY_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("dirty bitmap is empty\n");
		goto finish_set_folio_dirty;
	}

	spin_lock(&bmap->lock);
	found = bitmap_find_next_zero_area(bmap->ptr, capacity,
					   folio_index, 1, 0);
	if (found == folio_index) {
		/* folio is dirty already */
		err = -EEXIST;
	}
	bitmap_clear(bmap->ptr, folio_index, 1);
	spin_unlock(&bmap->lock);

	if (err) {
		err = 0;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %lu is dirty already\n",
			  folio_index);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	folio = array->folios[folio_index];

	if (!folio) {
		err = -ERANGE;
		SSDFS_ERR("folio pointer is NULL\n");
		goto finish_set_folio_dirty;
	}

	folio_set_dirty(folio);

	atomic_set(&array->state, SSDFS_FOLIO_ARRAY_DIRTY);

finish_set_folio_dirty:
	up_read(&array->lock);

	return err;
}

/*
 * ssdfs_folio_array_clear_dirty_folio() - set folio as clean
 * @array: folio array object
 * @folio_index: index of the folio in the folio array
 *
 * This method tries to set folio as clean in the folio array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - no allocated folio for the requested index.
 */
int ssdfs_folio_array_clear_dirty_folio(struct ssdfs_folio_array *array,
					unsigned long folio_index)
{
	struct folio *folio;
	struct ssdfs_folio_array_bitmap *bmap;
	int capacity;
	unsigned long found;
	bool is_clean = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, folio_index %lu, state %#x\n",
		  array, folio_index,
		  atomic_read(&array->state));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&array->state)) {
	case SSDFS_FOLIO_ARRAY_CREATED:
	case SSDFS_FOLIO_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of folio array\n",
			  atomic_read(&array->state));
		return -ERANGE;
	}

	capacity = atomic_read(&array->folios_capacity);

	if (folio_index >= capacity) {
		SSDFS_ERR("folio_index %lu >= folios_capacity %d\n",
			  folio_index,
			  capacity);
		return -EINVAL;
	}

	down_read(&array->lock);

	bmap = &array->bmap[SSDFS_FOLIO_ARRAY_ALLOC_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("allocation bitmap is empty\n");
		goto finish_clear_folio_dirty;
	}

	spin_lock(&bmap->lock);
	found = bitmap_find_next_zero_area(bmap->ptr, capacity,
					   folio_index, 1, 0);
	if (found != folio_index) {
		/* folio is not allocated yet */
		err = -ENOENT;
	}
	spin_unlock(&bmap->lock);

	if (err) {
		SSDFS_ERR("folio %lu is not allocated yet\n",
			  folio_index);
		goto finish_clear_folio_dirty;
	}

	bmap = &array->bmap[SSDFS_FOLIO_ARRAY_DIRTY_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("dirty bitmap is empty\n");
		goto finish_clear_folio_dirty;
	}

	spin_lock(&bmap->lock);
	bitmap_set(bmap->ptr, folio_index, 1);
	is_clean = bitmap_full(bmap->ptr, capacity);
	spin_unlock(&bmap->lock);

	folio = array->folios[folio_index];

	if (!folio) {
		err = -ERANGE;
		SSDFS_ERR("folio pointer is NULL\n");
		goto finish_clear_folio_dirty;
	}

	folio_clear_dirty(folio);

	if (is_clean)
		atomic_set(&array->state, SSDFS_FOLIO_ARRAY_CREATED);

finish_clear_folio_dirty:
	up_read(&array->lock);

	return err;
}

/*
 * ssdfs_folio_array_clear_dirty_range() - clear dirty folios in the range
 * @array: folio array object
 * @start: starting index
 * @end: ending index (inclusive)
 *
 * This method tries to set the range's dirty folios as clean
 * in the folio array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_folio_array_clear_dirty_range(struct ssdfs_folio_array *array,
					unsigned long start,
					unsigned long end)
{
	struct folio *folio;
	struct ssdfs_folio_array_bitmap *bmap;
	int capacity;
	bool is_clean = false;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, start %lu, end %lu, state %#x\n",
		  array, start, end,
		  atomic_read(&array->state));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&array->state)) {
	case SSDFS_FOLIO_ARRAY_CREATED:
		SSDFS_DBG("no dirty folios in folio array\n");
		return 0;

	case SSDFS_FOLIO_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of folio array\n",
			  atomic_read(&array->state));
		return -ERANGE;
	}

	if (start > end) {
		SSDFS_ERR("start %lu > end %lu\n",
			  start, end);
		return -EINVAL;
	}

	down_write(&array->lock);

	capacity = atomic_read(&array->folios_capacity);

	bmap = &array->bmap[SSDFS_FOLIO_ARRAY_DIRTY_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("dirty bitmap is empty\n");
		goto finish_clear_dirty_folios;
	}

	end = min_t(int, capacity, end + 1);

	for (i = start; i < end; i++) {
		folio = array->folios[i];

		if (folio)
			folio_clear_dirty(folio);
	}

	spin_lock(&bmap->lock);
	bitmap_set(bmap->ptr, start, end - start);
	is_clean = bitmap_full(bmap->ptr, capacity);
	spin_unlock(&bmap->lock);

	if (is_clean)
		atomic_set(&array->state, SSDFS_FOLIO_ARRAY_CREATED);

finish_clear_dirty_folios:
	up_write(&array->lock);

	return err;
}

/*
 * ssdfs_folio_array_clear_all_dirty_folios() - clear all dirty folios
 * @array: folio array object
 *
 * This method tries to set all dirty folios as clean in the folio array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_folio_array_clear_all_dirty_folios(struct ssdfs_folio_array *array)
{
	int capacity;
	unsigned long start = 0, end = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, state %#x\n",
		  array,
		  atomic_read(&array->state));
#endif /* CONFIG_SSDFS_DEBUG */

	capacity = atomic_read(&array->folios_capacity);

	if (capacity > 0)
		end = capacity - 1;

	return ssdfs_folio_array_clear_dirty_range(array, start, end);
}

/*
 * ssdfs_folio_array_lookup_range() - find folios for a requested tag
 * @array: folio array object
 * @start: pointer on start index value [in|out]
 * @end: ending index (inclusive)
 * @tag: tag value for the search
 * @max_folios: maximum number of folios in the foliovec
 * @batch: folio batch for storing found folios [out]
 *
 * This method tries to find folios in the folio array for
 * the requested tag.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - nothing was found for the requested tag.
 */
int ssdfs_folio_array_lookup_range(struct ssdfs_folio_array *array,
				  unsigned long *start,
				  unsigned long end,
				  int tag, int max_folios,
				  struct folio_batch *batch)
{
	int state;
	struct folio *folio;
	struct ssdfs_folio_array_bitmap *bmap;
	int capacity;
	unsigned long found;
	int count = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !start || !batch);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&array->state);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("array %p, start %lu, end %lu, "
		  "tag %#x, max_folios %d, state %#x\n",
		  array, *start, end, tag, max_folios, state);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (state) {
	case SSDFS_FOLIO_ARRAY_CREATED:
	case SSDFS_FOLIO_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of folio array\n",
			   state);
		return -ERANGE;
	}

	folio_batch_reinit(batch);

	if (*start > end) {
		SSDFS_ERR("start %lu > end %lu\n",
			  *start, end);
		return -EINVAL;
	}

	switch (tag) {
	case SSDFS_DIRTY_FOLIO_TAG:
		if (state != SSDFS_FOLIO_ARRAY_DIRTY) {
			SSDFS_DBG("folio array is clean\n");
			return -ENOENT;
		}
		break;

	default:
		SSDFS_ERR("unknown tag %#x\n",
			  tag);
		return -EINVAL;
	}

	max_folios = min_t(int, max_folios, (int)SSDFS_EXTENT_LEN_MAX);

	down_read(&array->lock);

	capacity = atomic_read(&array->folios_capacity);
	if (capacity <= 0) {
		err = -ERANGE;
		SSDFS_ERR("invalid capacity %d\n", capacity);
		goto finish_search;
	}

	bmap = &array->bmap[SSDFS_FOLIO_ARRAY_DIRTY_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("dirty bitmap is empty\n");
		goto finish_search;
	}

	end = min_t(int, capacity - 1, end);

	spin_lock(&bmap->lock);
	found = bitmap_find_next_zero_area(bmap->ptr, capacity,
					   *start, 1, 0);
	spin_unlock(&bmap->lock);

	*start = (int)found;

	while (found <= end) {
		folio = array->folios[found];

		if (folio) {
			if (!folio_test_dirty(folio)) {
				SSDFS_ERR("folio %lu is not dirty\n",
					  folio_index(folio));
			}
			ssdfs_folio_get(folio);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, count %d\n",
				  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

			folio_batch_add(batch, folio);
			count++;
		}

		if (count >= max_folios)
			goto finish_search;

		found++;

		if (found >= capacity)
			break;

		spin_lock(&bmap->lock);
		found = bitmap_find_next_zero_area(bmap->ptr, capacity,
						   found, 1, 0);
		spin_unlock(&bmap->lock);
	};

finish_search:
	up_read(&array->lock);

	return err;
}

/*
 * ssdfs_folio_array_define_last_folio() - define last folio index
 * @array: folio array object
 * @capacity: folios capacity in array
 *
 * This method tries to define last folio index.
 */
static inline
void ssdfs_folio_array_define_last_folio(struct ssdfs_folio_array *array,
					 int capacity)
{
	struct ssdfs_folio_array_bitmap *alloc_bmap;
	unsigned long *ptr;
	unsigned long found;
	unsigned long i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
	BUG_ON(!rwsem_is_locked(&array->lock));

	SSDFS_DBG("array %p, state %#x\n",
		  array, atomic_read(&array->state));
#endif /* CONFIG_SSDFS_DEBUG */

	alloc_bmap = &array->bmap[SSDFS_FOLIO_ARRAY_ALLOC_BMAP];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!alloc_bmap->ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	if (array->folios_count == 0) {
		/* empty array */
		array->last_folio = SSDFS_FOLIO_ARRAY_INVALID_LAST_FOLIO;
	} else if (array->last_folio >= SSDFS_FOLIO_ARRAY_INVALID_LAST_FOLIO) {
		/* do nothing */
	} else if (array->last_folio > 0) {
		for (i = array->last_folio; i > array->folios_count; i--) {
			spin_lock(&alloc_bmap->lock);
			ptr = alloc_bmap->ptr;
			found = bitmap_find_next_zero_area(ptr,
							   capacity,
							   i, 1, 0);
			spin_unlock(&alloc_bmap->lock);

			if (found == i)
				break;
		}

		array->last_folio = i;
	} else
		array->last_folio = SSDFS_FOLIO_ARRAY_INVALID_LAST_FOLIO;
}

/*
 * ssdfs_folio_array_delete_folio() - delete folio from the folio array
 * @array: folio array object
 * @folio_index: index of the folio
 *
 * This method tries to delete a folio from the folio array.
 *
 * RETURN:
 * [success] - pointer on deleted folio.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - folio array hasn't a folio for the index.
 */
struct folio *ssdfs_folio_array_delete_folio(struct ssdfs_folio_array *array,
					     unsigned long folio_index)
{
	struct folio *folio;
	struct ssdfs_folio_array_bitmap *alloc_bmap, *dirty_bmap;
	int capacity;
	unsigned long found;
	bool is_clean = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, folio_index %lu, state %#x\n",
		  array, folio_index,
		  atomic_read(&array->state));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&array->state)) {
	case SSDFS_FOLIO_ARRAY_CREATED:
	case SSDFS_FOLIO_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of folio array\n",
			  atomic_read(&array->state));
		return ERR_PTR(-ERANGE);
	}

	capacity = atomic_read(&array->folios_capacity);

	if (folio_index >= capacity) {
		SSDFS_ERR("folio_index %lu >= folios_capacity %d\n",
			  folio_index,
			  capacity);
		return ERR_PTR(-EINVAL);
	}

	down_write(&array->lock);

	alloc_bmap = &array->bmap[SSDFS_FOLIO_ARRAY_ALLOC_BMAP];
	if (!alloc_bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("alloc bitmap is empty\n");
		goto finish_delete_folio;
	}

	dirty_bmap = &array->bmap[SSDFS_FOLIO_ARRAY_DIRTY_BMAP];
	if (!dirty_bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("dirty bitmap is empty\n");
		goto finish_delete_folio;
	}

	spin_lock(&alloc_bmap->lock);
	found = bitmap_find_next_zero_area(alloc_bmap->ptr, capacity,
					   folio_index, 1, 0);
	if (found != folio_index) {
		/* folio is not allocated yet */
		err = -ENOENT;
	}
	spin_unlock(&alloc_bmap->lock);

	if (err) {
		SSDFS_ERR("folio %lu is not allocated yet\n",
			  folio_index);
		goto finish_delete_folio;
	}

	folio = array->folios[folio_index];

	if (!folio) {
		err = -ERANGE;
		SSDFS_ERR("folio pointer is NULL\n");
		goto finish_delete_folio;
	}

	spin_lock(&alloc_bmap->lock);
	bitmap_set(alloc_bmap->ptr, folio_index, 1);
	spin_unlock(&alloc_bmap->lock);

	spin_lock(&dirty_bmap->lock);
	bitmap_set(dirty_bmap->ptr, folio_index, 1);
	is_clean = bitmap_full(dirty_bmap->ptr, capacity);
	spin_unlock(&dirty_bmap->lock);

	array->folios_count--;
	array->folios[folio_index] = NULL;

	if (array->last_folio == folio_index)
		ssdfs_folio_array_define_last_folio(array, capacity);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folios_count %lu, last_folio %lu\n",
		  array->folios_count, array->last_folio);
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_clean)
		atomic_set(&array->state, SSDFS_FOLIO_ARRAY_CREATED);

finish_delete_folio:
	up_write(&array->lock);

	if (unlikely(err))
		return ERR_PTR(err);

	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_farray_forget_folio(folio);

	return folio;
}

/*
 * ssdfs_folio_array_release_folios() - release folios in the range
 * @array: folio array object
 * @start: pointer on start index value [in|out]
 * @end: ending index (inclusive)
 *
 * This method tries to release folios for the requested range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_folio_array_release_folios(struct ssdfs_folio_array *array,
				     unsigned long *start,
				     unsigned long end)
{
	struct folio *folio;
	struct ssdfs_folio_array_bitmap *alloc_bmap, *dirty_bmap;
	int capacity;
	unsigned long found, found_dirty;
#ifdef CONFIG_SSDFS_DEBUG
	unsigned long released = 0;
	unsigned long allocated_folios = 0;
	unsigned long dirty_folios = 0;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !start);

	SSDFS_DBG("array %p, start %lu, end %lu, state %#x\n",
		  array, *start, end,
		  atomic_read(&array->state));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&array->state)) {
	case SSDFS_FOLIO_ARRAY_CREATED:
	case SSDFS_FOLIO_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of folio array\n",
			   atomic_read(&array->state));
		return -ERANGE;
	}

	if (*start > end) {
		SSDFS_ERR("start %lu > end %lu\n",
			  *start, end);
		return -EINVAL;
	}

	down_write(&array->lock);

	capacity = atomic_read(&array->folios_capacity);
	if (capacity <= 0) {
		err = -ERANGE;
		SSDFS_ERR("invalid capacity %d\n", capacity);
		goto finish_release_folios_range;
	}

	if (array->folios_count == 0) {
		err = 0;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folios_count %lu\n",
			  array->folios_count);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_release_folios_range;
	}

#ifdef CONFIG_SSDFS_DEBUG
	released = array->folios_count;
#endif /* CONFIG_SSDFS_DEBUG */

	alloc_bmap = &array->bmap[SSDFS_FOLIO_ARRAY_ALLOC_BMAP];
	if (!alloc_bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("allocation bitmap is empty\n");
		goto finish_release_folios_range;
	}

#ifdef CONFIG_SSDFS_DEBUG
	spin_lock(&alloc_bmap->lock);
	allocated_folios = bitmap_weight(alloc_bmap->ptr, capacity);
	spin_unlock(&alloc_bmap->lock);
	allocated_folios = capacity - allocated_folios;
#endif /* CONFIG_SSDFS_DEBUG */

	dirty_bmap = &array->bmap[SSDFS_FOLIO_ARRAY_DIRTY_BMAP];
	if (!dirty_bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("dirty bitmap is empty\n");
		goto finish_release_folios_range;
	}

#ifdef CONFIG_SSDFS_DEBUG
	spin_lock(&dirty_bmap->lock);
	dirty_folios = bitmap_weight(dirty_bmap->ptr, capacity);
	spin_unlock(&dirty_bmap->lock);
	dirty_folios = capacity - dirty_folios;
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&alloc_bmap->lock);
	found = bitmap_find_next_zero_area(alloc_bmap->ptr, capacity,
					   *start, 1, 0);
	spin_unlock(&alloc_bmap->lock);

	end = min_t(int, capacity - 1, end);

	*start = found;

	while (found <= end) {
		spin_lock(&dirty_bmap->lock);
		found_dirty = bitmap_find_next_zero_area(dirty_bmap->ptr,
							 capacity,
						         found, 1, 0);
		spin_unlock(&dirty_bmap->lock);

		if (found == found_dirty) {
			err = -ERANGE;
			SSDFS_ERR("folio %lu is dirty\n",
				  found);
			goto finish_release_folios_range;
		}

		folio = array->folios[found];

		if (folio) {
			ssdfs_folio_lock(folio);
			folio_clear_uptodate(folio);
			ssdfs_clear_folio_private(folio, 0);
			ssdfs_folio_unlock(folio);

			ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, count %d\n",
				  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_farray_free_folio(folio);
			array->folios[found] = NULL;
		}

		spin_lock(&alloc_bmap->lock);
		bitmap_set(alloc_bmap->ptr, found, 1);
		spin_unlock(&alloc_bmap->lock);

		array->folios_count--;

		found++;

		if (found >= capacity)
			break;

		spin_lock(&alloc_bmap->lock);
		found = bitmap_find_next_zero_area(alloc_bmap->ptr,
						   capacity,
						   found, 1, 0);
		spin_unlock(&alloc_bmap->lock);
	};

	ssdfs_folio_array_define_last_folio(array, capacity);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folios_count %lu, last_folio %lu\n",
		  array->folios_count, array->last_folio);

	released -= array->folios_count;

	SSDFS_DBG("released %lu, folios_count %lu, "
		  "allocated_folios %lu, dirty_folios %lu\n",
		  released, array->folios_count,
		  allocated_folios, dirty_folios);
#endif /* CONFIG_SSDFS_DEBUG */

finish_release_folios_range:
	up_write(&array->lock);

	return err;
}

/*
 * ssdfs_folio_array_release_all_folios() - release all folios
 * @array: folio array object
 *
 * This method tries to release all folios in the folio array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_folio_array_release_all_folios(struct ssdfs_folio_array *array)
{
	int capacity;
	unsigned long start = 0, end = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, state %#x\n",
		  array,
		  atomic_read(&array->state));
#endif /* CONFIG_SSDFS_DEBUG */

	capacity = atomic_read(&array->folios_capacity);

	if (capacity > 0)
		end = capacity - 1;

	return ssdfs_folio_array_release_folios(array, &start, end);
}
