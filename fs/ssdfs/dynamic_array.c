/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dymanic_array.c - dynamic array implementation.
 *
 * Copyright (c) 2022-2024 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * Copyright (c) 2022-2023 Bytedance Ltd. and/or its affiliates.
 *              https://www.bytedance.com/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cong Wang
 */

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "dynamic_array.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_dynamic_array_folio_leaks;
atomic64_t ssdfs_dynamic_array_memory_leaks;
atomic64_t ssdfs_dynamic_array_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_dynamic_array_cache_leaks_increment(void *kaddr)
 * void ssdfs_dynamic_array_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_dynamic_array_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_dynamic_array_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_dynamic_array_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_dynamic_array_kfree(void *kaddr)
 * struct folio *ssdfs_dynamic_array_alloc_folio(gfp_t gfp_mask,
 *                                               unsigned int order)
 * struct folio *ssdfs_dynamic_array_add_batch_folio(struct folio_batch *batch,
 *                                                   unsigned int order)
 * void ssdfs_dynamic_array_free_folio(struct folio *folio)
 * void ssdfs_dynamic_array_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(dynamic_array)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(dynamic_array)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_dynamic_array_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_dynamic_array_folio_leaks, 0);
	atomic64_set(&ssdfs_dynamic_array_memory_leaks, 0);
	atomic64_set(&ssdfs_dynamic_array_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_dynamic_array_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_dynamic_array_folio_leaks) != 0) {
		SSDFS_ERR("DYNAMIC ARRAY: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_dynamic_array_folio_leaks));
	}

	if (atomic64_read(&ssdfs_dynamic_array_memory_leaks) != 0) {
		SSDFS_ERR("DYNAMIC ARRAY: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_dynamic_array_memory_leaks));
	}

	if (atomic64_read(&ssdfs_dynamic_array_cache_leaks) != 0) {
		SSDFS_ERR("DYNAMIC ARRAY: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_dynamic_array_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * ssdfs_dynamic_array_create() - create dynamic array
 * @array: pointer on dynamic array object
 * @capacity: maximum number of items in array
 * @item_size: item size in bytes
 * @alloc_pattern: pattern to init memory pages
 */
int ssdfs_dynamic_array_create(struct ssdfs_dynamic_array *array,
				u32 capacity, size_t item_size,
				u8 alloc_pattern)
{
	struct folio *folio;
	u64 max_threshold = (u64)ssdfs_folio_vector_max_threshold() * PAGE_SIZE;
	u32 folios_count;
	u64 bytes_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, capacity %u, item_size %zu\n",
		  array, capacity, item_size);
#endif /* CONFIG_SSDFS_DEBUG */

	array->state = SSDFS_DYNAMIC_ARRAY_STORAGE_ABSENT;
	array->alloc_pattern = alloc_pattern;

	if (capacity == 0) {
		SSDFS_ERR("invalid capacity %u\n",
			  capacity);
		return -EINVAL;
	}

	if (item_size == 0 || item_size > PAGE_SIZE) {
		SSDFS_ERR("invalid item_size %zu\n",
			  item_size);
		return -EINVAL;
	}

	array->capacity = capacity;
	array->items_count = 0;
	array->item_size = item_size;
	array->items_per_folio = PAGE_SIZE / item_size;

	folios_count = capacity + array->items_per_folio - 1;
	folios_count /= array->items_per_folio;

	if (folios_count == 0)
		folios_count = 1;

	if (folios_count > 1) {
		bytes_count = (u64)folios_count * PAGE_SIZE;
	} else {
		bytes_count = min_t(u64,
				    (u64)capacity * item_size,
				    (u64)array->items_per_folio * item_size);
	}

	if (bytes_count > max_threshold) {
		SSDFS_ERR("invalid request: "
			  "bytes_count %llu > max_threshold %llu, "
			  "capacity %u, item_size %zu\n",
			  bytes_count, max_threshold,
			  capacity, item_size);
		return -EINVAL;
	}

	if (bytes_count > PAGE_SIZE) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(folios_count >= ssdfs_folio_vector_max_threshold());
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_folio_vector_create(&array->batch,
						get_order(PAGE_SIZE),
						folios_count);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create folio vector: "
				  "bytes_count %llu, folios_count %u, "
				  "err %d\n",
				  bytes_count, folios_count, err);
			return err;
		}

		err = ssdfs_folio_vector_init(&array->batch);
		if (unlikely(err)) {
			ssdfs_folio_vector_destroy(&array->batch);
			SSDFS_ERR("fail to init folio vector: "
				  "bytes_count %llu, folios_count %u, "
				  "err %d\n",
				  bytes_count, folios_count, err);
			return err;
		}

		folio = ssdfs_folio_vector_allocate(&array->batch);
		if (IS_ERR_OR_NULL(folio)) {
			err = (folio == NULL ? -ENOMEM : PTR_ERR(folio));
			SSDFS_ERR("unable to allocate folio\n");
			return err;
		}

		ssdfs_folio_lock(folio);
		__ssdfs_memset_folio(folio, 0, PAGE_SIZE,
				     array->alloc_pattern, PAGE_SIZE);
		ssdfs_folio_unlock(folio);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

		array->bytes_count = PAGE_SIZE;
		array->state = SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC;
	} else {
		array->buf = ssdfs_dynamic_array_kzalloc(bytes_count,
							 GFP_KERNEL);
		if (!array->buf) {
			SSDFS_ERR("fail to allocate memory: "
				  "bytes_count %llu\n",
				  bytes_count);
			return -ENOMEM;
		}

		memset(array->buf, array->alloc_pattern, bytes_count);

		array->bytes_count = bytes_count;
		array->state = SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER;
	}

	return 0;
}

/*
 * ssdfs_dynamic_array_destroy() - destroy dynamic array
 * @array: pointer on dynamic array object
 */
void ssdfs_dynamic_array_destroy(struct ssdfs_dynamic_array *array)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, capacity %u, "
		  "item_size %zu, bytes_count %u\n",
		  array, array->capacity,
		  array->item_size, array->bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC:
		ssdfs_folio_vector_release(&array->batch);
		ssdfs_folio_vector_destroy(&array->batch);
		break;

	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
		if (array->buf)
			ssdfs_dynamic_array_kfree(array->buf);
		break;

	default:
		SSDFS_WARN("unexpected state %#x\n", array->state);
		break;
	}

	array->capacity = 0;
	array->items_count = 0;
	array->item_size = 0;
	array->items_per_folio = 0;
	array->bytes_count = 0;
	array->state = SSDFS_DYNAMIC_ARRAY_STORAGE_ABSENT;
}

/*
 * SSDFS_DYNAMIC_ARRAY_ITEM_OFFSET() - calculate item offset
 * @array: pointer on dynamic array object
 * @index: item index
 */
static inline
u32 SSDFS_DYNAMIC_ARRAY_ITEM_OFFSET(struct ssdfs_dynamic_array *array,
				    u32 index)
{
	u64 item_offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, index %u, capacity %u, "
		  "item_size %zu, bytes_count %u\n",
		  array, index, array->capacity,
		  array->item_size, array->bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	item_offset = index / array->items_per_folio;

	if (item_offset > 0)
		item_offset <<= PAGE_SHIFT;

	item_offset += (u64)array->item_size * (index % array->items_per_folio);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(item_offset >= U32_MAX);

	SSDFS_DBG("index %u, item_offset %llu\n",
		  index, item_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u32)item_offset;
}

/*
 * ssdfs_dynamic_array_get_locked() - get locked item
 * @array: pointer on dynamic array object
 * @index: item index
 *
 * This method tries to get pointer on item. If short buffer
 * (< 4K) represents dynamic array, then the logic is pretty
 * straitforward. Otherwise, memory page is locked. The release
 * method should be called to unlock memory folio.
 *
 * RETURN:
 * [success] - pointer on requested item.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-E2BIG      - request is out of array capacity.
 * %-ERANGE     - internal error.
 */
void *ssdfs_dynamic_array_get_locked(struct ssdfs_dynamic_array *array,
				     u32 index)
{
	struct ssdfs_smart_folio folio;
	void *ptr = NULL;
	u64 max_threshold = (u64)ssdfs_folio_vector_max_threshold() * PAGE_SIZE;
	u32 item_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, index %u, capacity %u, "
		  "item_size %zu, bytes_count %u\n",
		  array, index, array->capacity,
		  array->item_size, array->bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC:
	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
		/* continue logic */
		break;

	default:
		SSDFS_WARN("unexpected state %#x\n", array->state);
		return ERR_PTR(-ERANGE);
	}

	if (array->item_size == 0 || array->item_size > PAGE_SIZE) {
		SSDFS_ERR("invalid item_size %zu\n",
			  array->item_size);
		return ERR_PTR(-ERANGE);
	}

	if (array->capacity == 0) {
		SSDFS_ERR("invalid capacity %u\n",
			  array->capacity);
		return ERR_PTR(-ERANGE);
	}

	if (array->bytes_count == 0) {
		SSDFS_ERR("invalid bytes_count %u\n",
			  array->bytes_count);
		return ERR_PTR(-ERANGE);
	}

	if (index >= array->capacity) {
		SSDFS_WARN("invalid index: index %u, capacity %u\n",
			   index, array->capacity);
		return ERR_PTR(-ERANGE);
	}

	item_offset = SSDFS_DYNAMIC_ARRAY_ITEM_OFFSET(array, index);

	if (item_offset >= max_threshold) {
		SSDFS_ERR("invalid item_offset: "
			  "index %u, item_size %zu, "
			  "item_offset %u, bytes_count %u, "
			  "max_threshold %llu\n",
			  index, array->item_size,
			  item_offset, array->bytes_count,
			  max_threshold);
		return ERR_PTR(-E2BIG);
	}

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC:
		err = SSDFS_OFF2FOLIO(PAGE_SIZE, item_offset, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare folio descriptor: "
				  "err %d\n", err);
			return ERR_PTR(err);
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio.desc.folio_index >=
				ssdfs_folio_vector_capacity(&array->batch)) {
			SSDFS_ERR("invalid folio index: "
				  "folio_index %u, item_offset %u\n",
				  folio.desc.folio_index, item_offset);
			return ERR_PTR(-E2BIG);
		}

		while (folio.desc.folio_index >=
				ssdfs_folio_vector_count(&array->batch)) {
			struct folio *temp;

			temp = ssdfs_folio_vector_allocate(&array->batch);
			if (IS_ERR_OR_NULL(temp)) {
				err = (temp == NULL ?
						-ENOMEM : PTR_ERR(temp));
				SSDFS_ERR("unable to allocate folio\n");
				return ERR_PTR(err);
			}

			ssdfs_folio_lock(temp);
			__ssdfs_memset_folio(temp, 0, PAGE_SIZE,
					   array->alloc_pattern, PAGE_SIZE);
			ssdfs_folio_unlock(temp);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, count %d\n",
				  temp, folio_ref_count(temp));
#endif /* CONFIG_SSDFS_DEBUG */

			array->bytes_count += PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("array %p, index %u, capacity %u, "
				  "item_size %zu, bytes_count %u, "
				  "index %u, item_offset %u, "
				  "folio_index %u, folio_count %u\n",
				  array, index, array->capacity,
				  array->item_size, array->bytes_count,
				  index, item_offset,
				  folio.desc.folio_index,
				  ssdfs_folio_vector_count(&array->batch));
#endif /* CONFIG_SSDFS_DEBUG */
		}

		folio.ptr = array->batch.folios[folio.desc.folio_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio.ptr);

		SSDFS_DBG("index %u, block_size %u, offset %llu, "
			  "folio_index %u, folio_offset %llu, "
			  "page_in_folio %u, page_offset %u, "
			  "offset_inside_page %u\n",
			  index,
			  folio.desc.block_size,
			  folio.desc.offset,
			  folio.desc.folio_index,
			  folio.desc.folio_offset,
			  folio.desc.page_in_folio,
			  folio.desc.page_offset,
			  folio.desc.offset_inside_page);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(folio.ptr);
		ptr = kmap_local_folio(folio.ptr, 0);
		ptr = (u8 *)ptr + folio.desc.offset_inside_page;
		break;

	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
		if ((item_offset + array->item_size) > array->bytes_count) {
			SSDFS_ERR("invalid item offset: "
				  "item_offset %u, item_size %zu, "
				  "bytes_count %u\n",
				  item_offset,
				  array->item_size,
				  array->bytes_count);
			return ERR_PTR(-ERANGE);
		}

		ptr = (u8 *)array->buf + item_offset;
		break;

	default:
		SSDFS_WARN("unexpected state %#x\n", array->state);
		return ERR_PTR(-ERANGE);
	}

	if (index >= array->items_count)
		array->items_count = index + 1;

	return ptr;
}

/*
 * ssdfs_dynamic_array_get_content_locked() - get locked items range
 * @array: pointer on dynamic array object
 * @index: item index
 * @items_count: items count in range [out]
 *
 * This method tries to get pointer on range of items. If short buffer
 * (< 4K) represents dynamic array, then the logic is pretty
 * straitforward. Otherwise, memory page is locked. The release
 * method should be called to unlock memory page.
 *
 * RETURN:
 * [success] - pointer on requested range.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-E2BIG      - request is out of array capacity.
 * %-ERANGE     - internal error.
 */
void *ssdfs_dynamic_array_get_content_locked(struct ssdfs_dynamic_array *array,
					     u32 index, u32 *items_count)
{
	struct ssdfs_smart_folio folio;
	void *ptr = NULL;
	u64 max_threshold = (u64)ssdfs_folio_vector_max_threshold() * PAGE_SIZE;
	u32 item_offset;
	u32 first_index_in_folio;
	u32 offset_inside_folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, index %u, capacity %u, "
		  "item_size %zu, bytes_count %u\n",
		  array, index, array->capacity,
		  array->item_size, array->bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	*items_count = 0;

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC:
	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
		/* continue logic */
		break;

	default:
		SSDFS_WARN("unexpected state %#x\n", array->state);
		return ERR_PTR(-ERANGE);
	}

	if (array->item_size == 0 || array->item_size > PAGE_SIZE) {
		SSDFS_ERR("invalid item_size %zu\n",
			  array->item_size);
		return ERR_PTR(-ERANGE);
	}

	if (array->capacity == 0) {
		SSDFS_ERR("invalid capacity %u\n",
			  array->capacity);
		return ERR_PTR(-ERANGE);
	}

	if (array->bytes_count == 0) {
		SSDFS_ERR("invalid bytes_count %u\n",
			  array->bytes_count);
		return ERR_PTR(-ERANGE);
	}

	if (array->items_count > array->capacity) {
		SSDFS_ERR("corrupted array: "
			  "items_count %u > capacity %u\n",
			  array->items_count,
			  array->capacity);
		return ERR_PTR(-ERANGE);
	}

	if (index >= array->capacity) {
		SSDFS_ERR("invalid index: index %u, capacity %u\n",
			  index, array->capacity);
		return ERR_PTR(-ERANGE);
	}

	item_offset = SSDFS_DYNAMIC_ARRAY_ITEM_OFFSET(array, index);

	if (item_offset >= max_threshold) {
		SSDFS_ERR("invalid item_offset: "
			  "index %u, item_size %zu, "
			  "item_offset %u, bytes_count %u, "
			  "max_threshold %llu\n",
			  index, array->item_size,
			  item_offset, array->bytes_count,
			  max_threshold);
		return ERR_PTR(-E2BIG);
	}

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC:
		err = SSDFS_OFF2FOLIO(PAGE_SIZE, item_offset, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare folio descriptor: "
				  "err %d\n", err);
			return ERR_PTR(err);
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio.desc.folio_index >=
				ssdfs_folio_vector_count(&array->batch)) {
			SSDFS_ERR("invalid folio index: "
				  "folio_index %u, item_offset %u\n",
				  folio.desc.folio_index, item_offset);
			return ERR_PTR(-E2BIG);
		}

		folio.ptr = array->batch.folios[folio.desc.folio_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		first_index_in_folio = index % array->items_per_folio;
		offset_inside_folio = first_index_in_folio * array->item_size;

		ssdfs_folio_lock(folio.ptr);
		ptr = kmap_local_folio(folio.ptr, 0);
		ptr = (u8 *)ptr + offset_inside_folio;

		*items_count = array->items_count - index;
		*items_count = min_t(u32, *items_count,
					array->items_per_folio -
						first_index_in_folio);
		break;

	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
		if ((item_offset + array->item_size) > array->bytes_count) {
			SSDFS_ERR("invalid item offset: "
				  "item_offset %u, item_size %zu, "
				  "bytes_count %u\n",
				  item_offset,
				  array->item_size,
				  array->bytes_count);
			return ERR_PTR(-ERANGE);
		}

		ptr = (u8 *)array->buf + item_offset;
		*items_count = array->items_count - index;
		break;

	default:
		SSDFS_WARN("unexpected state %#x\n", array->state);
		return ERR_PTR(-ERANGE);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_count %u\n", *items_count);
#endif /* CONFIG_SSDFS_DEBUG */

	return ptr;
}

/*
 * ssdfs_dynamic_array_release() - release item
 * @array: pointer on dynamic array object
 * @index: item index
 * @ptr: pointer on item
 *
 * This method tries to release item pointer.
 *
 * RETURN:
 * [success] - pointer on requested item.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-E2BIG      - request is out of array capacity.
 * %-ERANGE     - internal error.
 */
int ssdfs_dynamic_array_release(struct ssdfs_dynamic_array *array,
				u32 index, void *ptr)
{
	struct folio *folio;
	u32 item_offset;
	u64 folio_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !ptr);

	SSDFS_DBG("array %p, index %u, capacity %u, "
		  "item_size %zu, bytes_count %u\n",
		  array, index, array->capacity,
		  array->item_size, array->bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC:
		/* continue logic */
		break;

	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
		/* do nothing */
		return 0;

	default:
		SSDFS_WARN("unexpected state %#x\n", array->state);
		return -ERANGE;
	}

	if (array->item_size == 0 || array->item_size > PAGE_SIZE) {
		SSDFS_ERR("invalid item_size %zu\n",
			  array->item_size);
		return -ERANGE;
	}

	if (array->capacity == 0) {
		SSDFS_ERR("invalid capacity %u\n",
			  array->capacity);
		return -ERANGE;
	}

	if (array->bytes_count == 0) {
		SSDFS_ERR("invalid bytes_count %u\n",
			  array->bytes_count);
		return -ERANGE;
	}

	if (index >= array->capacity) {
		SSDFS_ERR("invalid index: index %u, capacity %u\n",
			  index, array->capacity);
		return -ERANGE;
	}

	item_offset = SSDFS_DYNAMIC_ARRAY_ITEM_OFFSET(array, index);

	if (item_offset >= array->bytes_count) {
		SSDFS_ERR("invalid item_offset: "
			  "index %u, item_size %zu, "
			  "item_offset %u, bytes_count %u\n",
			  index, array->item_size,
			  item_offset, array->bytes_count);
		return -E2BIG;
	}

	folio_index = index / array->items_per_folio;

	if (folio_index >= ssdfs_folio_vector_count(&array->batch)) {
		SSDFS_ERR("invalid folio index: "
			  "folio_index %llu, item_offset %u\n",
			  folio_index, item_offset);
		return -E2BIG;
	}

	folio = array->batch.folios[folio_index];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	kunmap_local(ptr);
	ssdfs_folio_unlock(folio);

	return 0;
}

/*
 * ssdfs_dynamic_array_set() - store item into dynamic array
 * @array: pointer on dynamic array object
 * @index: item index
 * @item: pointer on item
 *
 * This method tries to store item into dynamic array.
 *
 * RETURN:
 * [success] - pointer on requested item.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-E2BIG      - request is out of array capacity.
 * %-ERANGE     - internal error.
 */
int ssdfs_dynamic_array_set(struct ssdfs_dynamic_array *array,
			    u32 index, void *item)
{
	struct ssdfs_smart_folio folio;
	void *kaddr = NULL;
	u64 max_threshold = (u64)ssdfs_folio_vector_max_threshold() * PAGE_SIZE;
	u32 item_offset;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !item);

	SSDFS_DBG("array %p, index %u, capacity %u, "
		  "item_size %zu, bytes_count %u\n",
		  array, index, array->capacity,
		  array->item_size, array->bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC:
	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
		/* continue logic */
		break;

	default:
		SSDFS_WARN("unexpected state %#x\n", array->state);
		return -ERANGE;
	}

	if (array->item_size == 0 || array->item_size > PAGE_SIZE) {
		SSDFS_ERR("invalid item_size %zu\n",
			  array->item_size);
		return -ERANGE;
	}

	if (array->capacity == 0) {
		SSDFS_ERR("invalid capacity %u\n",
			  array->capacity);
		return -ERANGE;
	}

	if (array->bytes_count == 0) {
		SSDFS_ERR("invalid bytes_count %u\n",
			  array->bytes_count);
		return -ERANGE;
	}

	if (index >= array->capacity) {
		SSDFS_ERR("invalid index: index %u, capacity %u\n",
			  index, array->capacity);
		return -ERANGE;
	}

	item_offset = SSDFS_DYNAMIC_ARRAY_ITEM_OFFSET(array, index);

	if (item_offset >= max_threshold) {
		SSDFS_ERR("invalid item_offset: "
			  "index %u, item_size %zu, "
			  "item_offset %u, bytes_count %u, "
			  "max_threshold %llu\n",
			  index, array->item_size,
			  item_offset, array->bytes_count,
			  max_threshold);
		return -E2BIG;
	}

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC:
		err = SSDFS_OFF2FOLIO(PAGE_SIZE, item_offset, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare folio descriptor: "
				  "err %d\n", err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio.desc.folio_index >=
				ssdfs_folio_vector_capacity(&array->batch)) {
			SSDFS_ERR("invalid folio index: "
				  "folio_index %u, item_offset %u\n",
				  folio.desc.folio_index, item_offset);
			return -E2BIG;
		}

		while (folio.desc.folio_index >=
				ssdfs_folio_vector_count(&array->batch)) {
			struct folio *temp;

			temp = ssdfs_folio_vector_allocate(&array->batch);
			if (IS_ERR_OR_NULL(temp)) {
				err = (temp == NULL ?
						-ENOMEM : PTR_ERR(temp));
				SSDFS_ERR("unable to allocate folio\n");
				return err;
			}

			ssdfs_folio_lock(temp);
			__ssdfs_memset_folio(temp, 0, PAGE_SIZE,
					     array->alloc_pattern, PAGE_SIZE);
			ssdfs_folio_unlock(temp);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, count %d\n",
				  temp, folio_ref_count(temp));
#endif /* CONFIG_SSDFS_DEBUG */

			array->bytes_count += PAGE_SIZE;
		}

		folio.ptr = array->batch.folios[folio.desc.folio_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio.ptr);

		SSDFS_DBG("index %u, block_size %u, offset %llu, "
			  "folio_index %u, folio_offset %llu, "
			  "page_in_folio %u, page_offset %u, "
			  "offset_inside_page %u\n",
			  index,
			  folio.desc.block_size,
			  folio.desc.offset,
			  folio.desc.folio_index,
			  folio.desc.folio_offset,
			  folio.desc.page_in_folio,
			  folio.desc.page_offset,
			  folio.desc.offset_inside_page);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(folio.ptr);
		kaddr = kmap_local_folio(folio.ptr, 0);
		err = ssdfs_memcpy(kaddr,
				   folio.desc.offset_inside_page, PAGE_SIZE,
				   item,
				   0, array->item_size,
				   array->item_size);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio.ptr);
		break;

	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
		if ((item_offset + array->item_size) > array->bytes_count) {
			SSDFS_ERR("invalid item offset: "
				  "item_offset %u, item_size %zu, "
				  "bytes_count %u\n",
				  item_offset,
				  array->item_size,
				  array->bytes_count);
			return -ERANGE;
		}

		err = ssdfs_memcpy(array->buf, item_offset, array->bytes_count,
				   item, 0, array->item_size,
				   array->item_size);
		break;

	default:
		SSDFS_WARN("unexpected state %#x\n", array->state);
		return -ERANGE;
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to set item: index %u, err %d\n",
			  index, err);
	} else if (index >= array->items_count)
		array->items_count = index + 1;

	return err;
}

/*
 * ssdfs_dynamic_array_copy_content() - copy the whole dynamic array
 * @array: pointer on dynamic array object
 * @copy_buf: pointer on copy buffer
 * @buf_size: size of the buffer in bytes
 *
 * This method tries to copy the whole content of dynamic array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_dynamic_array_copy_content(struct ssdfs_dynamic_array *array,
				     void *copy_buf, size_t buf_size)
{
	struct folio *folio;
	u32 copied_bytes = 0;
	u32 folios_count;
	size_t bytes_count;
	u32 items_count;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !copy_buf);

	SSDFS_DBG("array %p, capacity %u, "
		  "item_size %zu, bytes_count %u, "
		  "copy_buf %p, buf_size %zu\n",
		  array, array->capacity,
		  array->item_size, array->bytes_count,
		  copy_buf, buf_size);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC:
	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
		/* continue logic */
		break;

	default:
		SSDFS_WARN("unexpected state %#x\n", array->state);
		return -ERANGE;
	}

	if (array->bytes_count == 0) {
		SSDFS_ERR("invalid bytes_count %u\n",
			  array->bytes_count);
		return -ERANGE;
	}

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC:
		folios_count = ssdfs_folio_vector_count(&array->batch);

		for (i = 0; i < folios_count; i++) {
			if (copied_bytes >= buf_size) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("stop copy: "
					  "copied_bytes %u, "
					  "buf_size %zu, "
					  "array->bytes_count %u, "
					  "folios_count %u\n",
					  copied_bytes,
					  buf_size,
					  array->bytes_count,
					  folios_count);
#endif /* CONFIG_SSDFS_DEBUG */
				break;
			}

			folio = array->batch.folios[i];

			if (!folio) {
				err = -ERANGE;
				SSDFS_ERR("fail to copy content: "
					  "copied_bytes %u, "
					  "array->bytes_count %u, "
					  "folio_index %d, "
					  "folios_count %u\n",
					  copied_bytes,
					  array->bytes_count,
					  i, folios_count);
				goto finish_copy_content;
			}

			items_count = i * array->items_per_folio;

			if (items_count >= array->items_count) {
				SSDFS_DBG("stop copy: "
					  "items_count %u, "
					  "array->items_count %u\n",
					  items_count,
					  array->items_count);
				break;
			}

			items_count = min_t(u32,
					    array->items_count - items_count,
					    array->items_per_folio);

			bytes_count = array->item_size * items_count;
			bytes_count = min_t(size_t, bytes_count,
						buf_size - copied_bytes);

			err = __ssdfs_memcpy_from_folio(copy_buf,
							copied_bytes,
							buf_size,
							folio,
							0,
							PAGE_SIZE,
							bytes_count);
			if (unlikely(err)) {
				SSDFS_ERR("fail to copy content: "
					  "copied_bytes %u, "
					  "array->bytes_count %u, "
					  "folio_index %d, "
					  "folios_count %u, "
					  "err %d\n",
					  copied_bytes,
					  array->bytes_count,
					  i, folios_count,
					  err);
				goto finish_copy_content;
			}

			copied_bytes += bytes_count;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("array %p, capacity %u, "
				  "item_size %zu, bytes_count %u, "
				  "folio_index %d, folios_count %u, "
				  "bytes_count %zu, copied_bytes %u\n",
				  array, array->capacity,
				  array->item_size, array->bytes_count,
				  i, folios_count, bytes_count, copied_bytes);
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
		bytes_count = array->item_size * array->items_count;

		if (bytes_count > array->bytes_count) {
			SSDFS_ERR("corrupted array: "
				  "bytes_count %zu > array->bytes_count %u\n",
				  bytes_count, array->bytes_count);
			return -ERANGE;
		}

		err = ssdfs_memcpy(copy_buf, 0, buf_size,
				   array->buf, 0, array->bytes_count,
				   bytes_count);
		break;

	default:
		BUG();
		break;
	}

finish_copy_content:
	return err;
}

/*
 * ssdfs_shift_folio_vector_content_right() - shift folio vector content right
 * @array: pointer on dynamic array object
 * @start_index: starting item index
 * @shift: shift value
 *
 * This method tries to shift range of items in array's content.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_shift_folio_vector_content_right(struct ssdfs_dynamic_array *array,
					   u32 start_index, u32 shift)
{
	struct folio *folio1, *folio2;
	void *kaddr;
	int folio_index1, folio_index2;
	int src_index, dst_index;
	u32 item_offset1, item_offset2;
	u32 vector_capacity;
	u32 range_len;
	u32 moved_items = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, start_index %u, shift %u, "
		  "capacity %u, item_size %zu, bytes_count %u\n",
		  array, start_index, shift, array->capacity,
		  array->item_size, array->bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC:
		/* continue logic */
		break;

	default:
		SSDFS_WARN("unexpected state %#x\n", array->state);
		return -ERANGE;
	}

	vector_capacity = ssdfs_folio_vector_capacity(&array->batch);

	range_len = array->items_count - start_index;
	src_index = start_index + range_len - 1;
	dst_index = src_index + shift;

	if (dst_index >= array->capacity) {
		SSDFS_ERR("shift is out of area: "
			  "src_index %d, shift %u, "
			  "capacity %u\n",
			  src_index, shift,
			  array->capacity);
		return -ERANGE;
	}

	do {
		u32 index_diff;
		int moving_items;
		u32 moving_bytes;

		folio_index2 = dst_index / array->items_per_folio;
		if (folio_index2 >= vector_capacity) {
			SSDFS_ERR("invalid folio index: "
				  "folio_index %d, capacity %u\n",
				  folio_index2, vector_capacity);
			return -E2BIG;
		}

		while (folio_index2 >= ssdfs_folio_vector_count(&array->batch)) {
			struct folio *folio;

			folio = ssdfs_folio_vector_allocate(&array->batch);
			if (IS_ERR_OR_NULL(folio)) {
				err = (folio == NULL ? -ENOMEM : PTR_ERR(folio));
				SSDFS_ERR("unable to allocate folio\n");
				return err;
			}

			ssdfs_folio_lock(folio);
			__ssdfs_memset_folio(folio, 0, PAGE_SIZE,
					     array->alloc_pattern, PAGE_SIZE);
			ssdfs_folio_unlock(folio);

			SSDFS_DBG("folio %p, count %d\n",
				  folio, folio_ref_count(folio));

			array->bytes_count += PAGE_SIZE;
		}

		folio_index1 = src_index / array->items_per_folio;
		if (folio_index1 >= vector_capacity) {
			SSDFS_ERR("invalid folio index: "
				  "folio_index %d, capacity %u\n",
				  folio_index1, vector_capacity);
			return -E2BIG;
		}

		if (folio_index1 != folio_index2) {
			u32 index_diff1, index_diff2;

			index_diff1 = (dst_index + 1) % array->items_per_folio;
			if (index_diff1 == 0)
				index_diff1 = 1;

			index_diff2 = (src_index + 1) % array->items_per_folio;
			if (index_diff2 == 0)
				index_diff2 = 1;

			index_diff = min_t(u32, index_diff1, index_diff2);
		} else {
			index_diff = (src_index + 1) % array->items_per_folio;

			if (index_diff == 0)
				index_diff = 1;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("src_index %d, dst_index %d, "
			  "array->items_count %u, range_len %u, "
			  "array->items_per_folio %u, index_diff %u, "
			  "folio_index2 %d, folio_index1 %d, "
			  "array->item_size %zu\n",
			  src_index, dst_index,
			  array->items_count, range_len,
			  array->items_per_folio, index_diff,
			  folio_index2, folio_index1,
			  array->item_size);

		BUG_ON(index_diff >= U16_MAX);
		BUG_ON(moved_items > range_len);
#endif /* CONFIG_SSDFS_DEBUG */

		moving_items = range_len - moved_items;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("range_len %u, moved_items %u, "
			  "moving_items %d, index_diff %u\n",
			  range_len, moved_items,
			  moving_items, index_diff);

		BUG_ON(moving_items < 0);
#endif /* CONFIG_SSDFS_DEBUG */

		moving_items = min_t(int, moving_items, (int)index_diff);

		if (moving_items == 0) {
			SSDFS_WARN("no items for moving\n");
			return -ERANGE;
		}

		moving_bytes = moving_items * array->item_size;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(moving_items >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		src_index -= moving_items - 1;
		dst_index = src_index + shift;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("moving_items %d, src_index %d, dst_index %d\n",
			  moving_items, src_index, dst_index);

		BUG_ON(start_index > src_index);
#endif /* CONFIG_SSDFS_DEBUG */

		folio_index1 = src_index / array->items_per_folio;
		index_diff = src_index % array->items_per_folio;
		item_offset1 = index_diff * array->item_size;

		folio_index2 = dst_index / array->items_per_folio;
		index_diff = dst_index % array->items_per_folio;
		item_offset2 = index_diff * array->item_size;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("items_offset1 %u, item_offset2 %u\n",
			  item_offset1, item_offset2);

		if ((item_offset1 + moving_bytes) > PAGE_SIZE) {
			SSDFS_WARN("invalid offset: "
				   "item_offset1 %u, moving_bytes %u\n",
				   item_offset1, moving_bytes);
			return -ERANGE;
		}

		if ((item_offset2 + moving_bytes) > PAGE_SIZE) {
			SSDFS_WARN("invalid offset: "
				   "item_offset2 %u, moving_bytes %u\n",
				   item_offset2, moving_bytes);
			return -ERANGE;
		}

		SSDFS_DBG("folio_index1 %d, item_offset1 %u, "
			  "folio_index2 %d, item_offset2 %u, "
			  "moving_bytes %u\n",
			  folio_index1, item_offset1,
			  folio_index2, item_offset2,
			  moving_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio_index1 != folio_index2) {
			folio1 = array->batch.folios[folio_index1];
			folio2 = array->batch.folios[folio_index2];
			ssdfs_folio_lock(folio1);
			ssdfs_folio_lock(folio2);
			err = __ssdfs_memmove_folio(folio2,
						    item_offset2, PAGE_SIZE,
						    folio1,
						    item_offset1, PAGE_SIZE,
						    moving_bytes);
			ssdfs_folio_unlock(folio2);
			ssdfs_folio_unlock(folio1);

			if (unlikely(err)) {
				SSDFS_ERR("fail to move: err %d\n", err);
				return err;
			}
		} else {
			folio1 = array->batch.folios[folio_index1];
			ssdfs_folio_lock(folio1);
			kaddr = kmap_local_folio(folio1, 0);
			err = ssdfs_memmove(kaddr, item_offset2, PAGE_SIZE,
					    kaddr, item_offset1, PAGE_SIZE,
					    moving_bytes);
			flush_dcache_folio(folio1);
			kunmap_local(kaddr);
			ssdfs_folio_unlock(folio1);

			if (unlikely(err)) {
				SSDFS_ERR("fail to move: err %d\n", err);
				return err;
			}
		}

		src_index--;
		dst_index--;
		moved_items += moving_items;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start_index %u, src_index %d, "
			  "dst_index %d, moved_items %u\n",
			  start_index, src_index,
			  dst_index, moved_items);
#endif /* CONFIG_SSDFS_DEBUG */
	} while (src_index >= (int)start_index);

	if (moved_items != range_len) {
		SSDFS_ERR("moved_items %u != range_len %u\n",
			  moved_items, range_len);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_shift_buffer_content_right() - shift buffer content right
 * @array: pointer on dynamic array object
 * @start_index: starting item index
 * @shift: shift value
 *
 * This method tries to shift range of items in array's content.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static inline
int ssdfs_shift_buffer_content_right(struct ssdfs_dynamic_array *array,
				     u32 start_index, u32 shift)
{
	u32 src_off, dst_off;
	u32 bytes_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, start_index %u, shift %u, "
		  "capacity %u, item_size %zu, bytes_count %u\n",
		  array, start_index, shift, array->capacity,
		  array->item_size, array->bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
		/* continue logic */
		break;

	default:
		SSDFS_WARN("unexpected state %#x\n", array->state);
		return -ERANGE;
	}

	src_off = start_index * array->item_size;
	dst_off = src_off + (shift * array->item_size);

	bytes_count = array->items_count - start_index;
	bytes_count *= array->item_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_index %u, shift %u, "
		  "src_off %u, dst_off %u, "
		  "bytes_count %u\n",
		  start_index, shift,
		  src_off, dst_off,
		  bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_memmove(array->buf, dst_off, array->bytes_count,
			    array->buf, src_off, array->bytes_count,
			    bytes_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move: src_off %u, dst_off %u, "
			  "bytes_count %u, array->bytes_count %u, "
			  "err %d\n",
			  src_off, dst_off,
			  bytes_count, array->bytes_count,
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_dynamic_array_shift_content_right() - shift content right
 * @array: pointer on dynamic array object
 * @start_index: starting item index
 * @shift: shift value
 *
 * This method tries to shift range of items in array's content.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-E2BIG      - request is out of array capacity.
 * %-ERANGE     - internal error.
 */
int ssdfs_dynamic_array_shift_content_right(struct ssdfs_dynamic_array *array,
					    u32 start_index, u32 shift)
{
	u64 max_threshold = (u64)ssdfs_folio_vector_max_threshold() * PAGE_SIZE;
	u32 item_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, start_index %u, shift %u, "
		  "capacity %u, item_size %zu, bytes_count %u\n",
		  array, start_index, shift, array->capacity,
		  array->item_size, array->bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC:
	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
		/* continue logic */
		break;

	default:
		SSDFS_WARN("unexpected state %#x\n", array->state);
		return -ERANGE;
	}

	if (array->item_size == 0 || array->item_size > PAGE_SIZE) {
		SSDFS_ERR("invalid item_size %zu\n",
			  array->item_size);
		return -ERANGE;
	}

	if (array->capacity == 0) {
		SSDFS_ERR("invalid capacity %u\n",
			  array->capacity);
		return -ERANGE;
	}

	if (array->bytes_count == 0) {
		SSDFS_ERR("invalid bytes_count %u\n",
			  array->bytes_count);
		return -ERANGE;
	}

	if (array->items_count > array->capacity) {
		SSDFS_ERR("corrupted array: "
			  "items_count %u > capacity %u\n",
			  array->items_count,
			  array->capacity);
		return -ERANGE;
	}

	if ((array->items_count + shift) > array->capacity) {
		SSDFS_ERR("invalid shift: items_count %u, "
			  "shift %u, capacity %u\n",
			  array->items_count, shift, array->capacity);
		return -ERANGE;
	}

	if ((start_index + shift) >= array->capacity) {
		SSDFS_ERR("invalid index: start_index %u, "
			  "shift %u, capacity %u\n",
			  start_index, shift, array->capacity);
		return -ERANGE;
	}

	item_offset = SSDFS_DYNAMIC_ARRAY_ITEM_OFFSET(array, start_index);

	if (item_offset >= max_threshold) {
		SSDFS_ERR("invalid item_offset: "
			  "start_index %u, item_size %zu, "
			  "item_offset %u, bytes_count %u, "
			  "max_threshold %llu\n",
			  start_index, array->item_size,
			  item_offset, array->bytes_count,
			  max_threshold);
		return -E2BIG;
	}

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC:
		err = ssdfs_shift_folio_vector_content_right(array,
							     start_index,
							     shift);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move: "
				  "start_index %u, shift %u, err %d\n",
				  start_index, shift, err);
			return err;
		}
		break;

	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
		err = ssdfs_shift_buffer_content_right(array,
							start_index,
							shift);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move: "
				  "start_index %u, shift %u, err %d\n",
				  start_index, shift, err);
			return err;
		}
		break;

	default:
		BUG();
		break;
	}

	array->items_count += shift;

	return 0;
}
