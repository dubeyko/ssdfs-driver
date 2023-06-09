// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dymanic_array.c - dynamic array implementation.
 *
 * Copyright (c) 2022-2023 Bytedance Ltd. and/or its affiliates.
 *              https://www.bytedance.com/
 * Copyright (c) 2022-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
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
#include "page_vector.h"
#include "ssdfs.h"
#include "dynamic_array.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_dynamic_array_page_leaks;
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
 * struct page *ssdfs_dynamic_array_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_dynamic_array_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_dynamic_array_free_page(struct page *page)
 * void ssdfs_dynamic_array_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(dynamic_array)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(dynamic_array)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_dynamic_array_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_dynamic_array_page_leaks, 0);
	atomic64_set(&ssdfs_dynamic_array_memory_leaks, 0);
	atomic64_set(&ssdfs_dynamic_array_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_dynamic_array_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_dynamic_array_page_leaks) != 0) {
		SSDFS_ERR("DYNAMIC ARRAY: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_dynamic_array_page_leaks));
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
	struct page *page;
	u64 max_threshold = (u64)ssdfs_page_vector_max_threshold() * PAGE_SIZE;
	u32 pages_count;
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
	array->items_per_mem_page = PAGE_SIZE / item_size;

	pages_count = capacity + array->items_per_mem_page - 1;
	pages_count /= array->items_per_mem_page;

	if (pages_count == 0)
		pages_count = 1;

	bytes_count = (u64)capacity * item_size;

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
		BUG_ON(pages_count >= ssdfs_page_vector_max_threshold());
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_page_vector_create(&array->pvec, pages_count);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create page vector: "
				  "bytes_count %llu, pages_count %u, "
				  "err %d\n",
				  bytes_count, pages_count, err);
			return err;
		}

		err = ssdfs_page_vector_init(&array->pvec);
		if (unlikely(err)) {
			ssdfs_page_vector_destroy(&array->pvec);
			SSDFS_ERR("fail to init page vector: "
				  "bytes_count %llu, pages_count %u, "
				  "err %d\n",
				  bytes_count, pages_count, err);
			return err;
		}

		page = ssdfs_page_vector_allocate(&array->pvec);
		if (IS_ERR_OR_NULL(page)) {
			err = (page == NULL ? -ENOMEM : PTR_ERR(page));
			SSDFS_ERR("unable to allocate page\n");
			return err;
		}

		ssdfs_lock_page(page);
		ssdfs_memset_page(page, 0, PAGE_SIZE,
				  array->alloc_pattern, PAGE_SIZE);
		ssdfs_unlock_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

		array->bytes_count = PAGE_SIZE;
		array->state = SSDFS_DYNAMIC_ARRAY_STORAGE_PAGE_VEC;
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
	case SSDFS_DYNAMIC_ARRAY_STORAGE_PAGE_VEC:
		ssdfs_page_vector_release(&array->pvec);
		ssdfs_page_vector_destroy(&array->pvec);
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
	array->items_per_mem_page = 0;
	array->bytes_count = 0;
	array->state = SSDFS_DYNAMIC_ARRAY_STORAGE_ABSENT;
}

/*
 * ssdfs_dynamic_array_get_locked() - get locked item
 * @array: pointer on dynamic array object
 * @index: item index
 *
 * This method tries to get pointer on item. If short buffer
 * (< 4K) represents dynamic array, then the logic is pretty
 * straitforward. Otherwise, memory page is locked. The release
 * method should be called to unlock memory page.
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
	struct page *page;
	void *ptr = NULL;
	u64 max_threshold = (u64)ssdfs_page_vector_max_threshold() * PAGE_SIZE;
	u64 item_offset = 0;
	u64 page_index;
	u32 page_off;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, index %u, capacity %u, "
		  "item_size %zu, bytes_count %u\n",
		  array, index, array->capacity,
		  array->item_size, array->bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_PAGE_VEC:
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

	item_offset = (u64)array->item_size * index;

	if (item_offset >= max_threshold) {
		SSDFS_ERR("invalid item_offset: "
			  "index %u, item_size %zu, "
			  "item_offset %llu, bytes_count %u, "
			  "max_threshold %llu\n",
			  index, array->item_size,
			  item_offset, array->bytes_count,
			  max_threshold);
		return ERR_PTR(-E2BIG);
	}

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_PAGE_VEC:
		page_index = index / array->items_per_mem_page;
		page_off = index % array->items_per_mem_page;
		page_off *= array->item_size;

		if (page_index >= ssdfs_page_vector_capacity(&array->pvec)) {
			SSDFS_ERR("invalid page index: "
				  "page_index %llu, item_offset %llu\n",
				  page_index, item_offset);
			return ERR_PTR(-E2BIG);
		}

		while (page_index >= ssdfs_page_vector_count(&array->pvec)) {
			page = ssdfs_page_vector_allocate(&array->pvec);
			if (IS_ERR_OR_NULL(page)) {
				err = (page == NULL ? -ENOMEM : PTR_ERR(page));
				SSDFS_ERR("unable to allocate page\n");
				return ERR_PTR(err);
			}

			ssdfs_lock_page(page);
			ssdfs_memset_page(page, 0, PAGE_SIZE,
					  array->alloc_pattern, PAGE_SIZE);
			ssdfs_unlock_page(page);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

			array->bytes_count += PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("array %p, index %u, capacity %u, "
					  "item_size %zu, bytes_count %u, "
					  "index %u, item_offset %llu, "
					  "page_index %llu, page_count %u\n",
					  array, index, array->capacity,
					  array->item_size, array->bytes_count,
					  index, item_offset, page_index,
					  ssdfs_page_vector_count(&array->pvec));
#endif /* CONFIG_SSDFS_DEBUG */
		}

		page = array->pvec.pages[page_index];

		ssdfs_lock_page(page);
		ptr = kmap_local_page(page);
		ptr = (u8 *)ptr + page_off;
		break;

	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
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
	struct page *page;
	void *ptr = NULL;
	u64 max_threshold = (u64)ssdfs_page_vector_max_threshold() * PAGE_SIZE;
	u64 item_offset = 0;
	u64 page_index;
	u32 page_off;
	u32 first_index_in_page;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, index %u, capacity %u, "
		  "item_size %zu, bytes_count %u\n",
		  array, index, array->capacity,
		  array->item_size, array->bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	*items_count = 0;

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_PAGE_VEC:
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

	item_offset = (u64)array->item_size * index;

	if (item_offset >= max_threshold) {
		SSDFS_ERR("invalid item_offset: "
			  "index %u, item_size %zu, "
			  "item_offset %llu, bytes_count %u, "
			  "max_threshold %llu\n",
			  index, array->item_size,
			  item_offset, array->bytes_count,
			  max_threshold);
		return ERR_PTR(-E2BIG);
	}

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_PAGE_VEC:
		page_index = index / array->items_per_mem_page;

		if (page_index >= ssdfs_page_vector_count(&array->pvec)) {
			SSDFS_ERR("invalid page index: "
				  "page_index %llu, item_offset %llu\n",
				  page_index, item_offset);
			return ERR_PTR(-E2BIG);
		}

		page = array->pvec.pages[page_index];

		first_index_in_page = index % array->items_per_mem_page;
		page_off = first_index_in_page * array->item_size;

		ssdfs_lock_page(page);
		ptr = kmap_local_page(page);
		ptr = (u8 *)ptr + page_off;

		*items_count = array->items_count - index;
		*items_count = min_t(u32, *items_count,
					array->items_per_mem_page -
						first_index_in_page);
		break;

	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
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
	struct page *page;
	u64 item_offset = 0;
	u64 page_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !ptr);

	SSDFS_DBG("array %p, index %u, capacity %u, "
		  "item_size %zu, bytes_count %u\n",
		  array, index, array->capacity,
		  array->item_size, array->bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_PAGE_VEC:
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

	item_offset = (u64)array->item_size * index;

	if (item_offset >= array->bytes_count) {
		SSDFS_ERR("invalid item_offset: "
			  "index %u, item_size %zu, "
			  "item_offset %llu, bytes_count %u\n",
			  index, array->item_size,
			  item_offset, array->bytes_count);
		return -E2BIG;
	}

	page_index = index / array->items_per_mem_page;

	if (page_index >= ssdfs_page_vector_count(&array->pvec)) {
		SSDFS_ERR("invalid page index: "
			  "page_index %llu, item_offset %llu\n",
			  page_index, item_offset);
		return -E2BIG;
	}

	page = array->pvec.pages[page_index];

	kunmap_local(ptr);
	ssdfs_unlock_page(page);

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
	struct page *page;
	void *kaddr = NULL;
	u64 max_threshold = (u64)ssdfs_page_vector_max_threshold() * PAGE_SIZE;
	u64 item_offset = 0;
	u64 page_index;
	u32 page_off;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !item);

	SSDFS_DBG("array %p, index %u, capacity %u, "
		  "item_size %zu, bytes_count %u\n",
		  array, index, array->capacity,
		  array->item_size, array->bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_PAGE_VEC:
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

	item_offset = (u64)array->item_size * index;

	if (item_offset >= max_threshold) {
		SSDFS_ERR("invalid item_offset: "
			  "index %u, item_size %zu, "
			  "item_offset %llu, bytes_count %u, "
			  "max_threshold %llu\n",
			  index, array->item_size,
			  item_offset, array->bytes_count,
			  max_threshold);
		return -E2BIG;
	}

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_PAGE_VEC:
		page_index = index / array->items_per_mem_page;
		page_off = index % array->items_per_mem_page;;
		page_off *= array->item_size;

		if (page_index >= ssdfs_page_vector_capacity(&array->pvec)) {
			SSDFS_ERR("invalid page index: "
				  "page_index %llu, item_offset %llu\n",
				  page_index, item_offset);
			return -E2BIG;
		}

		while (page_index >= ssdfs_page_vector_count(&array->pvec)) {
			page = ssdfs_page_vector_allocate(&array->pvec);
			if (IS_ERR_OR_NULL(page)) {
				err = (page == NULL ? -ENOMEM : PTR_ERR(page));
				SSDFS_ERR("unable to allocate page\n");
				return err;
			}

			ssdfs_lock_page(page);
			ssdfs_memset_page(page, 0, PAGE_SIZE,
					  array->alloc_pattern, PAGE_SIZE);
			ssdfs_unlock_page(page);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

			array->bytes_count += PAGE_SIZE;
		}

		page = array->pvec.pages[page_index];

		ssdfs_lock_page(page);
		kaddr = kmap_local_page(page);
		err = ssdfs_memcpy(kaddr, page_off, PAGE_SIZE,
				   item, 0, array->item_size,
				   array->item_size);
		kunmap_local(kaddr);
		ssdfs_unlock_page(page);
		break;

	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
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
	struct page *page;
	u32 copied_bytes = 0;
	u32 pages_count;
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
	case SSDFS_DYNAMIC_ARRAY_STORAGE_PAGE_VEC:
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
	case SSDFS_DYNAMIC_ARRAY_STORAGE_PAGE_VEC:
		pages_count = ssdfs_page_vector_count(&array->pvec);

		for (i = 0; i < pages_count; i++) {
			if (copied_bytes >= buf_size) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("stop copy: "
					  "copied_bytes %u, "
					  "buf_size %zu, "
					  "array->bytes_count %u, "
					  "pages_count %u\n",
					  copied_bytes,
					  buf_size,
					  array->bytes_count,
					  pages_count);
#endif /* CONFIG_SSDFS_DEBUG */
				break;
			}

			page = array->pvec.pages[i];

			if (!page) {
				err = -ERANGE;
				SSDFS_ERR("fail to copy content: "
					  "copied_bytes %u, "
					  "array->bytes_count %u, "
					  "page_index %d, "
					  "pages_count %u\n",
					  copied_bytes,
					  array->bytes_count,
					  i, pages_count);
				goto finish_copy_content;
			}

			items_count = i * array->items_per_mem_page;

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
					    array->items_per_mem_page);

			bytes_count = array->item_size * items_count;
			bytes_count = min_t(size_t, bytes_count,
						buf_size - copied_bytes);

			err = ssdfs_memcpy_from_page(copy_buf,
						     copied_bytes,
						     buf_size,
						     page,
						     0,
						     PAGE_SIZE,
						     bytes_count);
			if (unlikely(err)) {
				SSDFS_ERR("fail to copy content: "
					  "copied_bytes %u, "
					  "array->bytes_count %u, "
					  "page_index %d, "
					  "pages_count %u, "
					  "err %d\n",
					  copied_bytes,
					  array->bytes_count,
					  i, pages_count,
					  err);
				goto finish_copy_content;
			}

			copied_bytes += bytes_count;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("array %p, capacity %u, "
				  "item_size %zu, bytes_count %u, "
				  "page_index %d, pages_count %u, "
				  "bytes_count %zu, copied_bytes %u\n",
				  array, array->capacity,
				  array->item_size, array->bytes_count,
				  i, pages_count, bytes_count, copied_bytes);
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
 * ssdfs_shift_page_vector_content_right() - shift page vector content right
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
int ssdfs_shift_page_vector_content_right(struct ssdfs_dynamic_array *array,
					  u32 start_index, u32 shift)
{
	int page_index1, page_index2;
	int src_index, dst_index;
	struct page *page1, *page2;
	u32 item_offset1, item_offset2;
	void *kaddr;
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
	case SSDFS_DYNAMIC_ARRAY_STORAGE_PAGE_VEC:
		/* continue logic */
		break;

	default:
		SSDFS_WARN("unexpected state %#x\n", array->state);
		return -ERANGE;
	}

	vector_capacity = ssdfs_page_vector_capacity(&array->pvec);

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
		u32 offset_diff;
		u32 index_diff;
		int moving_items;
		u32 moving_bytes;

		page_index2 = dst_index / array->items_per_mem_page;
		if (page_index2 >= vector_capacity) {
			SSDFS_ERR("invalid page index: "
				  "page_index %d, capacity %u\n",
				  page_index2, vector_capacity);
			return -E2BIG;
		}

		while (page_index2 >= ssdfs_page_vector_count(&array->pvec)) {
			struct page *page;

			page = ssdfs_page_vector_allocate(&array->pvec);
			if (IS_ERR_OR_NULL(page)) {
				err = (page == NULL ? -ENOMEM : PTR_ERR(page));
				SSDFS_ERR("unable to allocate page\n");
				return err;
			}

			ssdfs_lock_page(page);
			ssdfs_memset_page(page, 0, PAGE_SIZE,
					  array->alloc_pattern, PAGE_SIZE);
			ssdfs_unlock_page(page);

			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));

			array->bytes_count += PAGE_SIZE;
		}

		item_offset2 = (u32)page_index2 * array->items_per_mem_page;
		index_diff = dst_index % array->items_per_mem_page;
		item_offset2 += index_diff * array->item_size;

		offset_diff = item_offset2 - (page_index2 * PAGE_SIZE);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(offset_diff % array->item_size);
#endif /* CONFIG_SSDFS_DEBUG */

		index_diff = offset_diff / array->item_size;
		index_diff++;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(index_diff >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		if (index_diff < shift) {
			/*
			 * The shift moves data out of the page.
			 * This is the reason that index_diff is
			 * lesser than shift. Keep the index_diff
			 * the same.
			 */
			SSDFS_DBG("index_diff %u, shift %u\n",
				  index_diff, shift);
		} else if (index_diff == shift) {
			/*
			 * It's the case when destination page
			 * has no items at all. Otherwise,
			 * it is the case of presence of free
			 * space in the begin of the page is equal
			 * to the @shift. This space was prepared
			 * by previous move operation. Simply,
			 * keep the index_diff the same.
			 */
			SSDFS_DBG("index_diff %u, shift %u\n",
				  index_diff, shift);
		} else {
			/*
			 * It needs to know the number of items
			 * from the page's beginning.
			 * So, excluding the shift from the account.
			 */
			index_diff -= shift;
		}

#ifdef CONFIG_SSDFS_DEBUG
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

		page_index1 = src_index / array->items_per_mem_page;
		item_offset1 = (u32)page_index1 * array->items_per_mem_page;
		index_diff = src_index % array->items_per_mem_page;
		item_offset1 += index_diff * array->item_size;

		page_index2 = dst_index / array->items_per_mem_page;
		item_offset2 = (u32)page_index2 * array->items_per_mem_page;
		index_diff = dst_index % array->items_per_mem_page;
		item_offset2 += index_diff * array->item_size;

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

		SSDFS_DBG("page_index1 %d, item_offset1 %u, "
			  "page_index2 %d, item_offset2 %u, "
			  "moving_bytes %u\n",
			  page_index1, item_offset1,
			  page_index2, item_offset2,
			  moving_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

		if (page_index1 != page_index2) {
			page1 = array->pvec.pages[page_index1];
			page2 = array->pvec.pages[page_index2];
			ssdfs_lock_page(page1);
			ssdfs_lock_page(page2);
			err = ssdfs_memmove_page(page2, item_offset2, PAGE_SIZE,
						 page1, item_offset1, PAGE_SIZE,
						 moving_bytes);
			ssdfs_unlock_page(page1);
			ssdfs_unlock_page(page2);

			if (unlikely(err)) {
				SSDFS_ERR("fail to move: err %d\n", err);
				return err;
			}
		} else {
			page1 = array->pvec.pages[page_index1];
			ssdfs_lock_page(page1);
			kaddr = kmap_local_page(page1);
			err = ssdfs_memmove(kaddr, item_offset2, PAGE_SIZE,
					    kaddr, item_offset1, PAGE_SIZE,
					    moving_bytes);
			flush_dcache_page(page1);
			kunmap_local(kaddr);
			ssdfs_unlock_page(page1);

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
	u64 max_threshold = (u64)ssdfs_page_vector_max_threshold() * PAGE_SIZE;
	u64 item_offset = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, start_index %u, shift %u, "
		  "capacity %u, item_size %zu, bytes_count %u\n",
		  array, start_index, shift, array->capacity,
		  array->item_size, array->bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_PAGE_VEC:
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

	if ((start_index + shift) >= array->capacity) {
		SSDFS_ERR("invalid index: start_index %u, "
			  "shift %u, capacity %u\n",
			  start_index, shift, array->capacity);
		return -ERANGE;
	}

	item_offset = (u64)array->item_size * start_index;

	if (item_offset >= max_threshold) {
		SSDFS_ERR("invalid item_offset: "
			  "start_index %u, item_size %zu, "
			  "item_offset %llu, bytes_count %u, "
			  "max_threshold %llu\n",
			  start_index, array->item_size,
			  item_offset, array->bytes_count,
			  max_threshold);
		return -E2BIG;
	}

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_PAGE_VEC:
		err = ssdfs_shift_page_vector_content_right(array,
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

	return 0;
}
