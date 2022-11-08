//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dymanic_array.c - dynamic array implementation.
 *
 * Copyright (c) 2022 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
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
	u64 max_threshold = (u64)ssdfs_page_vector_max_threshold() * PAGE_SIZE;
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
	array->item_size = item_size;

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
		u64 pages_count = (bytes_count + PAGE_SIZE - 1) / PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(pages_count >= ssdfs_page_vector_max_threshold());
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_page_vector_create(&array->pvec, (u32)pages_count);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create page vector: "
				  "bytes_count %llu, pages_count %llu, "
				  "err %d\n",
				  bytes_count, pages_count, err);
			return err;
		}

		err = ssdfs_page_vector_init(&array->pvec);
		if (unlikely(err)) {
			ssdfs_page_vector_destroy(&array->pvec);
			SSDFS_ERR("fail to init page vector: "
				  "bytes_count %llu, pages_count %llu, "
				  "err %d\n",
				  bytes_count, pages_count, err);
			return err;
		}

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
	array->item_size = 0;
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
		SSDFS_ERR("invalid index: index %u, capacity %u\n",
			  index, array->capacity);
		return ERR_PTR(-ERANGE);
	}

	item_offset = (u64)array->item_size * index;

	if (item_offset >= array->bytes_count) {
		SSDFS_ERR("invalid item_offset: "
			  "index %u, item_size %zu, "
			  "item_offset %llu, bytes_count %u\n",
			  index, array->item_size,
			  item_offset, array->bytes_count);
		return ERR_PTR(-E2BIG);
	}

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_PAGE_VEC:
		page_index = item_offset / PAGE_SIZE;
		page_off = item_offset % PAGE_SIZE;

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

			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));

			array->bytes_count += PAGE_SIZE;
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

	page_index = item_offset / PAGE_SIZE;

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

	if (item_offset >= array->bytes_count) {
		SSDFS_ERR("invalid item_offset: "
			  "index %u, item_size %zu, "
			  "item_offset %llu, bytes_count %u\n",
			  index, array->item_size,
			  item_offset, array->bytes_count);
		return -E2BIG;
	}

	switch (array->state) {
	case SSDFS_DYNAMIC_ARRAY_STORAGE_PAGE_VEC:
		page_index = item_offset / PAGE_SIZE;
		page_off = item_offset % PAGE_SIZE;

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

			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));

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
	}

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
			size_t bytes_count;

			if (copied_bytes >= buf_size) {
				SSDFS_DBG("stop copy: "
					  "copied_bytes %u, "
					  "buf_size %zu, "
					  "array->bytes_count %u, "
					  "pages_count %u\n",
					  copied_bytes,
					  buf_size,
					  array->bytes_count,
					  pages_count);
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

			bytes_count = min_t(size_t, (size_t)PAGE_SIZE,
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
		}
		break;

	case SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER:
		err = ssdfs_memcpy(copy_buf, 0, buf_size,
				   array->buf, 0, array->bytes_count,
				   array->bytes_count);
		break;

	default:
		BUG();
		break;
	}

finish_copy_content:
	return err;
}
