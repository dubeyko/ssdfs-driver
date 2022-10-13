//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/page_vector.c - page vector implementation.
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
#include "page_vector.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_page_vector_page_leaks;
atomic64_t ssdfs_page_vector_memory_leaks;
atomic64_t ssdfs_page_vector_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_page_vector_cache_leaks_increment(void *kaddr)
 * void ssdfs_page_vector_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_page_vector_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_page_vector_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_page_vector_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_page_vector_kfree(void *kaddr)
 * struct page *ssdfs_page_vector_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_page_vector_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_page_vector_free_page(struct page *page)
 * void ssdfs_page_vector_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(page_vector)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(page_vector)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_page_vector_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_page_vector_page_leaks, 0);
	atomic64_set(&ssdfs_page_vector_memory_leaks, 0);
	atomic64_set(&ssdfs_page_vector_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_page_vector_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_page_vector_page_leaks) != 0) {
		SSDFS_ERR("PAGE VECTOR: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_page_vector_page_leaks));
	}

	if (atomic64_read(&ssdfs_page_vector_memory_leaks) != 0) {
		SSDFS_ERR("PAGE VECTOR: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_page_vector_memory_leaks));
	}

	if (atomic64_read(&ssdfs_page_vector_cache_leaks) != 0) {
		SSDFS_ERR("PAGE VECTOR: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_page_vector_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * ssdfs_page_vector_create() - create page vector
 * @array: pointer on page vector
 * @capacity: max number of memory pages in vector
 */
int ssdfs_page_vector_create(struct ssdfs_page_vector *array,
			     u8 capacity)
{
	size_t size = sizeof(struct page *);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	array->count = 0;
	array->capacity = 0;

	size *= capacity;
	array->pages = ssdfs_page_vector_kzalloc(size, GFP_KERNEL);
	if (!array->pages) {
		SSDFS_ERR("fail to allocate memory: size %zu\n",
			  size);
		return -ENOMEM;
	}

	array->capacity = capacity;

	return 0;
}

/*
 * ssdfs_page_vector_destroy() - destroy page vector
 * @array: pointer on page vector
 */
void ssdfs_page_vector_destroy(struct ssdfs_page_vector *array)
{
#ifdef CONFIG_SSDFS_DEBUG
	int i;

	BUG_ON(!array);

	if (array->count > 0) {
		SSDFS_ERR("invalid state: count %u\n",
			  array->count);
	}

	for (i = 0; i < array->capacity; i++) {
		struct page *page = array->pages[i];

		if (page)
			SSDFS_ERR("page %d is not released\n", i);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	array->count = 0;

	if (array->pages) {
#ifdef CONFIG_SSDFS_DEBUG
		if (array->capacity == 0) {
			SSDFS_ERR("invalid state: capacity %u\n",
				  array->capacity);
		}
#endif /* CONFIG_SSDFS_DEBUG */

		array->capacity = 0;
		ssdfs_page_vector_kfree(array->pages);
		array->pages = NULL;
	}
}

/*
 * ssdfs_page_vector_init() - init page vector
 * @array: pointer on page vector
 */
int ssdfs_page_vector_init(struct ssdfs_page_vector *array)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	if (!array->pages) {
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
		memset(array->pages, 0,
			sizeof(struct page *) * array->capacity);
	}

	return 0;
}

/*
 * ssdfs_page_vector_reinit() - reinit page vector
 * @array: pointer on page vector
 */
int ssdfs_page_vector_reinit(struct ssdfs_page_vector *array)
{
#ifdef CONFIG_SSDFS_DEBUG
	int i;

	BUG_ON(!array);

	if (!array->pages) {
		SSDFS_ERR("fail to reinit\n");
		return -ERANGE;
	}

	for (i = 0; i < array->capacity; i++) {
		struct page *page = array->pages[i];

		if (page)
			SSDFS_WARN("page %d is not released\n", i);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	array->count = 0;

	if (array->capacity == 0) {
		SSDFS_ERR("invalid state: capacity %u\n",
			  array->capacity);
		return -ERANGE;
	} else {
		memset(array->pages, 0,
			sizeof(struct page *) * array->capacity);
	}

	return 0;
}

/*
 * ssdfs_page_vector_count() - count of paged in page vector
 * @array: pointer on page vector
 */
u32 ssdfs_page_vector_count(struct ssdfs_page_vector *array)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	return array->count;
}

/*
 * ssdfs_page_vector_space() - free space in page vector
 * @array: pointer on page vector
 */
u32 ssdfs_page_vector_space(struct ssdfs_page_vector *array)
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
 * ssdfs_page_vector_add() - add page in page vector
 * @array: pointer on page vector
 * @page: memory page
 */
int ssdfs_page_vector_add(struct ssdfs_page_vector *array,
			  struct page *page)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !page);

	if (array->count >= array->capacity) {
		SSDFS_ERR("array is full: count %u\n",
			  array->count);
		return -ENOSPC;
	}

	if (!array->pages) {
		SSDFS_ERR("fail to add page: "
			  "count %u, capacity %u\n",
			  array->count, array->capacity);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	array->pages[array->count] = page;
	array->count++;

	ssdfs_page_vector_account_page(page);

	return 0;
}

/*
 * ssdfs_page_vector_allocate() - allocate + add page
 * @array: pointer on page vector
 */
struct page *ssdfs_page_vector_allocate(struct ssdfs_page_vector *array)
{
	struct page *page;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	if (ssdfs_page_vector_space(array) == 0) {
		SSDFS_ERR("page vector hasn't space\n");
		return ERR_PTR(-E2BIG);
	}

	page = ssdfs_page_vector_alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (IS_ERR_OR_NULL(page)) {
		err = (page == NULL ? -ENOMEM : PTR_ERR(page));
		SSDFS_ERR("unable to allocate memory page\n");
		return ERR_PTR(err);
	}

	/*
	 * ssdfs_page_vector_add() accounts page
	 */
	ssdfs_page_vector_forget_page(page);

	err = ssdfs_page_vector_add(array, page);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add page: err %d\n",
			  err);
		ssdfs_free_page(page);
		return ERR_PTR(err);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("array %p, page vector count %u\n",
		  array->pages, ssdfs_page_vector_count(array));
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
	SSDFS_DBG("page %p, allocated_pages %lld\n",
		  page, atomic64_read(&ssdfs_page_vector_page_leaks));
#endif /* CONFIG_SSDFS_DEBUG */

	return page;
}

/*
 * ssdfs_page_vector_remove() - remove page
 * @array: pointer on page vector
 * @page_index: index of the page
 */
struct page *ssdfs_page_vector_remove(struct ssdfs_page_vector *array,
				      u8 page_index)
{
	struct page *page;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	if (ssdfs_page_vector_count(array) == 0) {
		SSDFS_ERR("page vector is empty\n");
		return ERR_PTR(-ENODATA);
	}

	if (array->count > array->capacity) {
		SSDFS_ERR("page vector is corrupted: "
			  "array->count %u, array->capacity %u\n",
			  array->count, array->capacity);
		return ERR_PTR(-ERANGE);
	}

	if (page_index >= array->count) {
		SSDFS_ERR("page index is out of range: "
			  "page_index %u, array->count %u\n",
			  page_index, array->count);
		return ERR_PTR(-ENOENT);
	}

	page = array->pages[page_index];

	if (!page) {
		SSDFS_ERR("page index is absent: "
			  "page_index %u, array->count %u\n",
			  page_index, array->count);
		return ERR_PTR(-ENOENT);
	}

	ssdfs_page_vector_forget_page(page);
	array->pages[page_index] = NULL;

	return page;
}

/*
 * ssdfs_page_vector_release() - release pages from page vector
 * @array: pointer on page vector
 */
void ssdfs_page_vector_release(struct ssdfs_page_vector *array)
{
	struct page *page;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	if (!array->pages) {
		SSDFS_ERR("fail to release: "
			  "count %u, capacity %u\n",
			  array->count, array->capacity);
		return;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < ssdfs_page_vector_count(array); i++) {
		page = array->pages[i];

		if (!page)
			continue;

		ssdfs_page_vector_free_page(page);
		array->pages[i] = NULL;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, allocated_pages %lld\n",
			  page,
			  atomic64_read(&ssdfs_page_vector_page_leaks));
#endif /* CONFIG_SSDFS_DEBUG */
	}

	ssdfs_page_vector_reinit(array);
}
