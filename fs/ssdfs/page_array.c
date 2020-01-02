//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/page_array.c - page array object's functionality.
 *
 * Copyright (c) 2014-2020 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2020, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "page_array.h"

/*
 * ssdfs_create_page_array() - create page array
 * @capacity: maximum number of pages in the array
 * @array: pointer of memory area for the array creation [out]
 *
 * This method tries to create the page array with @capacity
 * of maximum number of pages in the array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 */
int ssdfs_create_page_array(int capacity, struct ssdfs_page_array *array)
{
	void *addr[SSDFS_PAGE_ARRAY_BMAP_COUNT];
	size_t bmap_bytes;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
	BUG_ON(atomic_read(&array->state) != SSDFS_PAGE_ARRAY_UNKNOWN_STATE);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("capacity %d, array %p\n",
		  capacity, array);

	if (capacity == 0) {
		SSDFS_ERR("invalid capacity %d\n",
			  capacity);
		return -EINVAL;
	}

	init_rwsem(&array->lock);
	atomic_set(&array->pages_capacity, capacity);
	array->pages_count = 0;

	array->pages = kcalloc(capacity, sizeof(struct page *),
				GFP_KERNEL);
	if (!array->pages) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate memory: capacity %d\n",
			  capacity);
		goto finish_create_page_array;
	}

	bmap_bytes = capacity + BITS_PER_LONG;
	bmap_bytes /= BITS_PER_BYTE;
	array->bmap_bytes = bmap_bytes;

	for (i = 0; i < SSDFS_PAGE_ARRAY_BMAP_COUNT; i++) {
		spin_lock_init(&array->bmap[i].lock);
		array->bmap[i].ptr = NULL;
	}

	for (i = 0; i < SSDFS_PAGE_ARRAY_BMAP_COUNT; i++) {
		addr[i] = kmalloc(bmap_bytes, GFP_KERNEL);

		if (!addr[i]) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate bmap: index %d\n",
				  i);
			for (; i >= 0; i--)
				kfree(addr[i]);
			goto free_page_array;
		}

		memset(addr[i], 0xFF, bmap_bytes);
	}

	down_write(&array->lock);
	for (i = 0; i < SSDFS_PAGE_ARRAY_BMAP_COUNT; i++) {
		spin_lock(&array->bmap[i].lock);
		array->bmap[i].ptr = addr[i];
		addr[i] = NULL;
		spin_unlock(&array->bmap[i].lock);
	}
	up_write(&array->lock);

	atomic_set(&array->state, SSDFS_PAGE_ARRAY_CREATED);

	return 0;

free_page_array:
	kfree(array->pages);
	array->pages = NULL;

finish_create_page_array:
	return err;
}

/*
 * ssdfs_destroy_page_array() - destroy page array
 * @array: page array object
 *
 * This method tries to destroy the page array.
 */
void ssdfs_destroy_page_array(struct ssdfs_page_array *array)
{
	int state;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
	BUG_ON(rwsem_is_locked(&array->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, state %#x\n",
		  array,
		  atomic_read(&array->state));

	ssdfs_page_array_release_all_pages(array);

	state = atomic_xchg(&array->state, SSDFS_PAGE_ARRAY_UNKNOWN_STATE);

	switch (state) {
	case SSDFS_PAGE_ARRAY_CREATED:
		/* expected state */
		break;

	case SSDFS_PAGE_ARRAY_DIRTY:
		SSDFS_WARN("page array is dirty on destruction\n");
		break;

	default:
		SSDFS_WARN("unexpected state %#x of page array\n",
			  state);
		break;
	}

	atomic_set(&array->pages_capacity, 0);
	array->pages_count = 0;

	if (array->pages)
		kfree(array->pages);
	array->pages = NULL;

	array->bmap_bytes = 0;

	for (i = 0; i < SSDFS_PAGE_ARRAY_BMAP_COUNT; i++) {
		spin_lock(&array->bmap[i].lock);
		if (array->bmap[i].ptr)
			kfree(array->bmap[i].ptr);
		array->bmap[i].ptr = NULL;
		spin_unlock(&array->bmap[i].lock);
	}
}

/*
 * ssdfs_reinit_page_array() - change the capacity of the page array
 * @capacity: new value of the capacity
 * @array: pointer of memory area for the array creation
 *
 * This method tries to change the capacity of the page array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
int ssdfs_reinit_page_array(int capacity, struct ssdfs_page_array *array)
{
	struct page **pages;
	void *addr[SSDFS_PAGE_ARRAY_BMAP_COUNT];
	int old_capacity;
	size_t bmap_bytes;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, capacity %d, state %#x\n",
		  array, capacity,
		  atomic_read(&array->state));

	switch (atomic_read(&array->state)) {
	case SSDFS_PAGE_ARRAY_CREATED:
	case SSDFS_PAGE_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of page array\n",
			  atomic_read(&array->state));
		return -ERANGE;
	}

	old_capacity = atomic_read(&array->pages_capacity);

	if (capacity < old_capacity) {
		SSDFS_ERR("unable to shrink: "
			  "capacity %d, pages_capacity %d\n",
			  capacity,
			  old_capacity);
		return -EINVAL;
	}

	if (capacity == old_capacity) {
		SSDFS_WARN("capacity %d == pages_capacity %d\n",
			   capacity,
			   old_capacity);
		return 0;
	}

	down_write(&array->lock);

	atomic_set(&array->pages_capacity, capacity);

	pages = kcalloc(capacity, sizeof(struct page *),
			GFP_KERNEL);
	if (!pages) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate memory: capacity %d\n",
			  capacity);
		goto finish_reinit;
	}

	bmap_bytes = capacity + BITS_PER_LONG;
	bmap_bytes /= BITS_PER_BYTE;

	for (i = 0; i < SSDFS_PAGE_ARRAY_BMAP_COUNT; i++) {
		addr[i] = kmalloc(bmap_bytes, GFP_KERNEL);

		if (!addr[i]) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate bmap: index %d\n",
				  i);
			for (; i >= 0; i--)
				kfree(addr[i]);
			kfree(pages);
			goto finish_reinit;
		}

		memset(addr[i], 0xFF, bmap_bytes);
	}

	memcpy(pages, array->pages,
		sizeof(struct page *) * old_capacity);
	kfree(array->pages);
	array->pages = pages;

	for (i = 0; i < SSDFS_PAGE_ARRAY_BMAP_COUNT; i++) {
		spin_lock(&array->bmap[i].lock);
		memcpy(addr[i], array->bmap[i].ptr, array->bmap_bytes);
		kfree(array->bmap[i].ptr);
		array->bmap[i].ptr = addr[i];
		addr[i] = NULL;
		spin_unlock(&array->bmap[i].lock);
	}

	array->bmap_bytes = bmap_bytes;

finish_reinit:
	if (unlikely(err))
		atomic_set(&array->pages_capacity, old_capacity);

	up_write(&array->lock);

	return err;
}

/*
 * ssdfs_page_array_add_page() - add memory page into the page array
 * @array: page array object
 * @page: memory page
 * @page_index: index of the page in the page array
 *
 * This method tries to add a page into the page array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - page array contains the page for the index.
 */
int ssdfs_page_array_add_page(struct ssdfs_page_array *array,
			      struct page *page,
			      unsigned long page_index)
{
	struct ssdfs_page_array_bitmap *bmap;
	int capacity;
	unsigned long found;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !page);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, page %p, page_index %lu, state %#x\n",
		  array, page, page_index,
		  atomic_read(&array->state));

	switch (atomic_read(&array->state)) {
	case SSDFS_PAGE_ARRAY_CREATED:
	case SSDFS_PAGE_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of page array\n",
			  atomic_read(&array->state));
		return -ERANGE;
	}

	capacity = atomic_read(&array->pages_capacity);

	if (page_index >= capacity) {
		SSDFS_ERR("page_index %lu >= pages_capacity %d\n",
			  page_index,
			  capacity);
		return -EINVAL;
	}

	down_write(&array->lock);

	capacity = atomic_read(&array->pages_capacity);

	if (array->pages_count > capacity) {
		err = -ERANGE;
		SSDFS_ERR("corrupted page array: "
			  "pages_count %lu, pages_capacity %d\n",
			  array->pages_count,
			  capacity);
		goto finish_add_page;
	}

	if (array->pages_count == capacity) {
		err = -EEXIST;
		SSDFS_ERR("page %lu is allocated already\n",
			  page_index);
		goto finish_add_page;
	}

	bmap = &array->bmap[SSDFS_PAGE_ARRAY_ALLOC_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("bitmap is empty\n");
		goto finish_add_page;
	}

	spin_lock(&bmap->lock);
	found = bitmap_find_next_zero_area(bmap->ptr, capacity,
					   page_index, 1, 0);
	if (found == page_index) {
		/* page is allocated already */
		err = -EEXIST;
	} else
		bitmap_clear(bmap->ptr, page_index, 1);
	spin_unlock(&bmap->lock);

	if (err) {
		SSDFS_ERR("page %lu is allocated already\n",
			  page_index);
		goto finish_add_page;
	}

	if (array->pages[page_index]) {
		err = -ERANGE;
		SSDFS_WARN("position %lu contains page pointer\n",
			   page_index);
		goto finish_add_page;
	} else {
		get_page(page);
		array->pages[page_index] = page;
		page->index = page_index;
	}

	array->pages_count++;

finish_add_page:
	up_write(&array->lock);

	return err;
}

/*
 * ssdfs_page_array_allocate_page_locked() - allocate and add page
 * @array: page array object
 * @page_index: index of the page in the page array
 *
 * This method tries to allocate, to add into the page array and
 * to lock page.
 *
 * RETURN:
 * [success] - pointer on allocated and locked page.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - unable to allocate memory page.
 * %-EEXIST     - page array contains the page for the index.
 */
struct page *
ssdfs_page_array_allocate_page_locked(struct ssdfs_page_array *array,
				      unsigned long page_index)
{
	struct page *page;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, page_index %lu, state %#x\n",
		  array, page_index,
		  atomic_read(&array->state));

	switch (atomic_read(&array->state)) {
	case SSDFS_PAGE_ARRAY_CREATED:
	case SSDFS_PAGE_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of page array\n",
			  atomic_read(&array->state));
		return ERR_PTR(-ERANGE);
	}

	page = alloc_page(GFP_KERNEL | GFP_NOFS | __GFP_ZERO);
	if (unlikely(!page)) {
		SSDFS_ERR("unable to allocate memory page\n");
		return ERR_PTR(-ENOMEM);
	}

	err = ssdfs_page_array_add_page(array, page, page_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add page: "
			  "page_index %lu, err %d\n",
			  page_index, err);
		ssdfs_free_page(page);
		return ERR_PTR(err);
	}

	lock_page(page);
	return page;
}

/*
 * ssdfs_page_array_get_page() - get page unlocked
 * @array: page array object
 * @page_index: index of the page in the page array
 *
 * This method tries to find a page into the page array.
 *
 * RETURN:
 * [success] - pointer on page.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - no allocated page for the requested index.
 */
struct page *ssdfs_page_array_get_page(struct ssdfs_page_array *array,
					unsigned long page_index)
{
	struct page *page;
	struct ssdfs_page_array_bitmap *bmap;
	int capacity;
	unsigned long found;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, page_index %lu, state %#x\n",
		  array, page_index,
		  atomic_read(&array->state));

	switch (atomic_read(&array->state)) {
	case SSDFS_PAGE_ARRAY_CREATED:
	case SSDFS_PAGE_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of page array\n",
			  atomic_read(&array->state));
		return ERR_PTR(-ERANGE);
	}

	capacity = atomic_read(&array->pages_capacity);

	if (page_index >= capacity) {
		SSDFS_ERR("page_index %lu >= pages_capacity %d\n",
			  page_index,
			  capacity);
		return ERR_PTR(-EINVAL);
	}

	down_read(&array->lock);

	bmap = &array->bmap[SSDFS_PAGE_ARRAY_ALLOC_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("bitmap is empty\n");
		goto finish_get_page;
	}

	spin_lock(&bmap->lock);
	found = bitmap_find_next_zero_area(bmap->ptr, capacity,
					   page_index, 1, 0);
	if (found != page_index) {
		/* page is not allocated yet */
		err = -ENOENT;
	}
	spin_unlock(&bmap->lock);

	if (err) {
		SSDFS_DBG("page %lu is not allocated yet\n",
			  page_index);
		goto finish_get_page;
	}

	page = array->pages[page_index];

	if (!page) {
		err = -ERANGE;
		SSDFS_ERR("page pointer is NULL\n");
		goto finish_get_page;
	}

finish_get_page:
	up_read(&array->lock);

	if (unlikely(err))
		return ERR_PTR(err);

	get_page(page);
	return page;
}

/*
 * ssdfs_page_array_get_page_locked() - get page locked
 * @array: page array object
 * @page_index: index of the page in the page array
 *
 * This method tries to find and to lock a page into the
 * page array.
 *
 * RETURN:
 * [success] - pointer on locked page.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - no allocated page for the requested index.
 */
struct page *ssdfs_page_array_get_page_locked(struct ssdfs_page_array *array,
					      unsigned long page_index)
{
	struct page *page;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, page_index %lu, state %#x\n",
		  array, page_index,
		  atomic_read(&array->state));

	page = ssdfs_page_array_get_page(array, page_index);
	if (PTR_ERR(page) == -ENOENT) {
		SSDFS_DBG("page %lu is not allocated yet\n",
			  page_index);
	} else if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to get the page: "
			  "page_index %lu, err %d\n",
			  page_index, (int)PTR_ERR(page));
	} else
		lock_page(page);

	return page;
}

/*
 * ssdfs_page_array_grab_page() - get or add page locked
 * @array: page array object
 * @page_index: index of the page in the page array
 *
 * This method tries to find and to lock a page into the
 * page array. If no such page then to add and to lock
 * the page.
 *
 * RETURN:
 * [success] - pointer on locked page.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to add the page.
 */
struct page *ssdfs_page_array_grab_page(struct ssdfs_page_array *array,
					unsigned long page_index)
{
	struct page *page = ERR_PTR(-ENOMEM);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, page_index %lu, state %#x\n",
		  array, page_index,
		  atomic_read(&array->state));

	page = ssdfs_page_array_get_page_locked(array, page_index);
	if (PTR_ERR(page) == -ENOENT) {
		page = ssdfs_page_array_allocate_page_locked(array,
							     page_index);
		if (IS_ERR_OR_NULL(page)) {
			if (!page)
				page = ERR_PTR(-ENOMEM);

			SSDFS_ERR("fail to allocate the page: "
				  "page_index %lu, err %d\n",
				  page_index, (int)PTR_ERR(page));
		} else
			get_page(page);

	} else if (IS_ERR_OR_NULL(page)) {
		if (!page)
			page = ERR_PTR(-ENOMEM);

		SSDFS_ERR("fail to get page: "
			  "page_index %lu, err %d\n",
			  page_index, (int)PTR_ERR(page));
	}

	return page;
}

/*
 * ssdfs_page_array_set_page_dirty() - set page dirty
 * @array: page array object
 * @page_index: index of the page in the page array
 *
 * This method tries to set page as dirty in the page array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - no allocated page for the requested index.
 */
int ssdfs_page_array_set_page_dirty(struct ssdfs_page_array *array,
				    unsigned long page_index)
{
	struct page *page;
	struct ssdfs_page_array_bitmap *bmap;
	int capacity;
	unsigned long found;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, page_index %lu, state %#x\n",
		  array, page_index,
		  atomic_read(&array->state));

	switch (atomic_read(&array->state)) {
	case SSDFS_PAGE_ARRAY_CREATED:
	case SSDFS_PAGE_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of page array\n",
			  atomic_read(&array->state));
		return -ERANGE;
	}

	capacity = atomic_read(&array->pages_capacity);

	if (page_index >= capacity) {
		SSDFS_ERR("page_index %lu >= pages_capacity %d\n",
			  page_index,
			  capacity);
		return -EINVAL;
	}

	down_read(&array->lock);

	bmap = &array->bmap[SSDFS_PAGE_ARRAY_ALLOC_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("allocation bitmap is empty\n");
		goto finish_set_page_dirty;
	}

	spin_lock(&bmap->lock);
	found = bitmap_find_next_zero_area(bmap->ptr, capacity,
					   page_index, 1, 0);
	if (found != page_index) {
		/* page is not allocated yet */
		err = -ENOENT;
	}
	spin_unlock(&bmap->lock);

	if (err) {
		SSDFS_ERR("page %lu is not allocated yet\n",
			  page_index);
		goto finish_set_page_dirty;
	}

	bmap = &array->bmap[SSDFS_PAGE_ARRAY_DIRTY_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("dirty bitmap is empty\n");
		goto finish_set_page_dirty;
	}

	spin_lock(&bmap->lock);
	found = bitmap_find_next_zero_area(bmap->ptr, capacity,
					   page_index, 1, 0);
	if (found == page_index) {
		/* page is dirty already */
		err = -EEXIST;
	}
	bitmap_clear(bmap->ptr, page_index, 1);
	spin_unlock(&bmap->lock);

	if (err) {
		err = 0;
		SSDFS_DBG("page %lu is dirty already\n",
			  page_index);
	}

	page = array->pages[page_index];

	if (!page) {
		err = -ERANGE;
		SSDFS_ERR("page pointer is NULL\n");
		goto finish_set_page_dirty;
	}

	SetPageDirty(page);

	atomic_set(&array->state, SSDFS_PAGE_ARRAY_DIRTY);

finish_set_page_dirty:
	up_read(&array->lock);

	return err;
}

/*
 * ssdfs_page_array_clear_dirty_page() - set page as clean
 * @array: page array object
 * @page_index: index of the page in the page array
 *
 * This method tries to set page as clean in the page array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - no allocated page for the requested index.
 */
int ssdfs_page_array_clear_dirty_page(struct ssdfs_page_array *array,
				      unsigned long page_index)
{
	struct page *page;
	struct ssdfs_page_array_bitmap *bmap;
	int capacity;
	unsigned long found;
	bool is_clean = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, page_index %lu, state %#x\n",
		  array, page_index,
		  atomic_read(&array->state));

	switch (atomic_read(&array->state)) {
	case SSDFS_PAGE_ARRAY_CREATED:
	case SSDFS_PAGE_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of page array\n",
			  atomic_read(&array->state));
		return -ERANGE;
	}

	capacity = atomic_read(&array->pages_capacity);

	if (page_index >= capacity) {
		SSDFS_ERR("page_index %lu >= pages_capacity %d\n",
			  page_index,
			  capacity);
		return -EINVAL;
	}

	down_read(&array->lock);

	bmap = &array->bmap[SSDFS_PAGE_ARRAY_ALLOC_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("allocation bitmap is empty\n");
		goto finish_clear_page_dirty;
	}

	spin_lock(&bmap->lock);
	found = bitmap_find_next_zero_area(bmap->ptr, capacity,
					   page_index, 1, 0);
	if (found != page_index) {
		/* page is not allocated yet */
		err = -ENOENT;
	}
	spin_unlock(&bmap->lock);

	if (err) {
		SSDFS_ERR("page %lu is not allocated yet\n",
			  page_index);
		goto finish_clear_page_dirty;
	}

	bmap = &array->bmap[SSDFS_PAGE_ARRAY_DIRTY_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("dirty bitmap is empty\n");
		goto finish_clear_page_dirty;
	}

	spin_lock(&bmap->lock);
	bitmap_set(bmap->ptr, page_index, 1);
	is_clean = bitmap_full(bmap->ptr, capacity);
	spin_unlock(&bmap->lock);

	page = array->pages[page_index];

	if (!page) {
		err = -ERANGE;
		SSDFS_ERR("page pointer is NULL\n");
		goto finish_clear_page_dirty;
	}

	ClearPageDirty(page);

	if (is_clean)
		atomic_set(&array->state, SSDFS_PAGE_ARRAY_CREATED);

finish_clear_page_dirty:
	up_read(&array->lock);

	return err;
}

/*
 * ssdfs_page_array_clear_dirty_range() - clear dirty pages in the range
 * @array: page array object
 * @start: starting index
 * @end: ending index (inclusive)
 *
 * This method tries to set the range's dirty pages as clean
 * in the page array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_page_array_clear_dirty_range(struct ssdfs_page_array *array,
					unsigned long start,
					unsigned long end)
{
	struct page *page;
	struct ssdfs_page_array_bitmap *bmap;
	int capacity;
	bool is_clean = false;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, start %lu, end %lu, state %#x\n",
		  array, start, end,
		  atomic_read(&array->state));

	switch (atomic_read(&array->state)) {
	case SSDFS_PAGE_ARRAY_CREATED:
		SSDFS_DBG("no dirty pages in page array\n");
		return 0;

	case SSDFS_PAGE_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of page array\n",
			  atomic_read(&array->state));
		return -ERANGE;
	}

	if (start > end) {
		SSDFS_ERR("start %lu > end %lu\n",
			  start, end);
		return -EINVAL;
	}

	down_write(&array->lock);

	capacity = atomic_read(&array->pages_capacity);

	bmap = &array->bmap[SSDFS_PAGE_ARRAY_DIRTY_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("dirty bitmap is empty\n");
		goto finish_clear_dirty_pages;
	}

	end = min_t(int, capacity, end + 1);

	for (i = start; i < end; i++) {
		page = array->pages[i];

		if (page)
			ClearPageDirty(page);
	}

	spin_lock(&bmap->lock);
	bitmap_set(bmap->ptr, start, end - start);
	is_clean = bitmap_full(bmap->ptr, capacity);
	spin_unlock(&bmap->lock);

	if (is_clean)
		atomic_set(&array->state, SSDFS_PAGE_ARRAY_CREATED);

finish_clear_dirty_pages:
	up_write(&array->lock);

	return err;
}

/*
 * ssdfs_page_array_clear_all_dirty_pages() - clear all dirty pages
 * @array: page array object
 *
 * This method tries to set all dirty pages as clean in the page array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_page_array_clear_all_dirty_pages(struct ssdfs_page_array *array)
{
	int capacity;
	unsigned long start = 0, end = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, state %#x\n",
		  array,
		  atomic_read(&array->state));

	capacity = atomic_read(&array->pages_capacity);

	if (capacity > 0)
		end = capacity - 1;

	return ssdfs_page_array_clear_dirty_range(array, start, end);
}

/*
 * ssdfs_page_array_lookup_range() - find pages for a requested tag
 * @array: page array object
 * @start: pointer on start index value [in|out]
 * @end: ending index (inclusive)
 * @tag: tag value for the search
 * @max_pages: maximum number of pages in the pagevec
 * @pvec: pagevec for storing found pages [out]
 *
 * This method tries to find pages in the page array for
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
int ssdfs_page_array_lookup_range(struct ssdfs_page_array *array,
				  unsigned long *start,
				  unsigned long end,
				  int tag, int max_pages,
				  struct pagevec *pvec)
{
	int state;
	struct page *page;
	struct ssdfs_page_array_bitmap *bmap;
	int capacity;
	unsigned long found;
	int count = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !start || !pvec);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&array->state);

	SSDFS_DBG("array %p, start %lu, end %lu, "
		  "tag %#x, max_pages %d, state %#x\n",
		  array, *start, end, tag, max_pages, state);

	switch (state) {
	case SSDFS_PAGE_ARRAY_CREATED:
	case SSDFS_PAGE_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of page array\n",
			   state);
		return -ERANGE;
	}

	pagevec_reinit(pvec);

	if (*start > end) {
		SSDFS_ERR("start %lu > end %lu\n",
			  *start, end);
		return -EINVAL;
	}

	switch (tag) {
	case SSDFS_DIRTY_PAGE_TAG:
		if (state != SSDFS_PAGE_ARRAY_DIRTY) {
			SSDFS_DBG("page array is clean\n");
			return -ENOENT;
		}
		break;

	default:
		SSDFS_ERR("unknown tag %#x\n",
			  tag);
		return -EINVAL;
	}

	max_pages = min_t(int, max_pages, (int)PAGEVEC_SIZE);

	down_read(&array->lock);

	capacity = atomic_read(&array->pages_capacity);
	if (capacity <= 0) {
		err = -ERANGE;
		SSDFS_ERR("invalid capacity %d\n", capacity);
		goto finish_search;
	}

	bmap = &array->bmap[SSDFS_PAGE_ARRAY_DIRTY_BMAP];
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
		page = array->pages[found];

		if (page) {
			if (!PageDirty(page)) {
				SSDFS_ERR("page %lu is not dirty\n",
					  page_index(page));
			}
			pagevec_add(pvec, page);
			count++;
		}

		if (count >= max_pages)
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
 * ssdfs_page_array_delete_page() - delete page from the page array
 * @array: page array object
 * @page_index: index of the page
 *
 * This method tries to delete a page from the page array.
 *
 * RETURN:
 * [success] - pointer on deleted page.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - page array hasn't a page for the index.
 */
struct page *ssdfs_page_array_delete_page(struct ssdfs_page_array *array,
					  unsigned long page_index)
{
	struct page *page;
	struct ssdfs_page_array_bitmap *alloc_bmap, *dirty_bmap;
	int capacity;
	unsigned long found;
	bool is_clean = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, page_index %lu, state %#x\n",
		  array, page_index,
		  atomic_read(&array->state));

	switch (atomic_read(&array->state)) {
	case SSDFS_PAGE_ARRAY_CREATED:
	case SSDFS_PAGE_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of page array\n",
			  atomic_read(&array->state));
		return ERR_PTR(-ERANGE);
	}

	capacity = atomic_read(&array->pages_capacity);

	if (page_index >= capacity) {
		SSDFS_ERR("page_index %lu >= pages_capacity %d\n",
			  page_index,
			  capacity);
		return ERR_PTR(-EINVAL);
	}

	down_write(&array->lock);

	alloc_bmap = &array->bmap[SSDFS_PAGE_ARRAY_ALLOC_BMAP];
	if (!alloc_bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("alloc bitmap is empty\n");
		goto finish_delete_page;
	}

	dirty_bmap = &array->bmap[SSDFS_PAGE_ARRAY_DIRTY_BMAP];
	if (!dirty_bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("dirty bitmap is empty\n");
		goto finish_delete_page;
	}

	spin_lock(&alloc_bmap->lock);
	found = bitmap_find_next_zero_area(alloc_bmap->ptr, capacity,
					   page_index, 1, 0);
	if (found != page_index) {
		/* page is not allocated yet */
		err = -ENOENT;
	}
	spin_unlock(&alloc_bmap->lock);

	if (err) {
		SSDFS_ERR("page %lu is not allocated yet\n",
			  page_index);
		goto finish_delete_page;
	}

	page = array->pages[page_index];

	if (!page) {
		err = -ERANGE;
		SSDFS_ERR("page pointer is NULL\n");
		goto finish_delete_page;
	}

	spin_lock(&alloc_bmap->lock);
	bitmap_set(alloc_bmap->ptr, page_index, 1);
	spin_unlock(&alloc_bmap->lock);

	spin_lock(&dirty_bmap->lock);
	bitmap_set(dirty_bmap->ptr, page_index, 1);
	is_clean = bitmap_full(dirty_bmap->ptr, capacity);
	spin_unlock(&dirty_bmap->lock);

	array->pages_count--;
	array->pages[page_index] = NULL;

	if (is_clean)
		atomic_set(&array->state, SSDFS_PAGE_ARRAY_CREATED);

finish_delete_page:
	up_write(&array->lock);

	if (unlikely(err))
		return ERR_PTR(err);

	put_page(page);
	return page;
}

/*
 * ssdfs_page_array_release_pages() - release pages in the range
 * @array: page array object
 * @start: pointer on start index value [in|out]
 * @end: ending index (inclusive)
 *
 * This method tries to release pages for the requested range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_page_array_release_pages(struct ssdfs_page_array *array,
				   unsigned long *start,
				   unsigned long end)
{
	struct page *page;
	struct ssdfs_page_array_bitmap *alloc_bmap, *dirty_bmap;
	int capacity;
	unsigned long found, found_dirty;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !start);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, start %lu, end %lu, state %#x\n",
		  array, *start, end,
		  atomic_read(&array->state));

	switch (atomic_read(&array->state)) {
	case SSDFS_PAGE_ARRAY_CREATED:
	case SSDFS_PAGE_ARRAY_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected state %#x of page array\n",
			   atomic_read(&array->state));
		return -ERANGE;
	}

	if (*start > end) {
		SSDFS_ERR("start %lu > end %lu\n",
			  *start, end);
		return -EINVAL;
	}

	down_write(&array->lock);

	capacity = atomic_read(&array->pages_capacity);
	if (capacity <= 0) {
		err = -ERANGE;
		SSDFS_ERR("invalid capacity %d\n", capacity);
		goto finish_release_pages_range;
	}

	if (array->pages_count == 0) {
		err = 0;
		SSDFS_DBG("pages_count %lu\n",
			  array->pages_count);
		goto finish_release_pages_range;
	}

	alloc_bmap = &array->bmap[SSDFS_PAGE_ARRAY_ALLOC_BMAP];
	if (!alloc_bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("allocation bitmap is empty\n");
		goto finish_release_pages_range;
	}

	dirty_bmap = &array->bmap[SSDFS_PAGE_ARRAY_DIRTY_BMAP];
	if (!dirty_bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("dirty bitmap is empty\n");
		goto finish_release_pages_range;
	}

	spin_lock(&alloc_bmap->lock);
	found = bitmap_find_next_zero_area(alloc_bmap->ptr, capacity,
					   *start, 1, 0);
	spin_unlock(&alloc_bmap->lock);

	end = min_t(int, capacity - 1, end);

	*start = (int)found;

	while (found <= end) {
		spin_lock(&dirty_bmap->lock);
		found_dirty = bitmap_find_next_zero_area(dirty_bmap->ptr,
							 capacity,
						         found, 1, 0);
		spin_unlock(&dirty_bmap->lock);

		if (found == found_dirty) {
			err = -ERANGE;
			SSDFS_ERR("page %lu is dirty\n",
				  found);
			goto finish_release_pages_range;
		}

		page = array->pages[found];

		if (page) {
			ssdfs_free_page(page);
			array->pages[found] = NULL;
		}

		spin_lock(&alloc_bmap->lock);
		bitmap_set(alloc_bmap->ptr, found, 1);
		spin_unlock(&alloc_bmap->lock);

		array->pages_count--;

		found++;

		if (found >= capacity)
			break;

		spin_lock(&alloc_bmap->lock);
		found = bitmap_find_next_zero_area(alloc_bmap->ptr,
						   capacity,
						   found, 1, 0);
		spin_unlock(&alloc_bmap->lock);
	};

finish_release_pages_range:
	up_write(&array->lock);

	return err;
}

/*
 * ssdfs_page_array_release_all_pages() - release all pages
 * @array: page array object
 *
 * This method tries to release all pages in the page array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_page_array_release_all_pages(struct ssdfs_page_array *array)
{
	int capacity;
	unsigned long start = 0, end = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, state %#x\n",
		  array,
		  atomic_read(&array->state));

	capacity = atomic_read(&array->pages_capacity);

	if (capacity > 0)
		end = capacity - 1;

	return ssdfs_page_array_release_pages(array, &start, end);
}
