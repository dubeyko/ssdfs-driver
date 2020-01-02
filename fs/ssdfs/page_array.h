//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/page_array.h - page array object declarations.
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

#ifndef _SSDFS_PAGE_ARRAY_H
#define _SSDFS_PAGE_ARRAY_H

/*
 * struct ssdfs_page_array_bitmap - bitmap of states
 * @lock: bitmap lock
 * @ptr: bitmap
 */
struct ssdfs_page_array_bitmap {
	spinlock_t lock;
	unsigned long *ptr;
};

/*
 * struct ssdfs_page_array - array of memory pages
 * @state: page array's state
 * @pages_capacity: maximum possible number of pages in array
 * @lock: page array's lock
 * @pages: array of memory pages' pointers
 * @pages_count: current number of allocated pages
 * @bmap_bytes: number of bytes in every bitmap
 * bmap: array of bitmaps
 */
struct ssdfs_page_array {
	atomic_t state;
	atomic_t pages_capacity;

	struct rw_semaphore lock;
	struct page **pages;
	unsigned long pages_count;
	size_t bmap_bytes;

#define SSDFS_PAGE_ARRAY_ALLOC_BMAP	(0)
#define SSDFS_PAGE_ARRAY_DIRTY_BMAP	(1)
#define SSDFS_PAGE_ARRAY_BMAP_COUNT	(2)
	struct ssdfs_page_array_bitmap bmap[SSDFS_PAGE_ARRAY_BMAP_COUNT];
};

/* Page array states */
enum {
	SSDFS_PAGE_ARRAY_UNKNOWN_STATE,
	SSDFS_PAGE_ARRAY_CREATED,
	SSDFS_PAGE_ARRAY_DIRTY,
	SSDFS_PAGE_ARRAY_STATE_MAX
};

/* Available tags */
enum {
	SSDFS_UNKNOWN_PAGE_TAG,
	SSDFS_DIRTY_PAGE_TAG,
	SSDFS_PAGE_TAG_MAX
};

/*
 * Page array's API
 */
int ssdfs_create_page_array(int capacity, struct ssdfs_page_array *array);
void ssdfs_destroy_page_array(struct ssdfs_page_array *array);
int ssdfs_reinit_page_array(int capacity, struct ssdfs_page_array *array);
int ssdfs_page_array_add_page(struct ssdfs_page_array *array,
			      struct page *page,
			      unsigned long page_index);
struct page *
ssdfs_page_array_allocate_page_locked(struct ssdfs_page_array *array,
				      unsigned long page_index);
struct page *ssdfs_page_array_get_page_locked(struct ssdfs_page_array *array,
					      unsigned long page_index);
struct page *ssdfs_page_array_get_page(struct ssdfs_page_array *array,
					unsigned long page_index);
struct page *ssdfs_page_array_grab_page(struct ssdfs_page_array *array,
					unsigned long page_index);
int ssdfs_page_array_set_page_dirty(struct ssdfs_page_array *array,
				    unsigned long page_index);
int ssdfs_page_array_clear_dirty_page(struct ssdfs_page_array *array,
				      unsigned long page_index);
int ssdfs_page_array_clear_dirty_range(struct ssdfs_page_array *array,
					unsigned long start,
					unsigned long end);
int ssdfs_page_array_clear_all_dirty_pages(struct ssdfs_page_array *array);
int ssdfs_page_array_lookup_range(struct ssdfs_page_array *array,
				  unsigned long *start,
				  unsigned long end,
				  int tag, int max_pages,
				  struct pagevec *pvec);
struct page *ssdfs_page_array_delete_page(struct ssdfs_page_array *array,
					  unsigned long page_index);
int ssdfs_page_array_release_pages(struct ssdfs_page_array *array,
				   unsigned long *start,
				   unsigned long end);
int ssdfs_page_array_release_all_pages(struct ssdfs_page_array *array);

#endif /* _SSDFS_PAGE_ARRAY_H */
