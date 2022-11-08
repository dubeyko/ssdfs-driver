//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/page_vector.h - page vector's declarations.
 *
 * Copyright (c) 2022 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_PAGE_VECTOR_H
#define _SSDFS_PAGE_VECTOR_H

/*
 * struct ssdfs_page_vector - vector of memory pages
 * @count: current number of pages in vector
 * @capacity: max number of pages in vector
 * @pages: array of pointers on pages
 */
struct ssdfs_page_vector {
	u32 count;
	u32 capacity;
	struct page **pages;
};

/*
 * Inline functions
 */

/*
 * ssdfs_page_vector_max_threshold() - maximum possible capacity
 */
static inline
u32 ssdfs_page_vector_max_threshold(void)
{
	return S32_MAX;
}

/*
 * Page vector's API
 */
int ssdfs_page_vector_create(struct ssdfs_page_vector *array,
			     u32 capacity);
void ssdfs_page_vector_destroy(struct ssdfs_page_vector *array);
int ssdfs_page_vector_init(struct ssdfs_page_vector *array);
int ssdfs_page_vector_reinit(struct ssdfs_page_vector *array);
u32 ssdfs_page_vector_count(struct ssdfs_page_vector *array);
u32 ssdfs_page_vector_space(struct ssdfs_page_vector *array);
u32 ssdfs_page_vector_capacity(struct ssdfs_page_vector *array);
struct page *ssdfs_page_vector_allocate(struct ssdfs_page_vector *array);
int ssdfs_page_vector_add(struct ssdfs_page_vector *array,
			  struct page *page);
struct page *ssdfs_page_vector_remove(struct ssdfs_page_vector *array,
				      u32 page_index);
void ssdfs_page_vector_release(struct ssdfs_page_vector *array);

#endif /* _SSDFS_PAGE_VECTOR_H */
