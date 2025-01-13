/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/folio_vector.h - folio vector's declarations.
 *
 * Copyright (c) 2023-2025 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_FOLIO_VECTOR_H
#define _SSDFS_FOLIO_VECTOR_H

/*
 * struct ssdfs_folio_vector - vector of memory folios
 * @count: current number of folios in vector
 * @capacity: max number of folios in vector
 * @order: allocation order of a particular sized block of memory
 * @folios: array of pointers on folios
 */
struct ssdfs_folio_vector {
	u32 count;
	u32 capacity;
	unsigned order;
	struct folio **folios;
};

/*
 * Inline functions
 */

/*
 * ssdfs_folio_vector_max_threshold() - maximum possible capacity
 */
static inline
u32 ssdfs_folio_vector_max_threshold(void)
{
	return S32_MAX;
}

/*
 * Folio vector's API
 */
int ssdfs_folio_vector_create(struct ssdfs_folio_vector *array,
			      unsigned order,
			      u32 capacity);
void ssdfs_folio_vector_destroy(struct ssdfs_folio_vector *array);
int ssdfs_folio_vector_init(struct ssdfs_folio_vector *array);
int ssdfs_folio_vector_reinit(struct ssdfs_folio_vector *array);
u32 ssdfs_folio_vector_count(struct ssdfs_folio_vector *array);
u32 ssdfs_folio_vector_space(struct ssdfs_folio_vector *array);
u32 ssdfs_folio_vector_capacity(struct ssdfs_folio_vector *array);
struct folio *ssdfs_folio_vector_allocate(struct ssdfs_folio_vector *array);
int ssdfs_folio_vector_add(struct ssdfs_folio_vector *array,
			   struct folio *folio);
struct folio *ssdfs_folio_vector_remove(struct ssdfs_folio_vector *array,
					u32 folio_index);
void ssdfs_folio_vector_release(struct ssdfs_folio_vector *array);

#endif /* _SSDFS_FOLIO_VECTOR_H */
