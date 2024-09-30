/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/folio_array.h - folio array object declarations.
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

#ifndef _SSDFS_FOLIO_ARRAY_H
#define _SSDFS_FOLIO_ARRAY_H

/*
 * struct ssdfs_folio_array_bitmap - bitmap of states
 * @lock: bitmap lock
 * @ptr: bitmap
 */
struct ssdfs_folio_array_bitmap {
	spinlock_t lock;
	unsigned long *ptr;
};

/*
 * struct ssdfs_folio_array - array of memory folios
 * @state: folio array's state
 * @folios_capacity: maximum possible number of folios in array
 * @lock: folio array's lock
 * @folios: array of memory folios' pointers
 * @folios_count: current number of allocated folios
 * @last_folio: latest folio index
 * @order: allocation order of a particular sized block of memory
 * @folio_size: folio size in bytes
 * @bmap_bytes: number of bytes in every bitmap
 * bmap: array of bitmaps
 */
struct ssdfs_folio_array {
	atomic_t state;
	atomic_t folios_capacity;

	struct rw_semaphore lock;
	struct folio **folios;
	unsigned long folios_count;
#define SSDFS_FOLIO_ARRAY_INVALID_LAST_FOLIO	(ULONG_MAX)
	unsigned long last_folio;
	unsigned order;
	size_t folio_size;
	size_t bmap_bytes;

#define SSDFS_FOLIO_ARRAY_ALLOC_BMAP		(0)
#define SSDFS_FOLIO_ARRAY_DIRTY_BMAP		(1)
#define SSDFS_FOLIO_ARRAY_BMAP_COUNT		(2)
	struct ssdfs_folio_array_bitmap bmap[SSDFS_FOLIO_ARRAY_BMAP_COUNT];
};

/* Folio array states */
enum {
	SSDFS_FOLIO_ARRAY_UNKNOWN_STATE,
	SSDFS_FOLIO_ARRAY_CREATED,
	SSDFS_FOLIO_ARRAY_DIRTY,
	SSDFS_FOLIO_ARRAY_STATE_MAX
};

/* Available tags */
enum {
	SSDFS_UNKNOWN_FOLIO_TAG,
	SSDFS_DIRTY_FOLIO_TAG,
	SSDFS_FOLIO_TAG_MAX
};

/*
 * Inline methods
 */

static inline
unsigned long ssdfs_folio_array_get_folios_count(struct ssdfs_folio_array *array)
{
	unsigned long folios_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&array->lock);
	folios_count = array->folios_count;
	up_read(&array->lock);

	return folios_count;
}

/*
 * Folio array's API
 */
int ssdfs_create_folio_array(struct ssdfs_folio_array *array,
			     unsigned order,
			     int capacity);
void ssdfs_destroy_folio_array(struct ssdfs_folio_array *array);
int ssdfs_reinit_folio_array(int capacity, struct ssdfs_folio_array *array);
bool is_ssdfs_folio_array_empty(struct ssdfs_folio_array *array);
unsigned long
ssdfs_folio_array_get_last_folio_index(struct ssdfs_folio_array *array);
int ssdfs_folio_array_add_folio(struct ssdfs_folio_array *array,
				struct folio *folio,
				unsigned long folio_index);
struct folio *
ssdfs_folio_array_allocate_folio_locked(struct ssdfs_folio_array *array,
					unsigned long folio_index);
struct folio *ssdfs_folio_array_get_folio_locked(struct ssdfs_folio_array *array,
						 unsigned long folio_index);
struct folio *ssdfs_folio_array_get_folio(struct ssdfs_folio_array *array,
					  unsigned long folio_index);
struct folio *ssdfs_folio_array_grab_folio(struct ssdfs_folio_array *array,
					   unsigned long folio_index);
int ssdfs_folio_array_set_folio_dirty(struct ssdfs_folio_array *array,
					unsigned long folio_index);
int ssdfs_folio_array_clear_dirty_folio(struct ssdfs_folio_array *array,
					unsigned long folio_index);
int ssdfs_folio_array_clear_dirty_range(struct ssdfs_folio_array *array,
					unsigned long start,
					unsigned long end);
int ssdfs_folio_array_clear_all_dirty_folios(struct ssdfs_folio_array *array);
int ssdfs_folio_array_lookup_range(struct ssdfs_folio_array *array,
				   unsigned long *start,
				   unsigned long end,
				   int tag, int max_folios,
				   struct folio_batch *batch);
struct folio *ssdfs_folio_array_delete_folio(struct ssdfs_folio_array *array,
					     unsigned long folio_index);
int ssdfs_folio_array_release_folios(struct ssdfs_folio_array *array,
				     unsigned long *start,
				     unsigned long end);
int ssdfs_folio_array_release_all_folios(struct ssdfs_folio_array *array);

#endif /* _SSDFS_FOLIO_ARRAY_H */
