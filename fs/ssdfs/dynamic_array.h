/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dynamic_array.h - dynamic array's declarations.
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

#ifndef _SSDFS_DYNAMIC_ARRAY_H
#define _SSDFS_DYNAMIC_ARRAY_H

#include "folio_vector.h"

/*
 * struct ssdfs_dynamic_array - dynamic array
 * @state: array state
 * @item_size: size of item in bytes
 * @items_per_folio: number of items per memory folio
 * @items_count: items count in array
 * @capacity: maximum available items count
 * @bytes_count: currently allocated bytes count
 * @alloc_pattern: pattern to init memory pages
 * @batch: vector of folios
 * @buf: pointer on memory buffer
 */
struct ssdfs_dynamic_array {
	int state;
	size_t item_size;
	u32 items_per_folio;
	u32 items_count;
	u32 capacity;
	u32 bytes_count;
	u8 alloc_pattern;
	struct ssdfs_folio_vector batch;
	void *buf;
};

/* Dynamic array's states */
enum {
	SSDFS_DYNAMIC_ARRAY_STORAGE_ABSENT,
	SSDFS_DYNAMIC_ARRAY_STORAGE_FOLIO_VEC,
	SSDFS_DYNAMIC_ARRAY_STORAGE_BUFFER,
	SSDFS_DYNAMIC_ARRAY_STORAGE_STATE_MAX
};

/*
 * Inline functions
 */

static inline
u32 ssdfs_dynamic_array_allocated_bytes(struct ssdfs_dynamic_array *array)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	return array->bytes_count;
}

static inline
u32 ssdfs_dynamic_array_items_count(struct ssdfs_dynamic_array *array)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	if (array->bytes_count == 0 || array->item_size == 0)
		return 0;

	return array->bytes_count / array->item_size;
}

/*
 * Dynamic array's API
 */
int ssdfs_dynamic_array_create(struct ssdfs_dynamic_array *array,
				u32 capacity, size_t item_size,
				u8 alloc_pattern);
void ssdfs_dynamic_array_destroy(struct ssdfs_dynamic_array *array);
void *ssdfs_dynamic_array_get_locked(struct ssdfs_dynamic_array *array,
				     u32 index);
int ssdfs_dynamic_array_release(struct ssdfs_dynamic_array *array,
				u32 index, void *ptr);
int ssdfs_dynamic_array_set(struct ssdfs_dynamic_array *array,
			    u32 index, void *ptr);
int ssdfs_dynamic_array_copy_content(struct ssdfs_dynamic_array *array,
				     void *copy_buf, size_t buf_size);
void *ssdfs_dynamic_array_get_content_locked(struct ssdfs_dynamic_array *array,
					     u32 index, u32 *items_count);
int ssdfs_dynamic_array_shift_content_right(struct ssdfs_dynamic_array *array,
					    u32 start_index, u32 shift);

#endif /* _SSDFS_DYNAMIC_ARRAY_H */
