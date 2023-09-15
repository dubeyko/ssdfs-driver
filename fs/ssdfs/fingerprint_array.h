// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/fingerprint_array.h - fingerprint array's declarations.
 *
 * Copyright (c) 2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_FINGERPRINT_ARRAY_H
#define _SSDFS_FINGERPRINT_ARRAY_H

#include "dynamic_array.h"
#include "fingerprint.h"

/*
 * struct ssdfs_fingerprint_item - fingerprint item
 * @hash: fingerprint hash
 * @logical_blk: logical block ID
 * @blk_desc: logical block descriptor
 */
struct ssdfs_fingerprint_item {
	struct ssdfs_fingerprint hash;
	u32 logical_blk;
	struct ssdfs_block_descriptor blk_desc;
};

/*
 * struct ssdfs_fingerprint_pair - item + index pair
 * @item: fingerprint item
 * @item_index: item index in array
 */
struct ssdfs_fingerprint_pair {
	struct ssdfs_fingerprint_item item;
	u32 item_index;
};

/*
 * struct ssdfs_fingerprint_array - fingerprint array
 * @state: state of fingerprint array
 * @lock: array lock
 * @items_count: items count in array
 * @array: array of fingerprints
 */
struct ssdfs_fingerprint_array {
	atomic_t state;
	struct rw_semaphore lock;
	u32 items_count;
	struct ssdfs_dynamic_array array;
};

/* Fingeprint array states */
enum {
	SSDFS_FINGERPRINT_ARRAY_UNKNOWN_STATE,
	SSDFS_FINGERPRINT_ARRAY_CREATED,
	SSDFS_FINGERPRINT_ARRAY_STATE_MAX
};

/*
 * Fingerprint array's API
 */
int ssdfs_fingerprint_array_create(struct ssdfs_fingerprint_array *array,
				   u32 capacity);
void ssdfs_fingerprint_array_destroy(struct ssdfs_fingerprint_array *array);
int ssdfs_check_fingerprint_item(struct ssdfs_fingerprint *hash,
				 struct ssdfs_fingerprint_item *item);
int ssdfs_fingerprint_array_find(struct ssdfs_fingerprint_array *array,
				 struct ssdfs_fingerprint *hash,
				 u32 *item_index);
int ssdfs_fingerprint_array_get(struct ssdfs_fingerprint_array *array,
				u32 item_index,
				struct ssdfs_fingerprint_item *item);
int ssdfs_fingerprint_array_add(struct ssdfs_fingerprint_array *array,
				struct ssdfs_fingerprint_item *item,
				u32 item_index);

#endif /* _SSDFS_FINGERPRINT_ARRAY_H */
