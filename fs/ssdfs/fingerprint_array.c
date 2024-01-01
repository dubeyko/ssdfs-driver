/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/fingerprint_array.c - fingerprint array implementation.
 *
 * Copyright (c) 2023-2024 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
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
#include "fingerprint_array.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_fingerprint_array_folio_leaks;
atomic64_t ssdfs_fingerprint_array_memory_leaks;
atomic64_t ssdfs_fingerprint_array_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_fingerprint_array_cache_leaks_increment(void *kaddr)
 * void ssdfs_fingerprint_array_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_fingerprint_array_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_fingerprint_array_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_fingerprint_array_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_fingerprint_array_kfree(void *kaddr)
 * struct folio *ssdfs_fingerprint_array_alloc_folio(gfp_t gfp_mask,
 *                          			     unsigned int order)
 * struct folio *ssdfs_file_add_batch_folio(struct folio_batch *batch,
 *                                          unsigned int order)
 * void ssdfs_fingerprint_array_free_folio(struct folio *folio)
 * void ssdfs_file_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(fingerprint_array)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(fingerprint_array)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_fingerprint_array_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_fingerprint_array_folio_leaks, 0);
	atomic64_set(&ssdfs_fingerprint_array_memory_leaks, 0);
	atomic64_set(&ssdfs_fingerprint_array_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_fingerprint_array_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_fingerprint_array_folio_leaks) != 0) {
		SSDFS_ERR("FINGERPRINT ARRAY: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_fingerprint_array_folio_leaks));
	}

	if (atomic64_read(&ssdfs_fingerprint_array_memory_leaks) != 0) {
		SSDFS_ERR("FINGERPRINT ARRAY: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_fingerprint_array_memory_leaks));
	}

	if (atomic64_read(&ssdfs_fingerprint_array_cache_leaks) != 0) {
		SSDFS_ERR("FINGERPRINT ARRAY: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_fingerprint_array_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * ssdfs_fingerprint_array_create() - create fingerprint array
 * @farray: pointer on fingerprint array object
 * @capacity: maximum number of items in array
 */
int ssdfs_fingerprint_array_create(struct ssdfs_fingerprint_array *farray,
				   u32 capacity)
{
	size_t item_size = sizeof(struct ssdfs_fingerprint_item);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!farray);

	SSDFS_DBG("array %p, capacity %u, item_size %zu\n",
		  farray, capacity, item_size);
#endif /* CONFIG_SSDFS_DEBUG */

	atomic_set(&farray->state, SSDFS_FINGERPRINT_ARRAY_UNKNOWN_STATE);

	init_rwsem(&farray->lock);
	farray->items_count = 0;

	err = ssdfs_dynamic_array_create(&farray->array,
					 capacity, item_size,
					 0xFF);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create dynamic array: "
			  "capacity %u, item_size %zu, err %d\n",
			  capacity, item_size, err);
		return err;
	}

	atomic_set(&farray->state, SSDFS_FINGERPRINT_ARRAY_CREATED);

	return 0;
}

/*
 * ssdfs_fingerprint_array_destroy() - destroy fingerprint array
 * @farray: pointer on fingerprint array object
 */
void ssdfs_fingerprint_array_destroy(struct ssdfs_fingerprint_array *farray)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!farray);

	SSDFS_DBG("array %p\n", farray);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&farray->state)) {
	case SSDFS_FINGERPRINT_ARRAY_CREATED:
		/* continue logic */
		break;

	default:
		/* do nothing */
		return;
	}

	down_write(&farray->lock);
	ssdfs_dynamic_array_destroy(&farray->array);
	farray->items_count = 0;
	up_write(&farray->lock);
}

/*
 * ssdfs_check_fingerprint_item() - compare fingerprint item with hash
 * @hash: fingerprint with hash value
 * @item: fingerprint item for comparison with hash value
 *
 * This method tries to compare the fingerprint hashes.
 *
 * RETURN:
 * [success]
 *
 * %-ENOENT     - hash is lesser than item's fingerprint.
 * %-EEXIST     - hash is equal to item's fingerprint.
 * %-EAGAIN     - hash is bigger than item's fingerprint.
 *
 * [failure]
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_check_fingerprint_item(struct ssdfs_fingerprint *hash,
				 struct ssdfs_fingerprint_item *item)
{
	int res;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!item || !hash);

	SSDFS_DBG("item %p, hash %p\n",
		  item, hash);

	SSDFS_DBG("HASH: type %#x, len %u\n",
		  hash->type, hash->len);
	SSDFS_DBG("HASH DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     hash->buf,
			     SSDFS_FINGERPRINT_LENGTH_MAX);
	SSDFS_DBG("\n");

	SSDFS_DBG("ITEM HASH: type %#x, len %u\n",
		  item->hash.type, item->hash.len);
	SSDFS_DBG("ITEM HASH DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     item->hash.buf,
			     SSDFS_FINGERPRINT_LENGTH_MAX);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	if (!IS_FINGERPRINT_VALID(hash)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("hash is invalid\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return -EINVAL;
	}

	if (!IS_FINGERPRINT_VALID(&item->hash)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("item is invalid\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return -EINVAL;
	}

	if (!IS_FINGERPRINTS_COMPARABLE(hash, &item->hash)) {
		SSDFS_ERR("fingerprings are incomparable\n");
		return -EINVAL;
	}

	res = ssdfs_compare_fingerprints(hash, &item->hash);
	if (res < 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("search fingerprint is lesser\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOENT;
	} else if (res == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("identical fingerprint is found\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return -EEXIST;
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("search fingerprint is bigger\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return -EAGAIN;
	}

	return 0;
}

/*
 * ssdfs_fingerprint_array_find_nolock() - find fingerprint item without lock
 * @farray: pointer on fingerprint array object
 * @hash: fingerprint with hash value
 * @item_index: pointer on found item index [out]
 *
 * This method tries to find the position in array for
 * requested fingerprint hash without lock.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOENT     - item is not found.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_fingerprint_array_find_nolock(struct ssdfs_fingerprint_array *farray,
					struct ssdfs_fingerprint *hash,
					u32 *item_index)
{
	struct ssdfs_fingerprint_item *items_array;
	struct ssdfs_fingerprint_item *item;
	void *kaddr;
	u32 total_items;
	u32 items_count;
	u32 processed_items = 0;
	u32 lower_bound;
	u32 upper_bound;
	u32 cur_index;
	u32 diff;
	int res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!farray || !hash || !item_index);
	BUG_ON(!rwsem_is_locked(&farray->lock));

	SSDFS_DBG("array %p, hash %p\n",
		  farray, hash);
#endif /* CONFIG_SSDFS_DEBUG */

	total_items = ssdfs_dynamic_array_items_count(&farray->array);
	if (total_items == 0) {
		err = -ENOENT;
		*item_index = 0;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("empty array: total_items %u\n",
			  total_items);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_search_item;
	}

	if (farray->items_count > total_items) {
		err = -ERANGE;
		SSDFS_ERR("items_count %u > total_items %u\n",
			  farray->items_count,
			  total_items);
		goto finish_search_item;
	}

	if (farray->items_count == 0) {
		err = -ENOENT;
		*item_index = 0;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("empty array: items_count %u\n",
			  farray->items_count);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_search_item;
	}

	while (processed_items < farray->items_count) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("processed_items %u, total_items %u\n",
			  processed_items, farray->items_count);
#endif /* CONFIG_SSDFS_DEBUG */

		kaddr = ssdfs_dynamic_array_get_content_locked(&farray->array,
								processed_items,
								&items_count);
		if (IS_ERR_OR_NULL(kaddr)) {
			err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
			SSDFS_ERR("fail to get fingerprints range: "
				  "processed_items %u, err %d\n",
				  processed_items, err);
			goto finish_search_item;
		}

		if (items_count == 0) {
			err = -ENOENT;
			*item_index = processed_items;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fingerprint portion is empty\n");
#endif /* CONFIG_SSDFS_DEBUG */
			goto unlock_fingerprints_portion;
		}

		items_array = (struct ssdfs_fingerprint_item *)kaddr;

		item = &items_array[0];

		err = ssdfs_check_fingerprint_item(hash, item);
		if (err == -ENOENT) {
			*item_index = processed_items;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("stop search: item %u, err %d\n",
				  *item_index, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto unlock_fingerprints_portion;
		} else if (err == -EEXIST) {
			*item_index = processed_items;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("stop search: item %u, err %d\n",
				  *item_index, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto unlock_fingerprints_portion;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to check fingerprint: err %d\n",
				  err);
			goto unlock_fingerprints_portion;
		} else
			BUG();

		if (items_count == 1) {
			err = -EAGAIN;
			*item_index = processed_items;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("continue search: "
				  "item %u\n",
				  *item_index);
#endif /* CONFIG_SSDFS_DEBUG */
			goto unlock_fingerprints_portion;
		}

		item = &items_array[items_count - 1];

		err = ssdfs_check_fingerprint_item(hash, item);
		if (err == -ENOENT) {
			/*
			 * Continue search in the range
			 */
		} else if (err == -EEXIST) {
			*item_index = items_count - 1;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("stop search: item %u, err %d\n",
				  *item_index, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto unlock_fingerprints_portion;
		} else if (err == -EAGAIN) {
			*item_index = items_count - 1;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("continue search: "
				  "item %u\n",
				  *item_index);
#endif /* CONFIG_SSDFS_DEBUG */
			goto unlock_fingerprints_portion;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to check fingerprint: err %d\n",
				  err);
			goto unlock_fingerprints_portion;
		} else
			BUG();

		lower_bound = 0;
		*item_index = lower_bound;
		upper_bound = items_count;
		cur_index = upper_bound / 2;

		do {
			item = &items_array[cur_index];

			err = ssdfs_check_fingerprint_item(hash, item);
			if (err == -ENOENT) {
				/* correct upper_bound */
				upper_bound = cur_index;
			} else if (err == -EEXIST) {
				*item_index = cur_index;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("stop search: item %u, err %d\n",
					  *item_index, err);
#endif /* CONFIG_SSDFS_DEBUG */
				goto unlock_fingerprints_portion;
			} else if (err == -EAGAIN) {
				/* correct lower_bound */
				lower_bound = cur_index;
				*item_index = lower_bound;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to check fingerprint: err %d\n",
					  err);
				goto unlock_fingerprints_portion;
			} else
				BUG();

			diff = upper_bound - lower_bound;
			cur_index = lower_bound + (diff / 2);
		} while (lower_bound < upper_bound);

unlock_fingerprints_portion:
		res = ssdfs_dynamic_array_release(&farray->array,
						  processed_items,
						  kaddr);
		if (unlikely(res)) {
			SSDFS_ERR("fail to release fingerprints portion: "
				  "processed_items %u, err %d\n",
				  processed_items, res);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}

		processed_items += items_count;

		if (err == -EAGAIN) {
			if (processed_items < farray->items_count) {
				err = 0;

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("continue search: "
					  "item %u\n",
					  *item_index);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			} else {
				err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("stop search: "
					  "nothing is found: item %u\n",
					  *item_index);
#endif /* CONFIG_SSDFS_DEBUG */
				break;
			}
		} else if (err)
			break;
	}

	if (err == -EEXIST) {
		err = 0;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fingerprint is found: "
			  "item %u\n",
			  *item_index);
#endif /* CONFIG_SSDFS_DEBUG */
	}

finish_search_item:
	return err;
}

/*
 * ssdfs_fingerprint_array_find() - find fingerprint item
 * @farray: pointer on fingerprint array object
 * @hash: fingerprint with hash value
 * @item_index: pointer on found item index [out]
 *
 * This method tries to find the position in array for
 * requested fingerprint hash.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOENT     - item is not found.
 * %-ERANGE     - internal error.
 */
int ssdfs_fingerprint_array_find(struct ssdfs_fingerprint_array *farray,
				 struct ssdfs_fingerprint *hash,
				 u32 *item_index)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!farray || !hash || !item_index);

	SSDFS_DBG("array %p, hash %p\n",
		  farray, hash);
#endif /* CONFIG_SSDFS_DEBUG */

	*item_index = U32_MAX;

	down_read(&farray->lock);
	err = ssdfs_fingerprint_array_find_nolock(farray, hash, item_index);
	up_read(&farray->lock);

	return err;
}

/*
 * ssdfs_fingerprint_array_get_nolock() - get fingerprint item without lock
 * @farray: pointer on fingerprint array object
 * @item_index: item index
 * @item: pointer on buffer for requested fingerprint item [out]
 *
 * This method tries to extract the item on @item_index position
 * in array without lock.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static inline
int ssdfs_fingerprint_array_get_nolock(struct ssdfs_fingerprint_array *farray,
					u32 item_index,
					struct ssdfs_fingerprint_item *item)
{
	void *kaddr;
	size_t item_size = sizeof(struct ssdfs_fingerprint_item);
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!farray || !item);
	BUG_ON(!rwsem_is_locked(&farray->lock));

	SSDFS_DBG("array %p, item_index %u\n",
		  farray, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	kaddr = ssdfs_dynamic_array_get_locked(&farray->array, item_index);
	if (IS_ERR_OR_NULL(kaddr)) {
		err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
		SSDFS_ERR("fail to get fingerprint item: "
			  "item_index %u, err %d\n",
			  item_index, err);
		goto finish_get_item;
	}

	ssdfs_memcpy(item, 0, item_size,
		     kaddr, 0, item_size,
		     item_size);

	err = ssdfs_dynamic_array_release(&farray->array, item_index, kaddr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to release: "
			  "item_index %u, err %d\n",
			  item_index, err);
		goto finish_get_item;
	}

finish_get_item:
	return err;
}

/*
 * ssdfs_fingerprint_array_get() - get fingerprint item
 * @farray: pointer on fingerprint array object
 * @item_index: item index
 * @item: pointer on buffer for requested fingerprint item [out]
 *
 * This method tries to extract the item on @item_index position
 * in array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_fingerprint_array_get(struct ssdfs_fingerprint_array *farray,
				u32 item_index,
				struct ssdfs_fingerprint_item *item)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!farray || !item);

	SSDFS_DBG("array %p, item_index %u\n",
		  farray, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&farray->lock);
	err = ssdfs_fingerprint_array_get_nolock(farray, item_index, item);
	up_read(&farray->lock);

	return err;
}

/*
 * ssdfs_fingerprint_array_add() - add fingerprint item into array
 * @farray: pointer on fingerprint array object
 * @item: fingerprint item
 * @item_index: item index
 *
 * This method tries to add the item in array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EEXIST     - item exists in the array.
 * %-ERANGE     - internal error.
 */
int ssdfs_fingerprint_array_add(struct ssdfs_fingerprint_array *farray,
				struct ssdfs_fingerprint_item *item,
				u32 item_index)
{
	struct ssdfs_fingerprint_item existing;
	u32 total_items;
	u32 cur_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!farray || !item);

	SSDFS_DBG("array %p, item_index %u\n",
		  farray, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&farray->lock);

	total_items = farray->items_count;

	if (item_index >= U32_MAX || item_index > total_items) {
		err = ssdfs_fingerprint_array_find_nolock(farray,
							  &item->hash,
							  &item_index);
		if (err == -ENOENT) {
			err = 0;
			/* expected state */
		} else if (err == -EEXIST) {
			SSDFS_ERR("item exists for requested fingerprint\n");
			goto finish_add_fingerprint;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find position for fingerprint: "
				  "err %d\n", err);
			goto finish_add_fingerprint;
		} else {
			err = -ERANGE;
			SSDFS_ERR("unexpected result of position search\n");
			goto finish_add_fingerprint;
		}
	}

	if (item_index > total_items) {
		err = -ERANGE;
		SSDFS_ERR("item_index %u > total_items %u\n",
			  item_index, total_items);
		goto finish_add_fingerprint;
	}

	if (total_items == 0) {
		err = ssdfs_dynamic_array_set(&farray->array, item_index, item);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add fingerprint: "
				  "item_index %u, err %d\n",
				  item_index, err);
			goto finish_add_fingerprint;
		}
	} else if (item_index == total_items) {
		cur_index = item_index - 1;

		err = ssdfs_fingerprint_array_get_nolock(farray,
							 cur_index,
							 &existing);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get previous item: "
				  "index %u, err %d\n",
				  cur_index, err);
			goto finish_add_fingerprint;
		}

		err = ssdfs_check_fingerprint_item(&existing.hash, item);
		if (err == -ENOENT) {
			err = 0;
			/*
			 * Continue logic
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("corrupted fingerprints' sequence: "
				  "index1 %u, index2 %u, err %d\n",
				  cur_index, item_index, err);
			goto finish_add_fingerprint;
		} else
			BUG();

		err = ssdfs_dynamic_array_set(&farray->array, item_index, item);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add fingerprint: "
				  "item_index %u, err %d\n",
				  item_index, err);
			goto finish_add_fingerprint;
		}
	} else {
		cur_index = item_index;

		err = ssdfs_fingerprint_array_get_nolock(farray,
							 cur_index,
							 &existing);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get previous item: "
				  "index %u, err %d\n",
				  cur_index, err);
			goto finish_add_fingerprint;
		}

		err = ssdfs_check_fingerprint_item(&item->hash, &existing);
		if (err == -ENOENT) {
			err = 0;
			/*
			 * Continue logic
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("corrupted fingerprints' sequence: "
				  "index1 %u, index2 %u, err %d\n",
				  cur_index, item_index, err);
			goto finish_add_fingerprint;
		} else
			BUG();

		cur_index = item_index - 1;

		err = ssdfs_fingerprint_array_get_nolock(farray,
							 cur_index,
							 &existing);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get previous item: "
				  "index %u, err %d\n",
				  cur_index, err);
			goto finish_add_fingerprint;
		}

		err = ssdfs_check_fingerprint_item(&existing.hash, item);
		if (err == -ENOENT) {
			err = 0;
			/*
			 * Continue logic
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("corrupted fingerprints' sequence: "
				  "index1 %u, index2 %u, err %d\n",
				  cur_index, item_index, err);
			goto finish_add_fingerprint;
		} else
			BUG();

		err = ssdfs_dynamic_array_shift_content_right(&farray->array,
							      item_index, 1);
		if (unlikely(err)) {
			SSDFS_ERR("fail to shift range: "
				  "index %u, err %d\n",
				  item_index, err);
			goto finish_add_fingerprint;
		}

		err = ssdfs_dynamic_array_set(&farray->array, item_index, item);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add fingerprint: "
				  "item_index %u, err %d\n",
				  item_index, err);
			goto finish_add_fingerprint;
		}
	}

	farray->items_count++;

finish_add_fingerprint:
	up_write(&farray->lock);

	return err;
}
