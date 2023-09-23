// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_mapping_table_cache.c - PEB mapping table cache functionality.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2023 Viacheslav Dubeyko <slava@dubeyko.com>
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

#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "page_array.h"
#include "folio_array.h"
#include "peb_mapping_table.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_map_cache_page_leaks;
atomic64_t ssdfs_map_cache_folio_leaks;
atomic64_t ssdfs_map_cache_memory_leaks;
atomic64_t ssdfs_map_cache_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_map_cache_cache_leaks_increment(void *kaddr)
 * void ssdfs_map_cache_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_map_cache_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_map_cache_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_map_cache_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_map_cache_kfree(void *kaddr)
 * struct page *ssdfs_map_cache_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_map_cache_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_map_cache_free_page(struct page *page)
 * void ssdfs_map_cache_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(map_cache)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(map_cache)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_map_cache_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_map_cache_page_leaks, 0);
	atomic64_set(&ssdfs_map_cache_folio_leaks, 0);
	atomic64_set(&ssdfs_map_cache_memory_leaks, 0);
	atomic64_set(&ssdfs_map_cache_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_map_cache_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_map_cache_page_leaks) != 0) {
		SSDFS_ERR("MAPPING CACHE: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_map_cache_page_leaks));
	}

	if (atomic64_read(&ssdfs_map_cache_folio_leaks) != 0) {
		SSDFS_ERR("MAPPING CACHE: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_map_cache_folio_leaks));
	}

	if (atomic64_read(&ssdfs_map_cache_memory_leaks) != 0) {
		SSDFS_ERR("MAPPING CACHE: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_map_cache_memory_leaks));
	}

	if (atomic64_read(&ssdfs_map_cache_cache_leaks) != 0) {
		SSDFS_ERR("MAPPING CACHE: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_map_cache_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * ssdfs_maptbl_cache_init() - init mapping table cache
 */
void ssdfs_maptbl_cache_init(struct ssdfs_maptbl_cache *cache)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache);

	SSDFS_DBG("cache %p\n", cache);
#endif /* CONFIG_SSDFS_DEBUG */

	init_rwsem(&cache->lock);
	folio_batch_init(&cache->batch);
	atomic_set(&cache->bytes_count, 0);
	ssdfs_peb_mapping_queue_init(&cache->pm_queue);
}

/*
 * ssdfs_maptbl_cache_destroy() - destroy mapping table cache
 */
void ssdfs_maptbl_cache_destroy(struct ssdfs_maptbl_cache *cache)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache);

	SSDFS_DBG("cache %p\n", cache);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_map_cache_folio_batch_release(&cache->batch);
	ssdfs_peb_mapping_queue_remove_all(&cache->pm_queue);
}

/*
 * __ssdfs_maptbl_cache_area_size() - calculate areas' size in fragment
 * @hdr: fragment's header
 * @leb2peb_area_size: LEB2PEB area size [out]
 * @peb_state_area_size: PEB state area size [out]
 *
 * This method calculates size in bytes of LEB2PEB area and
 * PEB state area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE    - internal error.
 * %-ENODATA   - fragment is empty.
 */
static inline
int __ssdfs_maptbl_cache_area_size(struct ssdfs_maptbl_cache_header *hdr,
				   size_t *leb2peb_area_size,
				   size_t *peb_state_area_size)
{
	size_t hdr_size = sizeof(struct ssdfs_maptbl_cache_header);
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	size_t magic_size = peb_state_size;
	u16 bytes_count;
	u16 items_count;
	size_t threshold_size;
	size_t capacity;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr || !leb2peb_area_size || !peb_state_area_size);

	SSDFS_DBG("hdr %p\n", hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	*leb2peb_area_size = 0;
	*peb_state_area_size = magic_size;

	bytes_count = le16_to_cpu(hdr->bytes_count);
	items_count = le16_to_cpu(hdr->items_count);

	threshold_size = hdr_size + magic_size;

	if (bytes_count < threshold_size) {
		SSDFS_ERR("fragment is corrupted: "
			  "hdr_size %zu, bytes_count %u\n",
			  hdr_size, bytes_count);
		return -ERANGE;
	} else if (bytes_count == threshold_size) {
		SSDFS_DBG("fragment is empty\n");
		return -ENODATA;
	}

	capacity =
		(bytes_count - threshold_size) / (pair_size + peb_state_size);

	if (items_count > capacity) {
		SSDFS_ERR("items_count %u > capacity %zu\n",
			  items_count, capacity);
		return -ERANGE;
	}

	*leb2peb_area_size = capacity * pair_size;
	*peb_state_area_size = magic_size + (capacity * peb_state_size);

	return 0;
}

/*
 * ssdfs_leb2peb_pair_area_size() - calculate LEB2PEB area size
 * @hdr: fragment's header
 *
 * This method calculates size in bytes of LEB2PEB area.
 *
 * RETURN:
 * [success] - LEB2PEB area size in bytes.
 * [failure] - error code:
 *
 * %-ERANGE    - internal error.
 * %-ENODATA   - fragment is empty.
 */
static inline
int ssdfs_leb2peb_pair_area_size(struct ssdfs_maptbl_cache_header *hdr)
{
	size_t leb2peb_area_size;
	size_t peb_state_area_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr);

	SSDFS_DBG("hdr %p\n", hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_maptbl_cache_area_size(hdr,
					     &leb2peb_area_size,
					     &peb_state_area_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define leb2peb area size: "
			  "err %d\n",
			  err);
		return err;
	}

	return (int)leb2peb_area_size;
}

/*
 * ssdfs_maptbl_cache_fragment_capacity() - calculate fragment capacity
 *
 * This method calculates the capacity (maximum number of items)
 * of fragment.
 */
static inline
size_t ssdfs_maptbl_cache_fragment_capacity(void)
{
	size_t hdr_size = sizeof(struct ssdfs_maptbl_cache_header);
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	size_t magic_size = peb_state_size;
	size_t size = PAGE_SIZE;
	size_t count;

	size -= hdr_size + magic_size;
	count = size / (pair_size + peb_state_size);

	return count;
}

/*
 * LEB2PEB_PAIR_AREA() - get pointer on first LEB2PEB pair
 * @kaddr: pointer on fragment's beginning
 */
static inline
struct ssdfs_leb2peb_pair *LEB2PEB_PAIR_AREA(void *kaddr)
{
	size_t hdr_size = sizeof(struct ssdfs_maptbl_cache_header);

	return (struct ssdfs_leb2peb_pair *)((u8 *)kaddr + hdr_size);
}

/*
 * ssdfs_peb_state_area_size() - calculate PEB state area size
 * @hdr: fragment's header
 *
 * This method calculates size in bytes of PEB state area.
 *
 * RETURN:
 * [success] - PEB state area size in bytes.
 * [failure] - error code:
 *
 * %-ERANGE    - internal error.
 * %-ENODATA   - fragment is empty.
 */
static inline
int ssdfs_peb_state_area_size(struct ssdfs_maptbl_cache_header *hdr)
{
	size_t leb2peb_area_size;
	size_t peb_state_area_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr);

	SSDFS_DBG("hdr %p\n", hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_maptbl_cache_area_size(hdr,
					     &leb2peb_area_size,
					     &peb_state_area_size);
	if (err == -ENODATA) {
		/* empty area */
		err = 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to define peb state area size: "
			  "err %d\n",
			  err);
		return err;
	}

	return (int)peb_state_area_size;
}

/*
 * PEB_STATE_AREA() - get pointer on PEB state area
 * @kaddr: pointer on fragment's beginning
 * @area_offset: PEB state area's offset
 *
 * This method tries to prepare pointer on the
 * PEB state area in the fragment.
 *
 * RETURN:
 * [success] - pointer on the PEB state area.
 * [failure] - error code:
 *
 * %-ERANGE    - corrupted PEB state area.
 */
static inline
void *PEB_STATE_AREA(void *kaddr, u32 *area_offset)
{
	struct ssdfs_maptbl_cache_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_maptbl_cache_header);
	size_t leb2peb_area_size;
	size_t peb_state_area_size;
	void *start = NULL;
	__le32 *magic = NULL;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !area_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
	*area_offset = U32_MAX;

	err = __ssdfs_maptbl_cache_area_size(hdr,
					     &leb2peb_area_size,
					     &peb_state_area_size);
	if (err == -ENODATA) {
		/* empty area */
		err = 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to get area size: err %d\n", err);
		return ERR_PTR(err);
	}

	if ((hdr_size + leb2peb_area_size + peb_state_area_size) > PAGE_SIZE) {
		err = -ERANGE;
		SSDFS_ERR("invalid state: "
			  "hdr_size %zu, leb2peb_area_size %zu, "
			  "peb_state_area_size %zu\n",
			  hdr_size, leb2peb_area_size,
			  peb_state_area_size);
		return ERR_PTR(err);
	}

	*area_offset = hdr_size + leb2peb_area_size;
	start = (u8 *)kaddr + hdr_size + leb2peb_area_size;
	magic = (__le32 *)start;

	if (le32_to_cpu(*magic) != SSDFS_MAPTBL_CACHE_PEB_STATE_MAGIC) {
		SSDFS_ERR("invalid magic %#x\n",
			  le32_to_cpu(*magic));
		return ERR_PTR(-ERANGE);
	}

	return start;
}

/*
 * FIRST_PEB_STATE() - get pointer on first PEB state
 * @kaddr: pointer on fragment's beginning
 * @area_offset: PEB state area's offset
 *
 * This method tries to prepare pointer on the first
 * PEB state in the fragment.
 *
 * RETURN:
 * [success] - pointer on first PEB state.
 * [failure] - error code:
 *
 * %-ERANGE    - corrupted PEB state area.
 */
static inline
struct ssdfs_maptbl_cache_peb_state *FIRST_PEB_STATE(void *kaddr,
						     u32 *area_offset)
{
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	size_t magic_size = peb_state_size;
	void *start = PEB_STATE_AREA(kaddr, area_offset);

	if (IS_ERR_OR_NULL(start))
		return (struct ssdfs_maptbl_cache_peb_state *)start;

	return (struct ssdfs_maptbl_cache_peb_state *)((u8 *)start +
							magic_size);
}

/*
 * ssdfs_find_range_lower_limit() - find the first item of range
 * @hdr: mapping table cache's header
 * @leb_id: LEB ID
 * @start_index: starting index
 * @start_pair: pointer on starting LEB2PEB pair
 * @found_index: pointer on found index [out]
 *
 * This method tries to find position of the first item
 * for the same @leb_id in the range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL    - invalid input.
 * %-ERANGE    - internal error.
 */
static
int ssdfs_find_range_lower_limit(struct ssdfs_maptbl_cache_header *hdr,
				 u64 leb_id, int start_index,
				 struct ssdfs_leb2peb_pair *start_pair,
				 int *found_index)
{
	struct ssdfs_leb2peb_pair *cur_pair = NULL;
	u16 items_count;
	u64 cur_leb_id;
	int i = 0, j = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr || !start_pair || !found_index);

	SSDFS_DBG("hdr %p, leb_id %llu, start_index %d, "
		  "start_pair %p, found_index %p\n",
		  hdr, leb_id, start_index, start_pair, found_index);
#endif /* CONFIG_SSDFS_DEBUG */

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache\n");
		return -ERANGE;
	}

	if (start_index < 0 || start_index >= items_count) {
		SSDFS_ERR("invalid index: "
			  "start_index %d, items_count %u\n",
			  start_index, items_count);
		return -EINVAL;
	}

	if (leb_id != le64_to_cpu(start_pair->leb_id)) {
		SSDFS_ERR("invalid ID: "
			  "leb_id1 %llu, leb_id2 %llu\n",
			  leb_id,
			  le64_to_cpu(start_pair->leb_id));
		return -EINVAL;
	}

	*found_index = start_index;

	for (i = start_index - 1, j = 1; i >= 0; i--, j++) {
		cur_pair = start_pair - j;
		cur_leb_id = le64_to_cpu(cur_pair->leb_id);

		if (cur_leb_id == leb_id) {
			*found_index = i;
			continue;
		} else
			return 0;

		if ((start_index - i) >= 2) {
			SSDFS_ERR("corrupted cache\n");
			return -ERANGE;
		}
	}

	return 0;
}

/*
 * ssdfs_find_range_upper_limit() - find the last item of range
 * @hdr: mapping table cache's header
 * @leb_id: LEB ID
 * @start_index: starting index
 * @start_pair: pointer on starting LEB2PEB pair
 * @found_index: pointer on found index [out]
 *
 * This method tries to find position of the last item
 * for the same @leb_id in the range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL    - invalid input.
 * %-ERANGE    - internal error.
 */
static
int ssdfs_find_range_upper_limit(struct ssdfs_maptbl_cache_header *hdr,
				 u64 leb_id, int start_index,
				 struct ssdfs_leb2peb_pair *start_pair,
				 int *found_index)
{
	struct ssdfs_leb2peb_pair *cur_pair = NULL;
	u16 items_count;
	u64 cur_leb_id;
	int i = 0, j = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr || !start_pair || !found_index);

	SSDFS_DBG("hdr %p, leb_id %llu, start_index %d, "
		  "start_pair %p, found_index %p\n",
		  hdr, leb_id, start_index, start_pair, found_index);
#endif /* CONFIG_SSDFS_DEBUG */

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache\n");
		return -ERANGE;
	}

	if (start_index < 0 || start_index >= items_count) {
		SSDFS_ERR("invalid index: "
			  "start_index %d, items_count %u\n",
			  start_index, items_count);
		return -EINVAL;
	}

	if (leb_id != le64_to_cpu(start_pair->leb_id)) {
		SSDFS_ERR("invalid ID: "
			  "leb_id1 %llu, leb_id2 %llu\n",
			  leb_id,
			  le64_to_cpu(start_pair->leb_id));
		return -EINVAL;
	}

	*found_index = start_index;

	for (i = start_index + 1, j = 1; i < items_count; i++, j++) {
		cur_pair = start_pair + j;
		cur_leb_id = le64_to_cpu(cur_pair->leb_id);

		if (cur_leb_id == leb_id) {
			*found_index = i;
			continue;
		} else
			return 0;

		if ((i - start_index) >= 2) {
			SSDFS_ERR("corrupted cache\n");
			return -ERANGE;
		}
	}

	return 0;
}

/*
 * ssdfs_find_result_pair() - extract pair of descriptors
 * @hdr: mapping table cache's header
 * @sequence_id: fragment ID
 * @leb_id: LEB ID
 * @peb_index: main/relation PEB index
 * @cur_index: current index of item in cache
 * @start_pair: pointer on starting pair in cache
 * @cur_pair: pointer on current pair for @current_index
 * @res: pointer on the extracted pair of descriptors [out]
 *
 * This method tries to extract the pair of descriptor for
 * main and relation LEB2PEB pairs.
 *
 * RETURN:
 * [success] - error code:
 * %-EAGAIN    - repeat the search for the next memory folio
 * %-EEXIST    - @leb_id is found.
 *
 * [failure] - error code:
 * %-ERANGE    - internal error.
 */
static
int ssdfs_find_result_pair(struct ssdfs_maptbl_cache_header *hdr,
			   unsigned sequence_id,
			   u64 leb_id,
			   int peb_index,
			   int cur_index,
			   struct ssdfs_leb2peb_pair *start_pair,
			   struct ssdfs_leb2peb_pair *cur_pair,
			   struct ssdfs_maptbl_cache_search_result *res)
{
	struct ssdfs_maptbl_cache_item *cur_item;
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	int lo_limit = -1;
	int up_limit = -1;
	u16 items_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr || !start_pair || !cur_pair || !res);

	SSDFS_DBG("sequence_id %u, leb_id %llu, "
		  "peb_index %#x, cur_index %d\n",
		  sequence_id, leb_id, peb_index, cur_index);
#endif /* CONFIG_SSDFS_DEBUG */

	cur_item = &res->pebs[peb_index];
	cur_item->state = SSDFS_MAPTBL_CACHE_SEARCH_ERROR;

	items_count = le16_to_cpu(hdr->items_count);
	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache\n");
		return -ERANGE;
	}

	err = ssdfs_find_range_lower_limit(hdr, leb_id, cur_index,
					   cur_pair, &lo_limit);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find lower_limit: "
			  "leb_id %llu, cur_index %d, "
			  "err %d\n",
			  leb_id, cur_index, err);
		return err;
	}

	err = ssdfs_find_range_upper_limit(hdr, leb_id, cur_index,
					   cur_pair, &up_limit);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find upper_limit: "
			  "leb_id %llu, cur_index %d, "
			  "err %d\n",
			  leb_id, cur_index, err);
		return err;
	}

	switch (peb_index) {
	case SSDFS_MAPTBL_MAIN_INDEX:
		/* save main item */
		cur_item->state = SSDFS_MAPTBL_CACHE_ITEM_FOUND;
		cur_item->folio_index = sequence_id;
		cur_item->item_index = lo_limit;
		cur_pair = start_pair + lo_limit;
		ssdfs_memcpy(&cur_item->found, 0, pair_size,
			     cur_pair, 0, pair_size,
			     pair_size);
		peb_index = SSDFS_MAPTBL_RELATION_INDEX;
		cur_item = &res->pebs[peb_index];
		cur_item->state = SSDFS_MAPTBL_CACHE_ITEM_ABSENT;

		if (lo_limit == up_limit && (up_limit + 1) == items_count) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("leb_id %llu, peb_index %d, cur_index %d, "
				  "lo_limit %d, up_limit %d, items_count %u\n",
				  leb_id, peb_index, cur_index,
				  lo_limit, up_limit, items_count);
#endif /* CONFIG_SSDFS_DEBUG */
			return -EAGAIN;
		} else if (lo_limit == up_limit)
			return -EEXIST;

		/* save relation item */
		cur_item->state = SSDFS_MAPTBL_CACHE_ITEM_FOUND;
		cur_item->folio_index = sequence_id;
		cur_item->item_index = up_limit;
		cur_pair = start_pair + up_limit;
		ssdfs_memcpy(&cur_item->found, 0, pair_size,
			     cur_pair, 0, pair_size,
			     pair_size);
		break;

	case SSDFS_MAPTBL_RELATION_INDEX:
		if (lo_limit != up_limit && lo_limit != 0) {
			SSDFS_ERR("corrupted cache\n");
			return -ERANGE;
		}

		cur_item->state = SSDFS_MAPTBL_CACHE_ITEM_FOUND;
		cur_item->folio_index = sequence_id;
		cur_item->item_index = lo_limit;
		cur_pair = start_pair + lo_limit;
		ssdfs_memcpy(&cur_item->found, 0, pair_size,
			     cur_pair, 0, pair_size,
			     pair_size);
		break;

	default:
		SSDFS_ERR("invalid index %d\n", peb_index);
		return -ERANGE;
	}

	return -EEXIST;
}

static
void ssdfs_maptbl_cache_show_items(void *kaddr)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *start_pair, *cur_pair;
	struct ssdfs_maptbl_cache_peb_state *start_state = NULL;
	struct ssdfs_maptbl_cache_peb_state *state_ptr;
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	u16 items_count;
	u32 area_offset = U32_MAX;
	int i;

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
	items_count = le16_to_cpu(hdr->items_count);
	start_pair = LEB2PEB_PAIR_AREA(kaddr);

	SSDFS_ERR("MAPTBL CACHE:\n");

	SSDFS_ERR("LEB2PEB pairs:\n");
	for (i = 0; i < items_count; i++) {
		cur_pair = start_pair + i;
		SSDFS_ERR("item %d, leb_id %llu, peb_id %llu\n",
			  i,
			  le64_to_cpu(cur_pair->leb_id),
			  le64_to_cpu(cur_pair->peb_id));
	}

	start_state = FIRST_PEB_STATE(kaddr, &area_offset);

	SSDFS_ERR("PEB states:\n");
	for (i = 0; i < items_count; i++) {
		state_ptr =
		    (struct ssdfs_maptbl_cache_peb_state *)((u8 *)start_state +
							(peb_state_size * i));
		SSDFS_ERR("item %d, consistency %#x, "
			  "state %#x, flags %#x, "
			  "shared_peb_index %u\n",
			  i, state_ptr->consistency,
			  state_ptr->state, state_ptr->flags,
			  state_ptr->shared_peb_index);
	}
}

/*
 * __ssdfs_maptbl_cache_find_leb() - find position of LEB
 * @kaddr: pointer on maptbl cache's fragment
 * @sequence_id: fragment ID
 * @leb_id: LEB ID
 * @res: pointer on the extracted pair of descriptors [out]
 *
 * This method tries to find position of LEB for extracting
 * or inserting a LEB/PEB pair.
 *
 * RETURN:
 * [success] - error code:
 * %-EAGAIN    - repeat the search for the next memory folio
 * %-EFAULT    - @leb_id doesn't found; position can be used for inserting.
 * %-E2BIG     - folio is full; @leb_id is greater than ending LEB number.
 * %-ENODATA   - @leb_id is greater than ending LEB number.
 * %-EEXIST    - @leb_id is found.
 *
 * [failure] - error code:
 * %-ERANGE    - internal error.
 */
static
int __ssdfs_maptbl_cache_find_leb(void *kaddr,
				  unsigned sequence_id,
				  u64 leb_id,
				  struct ssdfs_maptbl_cache_search_result *res)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_maptbl_cache_item *cur_item;
	int cur_item_index = SSDFS_MAPTBL_MAIN_INDEX;
	struct ssdfs_leb2peb_pair *start_pair, *cur_pair;
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	u64 start_leb, end_leb;
	u64 start_diff, end_diff;
	u64 cur_leb_id;
	u16 items_count;
	int i = 0;
	int step, cur_index;
	bool disable_step = false;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !res);

	SSDFS_DBG("kaddr %p, sequence_id %u, "
		  "leb_id %llu, res %p\n",
		  kaddr, sequence_id, leb_id, res);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
	if (le16_to_cpu(hdr->sequence_id) != sequence_id) {
		SSDFS_ERR("invalid sequence_id %u\n", sequence_id);
		return -ERANGE;
	}

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("maptbl cache fragment %u is empty\n",
			  sequence_id);
		return -ERANGE;
	}

	start_pair = LEB2PEB_PAIR_AREA(kaddr);
	start_leb = le64_to_cpu(hdr->start_leb);
	end_leb = le64_to_cpu(hdr->end_leb);

	cur_item = &res->pebs[cur_item_index];

	switch (cur_item->state) {
	case SSDFS_MAPTBL_CACHE_ITEM_UNKNOWN:
		/*
		 * Continue the search for main item
		 */
		break;

	case SSDFS_MAPTBL_CACHE_ITEM_FOUND:
		cur_item_index = SSDFS_MAPTBL_RELATION_INDEX;
		cur_item = &res->pebs[cur_item_index];

		switch (cur_item->state) {
		case SSDFS_MAPTBL_CACHE_ITEM_UNKNOWN:
			/*
			 * Continue the search for relation item
			 */
			break;

		default:
			SSDFS_ERR("invalid search result's state %#x\n",
				  cur_item->state);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("invalid search result's state %#x\n",
			  cur_item->state);
		return -ERANGE;
	}

	if (leb_id < start_leb) {
		cur_item->state = SSDFS_MAPTBL_CACHE_ITEM_ABSENT;
		cur_item->folio_index = sequence_id;
		cur_item->item_index = 0;
		ssdfs_memcpy(&cur_item->found, 0, pair_size,
			     start_pair, 0, pair_size,
			     pair_size);
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("leb_id %llu, start_leb %llu, end_leb %llu\n",
			  leb_id, start_leb, end_leb);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EFAULT;
	}

	if (end_leb < leb_id) {
		size_t capacity = ssdfs_maptbl_cache_fragment_capacity();

		if ((items_count + 1) > capacity)
			return -E2BIG;
		else {
			cur_item->state = SSDFS_MAPTBL_CACHE_ITEM_ABSENT;
			cur_item->folio_index = sequence_id;
			cur_item->item_index = items_count;
			ssdfs_memcpy(&cur_item->found, 0, pair_size,
				     start_pair + items_count, 0, pair_size,
				     pair_size);
			return -ENODATA;
		}
	}

	start_diff = leb_id - start_leb;
	end_diff = end_leb - leb_id;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_diff %llu, end_diff %llu\n",
		  start_diff, end_diff);
#endif /* CONFIG_SSDFS_DEBUG */

	if (start_diff <= end_diff) {
		/* straight search */
		SSDFS_DBG("straight search\n");

		i = 0;
		cur_index = 0;
		step = 1;
		while (i < items_count) {
			cur_pair = start_pair + cur_index;
			cur_leb_id = le64_to_cpu(cur_pair->leb_id);

			if (leb_id < cur_leb_id) {
				disable_step = true;
				cur_index = i;
				cur_pair = start_pair + cur_index;
				cur_leb_id = le64_to_cpu(cur_pair->leb_id);
			}

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cur_index %d, step %d, "
				  "cur_leb_id %llu, leb_id %llu\n",
				  cur_index, step, cur_leb_id, leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

			if (leb_id > cur_leb_id)
				goto continue_straight_search;
			else if (cur_leb_id == leb_id) {
				return ssdfs_find_result_pair(hdr, sequence_id,
							      leb_id,
							      cur_item_index,
							      cur_index,
							      start_pair,
							      cur_pair,
							      res);
			} else {
				cur_item->state =
					SSDFS_MAPTBL_CACHE_ITEM_ABSENT;
				cur_item->folio_index = sequence_id;
				cur_item->item_index = cur_index;
				ssdfs_memcpy(&cur_item->found, 0, pair_size,
					     cur_pair, 0, pair_size,
					     pair_size);
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("leb_id %llu, start_leb %llu, end_leb %llu, "
					  "cur_leb_id %llu, cur_index %d, step %d\n",
					  leb_id, start_leb, end_leb,
					  cur_leb_id, cur_index, step);
#endif /* CONFIG_SSDFS_DEBUG */
				return -EFAULT;
			}

continue_straight_search:
			if (!disable_step)
				step *= 2;

			i = cur_index + 1;

			if (disable_step)
				cur_index = i;
			else if ((i + step) < items_count) {
				cur_index = i + step;
			} else {
				disable_step = true;
				cur_index = i;
			}
		}
	} else {
		/* reverse search */
		SSDFS_DBG("reverse search\n");

		i = items_count - 1;
		cur_index = i;
		step = 1;
		while (i >= 0) {
			cur_pair = start_pair + cur_index;
			cur_leb_id = le64_to_cpu(cur_pair->leb_id);

			if (leb_id > cur_leb_id) {
				disable_step = true;
				cur_index = i;
				cur_pair = start_pair + cur_index;
				cur_leb_id = le64_to_cpu(cur_pair->leb_id);
			}

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cur_index %d, step %d, "
				  "cur_leb_id %llu, leb_id %llu\n",
				  cur_index, step, cur_leb_id, leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

			if (leb_id < cur_leb_id)
				goto continue_reverse_search;
			else if (cur_leb_id == leb_id) {
				return ssdfs_find_result_pair(hdr, sequence_id,
							      leb_id,
							      cur_item_index,
							      cur_index,
							      start_pair,
							      cur_pair,
							      res);
			} else {
				cur_item->state =
					SSDFS_MAPTBL_CACHE_ITEM_ABSENT;
				cur_item->folio_index = sequence_id;
				cur_index++;
				cur_pair = start_pair + cur_index;
				cur_item->item_index = cur_index;
				ssdfs_memcpy(&cur_item->found, 0, pair_size,
					     cur_pair, 0, pair_size,
					     pair_size);
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("leb_id %llu, start_leb %llu, end_leb %llu, "
					  "cur_leb_id %llu, cur_index %d, step %d\n",
					  leb_id, start_leb, end_leb,
					  cur_leb_id, cur_index, step);
#endif /* CONFIG_SSDFS_DEBUG */
				return -EFAULT;
			}

continue_reverse_search:
			if (!disable_step)
				step *= 2;

			i = cur_index - 1;

			if (disable_step)
				cur_index = i;
			else if (i >= step && ((i - step) >= 0))
				cur_index = i - step;
			else {
				disable_step = true;
				cur_index = i;
			}
		};
	}

	return -ERANGE;
}

/*
 * ssdfs_maptbl_cache_get_leb2peb_pair() - get LEB2PEB pair
 * @kaddr: pointer on fragment's beginning
 * @item_index: index of item in the fragment
 * @pair: pointer on requested LEB2PEB pair [out]
 *
 * This method tries to prepare pointer on the requested
 * LEB2PEB pair in the fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL    - invalid input.
 */
static
int ssdfs_maptbl_cache_get_leb2peb_pair(void *kaddr, u16 item_index,
					struct ssdfs_leb2peb_pair **pair)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *start = NULL;
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	u16 items_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !pair);

	SSDFS_DBG("kaddr %p, item_index %u, pair %p\n",
		  kaddr, item_index, pair);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
	items_count = le16_to_cpu(hdr->items_count);

	if (item_index >= items_count) {
		SSDFS_ERR("item_index %u >= items_count %u\n",
			  item_index, items_count);
		return -EINVAL;
	}

	start = LEB2PEB_PAIR_AREA(kaddr);

	*pair = (struct ssdfs_leb2peb_pair *)((u8 *)start +
					(pair_size * item_index));

	return 0;
}

/*
 * ssdfs_maptbl_cache_get_peb_state() - get PEB state
 * @kaddr: pointer on fragment's beginning
 * @item_index: index of item in the fragment
 * @ptr: pointer on requested PEB state [out]
 *
 * This method tries to prepare pointer on the requested
 * PEB state in the fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL    - invalid input.
 * %-ERANGE    - internal error.
 */
static
int ssdfs_maptbl_cache_get_peb_state(void *kaddr, u16 item_index,
				     struct ssdfs_maptbl_cache_peb_state **ptr)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_maptbl_cache_peb_state *start = NULL;
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	u16 items_count;
	u32 area_offset = U32_MAX;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !ptr);

	SSDFS_DBG("kaddr %p, item_index %u, ptr %p\n",
		  kaddr, item_index, ptr);

	SSDFS_DBG("PAGE DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     kaddr, PAGE_SIZE);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
	items_count = le16_to_cpu(hdr->items_count);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("CACHE HEADER\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     kaddr, 32);
#endif /* CONFIG_SSDFS_DEBUG */

	if (item_index >= items_count) {
		SSDFS_ERR("item_index %u >= items_count %u\n",
			  item_index, items_count);
		return -EINVAL;
	}

	start = FIRST_PEB_STATE(kaddr, &area_offset);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("PEB STATE START\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     start, 32);
#endif /* CONFIG_SSDFS_DEBUG */

	if (IS_ERR_OR_NULL(start)) {
		err = start == NULL ? -ERANGE : PTR_ERR(start);
		SSDFS_ERR("fail to get area's start pointer: "
			  "err %d\n", err);
		return err;
	}

	*ptr = (struct ssdfs_maptbl_cache_peb_state *)((u8 *)start +
					    (peb_state_size * item_index));

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("MODIFIED ITEM\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     *ptr, 32);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_maptbl_cache_find_leb() - find LEB ID inside maptbl cache's fragment
 * @cache: maptbl cache object
 * @leb_id: LEB ID
 * @res: pointer on the extracted pair of descriptors [out]
 * @pebr: description of PEBs relation [out]
 *
 * This method tries to find LEB/PEB pair for requested LEB ID
 * inside of fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL    - invalid input.
 * %-ERANGE    - internal error.
 * %-EFAULT    - cache doesn't contain LEB/PEB pair.
 * %-ENODATA   - try to search in the next fragment.
 * %-EAGAIN    - try to search the relation LEB/PEB pair in the next folio.
 */
static
int ssdfs_maptbl_cache_find_leb(struct ssdfs_maptbl_cache *cache,
				u64 leb_id,
				struct ssdfs_maptbl_cache_search_result *res,
				struct ssdfs_maptbl_peb_relation *pebr)
{
	struct ssdfs_maptbl_cache_peb_state *peb_state = NULL;
	struct folio *folio;
	unsigned folio_index;
	u16 item_index;
	struct ssdfs_leb2peb_pair *found;
	void *kaddr;
	u64 peb_id = U64_MAX;
	unsigned i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache || !res || !pebr);
	BUG_ON(!rwsem_is_locked(&cache->lock));

	SSDFS_DBG("cache %p, leb_id %llu, res %p, pebr %p\n",
		  cache, leb_id, res, pebr);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(res, 0xFF, sizeof(struct ssdfs_maptbl_cache_search_result));
	res->pebs[SSDFS_MAPTBL_MAIN_INDEX].state =
				SSDFS_MAPTBL_CACHE_ITEM_UNKNOWN;
	res->pebs[SSDFS_MAPTBL_RELATION_INDEX].state =
				SSDFS_MAPTBL_CACHE_ITEM_UNKNOWN;

	memset(pebr, 0xFF, sizeof(struct ssdfs_maptbl_peb_relation));

	for (i = 0; i < folio_batch_count(&cache->batch); i++) {
		folio = cache->batch.folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);
		err = __ssdfs_maptbl_cache_find_leb(kaddr, i, leb_id, res);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("leb_id %llu, folio_index %u, err %d\n",
			  leb_id, i, err);
#endif /* CONFIG_SSDFS_DEBUG */

		if (err == -ENODATA || err == -E2BIG)
			continue;
		else if (err == -EAGAIN)
			continue;
		else if (err == -EFAULT) {
			err = -ENODATA;
			goto finish_leb_id_search;
		} else if (err == -EEXIST) {
			err = 0;
			break;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find LEB: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_leb_id_search;
		}
	}

	if (err == -ENODATA || err == -E2BIG) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find: leb_id %llu\n", leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		err = -ENODATA;
		goto finish_leb_id_search;
	}

	for (i = SSDFS_MAPTBL_MAIN_INDEX; i < SSDFS_MAPTBL_RELATION_MAX; i++) {
		switch (res->pebs[i].state) {
		case SSDFS_MAPTBL_CACHE_ITEM_FOUND:
			folio_index = res->pebs[i].folio_index;
			item_index = res->pebs[i].item_index;
			found = &res->pebs[i].found;

			if (folio_index >= folio_batch_count(&cache->batch)) {
				err = -ERANGE;
				SSDFS_ERR("invalid folio index %u\n",
					  folio_index);
				goto finish_leb_id_search;
			}

			folio = cache->batch.folios[folio_index];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_folio_lock(folio);
			kaddr = kmap_local_folio(folio, 0);
			err = ssdfs_maptbl_cache_get_peb_state(kaddr,
								item_index,
								&peb_state);
			kunmap_local(kaddr);
			ssdfs_folio_unlock(folio);

			if (unlikely(err)) {
				SSDFS_ERR("fail to get peb state: "
					  "item_index %u, err %d\n",
					  item_index, err);
				goto finish_leb_id_search;
			}

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!peb_state);
#endif /* CONFIG_SSDFS_DEBUG */

			if (le64_to_cpu(found->leb_id) != leb_id) {
				err = -ERANGE;
				SSDFS_ERR("leb_id1 %llu != leb_id2 %llu\n",
					  le64_to_cpu(found->leb_id),
					  leb_id);
				goto finish_leb_id_search;
			}

			peb_id = le64_to_cpu(found->peb_id);

			pebr->pebs[i].peb_id = peb_id;
			pebr->pebs[i].shared_peb_index =
					peb_state->shared_peb_index;
			pebr->pebs[i].type =
					SSDFS_MAPTBL_UNKNOWN_PEB_TYPE;
			pebr->pebs[i].state = peb_state->state;
			pebr->pebs[i].flags = peb_state->flags;
			pebr->pebs[i].consistency = peb_state->consistency;
			break;

		case SSDFS_MAPTBL_CACHE_ITEM_ABSENT:
			continue;

		default:
			err = -ERANGE;
			SSDFS_ERR("search failure: "
				  "leb_id %llu, index %u, state %#x\n",
				  leb_id, i, res->pebs[i].state);
			goto finish_leb_id_search;
		}
	}

finish_leb_id_search:
	return err;
}

/*
 * ssdfs_maptbl_cache_convert_leb2peb_nolock() - cache-based LEB/PEB conversion
 * @cache: maptbl cache object
 * @leb_id: LEB ID number
 * @pebr: description of PEBs relation [out]
 *
 * This method tries to convert LEB ID into PEB ID on the basis of
 * mapping table's cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - LEB doesn't mapped to PEB yet.
 */
int ssdfs_maptbl_cache_convert_leb2peb_nolock(struct ssdfs_maptbl_cache *cache,
					 u64 leb_id,
					 struct ssdfs_maptbl_peb_relation *pebr)
{
	struct ssdfs_maptbl_cache_search_result res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache || !pebr);
	BUG_ON(atomic_read(&cache->bytes_count) == 0);
	BUG_ON(folio_batch_count(&cache->batch) == 0);
	BUG_ON(atomic_read(&cache->bytes_count) >
		(folio_batch_count(&cache->batch) * PAGE_SIZE));
	BUG_ON(atomic_read(&cache->bytes_count) <=
		((folio_batch_count(&cache->batch) - 1) * PAGE_SIZE));
	BUG_ON(!rwsem_is_locked(&cache->lock));

	SSDFS_DBG("cache %p, leb_id %llu, pebr %p\n",
		  cache, leb_id, pebr);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_maptbl_cache_find_leb(cache, leb_id, &res, pebr);
	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to convert leb %llu to peb\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to convert leb %llu to peb: "
			  "err %d\n",
			  leb_id, err);
		return err;
	}

	return 0;
}

/*
 * __ssdfs_maptbl_cache_convert_leb2peb() - cache-based LEB/PEB conversion
 * @cache: maptbl cache object
 * @leb_id: LEB ID number
 * @pebr: description of PEBs relation [out]
 *
 * This method tries to convert LEB ID into PEB ID on the basis of
 * mapping table's cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - LEB doesn't mapped to PEB yet.
 */
int __ssdfs_maptbl_cache_convert_leb2peb(struct ssdfs_maptbl_cache *cache,
					 u64 leb_id,
					 struct ssdfs_maptbl_peb_relation *pebr)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache || !pebr);
	BUG_ON(atomic_read(&cache->bytes_count) == 0);
	BUG_ON(folio_batch_count(&cache->batch) == 0);
	BUG_ON(atomic_read(&cache->bytes_count) >
		(folio_batch_count(&cache->batch) * PAGE_SIZE));
	BUG_ON(atomic_read(&cache->bytes_count) <=
		((folio_batch_count(&cache->batch) - 1) * PAGE_SIZE));

	SSDFS_DBG("cache %p, leb_id %llu, pebr %p\n",
		  cache, leb_id, pebr);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&cache->lock);
	err = ssdfs_maptbl_cache_convert_leb2peb_nolock(cache, leb_id, pebr);
	up_read(&cache->lock);

	return err;
}

/*
 * ssdfs_maptbl_cache_convert_leb2peb() - maptbl cache-based LEB/PEB conversion
 * @cache: maptbl cache object
 * @leb_id: LEB ID number
 * @pebr: description of PEBs relation [out]
 *
 * This method tries to convert LEB ID into PEB ID on the basis of
 * mapping table's cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - LEB doesn't mapped to PEB yet.
 */
int ssdfs_maptbl_cache_convert_leb2peb(struct ssdfs_maptbl_cache *cache,
					u64 leb_id,
					struct ssdfs_maptbl_peb_relation *pebr)
{
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache || !pebr);
	BUG_ON(atomic_read(&cache->bytes_count) == 0);
	BUG_ON(folio_batch_count(&cache->batch) == 0);
	BUG_ON(atomic_read(&cache->bytes_count) >
		(folio_batch_count(&cache->batch) * PAGE_SIZE));
	BUG_ON(atomic_read(&cache->bytes_count) <=
		((folio_batch_count(&cache->batch) - 1) * PAGE_SIZE));

	SSDFS_DBG("cache %p, leb_id %llu, pebr %p\n",
		  cache, leb_id, pebr);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_maptbl_cache_convert_leb2peb(cache, leb_id, pebr);
	if (unlikely(err))
		goto finish_leb2peb_conversion;

	for (i = SSDFS_MAPTBL_MAIN_INDEX; i < SSDFS_MAPTBL_RELATION_MAX; i++) {
		struct ssdfs_peb_mapping_info *pmi = NULL;
		int consistency = pebr->pebs[i].consistency;
		u64 peb_id = pebr->pebs[i].peb_id;

		switch (consistency) {
		case SSDFS_PEB_STATE_INCONSISTENT:
		case SSDFS_PEB_STATE_PRE_DELETED:
			pmi = ssdfs_peb_mapping_info_alloc();
			if (IS_ERR_OR_NULL(pmi)) {
				err = !pmi ? -ENOMEM : PTR_ERR(pmi);
				SSDFS_ERR("fail to alloc PEB mapping info: "
					  "leb_id %llu, err %d\n",
					  leb_id, err);
				goto finish_leb2peb_conversion;
			}

			ssdfs_peb_mapping_info_init(leb_id, peb_id,
						    consistency, pmi);
			ssdfs_peb_mapping_queue_add_tail(&cache->pm_queue, pmi);
			break;
		}
	}

	switch (pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].consistency) {
	case SSDFS_PEB_STATE_PRE_DELETED:
		ssdfs_memcpy(&pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX],
			     0, sizeof(struct ssdfs_maptbl_peb_descriptor),
			     &pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX],
			     0, sizeof(struct ssdfs_maptbl_peb_descriptor),
			     sizeof(struct ssdfs_maptbl_peb_descriptor));
		pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].peb_id = U64_MAX;
		pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].shared_peb_index =
									U8_MAX;
		pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].type =
						SSDFS_MAPTBL_UNKNOWN_PEB_TYPE;
		pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].state = U8_MAX;
		pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].flags = 0;
		pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].consistency =
							SSDFS_PEB_STATE_UNKNOWN;
		break;

	default:
		/* do nothing */
		break;
	}

finish_leb2peb_conversion:
	return err;
}

/*
 * ssdfs_maptbl_cache_init_folio() - init folio of maptbl cache
 * @kaddr: pointer on maptbl cache's fragment
 * @sequence_id: fragment's sequence ID number
 *
 * This method initialize empty maptbl cache fragment's folio.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static
int ssdfs_maptbl_cache_init_folio(void *kaddr, unsigned sequence_id)
{
	struct ssdfs_maptbl_cache_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_maptbl_cache_header);
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	size_t magic_size = peb_state_size;
	size_t threshold_size = hdr_size + magic_size;
	__le32 *magic;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);

	SSDFS_DBG("kaddr %p, sequence_id %u\n",
		  kaddr, sequence_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (sequence_id >= PAGEVEC_SIZE) {
		SSDFS_ERR("invalid sequence_id %u\n",
			  sequence_id);
		return -EINVAL;
	}

	memset(kaddr, 0, PAGE_SIZE);

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	hdr->magic.common = cpu_to_le32(SSDFS_SUPER_MAGIC);
	hdr->magic.key = cpu_to_le16(SSDFS_MAPTBL_CACHE_MAGIC);
	hdr->magic.version.major = SSDFS_MAJOR_REVISION;
	hdr->magic.version.minor = SSDFS_MINOR_REVISION;

	hdr->sequence_id = cpu_to_le16((u16)sequence_id);
	hdr->items_count = 0;
	hdr->bytes_count = cpu_to_le16((u16)threshold_size);

	hdr->start_leb = cpu_to_le64(U64_MAX);
	hdr->end_leb = cpu_to_le64(U64_MAX);

	magic = (__le32 *)((u8 *)kaddr + hdr_size);
	*magic = cpu_to_le32(SSDFS_MAPTBL_CACHE_PEB_STATE_MAGIC);

	return 0;
}

/*
 * ssdfs_shift_right_peb_state_area() - shift the whole PEB state area
 * @kaddr: pointer on maptbl cache's fragment
 * @shift: size of shift in bytes
 *
 * This method tries to shift the whole PEB state area
 * to the right in the fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static inline
int ssdfs_shift_right_peb_state_area(void *kaddr, size_t shift)
{
	struct ssdfs_maptbl_cache_header *hdr;
	void *area = NULL;
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	size_t diff_count;
	int area_size;
	u32 area_offset = U32_MAX;
	size_t bytes_count, new_bytes_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);

	SSDFS_DBG("kaddr %p, shift %zu\n", kaddr, shift);
#endif /* CONFIG_SSDFS_DEBUG */

	if (shift % pair_size) {
		SSDFS_ERR("invalid request: "
			  "shift %zu, pair_size %zu\n",
			  shift, pair_size);
		return -ERANGE;
	}

	diff_count = shift / pair_size;

	if (diff_count == 0) {
		SSDFS_ERR("invalid diff_count %zu\n", diff_count);
		return -ERANGE;
	}

	area = PEB_STATE_AREA(kaddr, &area_offset);
	if (IS_ERR_OR_NULL(area)) {
		err = !area ? PTR_ERR(area) : -ERANGE;
		SSDFS_ERR("fail to get the PEB state area: "
			  "err %d\n", err);
		return err;
	}

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
	bytes_count = le16_to_cpu(hdr->bytes_count);

	area_size = ssdfs_peb_state_area_size(hdr);
	if (area_size < 0) {
		err = area_size;
		SSDFS_ERR("fail to calculate PEB state area's size: "
			  "err %d\n", err);
		return err;
	} else if (area_size == 0) {
		SSDFS_ERR("invalid PEB state area's size %d\n",
			  area_size);
		return -ERANGE;
	}

	new_bytes_count = bytes_count;
	new_bytes_count += diff_count * pair_size;
	new_bytes_count += diff_count * peb_state_size;

	if (new_bytes_count > PAGE_SIZE) {
		SSDFS_ERR("shift is out of memory folio: "
			  "new_bytes_count %zu, shift %zu\n",
			  new_bytes_count, shift);
		return -ERANGE;
	}

	err = ssdfs_memmove(area, shift, PAGE_SIZE - area_offset,
			    area, 0, PAGE_SIZE - area_offset,
			    area_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move: err %d\n", err);
		return err;
	}

	hdr->bytes_count = cpu_to_le16((u16)new_bytes_count);

	return 0;
}

/*
 * ssdfs_shift_left_peb_state_area() - shift the whole PEB state area
 * @kaddr: pointer on maptbl cache's fragment
 * @shift: size of shift in bytes
 *
 * This method tries to shift the whole PEB state area
 * to the left in the fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static inline
int ssdfs_shift_left_peb_state_area(void *kaddr, size_t shift)
{
	struct ssdfs_maptbl_cache_header *hdr;
	void *area = NULL;
	size_t hdr_size = sizeof(struct ssdfs_maptbl_cache_header);
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	size_t magic_size = peb_state_size;
	size_t threshold_size = hdr_size + magic_size;
	size_t diff_count;
	int area_size;
	u32 area_offset = U32_MAX;
	size_t bytes_count;
	size_t calculated;
	size_t new_bytes_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);

	SSDFS_DBG("kaddr %p, shift %zu\n", kaddr, shift);
#endif /* CONFIG_SSDFS_DEBUG */

	if (shift % pair_size) {
		SSDFS_ERR("invalid request: "
			  "shift %zu, pair_size %zu\n",
			  shift, pair_size);
		return -ERANGE;
	}

	diff_count = shift / pair_size;

	if (diff_count == 0) {
		SSDFS_ERR("invalid diff_count %zu\n", diff_count);
		return -ERANGE;
	}

	area = PEB_STATE_AREA(kaddr, &area_offset);

	if (IS_ERR_OR_NULL(area)) {
		err = !area ? PTR_ERR(area) : -ERANGE;
		SSDFS_ERR("fail to get the PEB state area: "
			  "err %d\n", err);
		return err;
	}

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
	bytes_count = le16_to_cpu(hdr->bytes_count);

	area_size = ssdfs_peb_state_area_size(hdr);
	if (area_size < 0) {
		err = area_size;
		SSDFS_ERR("fail to calculate PEB state area's size: "
			  "err %d\n", err);
		return err;
	} else if (area_size == 0) {
		SSDFS_ERR("invalid PEB state area's size %d\n",
			  area_size);
		return -ERANGE;
	}

	new_bytes_count = bytes_count;

	calculated = diff_count * pair_size;
	if (new_bytes_count <= calculated) {
		SSDFS_ERR("invalid diff_count %zu\n",
			  diff_count);
		return -ERANGE;
	}

	new_bytes_count -= calculated;

	calculated = diff_count * peb_state_size;

	if (new_bytes_count <= calculated) {
		SSDFS_ERR("invalid diff_count %zu\n",
			  diff_count);
		return -ERANGE;
	}

	new_bytes_count -= calculated;

	if (new_bytes_count < threshold_size) {
		SSDFS_ERR("shift is inside of header: "
			  "new_bytes_count %zu, threshold_size %zu\n",
			  new_bytes_count, threshold_size);
		return -ERANGE;
	}

	if ((threshold_size + shift) >= area_offset) {
		SSDFS_ERR("invalid shift: "
			  "threshold_size %zu, shift %zu, "
			  "area_offset %u\n",
			  threshold_size, shift, area_offset);
		return -ERANGE;
	}

	err = ssdfs_memmove((u8 *)area - shift, 0, PAGE_SIZE - area_offset,
			    area, 0, PAGE_SIZE - area_offset,
			    area_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move: err %d\n", err);
		return err;
	}

	hdr->bytes_count = cpu_to_le16((u16)new_bytes_count);

	return 0;
}

/*
 * ssdfs_maptbl_cache_add_leb() - add LEB/PEB pair into maptbl cache
 * @kaddr: pointer on maptbl cache's fragment
 * @item_index: index of item in the fragment
 * @src_pair: inserting LEB/PEB pair
 * @src_state: inserting PEB state
 *
 * This method tries to insert LEB/PEB pair and PEB state
 * into the maptbl cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_cache_add_leb(void *kaddr, u16 item_index,
				struct ssdfs_leb2peb_pair *src_pair,
				struct ssdfs_maptbl_cache_peb_state *src_state)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *dest_pair;
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	struct ssdfs_maptbl_cache_peb_state *dest_state;
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	u16 items_count;
	u32 area_offset = U32_MAX;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !src_pair || !src_state);

	SSDFS_DBG("kaddr %p, item_index %u, "
		  "leb_id %llu, peb_id %llu\n",
		  kaddr, item_index,
		  le64_to_cpu(src_pair->leb_id),
		  le64_to_cpu(src_pair->peb_id));
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);

	if (item_index != items_count) {
		SSDFS_ERR("item_index %u != items_count %u\n",
			  item_index, items_count);
		return -EINVAL;
	}

	err = ssdfs_shift_right_peb_state_area(kaddr, pair_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shift the PEB state area: "
			  "err %d\n", err);
		return err;
	}

	dest_pair = LEB2PEB_PAIR_AREA(kaddr);
	dest_pair += item_index;

	ssdfs_memcpy(dest_pair, 0, pair_size,
		     src_pair, 0, pair_size,
		     pair_size);

	dest_state = FIRST_PEB_STATE(kaddr, &area_offset);
	if (IS_ERR_OR_NULL(dest_state)) {
		err = !dest_state ? PTR_ERR(dest_state) : -ERANGE;
		SSDFS_ERR("fail to get the PEB state area: "
			  "err %d\n", err);
		return err;
	}

	dest_state += item_index;

	ssdfs_memcpy(dest_state, 0, peb_state_size,
		     src_state, 0, peb_state_size,
		     peb_state_size);

	items_count++;
	hdr->items_count = cpu_to_le16(items_count);

	if (item_index == 0)
		hdr->start_leb = src_pair->leb_id;

	if ((item_index + 1) == items_count)
		hdr->end_leb = src_pair->leb_id;

	return 0;
}

struct folio *
ssdfs_maptbl_cache_add_batch_folio(struct ssdfs_maptbl_cache *cache)
{
	struct folio *folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache);

	SSDFS_DBG("cache %p\n", cache);
#endif /* CONFIG_SSDFS_DEBUG */

	folio = ssdfs_map_cache_add_batch_folio(&cache->batch,
						get_order(PAGE_SIZE));
	if (unlikely(IS_ERR_OR_NULL(folio))) {
		err = !folio ? -ENOMEM : PTR_ERR(folio);
		SSDFS_ERR("fail to add folio: err %d\n",
			  err);
	}

	return folio;
}

/*
 * ssdfs_maptbl_cache_add_folio() - add fragment into maptbl cache
 * @cache: maptbl cache object
 * @pair: adding LEB/PEB pair
 * @state: adding PEB state
 *
 * This method tries to add fragment into maptbl cache,
 * initialize it and insert LEB/PEB pair + PEB state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to add empty folio into maptbl cache.
 */
static
int ssdfs_maptbl_cache_add_folio(struct ssdfs_maptbl_cache *cache,
				struct ssdfs_leb2peb_pair *pair,
				struct ssdfs_maptbl_cache_peb_state *state)
{
	struct folio *folio;
	void *kaddr;
	u16 item_index;
	unsigned folio_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache || !pair || !state);

	SSDFS_DBG("cache %p, leb_id %llu, peb_id %llu\n",
		  cache, le64_to_cpu(pair->leb_id),
		  le64_to_cpu(pair->peb_id));
#endif /* CONFIG_SSDFS_DEBUG */

	item_index = 0;
	folio_index = folio_batch_count(&cache->batch);

	folio = ssdfs_map_cache_add_batch_folio(&cache->batch,
						get_order(PAGE_SIZE));
	if (unlikely(IS_ERR_OR_NULL(folio))) {
		err = !folio ? -ENOMEM : PTR_ERR(folio);
		SSDFS_ERR("fail to add folio: err %d\n",
			  err);
		return err;
	}

	ssdfs_folio_lock(folio);
	kaddr = kmap_local_folio(folio, 0);

	err = ssdfs_maptbl_cache_init_folio(kaddr, folio_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init maptbl cache's folio: "
			  "folio_index %u, err %d\n",
			  folio_index, err);
		goto finish_add_folio;
	}

	atomic_add(PAGE_SIZE, &cache->bytes_count);

	err = ssdfs_maptbl_cache_add_leb(kaddr, item_index, pair, state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add leb_id: "
			  "folio_index %u, item_index %u, err %d\n",
			  folio_index, item_index, err);
		goto finish_add_folio;
	}

finish_add_folio:
	flush_dcache_folio(folio);
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);

	return err;
}

/*
 * is_fragment_full() - check that fragment is full
 * @kaddr: pointer on maptbl cache's fragment
 */
static inline
bool is_fragment_full(void *kaddr)
{
	struct ssdfs_maptbl_cache_header *hdr;
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	size_t bytes_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);

	SSDFS_DBG("kaddr %p\n", kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	bytes_count = le16_to_cpu(hdr->bytes_count);
	bytes_count += pair_size + peb_state_size;

	return bytes_count > PAGE_SIZE;
}

/*
 * ssdfs_maptbl_cache_get_last_item() - get last item of the fragment
 * @kaddr: pointer on maptbl cache's fragment
 * @pair: pointer on LEB2PEB pair's buffer [out]
 * @state: pointer on PEB state's buffer [out]
 *
 * This method tries to extract the last item
 * (LEB2PEB pair + PEB state) from the fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - empty maptbl cache's folio.
 */
static
int ssdfs_maptbl_cache_get_last_item(void *kaddr,
				     struct ssdfs_leb2peb_pair *pair,
				     struct ssdfs_maptbl_cache_peb_state *state)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *found_pair = NULL;
	struct ssdfs_maptbl_cache_peb_state *found_state = NULL;
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	u16 items_count;
	u32 area_offset = U32_MAX;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !pair || !state);

	SSDFS_DBG("kaddr %p, pair %p, peb_state %p\n",
		  kaddr, pair, state);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache's folio\n");
		return -ENODATA;
	}

	found_pair = LEB2PEB_PAIR_AREA(kaddr);
	found_pair += items_count - 1;

	ssdfs_memcpy(pair, 0, pair_size,
		     found_pair, 0, pair_size,
		     pair_size);

	found_state = FIRST_PEB_STATE(kaddr, &area_offset);
	if (IS_ERR_OR_NULL(found_state)) {
		err = !found_state ? PTR_ERR(found_state) : -ERANGE;
		SSDFS_ERR("fail to get the PEB state area: "
			  "err %d\n", err);
		return err;
	}

	found_state += items_count - 1;
	ssdfs_memcpy(state, 0, peb_state_size,
		     found_state, 0, peb_state_size,
		     peb_state_size);

	return 0;
}

/*
 * ssdfs_maptbl_cache_move_right_leb2peb_pairs() - move LEB2PEB pairs
 * @kaddr: pointer on maptbl cache's fragment
 * @item_index: starting index
 *
 * This method tries to move LEB2PEB pairs to the right
 * starting from @item_index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_cache_move_right_leb2peb_pairs(void *kaddr,
						u16 item_index)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *area;
	size_t hdr_size = sizeof(struct ssdfs_maptbl_cache_header);
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	u16 items_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);

	SSDFS_DBG("kaddr %p, item_index %u\n",
		  kaddr, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache folio\n");
		return -ERANGE;
	}

	if (item_index >= items_count) {
		SSDFS_ERR("item_index %u > items_count %u\n",
			  item_index, items_count);
		return -EINVAL;
	}

	area = LEB2PEB_PAIR_AREA(kaddr);
	err = ssdfs_memmove(area,
			    (item_index + 1) * pair_size,
			    PAGE_SIZE - hdr_size,
			    area,
			    item_index * pair_size,
			    PAGE_SIZE - hdr_size,
			    (items_count - item_index) * pair_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move: err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_maptbl_cache_move_right_peb_states() - move PEB states
 * @kaddr: pointer on maptbl cache's fragment
 * @item_index: starting index
 *
 * This method tries to move PEB states to the right
 * starting from @item_index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_cache_move_right_peb_states(void *kaddr,
					     u16 item_index)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_maptbl_cache_peb_state *area;
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	u16 items_count;
	u32 area_offset = U32_MAX;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);

	SSDFS_DBG("kaddr %p, item_index %u\n",
		  kaddr, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache folio\n");
		return -ERANGE;
	}

	if (item_index >= items_count) {
		SSDFS_ERR("item_index %u > items_count %u\n",
			  item_index, items_count);
		return -EINVAL;
	}

	area = FIRST_PEB_STATE(kaddr, &area_offset);
	if (IS_ERR_OR_NULL(area)) {
		err = !area ? PTR_ERR(area) : -ERANGE;
		SSDFS_ERR("fail to get the PEB state area: "
			  "err %d\n", err);
		return err;
	}

	err = ssdfs_memmove(area,
			    (item_index + 1) * peb_state_size,
			    PAGE_SIZE - area_offset,
			    area,
			    item_index * peb_state_size,
			    PAGE_SIZE - area_offset,
			    (items_count - item_index) * peb_state_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move: err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * __ssdfs_maptbl_cache_insert_leb() - insert item into the fragment
 * @kaddr: pointer on maptbl cache's fragment
 * @item_index: starting index
 * @pair: adding LEB2PEB pair
 * @state: adding PEB state
 *
 * This method tries to insert the item (LEB2PEB pair + PEB state)
 * into the fragment in @item_index position.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_maptbl_cache_insert_leb(void *kaddr, u16 item_index,
				    struct ssdfs_leb2peb_pair *pair,
				    struct ssdfs_maptbl_cache_peb_state *state)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *dst_pair = NULL;
	struct ssdfs_maptbl_cache_peb_state *dst_state = NULL;
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	u16 items_count;
	u32 area_offset = U32_MAX;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !pair || !state);

	SSDFS_DBG("kaddr %p, item_index %u, pair %p, state %p\n",
		  kaddr, item_index, pair, state);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache folio\n");
		return -ERANGE;
	}

	if (item_index >= items_count) {
		SSDFS_ERR("item_index %u > items_count %u\n",
			  item_index, items_count);
		return -EINVAL;
	}

	dst_pair = LEB2PEB_PAIR_AREA(kaddr);
	dst_pair += item_index;

	ssdfs_memcpy(dst_pair, 0, pair_size,
		     pair, 0, pair_size,
		     pair_size);

	dst_state = FIRST_PEB_STATE(kaddr, &area_offset);
	if (IS_ERR_OR_NULL(dst_state)) {
		err = !dst_state ? PTR_ERR(dst_state) : -ERANGE;
		SSDFS_ERR("fail to get the PEB state area: "
			  "err %d\n", err);
		return err;
	}

	dst_state += item_index;

	ssdfs_memcpy(dst_state, 0, peb_state_size,
		     state, 0, peb_state_size,
		     peb_state_size);

	items_count++;
	hdr->items_count = cpu_to_le16(items_count);

	if (item_index == 0)
		hdr->start_leb = pair->leb_id;

	if ((item_index + 1) == items_count)
		hdr->end_leb = pair->leb_id;

	return 0;
}

/*
 * ssdfs_maptbl_cache_remove_leb() - remove item from the fragment
 * @cache: maptbl cache object
 * @folio_index: index of the folio
 * @item_index: index of the item
 *
 * This method tries to remove the item (LEB/PEB pair + PEB state)
 * from the fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_cache_remove_leb(struct ssdfs_maptbl_cache *cache,
				  unsigned folio_index,
				  u16 item_index)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *cur_pair;
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	struct ssdfs_maptbl_cache_peb_state *cur_state;
	struct folio *folio;
	void *kaddr;
	u16 items_count;
	size_t size;
	u32 area_offset = U32_MAX;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache);
	BUG_ON(folio_index >= folio_batch_count(&cache->batch));

	SSDFS_DBG("cache %p, folio_index %u, item_index %u\n",
		  cache, folio_index, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	folio = cache->batch.folios[folio_index];

	ssdfs_folio_lock(folio);
	kaddr = kmap_local_folio(folio, 0);

#ifdef CONFIG_SSDFS_DEBUG
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				kaddr, PAGE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);

	if (item_index >= items_count) {
		err = -ERANGE;
		SSDFS_ERR("item_index %u >= items_count %u\n",
			  item_index, items_count);
		goto finish_remove_item;
	} else if (items_count == 0) {
		err = -ERANGE;
		SSDFS_ERR("items_count %u\n", items_count);
		goto finish_remove_item;
	}

	cur_pair = LEB2PEB_PAIR_AREA(kaddr);
	cur_pair += item_index;

	if ((item_index + 1) < items_count) {
		size = items_count - item_index;
		size *= pair_size;

		memmove(cur_pair, cur_pair + 1, size);
	}

	cur_pair = LEB2PEB_PAIR_AREA(kaddr);
	cur_pair += items_count - 1;
	memset(cur_pair, 0xFF, pair_size);

	cur_state = FIRST_PEB_STATE(kaddr, &area_offset);
	if (IS_ERR_OR_NULL(cur_state)) {
		err = !cur_state ? PTR_ERR(cur_state) : -ERANGE;
		SSDFS_ERR("fail to get the PEB state area: "
			  "err %d\n", err);
		goto finish_remove_item;
	}

	cur_state += item_index;

	if ((item_index + 1) < items_count) {
		size = items_count - item_index;
		size *= sizeof(struct ssdfs_maptbl_cache_peb_state);

		memmove(cur_state, cur_state + 1, size);
	}

	cur_state = FIRST_PEB_STATE(kaddr, &area_offset);
	cur_state += items_count - 1;
	memset(cur_state, 0xFF, sizeof(struct ssdfs_maptbl_cache_peb_state));

	items_count--;
	hdr->items_count = cpu_to_le16(items_count);

	err = ssdfs_shift_left_peb_state_area(kaddr, pair_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shift PEB state area: "
			  "err %d\n", err);
		goto finish_remove_item;
	}

	if (items_count == 0) {
		hdr->start_leb = U64_MAX;
		hdr->end_leb = U64_MAX;
	} else {
		cur_pair = LEB2PEB_PAIR_AREA(kaddr);
		hdr->start_leb = cur_pair->leb_id;

		cur_pair += items_count - 1;
		hdr->end_leb = cur_pair->leb_id;
	}

#ifdef CONFIG_SSDFS_DEBUG
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				kaddr, PAGE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

finish_remove_item:
	flush_dcache_folio(folio);
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);

	return err;
}

/*
 * ssdfs_check_pre_deleted_peb_state() - check pre-deleted state of the item
 * @cache: maptbl cache object
 * @folio_index: index of the folio
 * @item_index: index of the item
 * @pair: adding LEB2PEB pair
 *
 * This method tries to check that requested item for @item_index
 * has the PRE-DELETED consistency. If it's true then this item
 * has to be deleted.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - requested LEB is absent.
 * %-ENOENT     - requested LEB exists and should be saved.
 */
static
int ssdfs_check_pre_deleted_peb_state(struct ssdfs_maptbl_cache *cache,
				     unsigned folio_index,
				     u16 item_index,
				     struct ssdfs_leb2peb_pair *pair)
{
	struct ssdfs_leb2peb_pair *cur_pair = NULL;
	struct ssdfs_maptbl_cache_peb_state *cur_state = NULL;
	struct folio *folio;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache || !pair);
	BUG_ON(le64_to_cpu(pair->leb_id) == U64_MAX);
	BUG_ON(le64_to_cpu(pair->peb_id) == U64_MAX);

	SSDFS_DBG("cache %p, start_folio %u, item_index %u\n",
		  cache, folio_index, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	folio = cache->batch.folios[folio_index];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_folio_lock(folio);
	kaddr = kmap_local_folio(folio, 0);

	err = ssdfs_maptbl_cache_get_leb2peb_pair(kaddr, item_index, &cur_pair);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get LEB2PEB pair: err %d\n", err);
		goto finish_check_pre_deleted_state;
	}

	if (le64_to_cpu(pair->leb_id) != le64_to_cpu(cur_pair->leb_id)) {
		err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("pair->leb_id %llu != cur_pair->leb_id %llu\n",
			  le64_to_cpu(pair->leb_id),
			  le64_to_cpu(cur_pair->leb_id));
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_check_pre_deleted_state;
	}

	err = ssdfs_maptbl_cache_get_peb_state(kaddr, item_index, &cur_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get PEB state: err %d\n", err);
		goto finish_check_pre_deleted_state;
	}

	switch (cur_state->consistency) {
	case SSDFS_PEB_STATE_CONSISTENT:
	case SSDFS_PEB_STATE_INCONSISTENT:
		err = -ENOENT;
		goto finish_check_pre_deleted_state;

	case SSDFS_PEB_STATE_PRE_DELETED:
		/* continue to delete */
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("unexpected PEB's state %#x\n",
			  cur_state->state);
		goto finish_check_pre_deleted_state;
	}

finish_check_pre_deleted_state:
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);

	if (err)
		return err;

	err = ssdfs_maptbl_cache_remove_leb(cache,
					    folio_index,
					    item_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete LEB: "
			  "folio_index %d, item_index %u, err %d\n",
			  folio_index, item_index, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_maptbl_cache_insert_leb() - insert item into the fragment
 * @cache: maptbl cache object
 * @start_folio: folio index
 * @item_index: index of the item
 * @pair: adding LEB/PEB pair
 * @state: adding PEB state
 *
 * This method tries to insert the item (LEB2PEB pair + PEB state)
 * into the mapping table cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_cache_insert_leb(struct ssdfs_maptbl_cache *cache,
				  unsigned start_folio,
				  u16 item_index,
				  struct ssdfs_leb2peb_pair *pair,
				  struct ssdfs_maptbl_cache_peb_state *state)
{
	struct ssdfs_leb2peb_pair cur_pair, saved_pair;
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	struct ssdfs_maptbl_cache_peb_state cur_state, saved_state;
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	struct folio *folio;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache || !pair || !state);
	BUG_ON(le64_to_cpu(pair->leb_id) == U64_MAX);
	BUG_ON(le64_to_cpu(pair->peb_id) == U64_MAX);

	SSDFS_DBG("cache %p, start_folio %u, item_index %u, "
		  "leb_id %llu, peb_id %llu\n",
		  cache, start_folio, item_index,
		  le64_to_cpu(pair->leb_id),
		  le64_to_cpu(pair->peb_id));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_check_pre_deleted_peb_state(cache, start_folio,
						item_index, pair);
	if (err == -ENODATA) {
		err = 0;
		/*
		 * No pre-deleted item was found.
		 * Continue the logic.
		 */
	} else if (err == -ENOENT) {
		/*
		 * Valid item was found.
		 */
		err = 0;
		item_index++;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to check the pre-deleted state: "
			  "err %d\n", err);
		return err;
	}

	ssdfs_memcpy(&cur_pair, 0, pair_size,
		     pair, 0, pair_size,
		     pair_size);
	ssdfs_memcpy(&cur_state, 0, peb_state_size,
		     state, 0, peb_state_size,
		     peb_state_size);

	memset(&saved_pair, 0xFF, pair_size);
	memset(&saved_state, 0xFF, peb_state_size);

	for (; start_folio < folio_batch_count(&cache->batch); start_folio++) {
		bool need_move_item = false;

		folio = cache->batch.folios[start_folio];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);

		need_move_item = is_fragment_full(kaddr);

		if (need_move_item) {
			err = ssdfs_maptbl_cache_get_last_item(kaddr,
							       &saved_pair,
							       &saved_state);
			if (unlikely(err)) {
				SSDFS_ERR("fail to get last item: "
					  "err %d\n", err);
				goto finish_folio_modification;
			}
		}

#ifdef CONFIG_SSDFS_DEBUG
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr, PAGE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_shift_right_peb_state_area(kaddr, pair_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to shift the PEB state area: "
				  "err %d\n", err);
			goto finish_folio_modification;
		}

#ifdef CONFIG_SSDFS_DEBUG
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr, PAGE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_maptbl_cache_move_right_leb2peb_pairs(kaddr,
								item_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move LEB2PEB pairs: "
				  "folio_index %u, item_index %u, "
				  "err %d\n",
				  start_folio, item_index, err);
			goto finish_folio_modification;
		}

#ifdef CONFIG_SSDFS_DEBUG
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr, PAGE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_maptbl_cache_move_right_peb_states(kaddr,
								item_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move PEB states: "
				  "folio_index %u, item_index %u, "
				  "err %d\n",
				  start_folio, item_index, err);
			goto finish_folio_modification;
		}

#ifdef CONFIG_SSDFS_DEBUG
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr, PAGE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

		err = __ssdfs_maptbl_cache_insert_leb(kaddr, item_index,
						      &cur_pair, &cur_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert leb descriptor: "
				  "folio_index %u, item_index %u, err %d\n",
				  start_folio, item_index, err);
			goto finish_folio_modification;
		}

#ifdef CONFIG_SSDFS_DEBUG
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr, PAGE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

finish_folio_modification:
		flush_dcache_folio(folio);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);

		if (err || !need_move_item)
			goto finish_insert_leb;

		item_index = 0;

		if (need_move_item) {
			ssdfs_memcpy(&cur_pair, 0, pair_size,
				     &saved_pair, 0, pair_size,
				     pair_size);
			ssdfs_memcpy(&cur_state, 0, peb_state_size,
				     &saved_state, 0, peb_state_size,
				     peb_state_size);
		}
	}

	err = ssdfs_maptbl_cache_add_folio(cache, &cur_pair, &cur_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add folio into maptbl cache: "
			  "err %d\n",
			  err);
	}

finish_insert_leb:
	return err;
}

/*
 * ssdfs_maptbl_cache_map_leb2peb() - save LEB/PEB pair into maptbl cache
 * @cache: maptbl cache object
 * @leb_id: LEB ID number
 * @pebr: descriptor of mapped LEB/PEB pair
 * @consistency: consistency of the item
 *
 * This method tries to save the item (LEB/PEB pair + PEB state)
 * into maptbl cache. If the item is consistent then it means that
 * as mapping table cache as mapping table contain the same
 * information about the item. Otherwise, for the case of inconsistent
 * state, the mapping table cache contains the actual info about
 * the item.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - LEB/PEB pair is cached already.
 */
int ssdfs_maptbl_cache_map_leb2peb(struct ssdfs_maptbl_cache *cache,
				   u64 leb_id,
				   struct ssdfs_maptbl_peb_relation *pebr,
				   int consistency)
{
	struct ssdfs_maptbl_cache_search_result res;
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *tmp_pair = NULL;
	u16 item_index = U16_MAX;
	struct ssdfs_leb2peb_pair cur_pair;
	struct ssdfs_maptbl_cache_peb_state cur_state;
	struct folio *folio;
	void *kaddr;
	unsigned i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache || !pebr);
	BUG_ON(leb_id == U64_MAX);

	SSDFS_DBG("cache %p, leb_id %llu, pebr %p, consistency %#x\n",
		  cache, leb_id, pebr, consistency);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(&res, 0xFF, sizeof(struct ssdfs_maptbl_cache_search_result));
	res.pebs[SSDFS_MAPTBL_MAIN_INDEX].state =
				SSDFS_MAPTBL_CACHE_ITEM_UNKNOWN;
	res.pebs[SSDFS_MAPTBL_RELATION_INDEX].state =
				SSDFS_MAPTBL_CACHE_ITEM_UNKNOWN;

	cur_pair.leb_id = cpu_to_le64(leb_id);
	cur_pair.peb_id =
		cpu_to_le64(pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id);

	switch (consistency) {
	case SSDFS_PEB_STATE_CONSISTENT:
	case SSDFS_PEB_STATE_INCONSISTENT:
		/* expected state */
		break;

	default:
		SSDFS_ERR("unexpected consistency %#x\n",
			  consistency);
		return -EINVAL;
	}

	cur_state.consistency = (u8)consistency;
	cur_state.state = pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state;
	cur_state.flags = pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].flags;
	cur_state.shared_peb_index =
		pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].shared_peb_index;

	down_write(&cache->lock);

	for (i = 0; i < folio_batch_count(&cache->batch); i++) {
		folio = cache->batch.folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);
		err = __ssdfs_maptbl_cache_find_leb(kaddr, i, leb_id, &res);
		item_index = res.pebs[SSDFS_MAPTBL_MAIN_INDEX].item_index;
		tmp_pair = &res.pebs[SSDFS_MAPTBL_MAIN_INDEX].found;
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);

		if (err == -EEXIST) {
			SSDFS_ERR("maptbl cache contains leb_id %llu\n",
				  leb_id);
			break;
		} else if (err == -EFAULT) {
			/* we've found place */
			break;
		} else if (!err)
			BUG();
	}

	if (i >= folio_batch_count(&cache->batch)) {
		if (err == -ENODATA) {
			/* correct folio index */
			i = folio_batch_count(&cache->batch) - 1;
		} else {
			err = -ERANGE;
			SSDFS_ERR("i %u >= folios_count %u\n",
				  i, folio_batch_count(&cache->batch));
			goto finish_leb_caching;
		}
	}

	if (err == -EEXIST)
		goto finish_leb_caching;
	else if (err == -E2BIG) {
		err = ssdfs_maptbl_cache_add_folio(cache, &cur_pair, &cur_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add folio into maptbl cache: "
				  "err %d\n",
				  err);
			goto finish_leb_caching;
		}
	} else if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(i >= folio_batch_count(&cache->batch));
#endif /* CONFIG_SSDFS_DEBUG */

		folio = cache->batch.folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);
		hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
		item_index = le16_to_cpu(hdr->items_count);
		err = ssdfs_maptbl_cache_add_leb(kaddr, item_index,
						 &cur_pair, &cur_state);
		flush_dcache_folio(folio);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);

		if (unlikely(err)) {
			SSDFS_ERR("fail to add leb_id: "
				  "folio_index %u, item_index %u, err %d\n",
				  i, item_index, err);
		}
	} else if (err == -EFAULT) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(i >= folio_batch_count(&cache->batch));
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_maptbl_cache_insert_leb(cache, i, item_index,
						    &cur_pair, &cur_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add LEB with shift: "
				  "folio_index %u, item_index %u, err %d\n",
				  i, item_index, err);
			goto finish_leb_caching;
		}
	} else
		BUG();

finish_leb_caching:
	up_write(&cache->lock);

	return err;
}

/*
 * __ssdfs_maptbl_cache_change_peb_state() - change PEB state of the item
 * @cache: maptbl cache object
 * @folio_index: index of memory folio
 * @item_index: index of the item in the folio
 * @peb_state: new state of the PEB
 * @consistency: consistency of the item
 *
 * This method tries to change the PEB state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - unable to get peb state.
 * %-ERANGE     - internal error.
 */
static inline
int __ssdfs_maptbl_cache_change_peb_state(struct ssdfs_maptbl_cache *cache,
					  unsigned folio_index,
					  u16 item_index,
					  int peb_state,
					  int consistency)
{
	struct ssdfs_maptbl_cache_peb_state *found_state = NULL;
	struct folio *folio;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache);
	BUG_ON(!rwsem_is_locked(&cache->lock));

	SSDFS_DBG("cache %p, folio_index %u, item_index %u, "
		  "peb_state %#x, consistency %#x\n",
		  cache, folio_index, item_index,
		  peb_state, consistency);
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio_index >= folio_batch_count(&cache->batch)) {
		SSDFS_ERR("invalid folio index %u\n", folio_index);
		return -ERANGE;
	}

	folio = cache->batch.folios[folio_index];
	ssdfs_folio_lock(folio);
	kaddr = kmap_local_folio(folio, 0);

	err = ssdfs_maptbl_cache_get_peb_state(kaddr, item_index,
						&found_state);
	if (err == -EINVAL) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to get peb state: "
			  "item_index %u\n",
			  item_index);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_folio_modification;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to get peb state: "
			  "item_index %u, err %d\n",
			  item_index, err);
		goto finish_folio_modification;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!found_state);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (consistency) {
	case SSDFS_PEB_STATE_CONSISTENT:
		found_state->consistency = (u8)consistency;
		found_state->state = (u8)peb_state;
		break;

	case SSDFS_PEB_STATE_INCONSISTENT:
		if (found_state->state != (u8)peb_state) {
			found_state->consistency = (u8)consistency;
			found_state->state = (u8)peb_state;
		}
		break;

	case SSDFS_PEB_STATE_PRE_DELETED:
		found_state->consistency = (u8)consistency;
		found_state->state = (u8)peb_state;
		break;

	default:
		SSDFS_ERR("unexpected consistency %#x\n",
			  consistency);
		return -EINVAL;
	}

finish_folio_modification:
	flush_dcache_folio(folio);
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);

	return err;
}

/*
 * ssdfs_maptbl_cache_define_relation_index() - define relation index
 * @pebr: descriptor of mapped LEB/PEB pair
 * @peb_state: new state of the PEB
 * @relation_index: index of the item in relation [out]
 */
static int
ssdfs_maptbl_cache_define_relation_index(struct ssdfs_maptbl_peb_relation *pebr,
					 int peb_state,
					 int *relation_index)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebr || !relation_index);

	SSDFS_DBG("MAIN_INDEX: peb_id %llu, type %#x, "
		  "state %#x, consistency %#x; "
		  "RELATION_INDEX: peb_id %llu, type %#x, "
		  "state %#x, consistency %#x\n",
		  pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id,
		  pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].type,
		  pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
		  pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].consistency,
		  pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].peb_id,
		  pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].type,
		  pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].state,
		  pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].consistency);
#endif /* CONFIG_SSDFS_DEBUG */

	*relation_index = SSDFS_MAPTBL_RELATION_MAX;

	switch (peb_state) {
	case SSDFS_MAPTBL_CLEAN_PEB_STATE:
	case SSDFS_MAPTBL_USING_PEB_STATE:
	case SSDFS_MAPTBL_USED_PEB_STATE:
	case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
	case SSDFS_MAPTBL_DIRTY_PEB_STATE:
		switch (pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].consistency) {
		case SSDFS_PEB_STATE_CONSISTENT:
		case SSDFS_PEB_STATE_INCONSISTENT:
			*relation_index = SSDFS_MAPTBL_MAIN_INDEX;
			break;

		case SSDFS_PEB_STATE_PRE_DELETED:
			*relation_index = SSDFS_MAPTBL_RELATION_INDEX;
			break;

		default:
			BUG();
		}
		break;

	case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
	case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
	case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
		switch (pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].consistency) {
		case SSDFS_PEB_STATE_CONSISTENT:
		case SSDFS_PEB_STATE_INCONSISTENT:
			*relation_index = SSDFS_MAPTBL_MAIN_INDEX;
			break;

		case SSDFS_PEB_STATE_PRE_DELETED:
			SSDFS_ERR("main index is pre-deleted\n");
			break;

		default:
			BUG();
		}
		break;

	case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
		switch (pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].consistency) {
		case SSDFS_PEB_STATE_CONSISTENT:
		case SSDFS_PEB_STATE_INCONSISTENT:
			*relation_index = SSDFS_MAPTBL_RELATION_INDEX;
			break;

		case SSDFS_PEB_STATE_PRE_DELETED:
			SSDFS_ERR("main index is pre-deleted\n");
			break;

		default:
			BUG();
		}
		break;

	default:
		SSDFS_ERR("unexpected peb_state %#x\n", peb_state);
		return -EINVAL;
	}

	if (*relation_index == SSDFS_MAPTBL_RELATION_MAX) {
		SSDFS_ERR("fail to define relation index\n");
		return -ERANGE;
	}

	return 0;
}

/*
 * can_peb_state_be_changed() - check that PEB state can be changed
 * @pebr: descriptor of mapped LEB/PEB pair
 * @peb_state: new state of the PEB
 * @consistency: consistency of the item
 * @relation_index: index of the item in relation
 */
static
bool can_peb_state_be_changed(struct ssdfs_maptbl_peb_relation *pebr,
				int peb_state,
				int consistency,
				int relation_index)
{
	int old_consistency = SSDFS_PEB_STATE_UNKNOWN;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebr);

	SSDFS_DBG("peb_state %#x, consistency %#x, relation_index %d\n",
		  peb_state, consistency, relation_index);

	SSDFS_DBG("MAIN_INDEX: peb_id %llu, type %#x, "
		  "state %#x, consistency %#x; "
		  "RELATION_INDEX: peb_id %llu, type %#x, "
		  "state %#x, consistency %#x\n",
		  pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id,
		  pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].type,
		  pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
		  pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].consistency,
		  pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].peb_id,
		  pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].type,
		  pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].state,
		  pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].consistency);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (relation_index) {
	case SSDFS_MAPTBL_MAIN_INDEX:
		old_consistency =
			pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].consistency;

		switch (consistency) {
		case SSDFS_PEB_STATE_CONSISTENT:
		case SSDFS_PEB_STATE_INCONSISTENT:
			switch (old_consistency) {
			case SSDFS_PEB_STATE_PRE_DELETED:
				SSDFS_WARN("invalid consistency: "
					   "peb_state %#x, consistency %#x, "
					   "relation_index %d\n",
					   peb_state,
					   consistency,
					   relation_index);
				return false;

			case SSDFS_PEB_STATE_CONSISTENT:
			case SSDFS_PEB_STATE_INCONSISTENT:
				/* valid consistency */
				break;

			default:
				SSDFS_WARN("invalid old consistency %#x\n",
					   old_consistency);
				return false;
			}

		case SSDFS_PEB_STATE_PRE_DELETED:
			/* valid consistency */
			break;

		default:
			SSDFS_WARN("invalid consistency: "
				   "peb_state %#x, consistency %#x, "
				   "relation_index %d\n",
				   peb_state,
				   consistency,
				   relation_index);
			return false;
		}

		switch (pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state) {
		case SSDFS_MAPTBL_CLEAN_PEB_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_CLEAN_PEB_STATE:
			case SSDFS_MAPTBL_USING_PEB_STATE:
			case SSDFS_MAPTBL_USED_PEB_STATE:
			case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_USING_PEB_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_CLEAN_PEB_STATE:
			case SSDFS_MAPTBL_USING_PEB_STATE:
			case SSDFS_MAPTBL_USED_PEB_STATE:
			case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_USED_PEB_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_CLEAN_PEB_STATE:
			case SSDFS_MAPTBL_USING_PEB_STATE:
			case SSDFS_MAPTBL_USED_PEB_STATE:
			case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_CLEAN_PEB_STATE:
			case SSDFS_MAPTBL_USING_PEB_STATE:
			case SSDFS_MAPTBL_USED_PEB_STATE:
			case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_DIRTY_PEB_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_CLEAN_PEB_STATE:
			case SSDFS_MAPTBL_USING_PEB_STATE:
			case SSDFS_MAPTBL_USED_PEB_STATE:
			case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_CLEAN_PEB_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_USING_PEB_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_USED_PEB_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_DIRTY_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		default:
			BUG();
		}
		break;

	case SSDFS_MAPTBL_RELATION_INDEX:
		old_consistency =
			pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].consistency;

		switch (consistency) {
		case SSDFS_PEB_STATE_CONSISTENT:
		case SSDFS_PEB_STATE_INCONSISTENT:
			switch (old_consistency) {
			case SSDFS_PEB_STATE_CONSISTENT:
			case SSDFS_PEB_STATE_INCONSISTENT:
				/* valid consistency */
				break;

			default:
				SSDFS_WARN("invalid old consistency %#x\n",
					   old_consistency);
				return false;
			}
			break;

		default:
			SSDFS_WARN("invalid consistency: "
				   "peb_state %#x, consistency %#x, "
				   "relation_index %d\n",
				   peb_state,
				   consistency,
				   relation_index);
			return false;
		}

		switch (pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].state) {
		case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
			case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
			case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
			case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
			case SSDFS_MAPTBL_CLEAN_PEB_STATE:
			case SSDFS_MAPTBL_USING_PEB_STATE:
			case SSDFS_MAPTBL_USED_PEB_STATE:
			case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
			case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
			case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
			case SSDFS_MAPTBL_CLEAN_PEB_STATE:
			case SSDFS_MAPTBL_USING_PEB_STATE:
			case SSDFS_MAPTBL_USED_PEB_STATE:
			case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
			case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
			case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
			case SSDFS_MAPTBL_CLEAN_PEB_STATE:
			case SSDFS_MAPTBL_USING_PEB_STATE:
			case SSDFS_MAPTBL_USED_PEB_STATE:
			case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
			case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
			case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
			case SSDFS_MAPTBL_CLEAN_PEB_STATE:
			case SSDFS_MAPTBL_USING_PEB_STATE:
			case SSDFS_MAPTBL_USED_PEB_STATE:
			case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_DIRTY_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
			case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
			case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
			case SSDFS_MAPTBL_MIGRATION_DST_DIRTY_STATE:
			case SSDFS_MAPTBL_CLEAN_PEB_STATE:
			case SSDFS_MAPTBL_USING_PEB_STATE:
			case SSDFS_MAPTBL_USED_PEB_STATE:
			case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_USING_PEB_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_CLEAN_PEB_STATE:
			case SSDFS_MAPTBL_USING_PEB_STATE:
			case SSDFS_MAPTBL_USED_PEB_STATE:
			case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_USED_PEB_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_CLEAN_PEB_STATE:
			case SSDFS_MAPTBL_USING_PEB_STATE:
			case SSDFS_MAPTBL_USED_PEB_STATE:
			case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_CLEAN_PEB_STATE:
			case SSDFS_MAPTBL_USING_PEB_STATE:
			case SSDFS_MAPTBL_USED_PEB_STATE:
			case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		case SSDFS_MAPTBL_DIRTY_PEB_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_CLEAN_PEB_STATE:
			case SSDFS_MAPTBL_USING_PEB_STATE:
			case SSDFS_MAPTBL_USED_PEB_STATE:
			case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
				goto finish_check;

			default:
				SSDFS_ERR("invalid change: "
					  "old peb_state %#x, "
					  "new peb_state %#x\n",
				    pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].state,
				    peb_state);
				return false;
			}
			break;

		default:
			BUG();
		}
		break;

	default:
		BUG();
	}

finish_check:
	return true;
}

/*
 * ssdfs_maptbl_cache_change_peb_state_nolock() - change PEB state of the item
 * @cache: maptbl cache object
 * @leb_id: LEB ID number
 * @peb_state: new state of the PEB
 * @consistency: consistency of the item
 *
 * This method tries to change the PEB state. If the item is consistent
 * then it means that as mapping table cache as mapping table
 * contain the same information about the item. Otherwise,
 * for the case of inconsistent state, the mapping table cache contains
 * the actual info about the item.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_maptbl_cache_change_peb_state_nolock(struct ssdfs_maptbl_cache *cache,
						u64 leb_id, int peb_state,
						int consistency)
{
	struct ssdfs_maptbl_cache_search_result res;
	struct ssdfs_maptbl_peb_relation pebr;
	int relation_index = SSDFS_MAPTBL_RELATION_MAX;
	int state;
	unsigned folio_index;
	u16 item_index = U16_MAX;
	unsigned i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache);
	BUG_ON(leb_id == U64_MAX);
	BUG_ON(!rwsem_is_locked(&cache->lock));

	SSDFS_DBG("cache %p, leb_id %llu, peb_state %#x, consistency %#x\n",
		  cache, leb_id, peb_state, consistency);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (consistency) {
	case SSDFS_PEB_STATE_CONSISTENT:
	case SSDFS_PEB_STATE_INCONSISTENT:
	case SSDFS_PEB_STATE_PRE_DELETED:
		/* expected state */
		break;

	default:
		SSDFS_ERR("unexpected consistency %#x\n",
			  consistency);
		return -EINVAL;
	}

	switch (peb_state) {
	case SSDFS_MAPTBL_CLEAN_PEB_STATE:
	case SSDFS_MAPTBL_USING_PEB_STATE:
	case SSDFS_MAPTBL_USED_PEB_STATE:
	case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
	case SSDFS_MAPTBL_DIRTY_PEB_STATE:
	case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
	case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
	case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_DIRTY_STATE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("unexpected peb_state %#x\n", peb_state);
		return -EINVAL;
	}

	err = ssdfs_maptbl_cache_find_leb(cache, leb_id, &res, &pebr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find: leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_peb_state_change;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("MAIN_INDEX: state %#x, folio_index %u, item_index %u; "
		  "RELATION_INDEX: state %#x, folio_index %u, item_index %u\n",
		  res.pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
		  res.pebs[SSDFS_MAPTBL_MAIN_INDEX].folio_index,
		  res.pebs[SSDFS_MAPTBL_MAIN_INDEX].item_index,
		  res.pebs[SSDFS_MAPTBL_RELATION_INDEX].state,
		  res.pebs[SSDFS_MAPTBL_RELATION_INDEX].folio_index,
		  res.pebs[SSDFS_MAPTBL_RELATION_INDEX].item_index);

	SSDFS_DBG("MAIN_INDEX: peb_id %llu, type %#x, "
		  "state %#x, consistency %#x; "
		  "RELATION_INDEX: peb_id %llu, type %#x, "
		  "state %#x, consistency %#x\n",
		  pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id,
		  pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].type,
		  pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
		  pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].consistency,
		  pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].peb_id,
		  pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].type,
		  pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].state,
		  pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].consistency);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_maptbl_cache_define_relation_index(&pebr, peb_state,
							&relation_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define relation index: "
			  "leb_id %llu, peb_state %#x, err %d\n",
			  leb_id, peb_state, err);
		goto finish_peb_state_change;
	}

	if (!can_peb_state_be_changed(&pebr, peb_state,
					consistency, relation_index)) {
		err = -ERANGE;
		SSDFS_ERR("PEB state cannot be changed: "
			  "leb_id %llu, peb_state %#x, "
			  "consistency %#x, relation_index %d\n",
			  leb_id, peb_state, consistency, relation_index);
		goto finish_peb_state_change;
	}

	state = res.pebs[relation_index].state;
	if (state != SSDFS_MAPTBL_CACHE_ITEM_FOUND) {
		err = -ERANGE;
		SSDFS_ERR("fail to change peb state: "
			  "state %#x\n",
			  state);
		goto finish_peb_state_change;
	}

	folio_index = res.pebs[relation_index].folio_index;
	item_index = res.pebs[relation_index].item_index;

	err = __ssdfs_maptbl_cache_change_peb_state(cache,
						    folio_index,
						    item_index,
						    peb_state,
						    consistency);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change peb state: "
			  "folio_index %u, item_index %u, "
			  "err %d\n",
			  folio_index, item_index, err);
		goto finish_peb_state_change;
	}

finish_peb_state_change:
	if (unlikely(err)) {
		struct folio *folio;
		void *kaddr;

		for (i = 0; i < folio_batch_count(&cache->batch); i++) {
			folio = cache->batch.folios[i];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_folio_lock(folio);
			kaddr = kmap_local_folio(folio, 0);
			ssdfs_maptbl_cache_show_items(kaddr);
			kunmap_local(kaddr);
			ssdfs_folio_unlock(folio);
		}
	}

	return err;
}

/*
 * ssdfs_maptbl_cache_change_peb_state() - change PEB state of the item
 * @cache: maptbl cache object
 * @leb_id: LEB ID number
 * @peb_state: new state of the PEB
 * @consistency: consistency of the item
 *
 * This method tries to change the PEB state. If the item is consistent
 * then it means that as mapping table cache as mapping table
 * contain the same information about the item. Otherwise,
 * for the case of inconsistent state, the mapping table cache contains
 * the actual info about the item.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_maptbl_cache_change_peb_state(struct ssdfs_maptbl_cache *cache,
					u64 leb_id, int peb_state,
					int consistency)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache);
	BUG_ON(leb_id == U64_MAX);

	SSDFS_DBG("cache %p, leb_id %llu, peb_state %#x, consistency %#x\n",
		  cache, leb_id, peb_state, consistency);
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&cache->lock);
	err = ssdfs_maptbl_cache_change_peb_state_nolock(cache,
							 leb_id,
							 peb_state,
							 consistency);
	up_write(&cache->lock);

	return err;
}

/*
 * ssdfs_maptbl_cache_add_migration_peb() - add item for migration PEB
 * @cache: maptbl cache object
 * @leb_id: LEB ID number
 * @pebr: descriptor of mapped LEB/PEB pair
 * @consistency: consistency of the item
 *
 * This method tries to add the item (LEB2PEB pair + PEB state)
 * for the migration PEB. If the item is consistent
 * then it means that as mapping table cache as mapping table
 * contain the same information about the item. Otherwise,
 * for the case of inconsistent state, the mapping table cache contains
 * the actual info about the item.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_maptbl_cache_add_migration_peb(struct ssdfs_maptbl_cache *cache,
					 u64 leb_id,
					 struct ssdfs_maptbl_peb_relation *pebr,
					 int consistency)
{
	struct ssdfs_maptbl_cache_search_result res;
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *tmp_pair = NULL;
	u16 item_index = U16_MAX, items_count = U16_MAX;
	struct ssdfs_leb2peb_pair cur_pair;
	struct ssdfs_maptbl_cache_peb_state cur_state;
	struct folio *folio;
	void *kaddr;
	unsigned i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache || !pebr);
	BUG_ON(leb_id == U64_MAX);

	SSDFS_DBG("cache %p, leb_id %llu, pebr %p, consistency %#x\n",
		  cache, leb_id, pebr, consistency);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(&res, 0xFF, sizeof(struct ssdfs_maptbl_cache_search_result));
	res.pebs[SSDFS_MAPTBL_MAIN_INDEX].state =
				SSDFS_MAPTBL_CACHE_ITEM_UNKNOWN;
	res.pebs[SSDFS_MAPTBL_RELATION_INDEX].state =
				SSDFS_MAPTBL_CACHE_ITEM_UNKNOWN;

	cur_pair.leb_id = cpu_to_le64(leb_id);
	cur_pair.peb_id =
		cpu_to_le64(pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].peb_id);

	switch (consistency) {
	case SSDFS_PEB_STATE_CONSISTENT:
	case SSDFS_PEB_STATE_INCONSISTENT:
		/* expected state */
		break;

	default:
		SSDFS_ERR("unexpected consistency %#x\n",
			  consistency);
		return -EINVAL;
	}

	cur_state.consistency = (u8)consistency;
	cur_state.state = pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].state;
	cur_state.flags = pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].flags;
	cur_state.shared_peb_index =
		pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].shared_peb_index;

	down_write(&cache->lock);

	for (i = 0; i < folio_batch_count(&cache->batch); i++) {
		folio = cache->batch.folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);
		hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
		items_count = le16_to_cpu(hdr->items_count);
		err = __ssdfs_maptbl_cache_find_leb(kaddr, i, leb_id, &res);
		item_index = res.pebs[SSDFS_MAPTBL_MAIN_INDEX].item_index;
		tmp_pair = &res.pebs[SSDFS_MAPTBL_MAIN_INDEX].found;
		flush_dcache_folio(folio);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);

		if (err == -EEXIST || err == -EFAULT)
			break;
		else if (err != -E2BIG && err != -ENODATA)
			break;
		else if (err == -EAGAIN)
			continue;
		else if (!err)
			BUG();
	}

	if (err != -EEXIST && err != -EAGAIN) {
		SSDFS_ERR("maptbl cache hasn't item for leb_id %llu, err %d\n",
			  leb_id, err);

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);
		ssdfs_maptbl_cache_show_items(kaddr);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);

		goto finish_add_migration_peb;
	}

	if ((item_index + 1) >= ssdfs_maptbl_cache_fragment_capacity()) {
		err = ssdfs_maptbl_cache_add_folio(cache, &cur_pair, &cur_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add folio into maptbl cache: "
				  "err %d\n",
				  err);
			goto finish_add_migration_peb;
		}
	} else if ((item_index + 1) < items_count) {
		err = ssdfs_maptbl_cache_insert_leb(cache, i, item_index,
						    &cur_pair, &cur_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert LEB: "
				  "folio_index %u, item_index %u, err %d\n",
				  i, item_index, err);
			goto finish_add_migration_peb;
		}
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(i >= folio_batch_count(&cache->batch));
#endif /* CONFIG_SSDFS_DEBUG */

		folio = cache->batch.folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);
		hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
		item_index = le16_to_cpu(hdr->items_count);
		err = ssdfs_maptbl_cache_add_leb(kaddr, item_index,
						 &cur_pair, &cur_state);
		flush_dcache_folio(folio);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);

		if (unlikely(err)) {
			SSDFS_ERR("fail to add leb_id: "
				  "folio_index %u, item_index %u, err %d\n",
				  i, item_index, err);
			goto finish_add_migration_peb;
		}
	}

finish_add_migration_peb:
	up_write(&cache->lock);

	return err;
}

/*
 * ssdfs_maptbl_cache_get_first_item() - get first item of the fragment
 * @kaddr: pointer on maptbl cache's fragment
 * @pair: pointer on LEB2PEB pair's buffer [out]
 * @state: pointer on PEB state's buffer [out]
 *
 * This method tries to retrieve the first item of the fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - empty maptbl cache folio.
 */
static
int ssdfs_maptbl_cache_get_first_item(void *kaddr,
				     struct ssdfs_leb2peb_pair *pair,
				     struct ssdfs_maptbl_cache_peb_state *state)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *found_pair = NULL;
	struct ssdfs_maptbl_cache_peb_state *found_state = NULL;
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	u16 items_count;
	u32 area_offset = U32_MAX;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !pair || !state);

	SSDFS_DBG("kaddr %p, pair %p, peb_state %p\n",
		  kaddr, pair, state);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache folio\n");
		return -ENODATA;
	}

	found_pair = LEB2PEB_PAIR_AREA(kaddr);
	ssdfs_memcpy(pair, 0, pair_size,
		     found_pair, 0, pair_size,
		     pair_size);

	found_state = FIRST_PEB_STATE(kaddr, &area_offset);
	if (IS_ERR_OR_NULL(found_state)) {
		err = !found_state ? PTR_ERR(found_state) : -ERANGE;
		SSDFS_ERR("fail to get the PEB state area: "
			  "err %d\n", err);
		return err;
	}

	ssdfs_memcpy(state, 0, peb_state_size,
		     found_state, 0, peb_state_size,
		     peb_state_size);

	return 0;
}

/*
 * ssdfs_maptbl_cache_move_left_leb2peb_pairs() - move LEB2PEB pairs
 * @kaddr: pointer on maptbl cache's fragment
 * @item_index: starting index
 *
 * This method tries to move the LEB2PEB pairs on one position
 * to the left starting from @item_index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
#ifdef CONFIG_SSDFS_UNDER_DEVELOPMENT_FUNC
static
int ssdfs_maptbl_cache_move_left_leb2peb_pairs(void *kaddr,
						u16 item_index)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *area;
	size_t hdr_size = sizeof(struct ssdfs_maptbl_cache_header);
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	u16 items_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);

	SSDFS_DBG("kaddr %p, item_index %u\n",
		  kaddr, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (item_index == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("do nothing: item_index %u\n",
			  item_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache folio\n");
		return -ERANGE;
	}

	if (item_index >= items_count) {
		SSDFS_ERR("item_index %u > items_count %u\n",
			  item_index, items_count);
		return -EINVAL;
	}

	area = LEB2PEB_PAIR_AREA(kaddr);
	err = ssdfs_memmove(area,
			    (item_index - 1) * pair_size,
			    PAGE_SIZE - hdr_size,
			    area,
			    item_index * pair_size,
			    PAGE_SIZE - hdr_size,
			    (items_count - item_index) * pair_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move: err %d\n", err);
		return err;
	}

	return 0;
}
#endif /* CONFIG_SSDFS_UNDER_DEVELOPMENT_FUNC */

/*
 * ssdfs_maptbl_cache_move_left_peb_states() - move PEB states
 * @kaddr: pointer on maptbl cache's fragment
 * @item_index: starting index
 *
 * This method tries to move the PEB states on one position
 * to the left starting from @item_index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
#ifdef CONFIG_SSDFS_UNDER_DEVELOPMENT_FUNC
static
int ssdfs_maptbl_cache_move_left_peb_states(void *kaddr,
					     u16 item_index)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_maptbl_cache_peb_state *area;
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	u16 items_count;
	u32 area_offset = U32_MAX;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);

	SSDFS_DBG("kaddr %p, item_index %u\n",
		  kaddr, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (item_index == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("do nothing: item_index %u\n",
			  item_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache folio\n");
		return -ERANGE;
	}

	if (item_index >= items_count) {
		SSDFS_ERR("item_index %u > items_count %u\n",
			  item_index, items_count);
		return -EINVAL;
	}

	area = FIRST_PEB_STATE(kaddr, &area_offset);
	if (IS_ERR_OR_NULL(area)) {
		err = !area ? PTR_ERR(area) : -ERANGE;
		SSDFS_ERR("fail to get the PEB state area: "
			  "err %d\n", err);
		return err;
	}

	err = ssdfs_memmove(area,
			    (item_index - 1) * peb_state_size,
			    PAGE_SIZE - area_offset,
			    area,
			    item_index * peb_state_size,
			    PAGE_SIZE - area_offset,
			    (items_count - item_index) * peb_state_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move: err %d\n", err);
		return err;
	}

	return 0;
}
#endif /* CONFIG_SSDFS_UNDER_DEVELOPMENT_FUNC */

/*
 * ssdfs_maptbl_cache_forget_leb2peb_nolock() - exclude LEB/PEB pair from cache
 * @cache: maptbl cache object
 * @leb_id: LEB ID number
 * @consistency: consistency of the item
 *
 * This method tries to exclude LEB/PEB pair from the cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_maptbl_cache_forget_leb2peb_nolock(struct ssdfs_maptbl_cache *cache,
					     u64 leb_id,
					     int consistency)
{
	struct ssdfs_maptbl_cache_search_result res;
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *found_pair = NULL;
	struct ssdfs_leb2peb_pair saved_pair;
	struct ssdfs_maptbl_cache_peb_state *found_state = NULL;
	struct ssdfs_maptbl_cache_peb_state saved_state;
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	struct folio *folio;
	void *kaddr;
	u16 item_index, items_count;
	unsigned i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache);
	BUG_ON(leb_id == U64_MAX);
	BUG_ON(!rwsem_is_locked(&cache->lock));

	SSDFS_DBG("cache %p, leb_id %llu, consistency %#x\n",
		  cache, leb_id, consistency);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(&res, 0xFF, sizeof(struct ssdfs_maptbl_cache_search_result));
	res.pebs[SSDFS_MAPTBL_MAIN_INDEX].state =
				SSDFS_MAPTBL_CACHE_ITEM_UNKNOWN;
	res.pebs[SSDFS_MAPTBL_RELATION_INDEX].state =
				SSDFS_MAPTBL_CACHE_ITEM_UNKNOWN;

	switch (consistency) {
	case SSDFS_PEB_STATE_CONSISTENT:
	case SSDFS_PEB_STATE_PRE_DELETED:
		/* expected state */
		break;

	default:
		SSDFS_ERR("unexpected consistency %#x\n",
			  consistency);
		return -EINVAL;
	}

	for (i = 0; i < folio_batch_count(&cache->batch); i++) {
		struct ssdfs_maptbl_cache_header *hdr;
		int search_state;

		folio = cache->batch.folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);

		hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
		items_count = le16_to_cpu(hdr->items_count);

		err = __ssdfs_maptbl_cache_find_leb(kaddr, i, leb_id, &res);
		item_index = res.pebs[SSDFS_MAPTBL_MAIN_INDEX].item_index;
		found_pair = &res.pebs[SSDFS_MAPTBL_MAIN_INDEX].found;
		search_state = res.pebs[SSDFS_MAPTBL_RELATION_INDEX].state;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("MAIN_INDEX: state %#x, "
			  "folio_index %u, item_index %u; "
			  "RELATION_INDEX: state %#x, "
			  "folio_index %u, item_index %u\n",
			  res.pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
			  res.pebs[SSDFS_MAPTBL_MAIN_INDEX].folio_index,
			  res.pebs[SSDFS_MAPTBL_MAIN_INDEX].item_index,
			  res.pebs[SSDFS_MAPTBL_RELATION_INDEX].state,
			  res.pebs[SSDFS_MAPTBL_RELATION_INDEX].folio_index,
			  res.pebs[SSDFS_MAPTBL_RELATION_INDEX].item_index);
#endif /* CONFIG_SSDFS_DEBUG */

		if (err == -EEXIST || err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(le64_to_cpu(found_pair->leb_id) != leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

			switch (search_state) {
			case SSDFS_MAPTBL_CACHE_ITEM_FOUND:
				if ((item_index + 1) >= items_count) {
					err = -ERANGE;
					SSDFS_ERR("invalid position found: "
						  "item_index %u, "
						  "items_count %u\n",
						  item_index, items_count);
				}
				break;

			case SSDFS_MAPTBL_CACHE_ITEM_ABSENT:
				if ((item_index + 1) > items_count) {
					err = -ERANGE;
					SSDFS_ERR("invalid position found: "
						  "item_index %u, "
						  "items_count %u\n",
						  item_index, items_count);
				}
				break;

			default:
				SSDFS_ERR("unexpected state %#x\n",
					  search_state);
				break;
			}

			err = ssdfs_maptbl_cache_get_peb_state(kaddr,
							       item_index,
							       &found_state);
			if (unlikely(err)) {
				SSDFS_ERR("fail to get peb state: "
					  "item_index %u, err %d\n",
					  item_index, err);
			} else {
				ssdfs_memcpy(&saved_state, 0, peb_state_size,
					     found_state, 0, peb_state_size,
					     peb_state_size);
			}

			/* it is expected existence of the item */
			err = -EEXIST;
		}

		flush_dcache_folio(folio);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);

		if (err == -EEXIST || err == -EFAULT)
			break;
		else if (err != -E2BIG && err != -ENODATA)
			break;
		else if (!err)
			BUG();
	}

	if (err != -EEXIST)
		goto finish_exclude_migration_peb;

	if (consistency == SSDFS_PEB_STATE_PRE_DELETED) {
		/* simply change the state */
		goto finish_exclude_migration_peb;
	} else {
		unsigned folio_index = i;
		u16 deleted_item = item_index;
		u8 new_peb_state = SSDFS_MAPTBL_UNKNOWN_PEB_STATE;

		err = ssdfs_maptbl_cache_remove_leb(cache, i, item_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to remove LEB: "
				  "folio_index %u, item_index %u, err %d\n",
				  i, item_index, err);
			goto finish_exclude_migration_peb;
		}

		for (++i; i < folio_batch_count(&cache->batch); i++) {
			folio = cache->batch.folios[i];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_folio_lock(folio);
			kaddr = kmap_local_folio(folio, 0);
			err = ssdfs_maptbl_cache_get_first_item(kaddr,
							       &saved_pair,
							       &saved_state);
			kunmap_local(kaddr);
			ssdfs_folio_unlock(folio);

			if (unlikely(err)) {
				SSDFS_ERR("fail to get first item: "
					  "err %d\n", err);
				goto finish_exclude_migration_peb;
			}

			folio = cache->batch.folios[i - 1];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_folio_lock(folio);
			kaddr = kmap_local_folio(folio, 0);

			hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
			items_count = le16_to_cpu(hdr->items_count);
			if (items_count == 0)
				item_index = 0;
			else
				item_index = items_count;

			err = ssdfs_maptbl_cache_add_leb(kaddr, item_index,
							 &saved_pair,
							 &saved_state);

			flush_dcache_folio(folio);
			kunmap_local(kaddr);
			ssdfs_folio_unlock(folio);

			if (unlikely(err)) {
				SSDFS_ERR("fail to add leb_id: "
					  "folio_index %u, item_index %u, "
					  "err %d\n",
					  i, item_index, err);
				goto finish_exclude_migration_peb;
			}

			item_index = 0;
			err = ssdfs_maptbl_cache_remove_leb(cache, i,
							    item_index);
			if (unlikely(err)) {
				SSDFS_ERR("fail to remove LEB: "
					  "folio_index %u, item_index %u, "
					  "err %d\n",
					  i, item_index, err);
				goto finish_exclude_migration_peb;
			}
		}

		i = folio_batch_count(&cache->batch);
		if (i == 0) {
			err = -ERANGE;
			SSDFS_ERR("invalid number of fragments %u\n", i);
			goto finish_exclude_migration_peb;
		} else
			i--;

		if (i < folio_index) {
			err = -ERANGE;
			SSDFS_ERR("invalid folio index: "
				  "i %u, folio_index %u\n",
				  i, folio_index);
			goto finish_exclude_migration_peb;
		}

		folio = cache->batch.folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);
		hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
		items_count = le16_to_cpu(hdr->items_count);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);

		if (items_count == 0) {
			cache->batch.folios[i] = NULL;
			cache->batch.nr--;
			ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, count %d\n",
				  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_map_cache_free_folio(folio);
			atomic_sub(PAGE_SIZE, &cache->bytes_count);

			if (i == folio_index) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("do nothing: "
					  "folio %u was deleted\n",
					  folio_index);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_exclude_migration_peb;
			}
		}

		switch (saved_state.state) {
		case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
		case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
		case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
			/* continue logic */
			break;

		default:
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("do not change PEB state: "
				  "folio_index %u, deleted_item %u, "
				  "state %#x\n",
				  folio_index, deleted_item,
				  saved_state.state);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_exclude_migration_peb;
		}

		if (deleted_item >= items_count) {
			err = -ERANGE;
			SSDFS_ERR("deleted_item %u >= items_count %u\n",
				  deleted_item, items_count);
			goto finish_exclude_migration_peb;
		}

		folio = cache->batch.folios[folio_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);
		err = ssdfs_maptbl_cache_get_peb_state(kaddr,
						       deleted_item,
						       &found_state);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);

		if (unlikely(err)) {
			SSDFS_ERR("fail to get peb state: "
				  "item_index %u, err %d\n",
				  deleted_item, err);
			goto finish_exclude_migration_peb;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("found_state->state %#x\n",
			  found_state->state);
#endif /* CONFIG_SSDFS_DEBUG */

		switch (found_state->state) {
		case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
			new_peb_state = SSDFS_MAPTBL_CLEAN_PEB_STATE;
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
			new_peb_state = SSDFS_MAPTBL_USING_PEB_STATE;
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
			new_peb_state = SSDFS_MAPTBL_USED_PEB_STATE;
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
			new_peb_state = SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE;
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_DIRTY_STATE:
			new_peb_state = SSDFS_MAPTBL_DIRTY_PEB_STATE;
			break;

		default:
			/* do nothing */
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("PEB not under migration: "
				  "state %#x\n",
				  found_state->state);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_exclude_migration_peb;
		}

		err = __ssdfs_maptbl_cache_change_peb_state(cache,
							    folio_index,
							    deleted_item,
							    new_peb_state,
							    consistency);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change peb state: "
				  "folio_index %u, item_index %u, "
				  "err %d\n",
				  folio_index, deleted_item, err);
			goto finish_exclude_migration_peb;
		}
	}

finish_exclude_migration_peb:
	if (consistency == SSDFS_PEB_STATE_PRE_DELETED) {
		err = ssdfs_maptbl_cache_change_peb_state_nolock(cache, leb_id,
							    saved_state.state,
							    consistency);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change PEB state: err %d\n", err);
			return err;
		}
	}

	return err;
}

/*
 * ssdfs_maptbl_cache_exclude_migration_peb() - exclude migration PEB
 * @cache: maptbl cache object
 * @leb_id: LEB ID number
 * @consistency: consistency of the item
 *
 * This method tries to exclude LEB/PEB pair after
 * finishing the migration.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_maptbl_cache_exclude_migration_peb(struct ssdfs_maptbl_cache *cache,
					     u64 leb_id,
					     int consistency)
{
	int err;

	down_write(&cache->lock);
	err = ssdfs_maptbl_cache_forget_leb2peb_nolock(cache, leb_id,
							consistency);
	up_write(&cache->lock);

	return err;
}

/*
 * ssdfs_maptbl_cache_forget_leb2peb() - exclude LEB/PEB pair from cache
 * @cache: maptbl cache object
 * @leb_id: LEB ID number
 * @consistency: consistency of the item
 *
 * This method tries to exclude LEB/PEB pair from the cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_maptbl_cache_forget_leb2peb(struct ssdfs_maptbl_cache *cache,
				      u64 leb_id,
				      int consistency)
{
	int err;

	down_write(&cache->lock);
	err = ssdfs_maptbl_cache_forget_leb2peb_nolock(cache, leb_id,
							consistency);
	up_write(&cache->lock);

	return err;
}
