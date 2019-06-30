//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_mapping_table_cache.c - PEB mapping table cache functionality.
 *
 * Copyright (c) 2014-2018 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2009-2018, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
 */

#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "page_array.h"
#include "peb_mapping_table.h"

#include <trace/events/ssdfs.h>

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("hdr %p\n", hdr);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("hdr %p\n", hdr);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("hdr %p\n", hdr);

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
void *PEB_STATE_AREA(void *kaddr)
{
	struct ssdfs_maptbl_cache_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_maptbl_cache_header);
	size_t leb2peb_area_size;
	size_t peb_state_area_size;
	void *start = NULL;
	__le32 *magic = NULL;
	int err;

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

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
struct ssdfs_maptbl_cache_peb_state *FIRST_PEB_STATE(void *kaddr)
{
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	size_t magic_size = peb_state_size;
	void *start = PEB_STATE_AREA(kaddr);

	if (IS_ERR_OR_NULL(start))
		return (struct ssdfs_maptbl_cache_peb_state *)start;

	return (struct ssdfs_maptbl_cache_peb_state *)((u8 *)start +
							magic_size);
}

/*
 * __ssdfs_maptbl_cache_find_leb() - find position of LEB
 * @kaddr: pointer on maptbl cache's fragment
 * @sequence_id: fragment ID
 * @leb_id: LEB ID
 * @found: pointer on found LEB/PEB pair [out]
 * @item_index: pointer on index of found LEB/PEB pair [out]
 *
 * This method tries to find position of LEB for extracting
 * or inserting a LEB/PEB pair.
 *
 * RETURN:
 * [success] - error code:
 * %-EFAULT    - @leb_id doesn't found; position can be used for inserting.
 * %-E2BIG     - page is full; @leb_id is greater than ending LEB number.
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
				  struct ssdfs_leb2peb_pair **found,
				  u16 *item_index)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *start_pair, *cur_pair;
	u64 start_leb, end_leb;
	u64 start_diff, end_diff;
	u64 cur_leb_id;
	u16 items_count;
	int i = 0;
	int step, cur_index;
	bool disable_step = false;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, sequence_id %u, "
		  "leb_id %llu, item_index %p\n",
		  kaddr, sequence_id, leb_id, item_index);

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
	*item_index = U16_MAX;
	*found = NULL;

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

	if (leb_id < start_leb) {
		*item_index = 0;
		*found = start_pair;
		return -EFAULT;
	}

	if (end_leb < leb_id) {
		size_t capacity = ssdfs_maptbl_cache_fragment_capacity();

		if ((items_count + 1) > capacity)
			return -E2BIG;
		else {
			*item_index = items_count;
			*found = start_pair + items_count;
			return -ENODATA;
		}
	}

	start_diff = leb_id - start_leb;
	end_diff = end_leb - leb_id;

	if (start_diff <= end_diff) {
		/* straight search */
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

			if (leb_id > cur_leb_id)
				goto continue_straight_search;
			else if (cur_leb_id == leb_id) {
				*item_index = cur_index;
				*found = cur_pair;
				return -EEXIST;
			} else {
				*item_index = cur_index;
				*found = cur_pair;
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

			if (leb_id < cur_leb_id)
				goto continue_reverse_search;
			else if (cur_leb_id == leb_id) {
				*item_index = cur_index;
				*found = cur_pair;

				if (*item_index > 0) {
					cur_pair--;
					cur_leb_id =
						le64_to_cpu(cur_pair->leb_id);

					if (cur_leb_id == leb_id) {
						--*item_index;
						*found = cur_pair;
					} else
						return -EEXIST;
				}

				if (*item_index > 0) {
					cur_pair--;
					cur_leb_id =
					    le64_to_cpu(cur_pair->leb_id);

					if (cur_leb_id == leb_id) {
						SSDFS_ERR("unexpected pairs\n");
						return -ERANGE;
					} else
						return -EEXIST;
				}
			} else {
				*item_index = cur_index;
				*found = cur_pair;
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, item_index %u, pair %p\n",
		  kaddr, item_index, pair);

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
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, item_index %u, ptr %p\n",
		  kaddr, item_index, ptr);

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
	items_count = le16_to_cpu(hdr->items_count);

	if (item_index >= items_count) {
		SSDFS_ERR("item_index %u >= items_count %u\n",
			  item_index, items_count);
		return -EINVAL;
	}

	start = FIRST_PEB_STATE(kaddr);

	if (IS_ERR_OR_NULL(start)) {
		err = start == NULL ? -ERANGE : PTR_ERR(start);
		SSDFS_ERR("fail to get area's start pointer: "
			  "err %d\n", err);
		return err;
	}

	*ptr = (struct ssdfs_maptbl_cache_peb_state *)((u8 *)start +
					    (peb_state_size * item_index));

	return 0;
}

/*
 * ssdfs_maptbl_cache_find_leb() - find LEB ID inside maptbl cache's fragment
 * @kaddr: pointer on maptbl cache's fragment
 * @sequence_id: fragment ID
 * @leb_id: LEB ID
 * @descriptor_index: index of descriptor in relation
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
 * %-EAGAIN    - try to search the relation LEB/PEB pair in the next page.
 */
static
int ssdfs_maptbl_cache_find_leb(void *kaddr,
				unsigned sequence_id,
				u64 leb_id,
				int descriptor_index,
				struct ssdfs_maptbl_peb_relation *pebr)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *found = NULL;
	struct ssdfs_maptbl_cache_peb_state *peb_state = NULL;
	u16 item_index = U16_MAX;
	u16 items_count;
	u64 peb_id1 = U64_MAX, peb_id2 = U64_MAX;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !pebr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, leb_id %llu, descriptor_index %d, pebr %p\n",
		  kaddr, leb_id, descriptor_index, pebr);

	memset(pebr, 0xFF, sizeof(struct ssdfs_maptbl_peb_relation));

	if (descriptor_index < 0 ||
	    descriptor_index >= SSDFS_MAPTBL_RELATION_MAX) {
		SSDFS_ERR("invalid descriptor_index %d\n",
			  descriptor_index);
		return -EINVAL;
	}

	err = __ssdfs_maptbl_cache_find_leb(kaddr, sequence_id, leb_id,
					    &found, &item_index);
	if (err == -EEXIST) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!found || item_index == U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		peb_id1 = le64_to_cpu(found->peb_id);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(peb_id1 == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	} else
		return !err ? -ERANGE : err;

	err = ssdfs_maptbl_cache_get_peb_state(kaddr, item_index,
						&peb_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get peb state: "
			  "item_index %u, err %d\n",
			  item_index, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!peb_state);
#endif /* CONFIG_SSDFS_DEBUG */

	pebr->pebs[descriptor_index].peb_id = peb_id1;
	pebr->pebs[descriptor_index].shared_peb_index =
					peb_state->shared_peb_index;
	pebr->pebs[descriptor_index].type =
				SSDFS_MAPTBL_UNKNOWN_PEB_TYPE;
	pebr->pebs[descriptor_index].state = peb_state->state;
	pebr->pebs[descriptor_index].flags = peb_state->flags;
	pebr->pebs[descriptor_index].consistency = peb_state->consistency;

	if (descriptor_index == SSDFS_MAPTBL_RELATION_INDEX)
		return 0;

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
	items_count = le16_to_cpu(hdr->items_count);

	if ((item_index + 1) > items_count) {
		/* try the next page */
		return -EAGAIN;
	}

	descriptor_index++;
	found++;
	peb_state++;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(leb_id > le64_to_cpu(found->leb_id));
#endif /* CONFIG_SSDFS_DEBUG */

	if (le64_to_cpu(found->leb_id) != leb_id)
		goto finish_leb_conversion;

	peb_id2 = le64_to_cpu(found->peb_id);

	pebr->pebs[descriptor_index].peb_id = peb_id2;
	pebr->pebs[descriptor_index].shared_peb_index =
					peb_state->shared_peb_index;
	pebr->pebs[descriptor_index].type =
				SSDFS_MAPTBL_UNKNOWN_PEB_TYPE;
	pebr->pebs[descriptor_index].state = peb_state->state;
	pebr->pebs[descriptor_index].flags = peb_state->flags;
	pebr->pebs[descriptor_index].consistency = peb_state->consistency;

finish_leb_conversion:
	return 0;
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
	struct page *page;
	void *kaddr;
	unsigned i;
	int index = SSDFS_MAPTBL_MAIN_INDEX;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache || !pebr);
	BUG_ON(atomic_read(&cache->bytes_count) == 0);
	BUG_ON(pagevec_count(&cache->pvec) == 0);
	BUG_ON(atomic_read(&cache->bytes_count) >
		(pagevec_count(&cache->pvec) * PAGE_SIZE));
	BUG_ON(atomic_read(&cache->bytes_count) <=
		((pagevec_count(&cache->pvec) - 1) * PAGE_SIZE));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("cache %p, leb_id %llu, pebr %p\n",
		  cache, leb_id, pebr);

	down_read(&cache->lock);

	for (i = 0; i < pagevec_count(&cache->pvec); i++) {
		page = cache->pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		lock_page(page);
		kaddr = kmap(page);
		err = ssdfs_maptbl_cache_find_leb(kaddr, i, leb_id,
						  index, pebr);
		kunmap(page);
		unlock_page(page);

		if (err == -ENODATA || err == -E2BIG)
			continue;
		else if (err == -EAGAIN)
			break;
		else if (err == -EFAULT) {
			err = -ENODATA;
			goto finish_leb_id_search;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find LEB: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_leb_id_search;
		} else {
			SSDFS_DBG("leb_id %llu, main peb_id %llu, "
				  "relation peb_id %llu\n",
				leb_id,
				pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id,
				pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].peb_id);
			goto finish_leb_id_search;
		}
	}

	if ((i + 1) < pagevec_count(&cache->pvec)) {
		page = cache->pvec.pages[i + 1];
		index = SSDFS_MAPTBL_RELATION_INDEX;

		lock_page(page);
		kaddr = kmap(page);
		err = ssdfs_maptbl_cache_find_leb(kaddr, i, leb_id,
						  index, pebr);
		kunmap(page);
		unlock_page(page);

		if (err == -EFAULT) {
			/* there is no relation PEB */
			err = 0;
			SSDFS_DBG("leb_id %llu, main peb_id %llu, "
				  "relation peb_id %llu\n",
				leb_id,
				pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id,
				pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].peb_id);
			goto finish_leb_id_search;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find LEB: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_leb_id_search;
		} else {
			SSDFS_DBG("leb_id %llu, main peb_id %llu, "
				  "relation peb_id %llu\n",
				leb_id,
				pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id,
				pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].peb_id);
			goto finish_leb_id_search;
		}
	}

finish_leb_id_search:
	up_read(&cache->lock);

	return err;
}

/*
 * ssdfs_maptbl_cache_init_page() - init page of maptbl cache
 * @kaddr: pointer on maptbl cache's fragment
 * @sequence_id: fragment's sequence ID number
 *
 * This method initialize empty maptbl cache fragment's page.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static
int ssdfs_maptbl_cache_init_page(void *kaddr, unsigned sequence_id)
{
	struct ssdfs_maptbl_cache_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_maptbl_cache_header);
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	size_t magic_size = peb_state_size;
	size_t threshold_size = hdr_size + magic_size;
	__le32 *magic;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, sequence_id %u\n",
		  kaddr, sequence_id);

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
	size_t bytes_count, new_bytes_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, shift %zu\n", kaddr, shift);

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

	area = PEB_STATE_AREA(kaddr);

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
		SSDFS_ERR("shift is out of memory page: "
			  "new_bytes_count %zu, shift %zu\n",
			  new_bytes_count, shift);
		return -ERANGE;
	}

	memmove((u8 *)area + shift, area, area_size);
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
	size_t bytes_count;
	size_t calculated;
	size_t new_bytes_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, shift %zu\n", kaddr, shift);

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

	area = PEB_STATE_AREA(kaddr);

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

	memmove((u8 *)area - shift, area, area_size);
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
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !src_pair || !src_state);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, item_index %u, "
		  "leb_id %llu, peb_id %llu\n",
		  kaddr, item_index,
		  le64_to_cpu(src_pair->leb_id),
		  le64_to_cpu(src_pair->peb_id));

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);
	if (item_index > items_count) {
		SSDFS_ERR("item_index %u > items_count %u\n",
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

	memcpy(dest_pair, src_pair, pair_size);

	dest_state = FIRST_PEB_STATE(kaddr);
	if (IS_ERR_OR_NULL(dest_state)) {
		err = !dest_state ? PTR_ERR(dest_state) : -ERANGE;
		SSDFS_ERR("fail to get the PEB state area: "
			  "err %d\n", err);
		return err;
	}

	dest_state += item_index;

	memcpy(dest_state, src_state, peb_state_size);

	items_count++;
	hdr->items_count = cpu_to_le16(items_count);

	if (item_index == 0)
		hdr->start_leb = src_pair->leb_id;

	if ((item_index + 1) == items_count)
		hdr->end_leb = src_pair->leb_id;

	return 0;
}

/*
 * ssdfs_maptbl_cache_add_page() - add fragment into maptbl cache
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
 * %-ENOMEM     - fail to add empty page into maptbl cache.
 */
static
int ssdfs_maptbl_cache_add_page(struct ssdfs_maptbl_cache *cache,
				struct ssdfs_leb2peb_pair *pair,
				struct ssdfs_maptbl_cache_peb_state *state)
{
	struct page *page;
	void *kaddr;
	u16 item_index;
	unsigned page_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache || !pair || !state);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("cache %p, leb_id %llu, peb_id %llu\n",
		  cache, le64_to_cpu(pair->leb_id),
		  le64_to_cpu(pair->peb_id));

	item_index = 0;
	page_index = pagevec_count(&cache->pvec);

	page = ssdfs_add_pagevec_page(&cache->pvec);
	if (unlikely(IS_ERR_OR_NULL(page))) {
		err = !page ? -ENOMEM : PTR_ERR(page);
		SSDFS_ERR("fail to add pagevec page: err %d\n",
			  err);
		return err;
	}

	lock_page(page);
	kaddr = kmap(page);

	err = ssdfs_maptbl_cache_init_page(kaddr, page_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init maptbl cache's page: "
			  "page_index %u, err %d\n",
			  page_index, err);
		goto finish_add_page;
	}

	atomic_add(PAGE_SIZE, &cache->bytes_count);

	err = ssdfs_maptbl_cache_add_leb(kaddr, item_index, pair, state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add leb_id: "
			  "page_index %u, item_index %u, err %d\n",
			  page_index, item_index, err);
		goto finish_add_page;
	}

finish_add_page:
	kunmap(page);
	unlock_page(page);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p\n", kaddr);

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
 * %-ENODATA    - empty maptbl cache's page.
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
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !pair || !state);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, pair %p, peb_state %p\n",
		  kaddr, pair, state);

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache's page\n");
		return -ENODATA;
	}

	found_pair = LEB2PEB_PAIR_AREA(kaddr);
	found_pair += items_count - 1;
	memcpy(pair, found_pair, pair_size);

	found_state = FIRST_PEB_STATE(kaddr);
	if (IS_ERR_OR_NULL(found_state)) {
		err = !found_state ? PTR_ERR(found_state) : -ERANGE;
		SSDFS_ERR("fail to get the PEB state area: "
			  "err %d\n", err);
		return err;
	}

	found_state += items_count - 1;
	memcpy(state, found_state, peb_state_size);

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
	struct ssdfs_leb2peb_pair *src, *dst;
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	u16 items_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, item_index %u\n",
		  kaddr, item_index);

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache page\n");
		return -ERANGE;
	}

	if (item_index >= items_count) {
		SSDFS_ERR("item_index %u > items_count %u\n",
			  item_index, items_count);
		return -EINVAL;
	}

	src = LEB2PEB_PAIR_AREA(kaddr);
	src += item_index;
	dst = src + 1;

	memmove(dst, src, (items_count - item_index) * pair_size);

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
	struct ssdfs_maptbl_cache_peb_state *src, *dst;
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	u16 items_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, item_index %u\n",
		  kaddr, item_index);

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache page\n");
		return -ERANGE;
	}

	if (item_index >= items_count) {
		SSDFS_ERR("item_index %u > items_count %u\n",
			  item_index, items_count);
		return -EINVAL;
	}

	src = FIRST_PEB_STATE(kaddr);
	if (IS_ERR_OR_NULL(src)) {
		err = !src ? PTR_ERR(src) : -ERANGE;
		SSDFS_ERR("fail to get the PEB state area: "
			  "err %d\n", err);
		return err;
	}

	src += item_index;
	dst = src + 1;

	memmove(dst, src, (items_count - item_index) * peb_state_size);

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
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !pair || !state);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, item_index %u, pair %p, state %p\n",
		  kaddr, item_index, pair, state);

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache page\n");
		return -ERANGE;
	}

	if (item_index >= items_count) {
		SSDFS_ERR("item_index %u > items_count %u\n",
			  item_index, items_count);
		return -EINVAL;
	}

	dst_pair = LEB2PEB_PAIR_AREA(kaddr);
	dst_pair += item_index;

	memcpy(dst_pair, pair, pair_size);

	dst_state = FIRST_PEB_STATE(kaddr);
	if (IS_ERR_OR_NULL(dst_state)) {
		err = !dst_state ? PTR_ERR(dst_state) : -ERANGE;
		SSDFS_ERR("fail to get the PEB state area: "
			  "err %d\n", err);
		return err;
	}

	dst_state += item_index;

	memcpy(dst_state, state, peb_state_size);

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
 * @page_index: index of the page
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
				  unsigned page_index,
				  u16 item_index)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *cur_pair;
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	struct ssdfs_maptbl_cache_peb_state *cur_state;
	struct page *page;
	void *kaddr;
	u16 items_count;
	size_t size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache);
	BUG_ON(page_index >= pagevec_count(&cache->pvec));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("cache %p, page_index %u, item_index %u\n",
		  cache, page_index, item_index);

	page = cache->pvec.pages[page_index];

	lock_page(page);
	kaddr = kmap(page);

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

	cur_state = FIRST_PEB_STATE(kaddr);
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

	cur_state = FIRST_PEB_STATE(kaddr);
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

finish_remove_item:
	kunmap(page);
	unlock_page(page);

	return err;
}

/*
 * ssdfs_check_pre_deleted_peb_state() - check pre-deleted state of the item
 * @cache: maptbl cache object
 * @page_index: index of the page
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
				     unsigned page_index,
				     u16 item_index,
				     struct ssdfs_leb2peb_pair *pair)
{
	struct ssdfs_leb2peb_pair *cur_pair = NULL;
	struct ssdfs_maptbl_cache_peb_state *cur_state = NULL;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache || !pair);
	BUG_ON(le64_to_cpu(pair->leb_id) == U64_MAX);
	BUG_ON(le64_to_cpu(pair->peb_id) == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("cache %p, start_page %u, item_index %u\n",
		  cache, page_index, item_index);

	page = cache->pvec.pages[page_index];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

	lock_page(page);
	kaddr = kmap(page);

	err = ssdfs_maptbl_cache_get_leb2peb_pair(kaddr, item_index, &cur_pair);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get LEB2PEB pair: err %d\n", err);
		goto finish_check_pre_deleted_state;
	}

	if (le64_to_cpu(pair->leb_id) != le64_to_cpu(cur_pair->leb_id)) {
		err = -ENODATA;
		SSDFS_DBG("pair->leb_id %llu != cur_pair->leb_id %llu\n",
			  le64_to_cpu(pair->leb_id),
			  le64_to_cpu(cur_pair->leb_id));
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
	kunmap(page);
	unlock_page(page);

	if (err)
		return err;

	err = ssdfs_maptbl_cache_remove_leb(cache,
					    page_index,
					    item_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete LEB: "
			  "page_index %d, item_index %u, err %d\n",
			  page_index, item_index, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_maptbl_cache_insert_leb() - insert item into the fragment
 * @cache: maptbl cache object
 * @start_page: page index
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
				  unsigned start_page,
				  u16 item_index,
				  struct ssdfs_leb2peb_pair *pair,
				  struct ssdfs_maptbl_cache_peb_state *state)
{
	struct ssdfs_leb2peb_pair cur_pair, saved_pair;
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	struct ssdfs_maptbl_cache_peb_state cur_state, saved_state;
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache || !pair || !state);
	BUG_ON(le64_to_cpu(pair->leb_id) == U64_MAX);
	BUG_ON(le64_to_cpu(pair->peb_id) == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("cache %p, start_page %u, item_index %u, "
		  "leb_id %llu, peb_id %llu\n",
		  cache, start_page, item_index,
		  le64_to_cpu(pair->leb_id),
		  le64_to_cpu(pair->peb_id));

	err = ssdfs_check_pre_deleted_peb_state(cache, start_page,
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

	memcpy(&cur_pair, pair, pair_size);
	memcpy(&cur_state, state, peb_state_size);

	for (; start_page < pagevec_count(&cache->pvec); start_page++) {
		bool need_move_item = false;

		page = cache->pvec.pages[start_page];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		lock_page(page);
		kaddr = kmap(page);

		need_move_item = is_fragment_full(kaddr);

		if (need_move_item) {
			err = ssdfs_maptbl_cache_get_last_item(kaddr,
							       &saved_pair,
							       &saved_state);
			if (unlikely(err)) {
				SSDFS_ERR("fail to get last item: "
					  "err %d\n", err);
				goto finish_page_modification;
			}
		}

		err = ssdfs_shift_right_peb_state_area(kaddr, pair_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to shift the PEB state area: "
				  "err %d\n", err);
			goto finish_page_modification;
		}

		err = ssdfs_maptbl_cache_move_right_leb2peb_pairs(kaddr,
								item_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move LEB2PEB pairs: "
				  "page_index %u, item_index %u, "
				  "err %d\n",
				  start_page, item_index, err);
			goto finish_page_modification;
		}

		err = ssdfs_maptbl_cache_move_right_peb_states(kaddr,
								item_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move PEB states: "
				  "page_index %u, item_index %u, "
				  "err %d\n",
				  start_page, item_index, err);
			goto finish_page_modification;
		}

		err = __ssdfs_maptbl_cache_insert_leb(kaddr, item_index,
						      &cur_pair, &cur_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert leb descriptor: "
				  "page_index %u, item_index %u, err %d\n",
				  start_page, item_index, err);
			goto finish_page_modification;
		}

finish_page_modification:
		kunmap(page);
		unlock_page(page);

		if (err || !need_move_item)
			goto finish_insert_leb;

		item_index = 0;
		memcpy(&cur_pair, &saved_pair, pair_size);
		memcpy(&cur_state, &saved_state, peb_state_size);
	}

	err = ssdfs_maptbl_cache_add_page(cache, &cur_pair, &cur_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add page into maptbl cache: "
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
	struct ssdfs_leb2peb_pair *tmp_pair = NULL;
	u16 item_index = U16_MAX;
	struct ssdfs_leb2peb_pair cur_pair;
	struct ssdfs_maptbl_cache_peb_state cur_state;
	struct page *page;
	void *kaddr;
	unsigned i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache || !pebr);
	BUG_ON(leb_id == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("cache %p, leb_id %llu, pebr %p, consistency %#x\n",
		  cache, leb_id, pebr, consistency);

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

	for (i = 0; i < pagevec_count(&cache->pvec); i++) {
		page = cache->pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		lock_page(page);
		kaddr = kmap(page);
		err = __ssdfs_maptbl_cache_find_leb(kaddr, i, leb_id,
						    &tmp_pair, &item_index);
		kunmap(page);
		unlock_page(page);

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

	if (i >= pagevec_count(&cache->pvec)) {
		if (err == -ENODATA) {
			/* correct page index */
			i = pagevec_count(&cache->pvec) - 1;
		} else {
			err = -ERANGE;
			SSDFS_ERR("i %u >= pages_count %u\n",
				  i, pagevec_count(&cache->pvec));
			goto finish_leb_caching;
		}
	}

	if (err == -EEXIST)
		goto finish_leb_caching;
	else if (err == -E2BIG) {
		err = ssdfs_maptbl_cache_add_page(cache, &cur_pair, &cur_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add page into maptbl cache: "
				  "err %d\n",
				  err);
			goto finish_leb_caching;
		}
	} else if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(i >= pagevec_count(&cache->pvec));
#endif /* CONFIG_SSDFS_DEBUG */

		page = cache->pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		lock_page(page);
		kaddr = kmap(page);
		err = ssdfs_maptbl_cache_add_leb(kaddr, item_index,
						 &cur_pair, &cur_state);
		kunmap(page);
		unlock_page(page);

		if (unlikely(err)) {
			SSDFS_ERR("fail to add leb_id: "
				  "page_index %u, item_index %u, err %d\n",
				  i, item_index, err);
		}
	} else if (err == -EFAULT) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(i >= pagevec_count(&cache->pvec));
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_maptbl_cache_insert_leb(cache, i, item_index,
						    &cur_pair, &cur_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add LEB with shift: "
				  "page_index %u, item_index %u, err %d\n",
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
 * @page_index: index of memory page
 * @item_index: index of the item in the page
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
					  unsigned page_index,
					  u16 item_index,
					  int peb_state,
					  int consistency)
{
	struct ssdfs_maptbl_cache_peb_state *found_state = NULL;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache);
	BUG_ON(!rwsem_is_locked(&cache->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("cache %p, page_index %u, item_index %u, "
		  "peb_state %#x, consistency %#x\n",
		  cache, page_index, item_index,
		  peb_state, consistency);

	if (page_index >= pagevec_count(&cache->pvec)) {
		SSDFS_ERR("invalid page index %u\n", page_index);
		return -ERANGE;
	}

	page = cache->pvec.pages[page_index];
	lock_page(page);
	kaddr = kmap(page);

	err = ssdfs_maptbl_cache_get_peb_state(kaddr, item_index,
						&found_state);
	if (err == -EINVAL) {
		SSDFS_DBG("unable to get peb state: "
			  "item_index %u\n",
			  item_index);
		goto finish_page_modification;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to get peb state: "
			  "item_index %u, err %d\n",
			  item_index, err);
		goto finish_page_modification;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!found_state);
#endif /* CONFIG_SSDFS_DEBUG */

	found_state->consistency = (u8)consistency;
	found_state->state = (u8)peb_state;

finish_page_modification:
	kunmap(page);
	unlock_page(page);

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
	struct ssdfs_leb2peb_pair *tmp_pair = NULL;
	u16 item_index = U16_MAX;
	struct page *page;
	void *kaddr;
	unsigned i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache);
	BUG_ON(leb_id == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("cache %p, leb_id %llu, peb_state %#x, consistency %#x\n",
		  cache, leb_id, peb_state, consistency);

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

	down_write(&cache->lock);

	for (i = 0; i < pagevec_count(&cache->pvec); i++) {
		page = cache->pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		lock_page(page);
		kaddr = kmap(page);
		err = __ssdfs_maptbl_cache_find_leb(kaddr, i, leb_id,
						    &tmp_pair, &item_index);
		kunmap(page);
		unlock_page(page);

		if (err == -EEXIST) {
			/* the position was found */
			break;
		} else if (!err)
			BUG();
	}

	if (err != -EEXIST) {
		SSDFS_ERR("fail to find the LEB %llu: err %d\n",
			  leb_id, err);
		goto finish_peb_state_change;
	} else
		err = 0;

	if (i >= pagevec_count(&cache->pvec)) {
		err = -ERANGE;
		SSDFS_ERR("invalid page index %u\n", i);
		goto finish_peb_state_change;
	}

	switch (peb_state) {
	case SSDFS_MAPTBL_BAD_PEB_STATE:
	case SSDFS_MAPTBL_CLEAN_PEB_STATE:
	case SSDFS_MAPTBL_USING_PEB_STATE:
	case SSDFS_MAPTBL_USED_PEB_STATE:
	case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
	case SSDFS_MAPTBL_DIRTY_PEB_STATE:
	case SSDFS_MAPTBL_PRE_ERASE_STATE:
	case SSDFS_MAPTBL_RECOVERING_STATE:
	case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
	case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
	case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
		err = __ssdfs_maptbl_cache_change_peb_state(cache, i,
							    item_index,
							    peb_state,
							    consistency);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change peb state: "
				  "page_index %u, item_index %u, "
				  "err %d\n",
				  i, item_index, err);
			goto finish_peb_state_change;
		}
		break;

	case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_DIRTY_STATE:
		item_index++;

		err = __ssdfs_maptbl_cache_change_peb_state(cache, i,
							    item_index,
							    peb_state,
							    consistency);
		if (err == -EINVAL) {
			i++;

			if (i >= pagevec_count(&cache->pvec)) {
				err = -ERANGE;
				SSDFS_ERR("invalid page index %u\n", i);
				goto finish_peb_state_change;
			}

			page = cache->pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

			lock_page(page);
			kaddr = kmap(page);
			err = __ssdfs_maptbl_cache_find_leb(kaddr, i, leb_id,
							    &tmp_pair,
							    &item_index);
			kunmap(page);
			unlock_page(page);

			if (err == -EEXIST) {
				err =
				    __ssdfs_maptbl_cache_change_peb_state(cache,
								i, item_index,
								peb_state,
								consistency);
				if (unlikely(err)) {
					SSDFS_ERR("fail to change peb state: "
						  "page_index %u, "
						  "item_index %u, "
						  "err %d\n",
						  i, item_index, err);
					goto finish_peb_state_change;
				}
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to find leb: "
					  "leb_id %llu, page_index %u, "
					  "err %d\n",
					  leb_id, i, err);
				goto finish_peb_state_change;
			}
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to change peb state: "
				  "page_index %u, item_index %u, "
				  "err %d\n",
				  i, item_index, err);
			goto finish_peb_state_change;
		}
		break;

	default:
		BUG();
	}

finish_peb_state_change:
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
	struct ssdfs_leb2peb_pair *tmp_pair = NULL;
	u16 item_index = U16_MAX, items_count = U16_MAX;
	struct ssdfs_leb2peb_pair cur_pair;
	struct ssdfs_maptbl_cache_peb_state cur_state;
	struct page *page;
	void *kaddr;
	unsigned i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache || !pebr);
	BUG_ON(leb_id == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("cache %p, leb_id %llu, pebr %p, consistency %#x\n",
		  cache, leb_id, pebr, consistency);

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

	for (i = 0; i < pagevec_count(&cache->pvec); i++) {
		struct ssdfs_maptbl_cache_header *hdr;

		page = cache->pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		lock_page(page);
		kaddr = kmap(page);

		hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
		items_count = le16_to_cpu(hdr->items_count);

		err = __ssdfs_maptbl_cache_find_leb(kaddr, i, leb_id,
						    &tmp_pair, &item_index);

		kunmap(page);
		unlock_page(page);

		if (err == -EEXIST || err == -EFAULT)
			break;
		else if (err != -E2BIG && err != -ENODATA)
			break;
		else if (!err)
			BUG();
	}

	if (err != -EEXIST) {
		SSDFS_ERR("maptbl cache hasn't item for leb_id %llu\n",
			  leb_id);
		goto finish_add_migration_peb;
	}

	if ((item_index + 1) >= ssdfs_maptbl_cache_fragment_capacity()) {
		err = ssdfs_maptbl_cache_add_page(cache, &cur_pair, &cur_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add page into maptbl cache: "
				  "err %d\n",
				  err);
			goto finish_add_migration_peb;
		}
	} else if ((item_index + 1) < items_count) {
		err = ssdfs_maptbl_cache_insert_leb(cache, i, item_index,
						    &cur_pair, &cur_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert LEB: "
				  "page_index %u, item_index %u, err %d\n",
				  i, item_index, err);
			goto finish_add_migration_peb;
		}
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(i >= pagevec_count(&cache->pvec));
#endif /* CONFIG_SSDFS_DEBUG */

		page = cache->pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		lock_page(page);
		kaddr = kmap(page);
		err = ssdfs_maptbl_cache_add_leb(kaddr, item_index,
						 &cur_pair, &cur_state);
		kunmap(page);
		unlock_page(page);

		if (unlikely(err)) {
			SSDFS_ERR("fail to add leb_id: "
				  "page_index %u, item_index %u, err %d\n",
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
 * %-ENODATA    - empty maptbl cache page.
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
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !pair || !state);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, pair %p, peb_state %p\n",
		  kaddr, pair, state);

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache page\n");
		return -ENODATA;
	}

	found_pair = LEB2PEB_PAIR_AREA(kaddr);
	memcpy(pair, found_pair, pair_size);

	found_state = FIRST_PEB_STATE(kaddr);
	if (IS_ERR_OR_NULL(found_state)) {
		err = !found_state ? PTR_ERR(found_state) : -ERANGE;
		SSDFS_ERR("fail to get the PEB state area: "
			  "err %d\n", err);
		return err;
	}

	memcpy(state, found_state, peb_state_size);

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
static
int ssdfs_maptbl_cache_move_left_leb2peb_pairs(void *kaddr,
						u16 item_index)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *src, *dst;
	size_t pair_size = sizeof(struct ssdfs_leb2peb_pair);
	u16 items_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, item_index %u\n",
		  kaddr, item_index);

	if (item_index == 0) {
		SSDFS_DBG("do nothing: item_index %u\n",
			  item_index);
		return 0;
	}

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache page\n");
		return -ERANGE;
	}

	if (item_index >= items_count) {
		SSDFS_ERR("item_index %u > items_count %u\n",
			  item_index, items_count);
		return -EINVAL;
	}

	src = LEB2PEB_PAIR_AREA(kaddr);
	src += item_index;
	dst = src - 1;

	memmove(dst, src, (items_count - item_index) * pair_size);

	return 0;
}

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
static
int ssdfs_maptbl_cache_move_left_peb_states(void *kaddr,
					     u16 item_index)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_maptbl_cache_peb_state *src, *dst;
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	u16 items_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, item_index %u\n",
		  kaddr, item_index);

	if (item_index == 0) {
		SSDFS_DBG("do nothing: item_index %u\n",
			  item_index);
		return 0;
	}

	hdr = (struct ssdfs_maptbl_cache_header *)kaddr;

	items_count = le16_to_cpu(hdr->items_count);

	if (items_count == 0) {
		SSDFS_ERR("empty maptbl cache page\n");
		return -ERANGE;
	}

	if (item_index >= items_count) {
		SSDFS_ERR("item_index %u > items_count %u\n",
			  item_index, items_count);
		return -EINVAL;
	}

	src = FIRST_PEB_STATE(kaddr);
	if (IS_ERR_OR_NULL(src)) {
		err = !src ? PTR_ERR(src) : -ERANGE;
		SSDFS_ERR("fail to get the PEB state area: "
			  "err %d\n", err);
		return err;
	}

	src += item_index;
	dst = src - 1;

	memmove(dst, src, (items_count - item_index) * peb_state_size);

	return 0;
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
	struct ssdfs_maptbl_cache_header *hdr;
	struct ssdfs_leb2peb_pair *found_pair = NULL;
	struct ssdfs_leb2peb_pair saved_pair;
	struct ssdfs_maptbl_cache_peb_state *found_state = NULL;
	struct ssdfs_maptbl_cache_peb_state saved_state;
	size_t peb_state_size = sizeof(struct ssdfs_maptbl_cache_peb_state);
	struct page *page;
	void *kaddr;
	u16 item_index, items_count;
	unsigned i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cache);
	BUG_ON(leb_id == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("cache %p, leb_id %llu\n",
		  cache, leb_id);

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

	down_write(&cache->lock);

	for (i = 0; i < pagevec_count(&cache->pvec); i++) {
		struct ssdfs_maptbl_cache_header *hdr;

		page = cache->pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		lock_page(page);
		kaddr = kmap(page);

		hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
		items_count = le16_to_cpu(hdr->items_count);

		err = __ssdfs_maptbl_cache_find_leb(kaddr, i, leb_id,
						    &found_pair, &item_index);

		if (err == -EEXIST) {
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(le64_to_cpu(found_pair->leb_id) != leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

			if ((item_index + 1) >= items_count) {
				err = -ERANGE;
				SSDFS_ERR("invalid position found: "
					  "item_index %u, items_count %u\n",
					  item_index, items_count);
			}

			err = ssdfs_maptbl_cache_get_peb_state(kaddr,
							       item_index,
							       &found_state);
			if (unlikely(err)) {
				SSDFS_ERR("fail to get peb state: "
					  "item_index %u, err %d\n",
					  item_index, err);
			} else {
				memcpy(&saved_state, found_state,
					peb_state_size);
			}
		}

		kunmap(page);
		unlock_page(page);

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
		err = ssdfs_maptbl_cache_change_peb_state(cache, leb_id,
							  saved_state.state,
							  consistency);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change PEB state: err %d\n", err);
			goto finish_exclude_migration_peb;
		}
	} else {
		err = ssdfs_maptbl_cache_remove_leb(cache, i, item_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to remove LEB: "
				  "page_index %u, item_index %u, err %d\n",
				  i, item_index, err);
			goto finish_exclude_migration_peb;
		}

		for (++i; i < pagevec_count(&cache->pvec); i++) {
			page = cache->pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

			lock_page(page);
			kaddr = kmap(page);
			err = ssdfs_maptbl_cache_get_first_item(kaddr,
							       &saved_pair,
							       &saved_state);
			kunmap(page);
			unlock_page(page);

			if (unlikely(err)) {
				SSDFS_ERR("fail to get first item: "
					  "err %d\n", err);
				goto finish_exclude_migration_peb;
			}

			page = cache->pvec.pages[i - 1];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

			lock_page(page);
			kaddr = kmap(page);

			hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
			items_count = le16_to_cpu(hdr->items_count);
			if (items_count == 0)
				item_index = 0;
			else
				item_index = items_count - 1;

			err = ssdfs_maptbl_cache_add_leb(kaddr, item_index,
							 &saved_pair,
							 &saved_state);

			kunmap(page);
			unlock_page(page);

			if (unlikely(err)) {
				SSDFS_ERR("fail to add leb_id: "
					  "page_index %u, item_index %u, "
					  "err %d\n",
					  i, item_index, err);
				goto finish_exclude_migration_peb;
			}

			item_index = 0;
			err = ssdfs_maptbl_cache_remove_leb(cache, i,
							    item_index);
			if (unlikely(err)) {
				SSDFS_ERR("fail to remove LEB: "
					  "page_index %u, item_index %u, "
					  "err %d\n",
					  i, item_index, err);
				goto finish_exclude_migration_peb;
			}
		}

		i = pagevec_count(&cache->pvec);
		if (i == 0) {
			err = -ERANGE;
			SSDFS_ERR("invalid number of fragments %u\n", i);
			goto finish_exclude_migration_peb;
		} else
			i--;

		page = cache->pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		lock_page(page);
		kaddr = kmap(page);
		hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
		items_count = le16_to_cpu(hdr->items_count);
		kunmap(page);
		unlock_page(page);

		if (items_count == 0) {
			cache->pvec.pages[i] = NULL;
			cache->pvec.nr--;
			put_page(page);
			ssdfs_free_page(page);
			atomic_sub(PAGE_SIZE, &cache->bytes_count);
		}
	}

finish_exclude_migration_peb:
	up_write(&cache->lock);

	return err;
}
