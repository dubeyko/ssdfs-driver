//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_mapping_table_thread.c - PEB mapping table thread functionality.
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
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "page_array.h"
#include "peb_mapping_table.h"

#include <trace/events/ssdfs.h>

/* Stage of recovering try */
enum {
	SSDFS_CHECK_RECOVERABILITY,
	SSDFS_MAKE_RECOVERING,
	SSDFS_RECOVER_STAGE_MAX
};

/* Possible states of erase operation */
enum {
	SSDFS_ERASE_RESULT_UNKNOWN,
	SSDFS_ERASE_DONE,
	SSDFS_IGNORE_ERASE,
	SSDFS_ERASE_FAILURE,
	SSDFS_BAD_BLOCK_DETECTED,
	SSDFS_ERASE_RESULT_MAX
};

/*
 * struct ssdfs_erase_result - PEB's erase operation result
 * @fragment_index: index of mapping table's fragment
 * @peb_index: PEB's index in fragment
 * @peb_id: PEB ID number
 * @state: state of erase operation
 */
struct ssdfs_erase_result {
	u32 fragment_index;
	u16 peb_index;
	u64 peb_id;
	int state;
};

/*
 * struct ssdfs_erase_result_array - array of erase operation results
 * @ptr: pointer on memory buffer
 * @capacity: maximal number of erase operation results in array
 * @size: count of erase operation results in array
 */
struct ssdfs_erase_result_array {
	struct ssdfs_erase_result *ptr;
	u32 capacity;
	u32 size;
};

/*
 * ssdfs_maptbl_collect_stripe_dirty_pebs() - collect dirty PEBs in stripe
 * @fdesc: fragment descriptor
 * @fragment_index: index of fragment
 * @stripe_index: index of stripe
 * @erases_per_stripe: count of erases per stripe
 * @array: array of erase operation results [out]
 *
 * This method tries to collect information about dirty PEBs
 * in the stripe.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE  - internal error.
 */
static int
ssdfs_maptbl_collect_stripe_dirty_pebs(struct ssdfs_maptbl_fragment_desc *fdesc,
					u32 fragment_index,
					int stripe_index,
					int erases_per_stripe,
					struct ssdfs_erase_result_array *array)
{
	struct ssdfs_peb_table_fragment_header *hdr;
	int found_pebs = 0;
	u16 stripe_pages = fdesc->stripe_pages;
	pgoff_t start_page;
	unsigned long *dirty_bmap;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc || !array);
	BUG_ON(!rwsem_is_locked(&fdesc->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fdesc %p, stripe_index %u, "
		  "erases_per_stripe %d\n",
		  fdesc, stripe_index,
		  erases_per_stripe);

	start_page = stripe_index * stripe_pages;
	start_page += fdesc->lebtbl_pages;

	for (i = 0; i < stripe_pages; i++) {
		pgoff_t page_index = start_page + i;
		struct page *page;
		void *kaddr;
		unsigned long found_item = 0;
		u16 peb_index;
		u16 pebs_count;

		page_index += (pgoff_t)fdesc->fragment_id *
					fdesc->fragment_pages;

		page = ssdfs_page_array_get_page_locked(&fdesc->array,
							page_index);
		if (IS_ERR_OR_NULL(page)) {
			err = page == NULL ? -ERANGE : PTR_ERR(page);
			SSDFS_ERR("fail to find page: page_index %lu\n",
				  page_index);
			return err;
		}

		kaddr = kmap(page);

		hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;
		dirty_bmap =
		    (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_DIRTY_BMAP][0];
		pebs_count = le16_to_cpu(hdr->pebs_count);

		while (found_pebs < erases_per_stripe) {
			found_item = find_next_bit(dirty_bmap, pebs_count,
						   found_item + 1);
			if (found_item >= pebs_count) {
				/* all dirty PEBs were found */
				goto finish_page_processing;
			}

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(array->size >= array->capacity);
#endif /* CONFIG_SSDFS_DEBUG */

			array->ptr[array->size].fragment_index = fragment_index;
			peb_index = DEFINE_PEB_INDEX_IN_FRAGMENT(fdesc,
								 page_index,
								 found_item);
			array->ptr[array->size].peb_index = peb_index;
			array->ptr[array->size].peb_id = GET_PEB_ID(kaddr,
								    found_item);
			array->ptr[array->size].state =
						SSDFS_ERASE_RESULT_UNKNOWN;

			array->size++;
			found_pebs++;
		};

finish_page_processing:
		kunmap(page);
		unlock_page(page);
		put_page(page);

		if (unlikely(err))
			return err;
	}

	return 0;
}

/*
 * ssdfs_maptbl_collect_dirty_pebs() - collect dirty PEBs in fragment
 * @tbl: mapping table object
 * @fragment_index: index of fragment
 * @erases_per_fragment: maximal amount of erases per fragment
 * @array: array of erase operation results [out]
 *
 * This method tries to collect information about dirty PEBs
 * in fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL  - invalid input.
 * %-ERANGE  - internal error.
 */
static
int ssdfs_maptbl_collect_dirty_pebs(struct ssdfs_peb_mapping_table *tbl,
				    u32 fragment_index,
				    int erases_per_fragment,
				    struct ssdfs_erase_result_array *array)
{
	struct ssdfs_maptbl_fragment_desc *fdesc;
	int state;
	u16 stripes_per_fragment;
	int erases_per_stripe;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !array);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));

	if (fragment_index >= tbl->fragments_count) {
		SSDFS_ERR("fragment_index %u >= tbl->fragments_count %u\n",
			  fragment_index, tbl->fragments_count);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tbl %p, fragment_index %u, "
		  "erases_per_fragment %d\n",
		  tbl, fragment_index,
		  erases_per_fragment);

	memset(array->ptr, 0,
		array->capacity * sizeof(struct ssdfs_erase_result));
	array->size = 0;

	fdesc = &tbl->desc_array[fragment_index];

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED ||
	    state == SSDFS_MAPTBL_FRAG_CREATED) {
		/* do nothing */
		return 0;
	}

	stripes_per_fragment = tbl->stripes_per_fragment;
	erases_per_stripe = erases_per_fragment / stripes_per_fragment;
	if (erases_per_stripe == 0)
		erases_per_stripe = 1;

	down_read(&fdesc->lock);

	if (fdesc->pre_erase_pebs == 0) {
		/* no dirty PEBs */
		goto finish_gathering;
	}

	for (i = 0; i < stripes_per_fragment; i++) {
		err = ssdfs_maptbl_collect_stripe_dirty_pebs(fdesc,
							     fragment_index,
							     i,
							     erases_per_stripe,
							     array);
		if (unlikely(err)) {
			SSDFS_ERR("fail to collect dirty PEBs: "
				  "fragment_index %u, stripe_index %d, "
				  "err %d\n",
				  fragment_index, i, err);
			goto finish_gathering;
		}
	}

finish_gathering:
	up_read(&fdesc->lock);

	return err;
}

/*
 * ssdfs_maptbl_erase_pebs_array() - erase PEBs
 * @fsi: file system info object
 * @array: array of erase operation results [in|out]
 *
 * This method tries to erase dirty PEBs.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EROFS   - file system in RO state.
 */
static
int ssdfs_maptbl_erase_pebs_array(struct ssdfs_fs_info *fsi,
				  struct ssdfs_erase_result_array *array)
{
	loff_t offset;
	size_t len = fsi->erasesize;
	u32 i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !array || !array->ptr);
	BUG_ON(!fsi->devops || !fsi->devops->erase);
	BUG_ON(array->capacity == 0);
	BUG_ON(array->capacity < array->size);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, capacity %u, size %u\n",
		  fsi, array->capacity, array->size);

	if (array->size == 0)
		return 0;

	for (i = 0; i < array->size; i++) {
		u64 peb_id = array->ptr[i].peb_id;

		if (((LLONG_MAX - 1) / fsi->erasesize) < peb_id) {
			SSDFS_NOTICE("ignore erasing peb %llu\n", peb_id);
			array->ptr[i].state = SSDFS_IGNORE_ERASE;
			continue;
		}

		offset = peb_id * fsi->erasesize;

		if (array->ptr[i].state == SSDFS_BAD_BLOCK_DETECTED) {
			err = fsi->devops->mark_peb_bad(fsi->sb, offset);
			if (unlikely(err)) {
				SSDFS_ERR("fail to mark PEB as bad: "
					  "peb %llu, err %d\n",
					  peb_id, err);
			}
			err = 0;
		} else {
			err = fsi->devops->erase(fsi->sb, offset, len);
			if (err == -EROFS) {
				SSDFS_DBG("file system has READ_ONLY state\n");
				return err;
			} else if (err == -EFAULT) {
				err = 0;
				SSDFS_DBG("erase operation failure: peb %llu\n",
					  peb_id);
				array->ptr[i].state = SSDFS_ERASE_FAILURE;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to erase: peb %llu, err %d\n",
					  peb_id, err);
				err = 0;
				array->ptr[i].state = SSDFS_IGNORE_ERASE;
			} else
				array->ptr[i].state = SSDFS_ERASE_DONE;
		}
	}

	return 0;
}

/*
 * ssdfs_maptbl_correct_peb_state() - correct state of erased PEB
 * @fdesc: fragment descriptor
 * @res: result of erase operation
 *
 * This method corrects PEB state after erasing.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL  - invalid input.
 * %-ERANGE  - internal error.
 */
static
int ssdfs_maptbl_correct_peb_state(struct ssdfs_maptbl_fragment_desc *fdesc,
				   struct ssdfs_erase_result *res)
{
	struct ssdfs_peb_table_fragment_header *hdr;
	struct ssdfs_peb_descriptor *ptr;
	pgoff_t page_index;
	struct page *page;
	void *kaddr;
	unsigned long *dirty_bmap, *used_bmap, *recover_bmap, *bad_bmap;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc || !res);
	BUG_ON(!rwsem_is_locked(&fdesc->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fdesc %p, res->fragment_index %u, res->peb_index %u, "
		  "res->peb_id %llu, res->state %#x\n",
		  fdesc, res->fragment_index, res->peb_index,
		  res->peb_id, res->state);

	if (res->state == SSDFS_IGNORE_ERASE) {
		SSDFS_DBG("ignore PEB: peb_id %llu\n", res->peb_id);
		return 0;
	}

	page_index = PEBTBL_PAGE_INDEX(fdesc, res->peb_index);
	page_index += (pgoff_t)fdesc->fragment_id * fdesc->fragment_pages;

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap(page);

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;
	dirty_bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_DIRTY_BMAP][0];
	used_bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_USED_BMAP][0];
	recover_bmap =
		(unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_RECOVER_BMAP][0];
	bad_bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_BADBLK_BMAP][0];

	ptr = GET_PEB_DESCRIPTOR(hdr, res->peb_index);
	if (IS_ERR_OR_NULL(ptr)) {
		err = IS_ERR(ptr) ? PTR_ERR(ptr) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "peb_index %u, err %d\n",
			  res->peb_index, err);
		goto finish_page_processing;
	}

	if (ptr->state != SSDFS_MAPTBL_PRE_ERASE_STATE ||
	    ptr->state != SSDFS_MAPTBL_RECOVERING_STATE) {
		err = -ERANGE;
		SSDFS_ERR("invalid PEB state: "
			  "peb_id %llu, peb_index %u, state %#x\n",
			  res->peb_id, res->peb_index, ptr->state);
		goto finish_page_processing;
	}

	le32_add_cpu(&ptr->erase_cycles, 1);
	ptr->type = SSDFS_MAPTBL_UNKNOWN_PEB_TYPE;

	switch (res->state) {
	case SSDFS_ERASE_DONE:
		ptr->state = SSDFS_MAPTBL_UNKNOWN_PEB_STATE;
		bitmap_clear(dirty_bmap, res->peb_index, 1);
		bitmap_clear(used_bmap, res->peb_index, 1);
		le16_add_cpu(&hdr->reserved_pebs, 1);
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(fdesc->pre_erase_pebs == 0);
#endif /* CONFIG_SSDFS_DEBUG */
		fdesc->pre_erase_pebs--;
		break;

	case SSDFS_ERASE_FAILURE:
		ptr->state = SSDFS_MAPTBL_RECOVERING_STATE;
		bitmap_clear(dirty_bmap, res->peb_index, 1);
		bitmap_set(recover_bmap, res->peb_index, 1);
		fdesc->recovering_pebs++;
		if (!(hdr->flags & SSDFS_PEBTBL_UNDER_RECOVERING)) {
			hdr->flags |= SSDFS_PEBTBL_UNDER_RECOVERING;
			hdr->recover_months = 1;
			hdr->recover_threshold = SSDFS_PEBTBL_FIRST_RECOVER_TRY;
		}
		break;

	default:
		BUG();
	};

finish_page_processing:
	kunmap(page);
	unlock_page(page);
	put_page(page);

	return err;
}

/*
 * ssdfs_maptbl_correct_fragment_dirty_pebs() - correct PEBs' state in fragment
 * @tbl: mapping table object
 * @array: array of erase operation results
 * @item_index: pointer on current index in array [in|out]
 *
 * This method corrects PEBs' state in fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL  - invalid input.
 * %-ERANGE  - internal error.
 */
static int
ssdfs_maptbl_correct_fragment_dirty_pebs(struct ssdfs_peb_mapping_table *tbl,
					 struct ssdfs_erase_result_array *array,
					 u32 *item_index)
{
	struct ssdfs_maptbl_fragment_desc *fdesc;
	u32 fragment_index;
	int state;
	int erased_pebs = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !array || !array->ptr || !item_index);
	BUG_ON(array->capacity == 0);
	BUG_ON(array->capacity < array->size);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tbl %p, capacity %u, size %u, item_index %u\n",
		  tbl, array->capacity, array->size, *item_index);

	if (*item_index >= array->size) {
		SSDFS_ERR("item_index %u >= array->size %u\n",
			  *item_index, array->size);
		return -EINVAL;
	}

	fragment_index = array->ptr[*item_index].fragment_index;

	if (fragment_index >= tbl->fragments_count) {
		SSDFS_ERR("fragment_index %u >= tbl->fragments_count %u\n",
			  fragment_index, tbl->fragments_count);
		return -ERANGE;
	}

	fdesc = &tbl->desc_array[fragment_index];

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED ||
	    state == SSDFS_MAPTBL_FRAG_CREATED) {
		SSDFS_ERR("fail to correct fragment: "
			  "fragment_index %u, state %#x\n",
			  fragment_index, state);
		return -ERANGE;
	}

	down_write(&fdesc->lock);

	if (fdesc->pre_erase_pebs == 0) {
		SSDFS_ERR("fdesc->pre_erase_pebs == 0\n");
		err = -ERANGE;
		goto finish_fragment_correction;
	}

	do {
		err = ssdfs_maptbl_correct_peb_state(fdesc,
						     &array->ptr[*item_index]);
		if (unlikely(err)) {
			SSDFS_ERR("fail to correct PEB state: "
				  "peb_id %llu, err %d\n",
				  array->ptr[*item_index].peb_id,
				  err);
			goto finish_fragment_correction;
		}

		if (array->ptr[*item_index].state != SSDFS_IGNORE_ERASE)
			erased_pebs++;

		++*item_index;
	} while (*item_index < array->size &&
		 fragment_index == array->ptr[*item_index].fragment_index);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(erased_pebs > atomic_read(&tbl->pre_erase_pebs));
#endif /* CONFIG_SSDFS_DEBUG */

	if (!atomic_add_negative(0 - erased_pebs, &tbl->pre_erase_pebs))
		SSDFS_WARN("erased_pebs %d\n", erased_pebs);

finish_fragment_correction:
	up_write(&fdesc->lock);

	if (!err) {
		atomic_set(&fdesc->state, SSDFS_MAPTBL_FRAG_DIRTY);
		mutex_lock(&tbl->bmap_lock);
		bitmap_set(tbl->dirty_bmap, fragment_index, 1);
		mutex_unlock(&tbl->bmap_lock);
	}

	return err;
}

/*
 * ssdfs_maptbl_correct_dirty_pebs() - correct PEBs' state after erasing
 * @tbl: mapping table object
 * @array: array of erase operation results
 */
static
int ssdfs_maptbl_correct_dirty_pebs(struct ssdfs_peb_mapping_table *tbl,
				    struct ssdfs_erase_result_array *array)
{
	u32 item_index = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !array || !array->ptr);
	BUG_ON(array->capacity == 0);
	BUG_ON(array->capacity < array->size);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tbl %p, capacity %u, size %u\n",
		  tbl, array->capacity, array->size);

	if (array->size == 0)
		return 0;

	do {
		err = ssdfs_maptbl_correct_fragment_dirty_pebs(tbl, array,
								&item_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to correct fragment's: err %d\n",
				  err);
			return err;
		}
	} while (item_index < array->size);

	if (item_index != array->size) {
		SSDFS_ERR("item_index %u != array->size %u\n",
			  item_index, array->size);
		return err;
	}

	return 0;
}

/*
 * is_time_to_recover_pebs() - check that it's time to recover PEBs
 * @tbl: mapping table object
 */
static inline
bool is_time_to_recover_pebs(struct ssdfs_peb_mapping_table *tbl)
{
#define BILLION		1000000000L
	u64 month_ns = 31 * 24 * 60 * 60 * BILLION;
	u64 current_cno, upper_bound_cno;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !tbl->fsi || !tbl->fsi->sb);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tbl %p\n", tbl);

	upper_bound_cno = atomic64_read(&tbl->last_peb_recover_cno);
	upper_bound_cno += month_ns;

	current_cno = ssdfs_current_cno(tbl->fsi->sb);

	SSDFS_DBG("current_cno %llu, upper_bound_cno %llu\n",
		  current_cno, upper_bound_cno);

	return current_cno >= upper_bound_cno;
}

/*
 * set_last_recovering_cno() - set current checkpoint as last recovering try
 * @tbl: mapping table object
 */
static inline
void set_last_recovering_cno(struct ssdfs_peb_mapping_table *tbl)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !tbl->fsi || !tbl->fsi->sb);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tbl %p\n", tbl);

	atomic64_set(&tbl->last_peb_recover_cno,
			ssdfs_current_cno(tbl->fsi->sb));
}

/*
 * ssdfs_maptbl_find_page_recovering_pebs() - finds recovering PEBs in a page
 * @fdesc: fragment descriptor
 * @fragment_index: fragment index
 * @page_index: page index
 * @max_erases: upper bound of erase operations for a page
 * @stage: phase of PEBs recovering
 * @array: array of erase operation results [out]
 *
 * This method tries to find PEBs for recovering.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL  - invalid input.
 * %-ERANGE  - internal error.
 * %-ENOSPC  - array is full.
 */
static int
ssdfs_maptbl_find_page_recovering_pebs(struct ssdfs_maptbl_fragment_desc *fdesc,
					u32 fragment_index,
					pgoff_t page_index,
					int max_erases,
					int stage,
					struct ssdfs_erase_result_array *array)
{
	struct ssdfs_peb_table_fragment_header *hdr;
	bool need_mark_peb_bad = false;
	unsigned long *recover_bmap;
	int recovering_pebs;
	u16 pebs_count;
	struct page *page;
	void *kaddr;
	unsigned long found_item, search_step;
	u16 peb_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc || !array);
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	if (stage >= SSDFS_RECOVER_STAGE_MAX) {
		SSDFS_ERR("invalid recovering stage %#x\n",
			  stage);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fdesc %p, fragment_index %u, page_index %lu, "
		  "max_erases %d, stage %#x\n",
		  fdesc, fragment_index, page_index,
		  max_erases, stage);

	page_index += (pgoff_t)fdesc->fragment_id * fdesc->fragment_pages;

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap(page);

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;

	switch (stage) {
	case SSDFS_CHECK_RECOVERABILITY:
		if (!(hdr->flags & SSDFS_PEBTBL_FIND_RECOVERING_PEBS)) {
			/* no PEBs for recovering */
			goto finish_page_processing;
		}
		break;

	case SSDFS_MAKE_RECOVERING:
		if (!(hdr->flags & SSDFS_PEBTBL_TRY_CORRECT_PEBS_AGAIN)) {
			/* no PEBs for recovering */
			goto finish_page_processing;
		} else if (!(hdr->flags & SSDFS_PEBTBL_FIND_RECOVERING_PEBS)) {
			err = -ERANGE;
			SSDFS_WARN("invalid flags combination: %#x\n",
				   hdr->flags);
			goto finish_page_processing;
		}
		break;

	default:
		BUG();
	};

	if (hdr->recover_months > 0) {
		hdr->recover_months--;
		goto finish_page_processing;
	}

	pebs_count = le16_to_cpu(hdr->pebs_count);
	recover_bmap =
		(unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_RECOVER_BMAP][0];
	recovering_pebs = bitmap_weight(recover_bmap, pebs_count);

	if (unlikely(recovering_pebs == 0)) {
		err = -ERANGE;
		SSDFS_ERR("recovering_pebs == 0\n");
		goto finish_page_processing;
	} else if (hdr->recover_threshold == SSDFS_PEBTBL_BADBLK_THRESHOLD) {
		/* simply reserve PEBs for marking as bad */
		need_mark_peb_bad = true;
	} else if (((recovering_pebs * 100) / pebs_count) < 20) {
		SSDFS_DBG("leave page %lu untouched: "
			  "recovering_pebs %d, pebs_count %u\n",
			  page_index, recovering_pebs, pebs_count);
		hdr->recover_months++;
		goto finish_page_processing;
	}

	max_erases = min_t(int, max_erases, (int)pebs_count);

	if (need_mark_peb_bad)
		search_step = 1;
	else
		search_step = pebs_count / max_erases;

	while (array->size < array->capacity) {
		unsigned long start = 0;
		int state;

		found_item = find_next_bit(recover_bmap, pebs_count,
					   start);
		if (found_item >= pebs_count) {
			/* all PEBs were found */
			goto finish_page_processing;
		}

		array->ptr[array->size].fragment_index = fragment_index;
		peb_index = DEFINE_PEB_INDEX_IN_FRAGMENT(fdesc, page_index,
							 found_item);
		array->ptr[array->size].peb_index = peb_index;
		array->ptr[array->size].peb_id = GET_PEB_ID(kaddr, found_item);

		if (need_mark_peb_bad)
			state = SSDFS_BAD_BLOCK_DETECTED;
		else
			state = SSDFS_ERASE_RESULT_UNKNOWN;

		array->ptr[array->size].state = state;
		array->size++;

		start = (found_item / search_step) * search_step;
	};

finish_page_processing:
	kunmap(page);
	unlock_page(page);
	put_page(page);

	if (array->size >= array->capacity) {
		err = -ENOSPC;
		SSDFS_DBG("array->size %u, max_erases %d\n",
			  array->size, max_erases);
	}

	return err;
}

/*
 * ssdfs_maptbl_collect_recovering_pebs() - collect recovering PEBs in fragment
 * @tbl: mapping table object
 * @fragment_index: fragment index
 * @erases_per_fragment: upper bound of erase operations for fragment
 * @stage: phase of PEBs recovering
 * @array: array of erase operation results [out]
 *
 * This method tries to find PEBs for recovering in fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL  - invalid input.
 * %-ERANGE  - internal error.
 */
static
int ssdfs_maptbl_collect_recovering_pebs(struct ssdfs_peb_mapping_table *tbl,
					 u32 fragment_index,
					 int erases_per_fragment,
					 int stage,
					 struct ssdfs_erase_result_array *array)
{
	struct ssdfs_maptbl_fragment_desc *fdesc;
	int state;
	pgoff_t index, max_index;
	int max_erases;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !array);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));

	if (fragment_index >= tbl->fragments_count) {
		SSDFS_ERR("fragment_index %u >= tbl->fragments_count %u\n",
			  fragment_index, tbl->fragments_count);
		return -EINVAL;
	}

	if (stage >= SSDFS_RECOVER_STAGE_MAX) {
		SSDFS_ERR("invalid recovering stage %#x\n",
			  stage);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tbl %p, fragment_index %u, "
		  "erases_per_fragment %d, stage %#x\n",
		  tbl, fragment_index,
		  erases_per_fragment, stage);

	memset(array->ptr, 0,
		array->capacity * sizeof(struct ssdfs_erase_result));
	array->size = 0;

	fdesc = &tbl->desc_array[fragment_index];

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED ||
	    state == SSDFS_MAPTBL_FRAG_CREATED) {
		/* do nothing */
		return 0;
	}

	down_read(&fdesc->lock);

	if (fdesc->recovering_pebs == 0) {
		/* no PEBs for recovering */
		goto finish_gathering;
	}

	max_index = fdesc->lebtbl_pages;
	max_index += tbl->stripes_per_fragment * fdesc->stripe_pages;
	max_erases = erases_per_fragment / fdesc->stripe_pages;

	for (index = fdesc->lebtbl_pages; index < max_index; index++) {
		err = ssdfs_maptbl_find_page_recovering_pebs(fdesc,
							     fragment_index,
							     index,
							     max_erases,
							     stage,
							     array);
		if (err == -ENOSPC) {
			err = 0;
			goto finish_gathering;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to collect recovering PEBs: "
				  "fragment_index %u, page_index %lu, "
				  "err %d\n",
				  fragment_index, index, err);
			goto finish_gathering;
		}
	}

finish_gathering:
	up_read(&fdesc->lock);

	return err;
}

/*
 * ssdfs_maptbl_increase_threshold() - increase threshold of waiting time
 * @hdr: PEB table fragment header
 */
static inline void
ssdfs_maptbl_increase_threshold(struct ssdfs_peb_table_fragment_header *hdr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("hdr %p, recover_threshold %u\n",
		  hdr, hdr->recover_threshold);

	switch (hdr->recover_threshold) {
	case SSDFS_PEBTBL_FIRST_RECOVER_TRY:
		hdr->recover_threshold = SSDFS_PEBTBL_SECOND_RECOVER_TRY;
		hdr->recover_months = 2;
		break;

	case SSDFS_PEBTBL_SECOND_RECOVER_TRY:
		hdr->recover_threshold = SSDFS_PEBTBL_THIRD_RECOVER_TRY;
		hdr->recover_months = 3;
		break;

	case SSDFS_PEBTBL_THIRD_RECOVER_TRY:
		hdr->recover_threshold = SSDFS_PEBTBL_FOURTH_RECOVER_TRY;
		hdr->recover_months = 4;
		break;

	case SSDFS_PEBTBL_FOURTH_RECOVER_TRY:
		hdr->recover_threshold = SSDFS_PEBTBL_FIFTH_RECOVER_TRY;
		hdr->recover_months = 5;
		break;

	case SSDFS_PEBTBL_FIFTH_RECOVER_TRY:
		hdr->recover_threshold = SSDFS_PEBTBL_SIX_RECOVER_TRY;
		hdr->recover_months = 6;
		break;

	case SSDFS_PEBTBL_SIX_RECOVER_TRY:
		hdr->recover_threshold = SSDFS_PEBTBL_BADBLK_THRESHOLD;
		hdr->recover_months = 0;
		break;

	default:
		/* do nothing */
		break;
	}
}

/*
 * ssdfs_maptbl_define_wait_time() - define time of next waiting iteration
 * @hdr: PEB table fragment header
 */
static inline void
ssdfs_maptbl_define_wait_time(struct ssdfs_peb_table_fragment_header *hdr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("hdr %p, recover_threshold %u\n",
		  hdr, hdr->recover_threshold);

	switch (hdr->recover_threshold) {
	case SSDFS_PEBTBL_FIRST_RECOVER_TRY:
		hdr->recover_months = 1;
		break;

	case SSDFS_PEBTBL_SECOND_RECOVER_TRY:
		hdr->recover_months = 2;
		break;

	case SSDFS_PEBTBL_THIRD_RECOVER_TRY:
		hdr->recover_months = 3;
		break;

	case SSDFS_PEBTBL_FOURTH_RECOVER_TRY:
		hdr->recover_months = 4;
		break;

	case SSDFS_PEBTBL_FIFTH_RECOVER_TRY:
		hdr->recover_months = 5;
		break;

	case SSDFS_PEBTBL_SIX_RECOVER_TRY:
		hdr->recover_months = 6;
		break;

	default:
		hdr->recover_months = 0;
		break;
	}
}

/*
 * ssdfs_maptbl_correct_page_recovered_pebs() - correct state of PEBs in page
 * @tbl: mapping table object
 * @ptr: fragment descriptor
 * @array: array of erase operation results
 * @item_index: pointer on current index in array [in|out]
 *
 * This method corrects PEBs state after recovering.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL  - invalid input.
 * %-ERANGE  - internal error.
 */
static int
ssdfs_maptbl_correct_page_recovered_pebs(struct ssdfs_peb_mapping_table *tbl,
					 struct ssdfs_maptbl_fragment_desc *ptr,
					 struct ssdfs_erase_result_array *array,
					 u32 *item_index)
{
	struct ssdfs_peb_table_fragment_header *hdr;
	struct ssdfs_peb_descriptor *peb_desc;
	struct ssdfs_erase_result *res;
	pgoff_t page_index, next_page;
	struct page *page;
	void *kaddr;
	unsigned long *dirty_bmap, *used_bmap, *recover_bmap, *bad_bmap;
	u32 recovered_pebs = 0, failed_pebs = 0, bad_pebs = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !ptr || !array || !array->ptr || !item_index);
	BUG_ON(array->capacity == 0);
	BUG_ON(array->capacity < array->size);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));
	BUG_ON(!rwsem_is_locked(&ptr->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fdesc %p, capacity %u, size %u, item_index %u\n",
		  ptr, array->capacity, array->size, *item_index);

	if (*item_index >= array->size) {
		SSDFS_ERR("item_index %u >= array->size %u\n",
			  *item_index, array->size);
		return -EINVAL;
	}

	res = &array->ptr[*item_index];
	page_index = PEBTBL_PAGE_INDEX(ptr, res->peb_index);
	page_index += (pgoff_t)ptr->fragment_id * ptr->fragment_pages;

	page = ssdfs_page_array_get_page_locked(&ptr->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap(page);

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;
	dirty_bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_DIRTY_BMAP][0];
	used_bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_USED_BMAP][0];
	recover_bmap =
		(unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_RECOVER_BMAP][0];
	bad_bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_BADBLK_BMAP][0];

	if (!(hdr->flags & SSDFS_PEBTBL_UNDER_RECOVERING)) {
		err = -ERANGE;
		SSDFS_ERR("page %lu isn't recovering\n", page_index);
		goto finish_page_processing;
	}

	do {
		res = &array->ptr[*item_index];

		peb_desc = GET_PEB_DESCRIPTOR(hdr, res->peb_index);
		if (IS_ERR_OR_NULL(peb_desc)) {
			err = IS_ERR(peb_desc) ? PTR_ERR(peb_desc) : -ERANGE;
			SSDFS_ERR("fail to get peb_descriptor: "
				  "peb_index %u, err %d\n",
				  res->peb_index, err);
			goto finish_page_processing;
		}

		if (peb_desc->state != SSDFS_MAPTBL_RECOVERING_STATE) {
			err = -ERANGE;
			SSDFS_ERR("invalid PEB state: "
				  "peb_id %llu, peb_index %u, state %#x\n",
				  res->peb_id, res->peb_index, res->state);
			goto finish_page_processing;
		}

		if (res->state == SSDFS_BAD_BLOCK_DETECTED) {
			peb_desc->state = SSDFS_MAPTBL_BAD_PEB_STATE;
			bitmap_clear(dirty_bmap, res->peb_index, 1);
			bitmap_set(bad_bmap, res->peb_index, 1);
			ptr->recovering_pebs--;

			bad_pebs++;
		} else if (res->state != SSDFS_ERASE_DONE) {
			/* do nothing */
			failed_pebs++;
		} else {
			peb_desc->state = SSDFS_MAPTBL_UNKNOWN_PEB_STATE;
			bitmap_clear(recover_bmap, res->peb_index, 1);
			bitmap_clear(used_bmap, res->peb_index, 1);
			le16_add_cpu(&hdr->reserved_pebs, 1);
			ptr->recovering_pebs--;

			recovered_pebs++;
		}

		++*item_index;

		res->peb_index = array->ptr[*item_index].peb_index;
		next_page = PEBTBL_PAGE_INDEX(ptr, res->peb_index);
	} while (*item_index < array->size && page_index == next_page);

	if (bad_pebs > 0) {
		err = -EAGAIN;
		hdr->flags |= SSDFS_PEBTBL_BADBLK_EXIST;
		hdr->flags &= ~SSDFS_PEBTBL_UNDER_RECOVERING;
		hdr->flags |= SSDFS_PEBTBL_TRY_CORRECT_PEBS_AGAIN;
		BUG_ON(recovered_pebs > 0);
	} else if (recovered_pebs == 0) {
		BUG_ON(failed_pebs == 0);
		ssdfs_maptbl_increase_threshold(hdr);
		hdr->flags &= ~SSDFS_PEBTBL_TRY_CORRECT_PEBS_AGAIN;
	} else if (recovered_pebs < failed_pebs) {
		/* use the same duration for recovering */
		ssdfs_maptbl_define_wait_time(hdr);
		hdr->flags &= ~SSDFS_PEBTBL_TRY_CORRECT_PEBS_AGAIN;
	} else {
		err = -EAGAIN;
		hdr->flags |= SSDFS_PEBTBL_TRY_CORRECT_PEBS_AGAIN;
	}

finish_page_processing:
	kunmap(page);
	unlock_page(page);
	put_page(page);

	return err;
}

/*
 * ssdfs_correct_fragment_recovered_pebs() - correct state of PEBs in fragment
 * @tbl: mapping table object
 * @array: array of erase operation results
 * @item_index: pointer on current index in array [in|out]
 *
 * This method corrects PEBs state after recovering.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL  - invalid input.
 * %-ERANGE  - internal error.
 * %-EAGAIN  - need to repeat recovering.
 */
static int
ssdfs_correct_fragment_recovered_pebs(struct ssdfs_peb_mapping_table *tbl,
				      struct ssdfs_erase_result_array *array,
				      u32 *item_index)
{
	struct ssdfs_maptbl_fragment_desc *fdesc;
	u32 fragment_index;
	int state;
	int err = 0, err2 = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !array || !array->ptr || !item_index);
	BUG_ON(array->capacity == 0);
	BUG_ON(array->capacity < array->size);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tbl %p, capacity %u, size %u, item_index %u\n",
		  tbl, array->capacity, array->size, *item_index);

	if (*item_index >= array->size) {
		SSDFS_ERR("item_index %u >= array->size %u\n",
			  *item_index, array->size);
		return -EINVAL;
	}

	fragment_index = array->ptr[*item_index].fragment_index;

	if (fragment_index >= tbl->fragments_count) {
		SSDFS_ERR("fragment_index %u >= tbl->fragments_count %u\n",
			  fragment_index, tbl->fragments_count);
		return -ERANGE;
	}

	fdesc = &tbl->desc_array[fragment_index];

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED ||
	    state == SSDFS_MAPTBL_FRAG_CREATED) {
		SSDFS_ERR("fail to correct fragment: "
			  "fragment_index %u, state %#x\n",
			  fragment_index, state);
		return -ERANGE;
	}

	down_write(&fdesc->lock);

	if (fdesc->recovering_pebs == 0) {
		SSDFS_ERR("fdesc->recovering_pebs == 0\n");
		err = -ERANGE;
		goto finish_fragment_correction;
	}

	do {
		err = ssdfs_maptbl_correct_page_recovered_pebs(tbl, fdesc,
							       array,
							       item_index);
		if (err == -EAGAIN) {
			err2 = -EAGAIN;
			err = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to correct page's PEB state: "
				  "item_index %u, err %d\n",
				  *item_index, err);
			goto finish_fragment_correction;
		}
	} while (*item_index < array->size &&
		 fragment_index == array->ptr[*item_index].fragment_index);

finish_fragment_correction:
	up_write(&fdesc->lock);

	if (!err) {
		atomic_set(&fdesc->state, SSDFS_MAPTBL_FRAG_DIRTY);
		mutex_lock(&tbl->bmap_lock);
		bitmap_set(tbl->dirty_bmap, fragment_index, 1);
		mutex_unlock(&tbl->bmap_lock);
		err = err2;
	}

	return err;
}

/*
 * ssdfs_maptbl_correct_recovered_pebs() - correct state of PEBs
 * @tbl: mapping table object
 * @array: array of erase operation results
 *
 * This method corrects PEBs state after recovering.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL  - invalid input.
 * %-ERANGE  - internal error.
 * %-EAGAIN  - need to repeat recovering.
 */
static
int ssdfs_maptbl_correct_recovered_pebs(struct ssdfs_peb_mapping_table *tbl,
					struct ssdfs_erase_result_array *array)
{
	u32 item_index = 0;
	int err = 0, err2 = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !array || !array->ptr);
	BUG_ON(array->capacity == 0);
	BUG_ON(array->capacity < array->size);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tbl %p, capacity %u, size %u\n",
		  tbl, array->capacity, array->size);

	if (array->size == 0)
		return 0;

	do {
		err = ssdfs_correct_fragment_recovered_pebs(tbl, array,
							    &item_index);
		if (err == -EAGAIN) {
			err2 = err;
			err = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to correct fragment's: err %d\n",
				  err);
			return err;
		}
	} while (item_index < array->size);

	if (item_index != array->size) {
		SSDFS_ERR("item_index %u != array->size %u\n",
			  item_index, array->size);
		return -ERANGE;
	}

	return !err ? err2 : err;
}

/*
 * ssdfs_maptbl_process_dirty_pebs() - process dirty PEBs
 * @tbl: mapping table object
 * @array: array of erase operation results
 */
static
int ssdfs_maptbl_process_dirty_pebs(struct ssdfs_peb_mapping_table *tbl,
				    struct ssdfs_erase_result_array *array)
{
	u32 fragments_count;
	int max_erase_ops;
	int erases_per_fragment;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !array || !array->ptr);
	BUG_ON(array->capacity == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tbl %p, capacity %u\n",
		  tbl, array->capacity);

	max_erase_ops = atomic_read(&tbl->max_erase_ops);
	max_erase_ops = min_t(int, max_erase_ops, array->capacity);

	if (max_erase_ops == 0) {
		SSDFS_WARN("max_erase_ops == 0\n");
		return 0;
	}

	down_read(&tbl->tbl_lock);

	fragments_count = tbl->fragments_count;
	erases_per_fragment = max_erase_ops / fragments_count;
	if (erases_per_fragment == 0)
		erases_per_fragment = 1;

	for (i = 0; i < fragments_count; i++) {
		err = ssdfs_maptbl_collect_dirty_pebs(tbl, i,
							erases_per_fragment,
							array);
		if (unlikely(err)) {
			SSDFS_ERR("fail to collect dirty pebs: "
				  "fragment_index %d, err %d\n",
				  i, err);
			goto finish_collect_dirty_pebs;
		}
	}

finish_collect_dirty_pebs:
	up_read(&tbl->tbl_lock);

	if (err)
		goto finish_dirty_pebs_processing;

	err = ssdfs_maptbl_erase_pebs_array(tbl->fsi, array);
	if (err == -EROFS) {
		err = 0;
		SSDFS_DBG("file system has READ-ONLY state\n");
		goto finish_dirty_pebs_processing;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to erase PEBs in array: err %d\n", err);
		goto finish_dirty_pebs_processing;
	}

	down_read(&tbl->tbl_lock);
	err = ssdfs_maptbl_correct_dirty_pebs(tbl, array);
	if (unlikely(err)) {
		SSDFS_ERR("fail to correct erased PEBs state: err %d\n",
			  err);
	}
	up_read(&tbl->tbl_lock);

finish_dirty_pebs_processing:
	return err;
}

/*
 * __ssdfs_maptbl_recover_pebs() - try to recover PEBs
 * @tbl: mapping table object
 * @array: array of erase operation results
 * @stage: phase of PEBs recovering
 *
 * This method tries to recover PEBs.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL  - invalid input.
 * %-ERANGE  - internal error.
 * %-EAGAIN  - need to repeat recovering.
 */
static
int __ssdfs_maptbl_recover_pebs(struct ssdfs_peb_mapping_table *tbl,
				struct ssdfs_erase_result_array *array,
				int stage)
{
	u32 fragments_count;
	int max_erase_ops;
	int erases_per_fragment;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !array || !array->ptr);
	BUG_ON(array->capacity == 0);

	if (stage >= SSDFS_RECOVER_STAGE_MAX) {
		SSDFS_ERR("invalid recovering stage %#x\n",
			  stage);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tbl %p, capacity %u, stage %#x\n",
		  tbl, array->capacity, stage);

	max_erase_ops = atomic_read(&tbl->max_erase_ops);
	max_erase_ops = min_t(int, max_erase_ops, array->capacity);

	if (max_erase_ops == 0) {
		SSDFS_WARN("max_erase_ops == 0\n");
		return 0;
	}

	down_read(&tbl->tbl_lock);

	fragments_count = tbl->fragments_count;
	erases_per_fragment = max_erase_ops / fragments_count;
	if (erases_per_fragment == 0)
		erases_per_fragment = 1;

	for (i = 0; i < fragments_count; i++) {
		err = ssdfs_maptbl_collect_recovering_pebs(tbl, i,
							   erases_per_fragment,
							   stage,
							   array);
		if (unlikely(err)) {
			SSDFS_ERR("fail to collect recovering pebs: "
				  "fragment_index %d, err %d\n",
				  i, err);
			goto finish_collect_recovering_pebs;
		}
	}

finish_collect_recovering_pebs:
	up_read(&tbl->tbl_lock);

	if (err)
		goto finish_pebs_recovering;

	err = ssdfs_maptbl_erase_pebs_array(tbl->fsi, array);
	if (err == -EROFS) {
		err = 0;
		SSDFS_DBG("file system has READ-ONLY state\n");
		goto finish_pebs_recovering;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to erase PEBs in array: err %d\n", err);
		goto finish_pebs_recovering;
	}

	down_read(&tbl->tbl_lock);
	err = ssdfs_maptbl_correct_recovered_pebs(tbl, array);
	if (unlikely(err)) {
		SSDFS_ERR("fail to correct recovered PEBs state: err %d\n",
			  err);
	}
	up_read(&tbl->tbl_lock);

finish_pebs_recovering:
	return err;
}

/*
 * ssdfs_maptbl_check_pebs_recoverability() - check PEBs recoverability
 * @tbl: mapping table object
 * @array: array of erase operation results
 *
 * This method check that PEBs are ready for recovering.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL  - invalid input.
 * %-ERANGE  - internal error.
 * %-EAGAIN  - need to repeat recovering.
 */
static inline int
ssdfs_maptbl_check_pebs_recoverability(struct ssdfs_peb_mapping_table *tbl,
					struct ssdfs_erase_result_array *array)
{
	int stage = SSDFS_CHECK_RECOVERABILITY;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !array || !array->ptr);
	BUG_ON(array->capacity == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tbl %p, capacity %u\n",
		  tbl, array->capacity);

	return __ssdfs_maptbl_recover_pebs(tbl, array, stage);
}

/*
 * ssdfs_maptbl_recover_pebs() - recover as many PEBs as possible
 * @tbl: mapping table object
 * @array: array of erase operation results
 *
 * This method tries to recover as many PEBs as possible.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL  - invalid input.
 * %-ERANGE  - internal error.
 * %-EAGAIN  - need to repeat recovering.
 */
static
int ssdfs_maptbl_recover_pebs(struct ssdfs_peb_mapping_table *tbl,
			      struct ssdfs_erase_result_array *array)
{
	int stage = SSDFS_MAKE_RECOVERING;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !array || !array->ptr);
	BUG_ON(array->capacity == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tbl %p, capacity %u\n",
		  tbl, array->capacity);

	return __ssdfs_maptbl_recover_pebs(tbl, array, stage);
}

/*
 * ssdfs_maptbl_resolve_peb_mapping() - resolve inconsistency
 * @tbl: mapping table object
 * @cache: mapping table cache
 * @pmi: PEB mapping info
 *
 * This method tries to resolve inconsistency of states between
 * mapping table and cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 *  %-EINVAL  - invalid input.
 *  %-EFAULT  - unable to do resolving.
 *  %-ENODATA - PEB ID is not found.
 *  %-EAGAIN  - repeat resolving again.
 */
static
int ssdfs_maptbl_resolve_peb_mapping(struct ssdfs_peb_mapping_table *tbl,
				     struct ssdfs_maptbl_cache *cache,
				     struct ssdfs_peb_mapping_info *pmi)
{
	struct ssdfs_maptbl_peb_relation pebr;
	int consistency = SSDFS_PEB_STATE_UNKNOWN;
	struct ssdfs_maptbl_fragment_desc *fdesc;
	int state;
	bool need_make_consistent = false;
	bool need_exclude_migration_peb = false;
	u64 peb_id;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !cache || !pmi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("leb_id %llu, peb_id %llu, consistency %#x\n",
		  pmi->leb_id, pmi->peb_id, pmi->consistency);

	if (pmi->leb_id >= U64_MAX) {
		SSDFS_ERR("invalid leb_id %llu\n", pmi->leb_id);
		return -EINVAL;
	}

	if (pmi->peb_id >= U64_MAX) {
		SSDFS_ERR("invalid peb_id %llu\n", pmi->peb_id);
		return -EINVAL;
	}

	switch (pmi->consistency) {
	case SSDFS_PEB_STATE_CONSISTENT:
		SSDFS_WARN("unexpected consistency %#x\n",
			   pmi->consistency);
		return -EINVAL;

	case SSDFS_PEB_STATE_INCONSISTENT:
	case SSDFS_PEB_STATE_PRE_DELETED:
		/* expected consistency */
		break;

	default:
		SSDFS_ERR("invalid consistency %#x\n",
			  pmi->consistency);
		return -ERANGE;
	}

	err = ssdfs_maptbl_cache_convert_leb2peb(cache,
						 pmi->leb_id,
						 &pebr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert LEB to PEB: "
			  "leb_id %llu, err %d\n",
			  pmi->leb_id, err);
		return err;
	}

	for (i = SSDFS_MAPTBL_MAIN_INDEX; i < SSDFS_MAPTBL_RELATION_MAX; i++) {
		peb_id = pebr.pebs[i].peb_id;

		if (peb_id == pmi->peb_id) {
			consistency = pebr.pebs[i].consistency;
			break;
		}
	}

	if (consistency == SSDFS_PEB_STATE_UNKNOWN) {
		SSDFS_DBG("peb_id %llu isn't be found\n", pmi->peb_id);
		return -ENODATA;
	}

	switch (consistency) {
	case SSDFS_PEB_STATE_CONSISTENT:
		SSDFS_DBG("peb_id %llu has consistent state already\n",
			  pmi->peb_id);
		return 0;

	default:
		if (consistency != pmi->consistency) {
			SSDFS_DBG("consistency1 %#x != consistency2 %#x\n",
				  consistency, pmi->consistency);
		}
		break;
	}

	down_read(&tbl->tbl_lock);

	fdesc = ssdfs_maptbl_get_fragment_descriptor(tbl, pmi->leb_id);
	if (IS_ERR_OR_NULL(fdesc)) {
		err = IS_ERR(fdesc) ? PTR_ERR(fdesc) : -ERANGE;
		SSDFS_ERR("fail to get fragment descriptor: "
			  "leb_id %llu, err %d\n",
			  pmi->leb_id, err);
		goto finish_resolving;
	}

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
		err = -EFAULT;
		SSDFS_ERR("fragment is corrupted: leb_id %llu\n",
			  pmi->leb_id);
		goto finish_resolving;
	} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
		struct completion *end = &fdesc->init_end;
		unsigned long res;

		up_read(&tbl->tbl_lock);
		res = wait_for_completion_timeout(end,
					SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("maptbl's fragment init failed: "
				  "leb_id %llu, err %d\n",
				  pmi->leb_id, err);
			goto finish_resolving_no_lock;
		}
		down_read(&tbl->tbl_lock);
	}

	switch (consistency) {
	case SSDFS_PEB_STATE_INCONSISTENT:
		down_write(&fdesc->lock);

		err = ssdfs_maptbl_solve_inconsistency(tbl, fdesc,
							pmi->leb_id,
							&pebr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to resolve inconsistency: "
				  "leb_id %llu, err %d\n",
				  pmi->leb_id, err);
			goto finish_inconsistent_case;
		}

		need_make_consistent = true;

finish_inconsistent_case:
		up_write(&fdesc->lock);

		if (!err) {
			ssdfs_maptbl_set_fragment_dirty(tbl, fdesc,
							pmi->leb_id);
		}
		break;

	case SSDFS_PEB_STATE_PRE_DELETED:
		down_write(&fdesc->lock);

		err = ssdfs_maptbl_solve_pre_deleted_state(tbl, fdesc,
							   pmi->leb_id);
		if (unlikely(err)) {
			SSDFS_ERR("fail to resolve pre-deleted state: "
				  "leb_id %llu, err %d\n",
				  pmi->leb_id, err);
			goto finish_pre_deleted_case;
		}

		need_exclude_migration_peb = true;

finish_pre_deleted_case:
		up_write(&fdesc->lock);

		if (!err) {
			ssdfs_maptbl_set_fragment_dirty(tbl, fdesc,
							pmi->leb_id);
		}
		break;

	default:
		err = -EFAULT;
		SSDFS_ERR("invalid consistency %#x\n",
			  consistency);
		goto finish_resolving;
	}

finish_resolving:
	up_read(&tbl->tbl_lock);

finish_resolving_no_lock:
	if (!err && need_make_consistent) {
		u8 peb_state;

		peb_id = pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id;
		peb_state = pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].state;
		if (peb_id != U64_MAX) {
			consistency = SSDFS_PEB_STATE_CONSISTENT;
			err = ssdfs_maptbl_cache_change_peb_state(cache,
								  pmi->leb_id,
								  peb_state,
								  consistency);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change PEB state: "
					  "leb_id %llu, peb_state %#x, "
					  "err %d\n",
					  pmi->leb_id, peb_state, err);
			}
		}

		peb_id = pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].peb_id;
		peb_state = pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].state;
		if (peb_id != U64_MAX) {
			consistency = SSDFS_PEB_STATE_CONSISTENT;
			err = ssdfs_maptbl_cache_change_peb_state(cache,
								  pmi->leb_id,
								  peb_state,
								  consistency);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change PEB state: "
					  "leb_id %llu, peb_state %#x, "
					  "err %d\n",
					  pmi->leb_id, peb_state, err);
			}
		}
	} else if (!err && need_exclude_migration_peb) {
		consistency = SSDFS_PEB_STATE_CONSISTENT;
		err = ssdfs_maptbl_cache_exclude_migration_peb(cache,
								pmi->leb_id,
								consistency);
		if (unlikely(err)) {
			SSDFS_ERR("fail to exclude migration PEB: "
				  "leb_id %llu, err %d\n",
				  pmi->leb_id, err);
		}
	}

	SSDFS_DBG("finished\n");

	return err;
}

/*
 * has_maptbl_pre_erase_pebs() - check that maptbl contains pre-erased PEBs
 * @tbl: mapping table object
 */
static inline
bool has_maptbl_pre_erase_pebs(struct ssdfs_peb_mapping_table *tbl)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	return atomic_read(&tbl->pre_erase_pebs) != 0;
}

#define MAPTBL_PTR(tbl) \
	((struct ssdfs_peb_mapping_table *)(tbl))
#define MAPTBL_THREAD_WAKE_CONDITION(tbl, cache) \
	(kthread_should_stop() || \
	 has_maptbl_pre_erase_pebs(MAPTBL_PTR(tbl)) || \
	 !is_ssdfs_peb_mapping_queue_empty(&cache->pm_queue))

/*
 * ssdfs_maptbl_thread_func() - maptbl object's thread's function
 */
static
int ssdfs_maptbl_thread_func(void *data)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_mapping_table *tbl = data;
	struct ssdfs_maptbl_cache *cache;
	struct ssdfs_peb_mapping_info *pmi;
	wait_queue_head_t *wait_queue;
	struct ssdfs_erase_result_array array = {NULL, 0, 0};
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!tbl) {
		SSDFS_ERR("pointer on mapping table object is NULL\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("MAPTBL thread\n");

	fsi = tbl->fsi;
	cache = &fsi->maptbl_cache;
	wait_queue = &tbl->wait_queue;

	array.capacity = tbl->pebs_per_fragment;
	array.size = 0;
	array.ptr = kcalloc(array.capacity,
			    sizeof(struct ssdfs_erase_result),
			    GFP_KERNEL);
	if (!array.ptr) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate erase_results array\n");
		goto sleep_maptbl_thread;
	}

repeat:
	if (kthread_should_stop()) {
		complete_all(&tbl->thread.full_stop);
		if (array.ptr)
			kfree(array.ptr);
		return err;
	}

	if (unlikely(err))
		goto sleep_maptbl_thread;

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR)
		err = -EFAULT;

	if (unlikely(err)) {
		SSDFS_ERR("fail to continue activity: err %d\n", err);
		goto sleep_maptbl_thread;
	}

	if (!has_maptbl_pre_erase_pebs(tbl) &&
	    is_ssdfs_peb_mapping_queue_empty(&cache->pm_queue)) {
		/* go to sleep */
		goto sleep_maptbl_thread;
	}

	while (!is_ssdfs_peb_mapping_queue_empty(&cache->pm_queue)) {
		err = ssdfs_peb_mapping_queue_remove_first(&cache->pm_queue,
							   &pmi);
		if (err == -ENODATA) {
			/* empty queue */
			err = 0;
			break;
		} else if (err == -ENOENT) {
			SSDFS_WARN("request queue contains NULL request\n");
			err = 0;
			continue;
		} else if (unlikely(err < 0)) {
			SSDFS_CRIT("fail to get request from the queue: "
				   "err %d\n",
				   err);
			goto check_next_step;
		}

		err = ssdfs_maptbl_resolve_peb_mapping(tbl, cache, pmi);
		if (err == -EAGAIN) {
			ssdfs_peb_mapping_queue_add_tail(&cache->pm_queue,
							 pmi);
			continue;
		} else if (unlikely(err)) {
			ssdfs_peb_mapping_queue_add_tail(&cache->pm_queue,
							 pmi);
			SSDFS_ERR("failed to resolve inconsistency: "
				  "leb_id %llu, peb_id %llu, err %d\n",
				  pmi->leb_id, pmi->peb_id, err);
			goto check_next_step;
		}

		ssdfs_peb_mapping_info_free(pmi);
	}

	if (has_maptbl_pre_erase_pebs(tbl)) {
		err = ssdfs_maptbl_process_dirty_pebs(tbl, &array);
		if (unlikely(err)) {
			SSDFS_ERR("fail to process dirty PEBs: err %d\n",
				  err);
		}
	}

check_next_step:
	if (kthread_should_stop())
		goto repeat;

	if (unlikely(err))
		goto sleep_maptbl_thread;

	if (!is_time_to_recover_pebs(tbl))
		goto sleep_maptbl_thread;

	err = ssdfs_maptbl_check_pebs_recoverability(tbl, &array);
	if (err && err != -EAGAIN) {
		SSDFS_ERR("fail to check PEBs recoverability: "
			  "err %d\n",
			  err);
		goto sleep_maptbl_thread;
	}

	set_last_recovering_cno(tbl);

	if (kthread_should_stop())
		goto repeat;

	while (err == -EAGAIN) {
		err = ssdfs_maptbl_recover_pebs(tbl, &array);
		if (err && err != -EAGAIN) {
			SSDFS_ERR("fail to recover PEBs: err %d\n",
				  err);
			goto sleep_maptbl_thread;
		}

		set_last_recovering_cno(tbl);

		if (kthread_should_stop())
			goto repeat;
	}

sleep_maptbl_thread:
	wait_event_interruptible(*wait_queue,
				 MAPTBL_THREAD_WAKE_CONDITION(tbl, cache));
	goto repeat;
}

static
struct ssdfs_thread_descriptor maptbl_thread = {
	.threadfn = ssdfs_maptbl_thread_func,
	.fmt = "ssdfs-maptbl",
};

/*
 * ssdfs_maptbl_start_thread() - start mapping table's thread
 * @tbl: mapping table object
 */
int ssdfs_maptbl_start_thread(struct ssdfs_peb_mapping_table *tbl)
{
	ssdfs_threadfn threadfn;
	const char *fmt;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tbl %p\n", tbl);

	threadfn = maptbl_thread.threadfn;
	fmt = maptbl_thread.fmt;

	tbl->thread.task = kthread_create(threadfn, tbl, fmt);
	if (IS_ERR_OR_NULL(tbl->thread.task)) {
		err = PTR_ERR(tbl->thread.task);
		SSDFS_ERR("fail to start mapping table's thread: "
			  "err %d\n", err);
		return err;
	}

	init_waitqueue_entry(&tbl->thread.wait, tbl->thread.task);
	add_wait_queue(&tbl->wait_queue, &tbl->thread.wait);
	init_completion(&tbl->thread.full_stop);

	wake_up_process(tbl->thread.task);

	return 0;
}

/*
 * ssdfs_maptbl_stop_thread() - stop mapping table's thread
 * @tbl: mapping table object
 */
int ssdfs_maptbl_stop_thread(struct ssdfs_peb_mapping_table *tbl)
{
	unsigned long res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!tbl->thread.task)
		return 0;

	err = kthread_stop(tbl->thread.task);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 * The wake_up_process() was never called.
		 */
		return 0;
	} else if (unlikely(err)) {
		SSDFS_WARN("thread function had some issue: err %d\n",
			    err);
		return err;
	}

	finish_wait(&tbl->wait_queue, &tbl->thread.wait);
	tbl->thread.task = NULL;

	res = wait_for_completion_timeout(&tbl->thread.full_stop,
					SSDFS_DEFAULT_TIMEOUT);
	if (res == 0) {
		err = -ERANGE;
		SSDFS_ERR("stop thread fails: err %d\n", err);
		return err;
	}

	return 0;
}
