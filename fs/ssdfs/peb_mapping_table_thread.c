/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_mapping_table_thread.c - PEB mapping table thread functionality.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2025 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include <linux/kthread.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "folio_array.h"
#include "peb_mapping_table.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_map_thread_folio_leaks;
atomic64_t ssdfs_map_thread_memory_leaks;
atomic64_t ssdfs_map_thread_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_map_thread_cache_leaks_increment(void *kaddr)
 * void ssdfs_map_thread_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_map_thread_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_map_thread_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_map_thread_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_map_thread_kfree(void *kaddr)
 * struct folio *ssdfs_map_thread_alloc_folio(gfp_t gfp_mask,
 *                                            unsigned int order)
 * struct folio *ssdfs_map_thread_add_batch_folio(struct folio_batch *batch,
 *                                                unsigned int order)
 * void ssdfs_map_thread_free_folio(struct folio *folio)
 * void ssdfs_map_thread_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(map_thread)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(map_thread)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_map_thread_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_map_thread_folio_leaks, 0);
	atomic64_set(&ssdfs_map_thread_memory_leaks, 0);
	atomic64_set(&ssdfs_map_thread_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_map_thread_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_map_thread_folio_leaks) != 0) {
		SSDFS_ERR("MAPPING TABLE THREAD: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_map_thread_folio_leaks));
	}

	if (atomic64_read(&ssdfs_map_thread_memory_leaks) != 0) {
		SSDFS_ERR("MAPPING TABLE THREAD: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_map_thread_memory_leaks));
	}

	if (atomic64_read(&ssdfs_map_thread_cache_leaks) != 0) {
		SSDFS_ERR("MAPPING TABLE THREAD: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_map_thread_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * is_time_to_erase_peb() - check that PEB can be erased
 * @hdr: fragment's header
 * @found_item: PEB index in the fragment
 */
static
bool is_time_to_erase_peb(struct ssdfs_peb_table_fragment_header *hdr,
			  unsigned long found_item)
{
#ifndef CONFIG_SSDFS_FIXED_SUPERBLOCK_SEGMENTS_SET
	unsigned long *used_bmap;
	unsigned long *dirty_bmap;
	u16 pebs_count;
	unsigned long protected_item = found_item;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr);

	SSDFS_DBG("hdr %p, found_item %lu\n",
		  hdr, found_item);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_peb_protected(found_item))
		return true;

	used_bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_USED_BMAP][0];
	dirty_bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_DIRTY_BMAP][0];
	pebs_count = le16_to_cpu(hdr->pebs_count);

	if (found_item >= pebs_count) {
		SSDFS_ERR("found_item %lu >= pebs_count %u\n",
			  found_item, pebs_count);
		return false;
	}

	for (i = 0; i < SSDFS_MAPTBL_PROTECTION_RANGE; i++) {
		unsigned long found;

		protected_item += SSDFS_MAPTBL_PROTECTION_STEP;

		if (protected_item >= pebs_count)
			protected_item = SSDFS_MAPTBL_FIRST_PROTECTED_INDEX;

		if (protected_item == found_item)
			return false;

		found = find_next_bit(used_bmap, pebs_count,
				      protected_item);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("i %d, protected_item %lu, found %lu\n",
			  i, protected_item, found);
#endif /* CONFIG_SSDFS_DEBUG */

		if (found == protected_item)
			continue;

		found = find_next_bit(dirty_bmap, pebs_count,
				      protected_item);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("i %d, protected_item %lu, found %lu\n",
			  i, protected_item, found);
#endif /* CONFIG_SSDFS_DEBUG */

		if (found == protected_item)
			continue;

		/* the item is protected */
		return false;
	}

	return true;
#else
	/*
	 * This method is designed to protect segments
	 * in special positions from erasing with the goal
	 * to guarantee reliable and fast search of latest
	 * actual superblock segment. In the case of using
	 * the fixed set of superblock segments, this
	 * techique of protection is useless.
	 */
	return true;
#endif /* CONFIG_SSDFS_FIXED_SUPERBLOCK_SEGMENTS_SET */
}

/*
 * does_peb_contain_snapshot() - check that PEB contains snapshot
 * @ptr: PEB descriptor
 */
static inline
bool does_peb_contain_snapshot(struct ssdfs_peb_descriptor *ptr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);

	SSDFS_DBG("ptr->state %#x\n",
		  ptr->state);
#endif /* CONFIG_SSDFS_DEBUG */

	if (ptr->state == SSDFS_MAPTBL_SNAPSHOT_STATE)
		return true;

	return false;
}

/*
 * ssdfs_maptbl_collect_stripe_dirty_pebs() - collect dirty PEBs in stripe
 * @tbl: mapping table object
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
ssdfs_maptbl_collect_stripe_dirty_pebs(struct ssdfs_peb_mapping_table *tbl,
					struct ssdfs_maptbl_fragment_desc *fdesc,
					u32 fragment_index,
					int stripe_index,
					int erases_per_stripe,
					struct ssdfs_erase_result_array *array)
{
	struct ssdfs_peb_table_fragment_header *hdr;
	struct ssdfs_peb_descriptor *ptr;
	int found_pebs = 0;
	u16 stripe_pages = fdesc->stripe_pages;
	pgoff_t start_page;
	unsigned long *dirty_bmap;
	bool has_protected_peb_collected = false;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc || !array);
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	SSDFS_DBG("fdesc %p, fragment_index %u, stripe_index %u, "
		  "erases_per_stripe %d\n",
		  fdesc, fragment_index, stripe_index,
		  erases_per_stripe);
#endif /* CONFIG_SSDFS_DEBUG */

	start_page = stripe_index * stripe_pages;
	start_page += fdesc->lebtbl_pages;

	for (i = 0; i < stripe_pages; i++) {
		pgoff_t folio_index = start_page + i;
		struct folio *folio;
		void *kaddr;
		unsigned long found_item = 0;
		u16 peb_index;
		u64 start_peb;
		u16 pebs_count;

		folio = ssdfs_folio_array_get_folio_locked(&fdesc->array,
							    folio_index);
		if (IS_ERR_OR_NULL(folio)) {
			err = folio == NULL ? -ERANGE : PTR_ERR(folio);
			SSDFS_ERR("fail to find folio: folio_index %lu\n",
				  folio_index);
			return err;
		}

		kaddr = kmap_local_folio(folio, 0);

		hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;
		dirty_bmap =
		    (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_DIRTY_BMAP][0];
		start_peb = le64_to_cpu(hdr->start_peb);
		pebs_count = le16_to_cpu(hdr->pebs_count);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment_index %u, stripe_index %d, "
			  "stripe_page %d, dirty_bits %d\n",
			  fragment_index, stripe_index, i,
			  bitmap_weight(dirty_bmap, pebs_count));
#endif /* CONFIG_SSDFS_DEBUG */

		while (found_pebs < erases_per_stripe) {
			found_item = find_next_bit(dirty_bmap, pebs_count,
						   found_item);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("found_item %lu, pebs_count %u\n",
				  found_item, pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

			if (found_item >= pebs_count) {
				/* all dirty PEBs were found */
				goto finish_folio_processing;
			}

			if ((start_peb + found_item) >= tbl->pebs_count) {
				/* all dirty PEBs were found */
				goto finish_folio_processing;
			}

			if (!is_time_to_erase_peb(hdr, found_item)) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("PEB %llu is protected yet\n",
					  GET_PEB_ID(kaddr, found_item));
#endif /* CONFIG_SSDFS_DEBUG */
				found_item++;
				continue;
			}

			if (is_peb_protected(found_item))
				has_protected_peb_collected = true;

			ptr = GET_PEB_DESCRIPTOR(hdr, found_item);
			if (IS_ERR_OR_NULL(ptr)) {
				err = IS_ERR(ptr) ? PTR_ERR(ptr) : -ERANGE;
				SSDFS_ERR("fail to get peb_descriptor: "
					  "found_item %lu, err %d\n",
					  found_item, err);
				goto finish_folio_processing;
			}

			if (ptr->state == SSDFS_MAPTBL_UNDER_ERASE_STATE) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("PEB %llu is under erase\n",
					  GET_PEB_ID(kaddr, found_item));
#endif /* CONFIG_SSDFS_DEBUG */
				found_item++;
				continue;
			}

			if (does_peb_contain_snapshot(ptr)) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("PEB %llu contains snapshot\n",
					  GET_PEB_ID(kaddr, found_item));
#endif /* CONFIG_SSDFS_DEBUG */
				found_item++;
				continue;
			}

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(array->size >= array->capacity);
#endif /* CONFIG_SSDFS_DEBUG */

			ptr->state = SSDFS_MAPTBL_UNDER_ERASE_STATE;

			peb_index = DEFINE_PEB_INDEX_IN_FRAGMENT(fdesc,
								 folio_index,
								 found_item);
			SSDFS_ERASE_RESULT_INIT(fragment_index, peb_index,
						GET_PEB_ID(kaddr, found_item),
						SSDFS_ERASE_RESULT_UNKNOWN,
						&array->ptr[array->size]);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("peb_id %llu, type %#x, state %#x\n",
				  GET_PEB_ID(kaddr, found_item),
				  ptr->type, ptr->state);
#endif /* CONFIG_SSDFS_DEBUG */

			array->size++;
			found_pebs++;
			found_item++;

			if (has_protected_peb_collected)
				goto finish_folio_processing;
		};

finish_folio_processing:
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);
		ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

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
 * %-ENOENT  - no dirty PEBs.
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

	SSDFS_DBG("tbl %p, fragment_index %u, "
		  "erases_per_fragment %d\n",
		  tbl, fragment_index,
		  erases_per_fragment);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(array->ptr, 0,
		array->capacity * sizeof(struct ssdfs_erase_result));
	array->size = 0;

	fdesc = &tbl->desc_array[fragment_index];

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED ||
	    state == SSDFS_MAPTBL_FRAG_CREATED) {
		/* do nothing */
		return -ENOENT;
	}

	stripes_per_fragment = tbl->stripes_per_fragment;
	erases_per_stripe = erases_per_fragment / stripes_per_fragment;
	if (erases_per_stripe == 0)
		erases_per_stripe = 1;

	down_read(&fdesc->lock);

	if (fdesc->pre_erase_pebs == 0) {
		/* no dirty PEBs */
		err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("no dirty PEBs: fdesc->pre_erase_pebs %u\n",
			  fdesc->pre_erase_pebs);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_gathering;
	}

	for (i = 0; i < stripes_per_fragment; i++) {
		err = ssdfs_maptbl_collect_stripe_dirty_pebs(tbl, fdesc,
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
 * ssdfs_maptbl_erase_peb() - erase particular PEB
 * @fsi: file system info object
 * @result: erase operation result [in|out]
 *
 * This method tries to erase dirty PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EROFS   - file system in RO state.
 */
int ssdfs_maptbl_erase_peb(struct ssdfs_fs_info *fsi,
			   struct ssdfs_erase_result *result)
{
	u64 peb_id;
	loff_t offset;
	size_t len = fsi->erasesize;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !result);
#endif /* CONFIG_SSDFS_DEBUG */

	peb_id = result->peb_id;

	if (((LLONG_MAX - 1) / fsi->erasesize) < peb_id) {
		SSDFS_NOTICE("ignore erasing peb %llu\n", peb_id);
		result->state = SSDFS_IGNORE_ERASE;
		return 0;
	}

	offset = peb_id * fsi->erasesize;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_id %llu, offset %llu\n",
		  peb_id, (u64)offset);
#endif /* CONFIG_SSDFS_DEBUG */

	if (result->state == SSDFS_BAD_BLOCK_DETECTED) {
		err = fsi->devops->mark_peb_bad(fsi->sb, offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to mark PEB as bad: "
				  "peb %llu, err %d\n",
				  peb_id, err);
		}
		err = 0;
	} else {
		err = fsi->devops->trim(fsi->sb, offset, len);
		if (err == -EROFS) {
			SSDFS_DBG("file system has READ_ONLY state\n");
			return err;
		} else if (err == -EFAULT) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("erase operation failure: peb %llu\n",
				  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			result->state = SSDFS_ERASE_FAILURE;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to erase: peb %llu, err %d\n",
				  peb_id, err);
			err = 0;
			result->state = SSDFS_IGNORE_ERASE;
		} else
			result->state = SSDFS_ERASE_DONE;
	}

	return 0;
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
static inline
int ssdfs_maptbl_erase_pebs_array(struct ssdfs_fs_info *fsi,
				  struct ssdfs_erase_result_array *array)
{
	u32 i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !array || !array->ptr);
	BUG_ON(!fsi->devops || !fsi->devops->trim);
	BUG_ON(array->capacity == 0);
	BUG_ON(array->capacity < array->size);

	SSDFS_DBG("fsi %p, capacity %u, size %u\n",
		  fsi, array->capacity, array->size);
#endif /* CONFIG_SSDFS_DEBUG */

	if (array->size == 0)
		return 0;

	for (i = 0; i < array->size; i++) {
		err = ssdfs_maptbl_erase_peb(fsi, &array->ptr[i]);
		if (unlikely(err)) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to erase PEB: "
				  "peb_id %llu, err %d\n",
				  array->ptr[i].peb_id, err);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		}
	}

	return 0;
}

/*
 * __ssdfs_maptbl_correct_peb_state() - correct state of erased PEB
 * @tbl: mapping table object
 * @fdesc: fragment descriptor
 * @hdr: PEB table fragment's header
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
int __ssdfs_maptbl_correct_peb_state(struct ssdfs_peb_mapping_table *tbl,
				     struct ssdfs_maptbl_fragment_desc *fdesc,
				     struct ssdfs_peb_table_fragment_header *hdr,
				     struct ssdfs_erase_result *res)
{
	struct ssdfs_peb_descriptor *ptr;
	unsigned long *dirty_bmap, *used_bmap, *recover_bmap, *bad_bmap;
	u16 item_index;
	u16 reserved_pebs;
	u16 pebs_count;
	int used_pebs, unused_pebs;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !fdesc || !hdr || !res);
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	SSDFS_DBG("fdesc %p, res->fragment_index %u, res->peb_index %u, "
		  "res->peb_id %llu, res->state %#x\n",
		  fdesc, res->fragment_index, res->peb_index,
		  res->peb_id, res->state);
#endif /* CONFIG_SSDFS_DEBUG */

	item_index = res->peb_index % fdesc->pebs_per_page;

	dirty_bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_DIRTY_BMAP][0];
	used_bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_USED_BMAP][0];
	recover_bmap =
		(unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_RECOVER_BMAP][0];
	bad_bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_BADBLK_BMAP][0];

	ptr = GET_PEB_DESCRIPTOR(hdr, item_index);
	if (IS_ERR_OR_NULL(ptr)) {
		err = IS_ERR(ptr) ? PTR_ERR(ptr) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "peb_index %u, err %d\n",
			  res->peb_index, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_id %llu, peb_index %u, state %#x\n",
		  res->peb_id, res->peb_index, ptr->state);
	SSDFS_DBG("erase_cycles %u, type %#x, "
		  "state %#x, flags %#x, shared_peb_index %u\n",
		  le32_to_cpu(ptr->erase_cycles),
		  ptr->type, ptr->state,
		  ptr->flags, ptr->shared_peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (ptr->state != SSDFS_MAPTBL_PRE_ERASE_STATE &&
	    ptr->state != SSDFS_MAPTBL_UNDER_ERASE_STATE &&
	    ptr->state != SSDFS_MAPTBL_RECOVERING_STATE) {
		SSDFS_ERR("invalid PEB state: "
			  "peb_id %llu, peb_index %u, state %#x\n",
			  res->peb_id, res->peb_index, ptr->state);
		return -ERANGE;
	}

	le32_add_cpu(&ptr->erase_cycles, 1);
	ptr->type = SSDFS_MAPTBL_UNKNOWN_PEB_TYPE;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_id %llu, erase_cycles %u, type %#x, "
		  "state %#x, flags %#x, shared_peb_index %u\n",
		  res->peb_id,
		  le32_to_cpu(ptr->erase_cycles),
		  ptr->type, ptr->state,
		  ptr->flags, ptr->shared_peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (res->state) {
	case SSDFS_ERASE_DONE:
		ptr->state = SSDFS_MAPTBL_UNKNOWN_PEB_STATE;
		bitmap_clear(dirty_bmap, item_index, 1);
		bitmap_clear(used_bmap, item_index, 1);

		pebs_count = le16_to_cpu(hdr->pebs_count);
		used_pebs = bitmap_weight(used_bmap, pebs_count);
		unused_pebs = pebs_count - used_pebs;

		WARN_ON(unused_pebs < 0);

		reserved_pebs = le16_to_cpu(hdr->reserved_pebs);
		if (reserved_pebs < unused_pebs) {
			le16_add_cpu(&hdr->reserved_pebs, 1);
			fdesc->reserved_pebs++;
		}
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("hdr->reserved_pebs %u\n",
			  le16_to_cpu(hdr->reserved_pebs));
		if (fdesc->reserved_pebs > fdesc->lebs_count) {
			SSDFS_ERR("reserved_pebs %u > lebs_count %u\n",
				  fdesc->reserved_pebs, fdesc->lebs_count);
			BUG();
		}
		BUG_ON(fdesc->pre_erase_pebs == 0);
#endif /* CONFIG_SSDFS_DEBUG */

		fdesc->pre_erase_pebs--;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fdesc->pre_erase_pebs %u\n",
			  fdesc->pre_erase_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_increase_volume_free_pages(tbl->fsi,
						 tbl->fsi->pages_per_peb);
		break;

	case SSDFS_ERASE_SB_PEB_DONE:
		ptr->type = SSDFS_MAPTBL_SBSEG_PEB_TYPE;
		ptr->state = SSDFS_MAPTBL_USING_PEB_STATE;
		bitmap_clear(dirty_bmap, item_index, 1);
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(fdesc->pre_erase_pebs == 0);
#endif /* CONFIG_SSDFS_DEBUG */
		fdesc->pre_erase_pebs--;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fdesc->pre_erase_pebs %u\n",
			  fdesc->pre_erase_pebs);
#endif /* CONFIG_SSDFS_DEBUG */
		break;

	case SSDFS_ERASE_FAILURE:
		ptr->state = SSDFS_MAPTBL_RECOVERING_STATE;
		bitmap_clear(dirty_bmap, item_index, 1);
		bitmap_set(recover_bmap, item_index, 1);
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

	return 0;
}

/*
 * ssdfs_maptbl_correct_peb_state() - correct state of erased PEB
 * @tbl: mapping table object
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
int ssdfs_maptbl_correct_peb_state(struct ssdfs_peb_mapping_table *tbl,
				   struct ssdfs_maptbl_fragment_desc *fdesc,
				   struct ssdfs_erase_result *res)
{
	struct ssdfs_peb_table_fragment_header *hdr;
	struct folio *folio;
	void *kaddr;
	pgoff_t folio_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc || !res);
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	SSDFS_DBG("fdesc %p, res->fragment_index %u, res->peb_index %u, "
		  "res->peb_id %llu, res->state %#x\n",
		  fdesc, res->fragment_index, res->peb_index,
		  res->peb_id, res->state);
#endif /* CONFIG_SSDFS_DEBUG */

	if (res->state == SSDFS_IGNORE_ERASE) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("ignore PEB: peb_id %llu\n", res->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	folio_index = PEBTBL_FOLIO_INDEX(fdesc, res->peb_index);

	folio = ssdfs_folio_array_get_folio_locked(&fdesc->array, folio_index);
	if (IS_ERR_OR_NULL(folio)) {
		err = folio == NULL ? -ERANGE : PTR_ERR(folio);
		SSDFS_ERR("fail to find folio: folio_index %lu\n",
			  folio_index);
		return err;
	}

	kaddr = kmap_local_folio(folio, 0);

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;

	err = __ssdfs_maptbl_correct_peb_state(tbl, fdesc, hdr, res);
	if (unlikely(err)) {
		SSDFS_ERR("fail to correct PEB state: "
			  "peb_id %llu, err %d\n",
			  res->peb_id, err);
		goto finish_folio_processing;
	}

	folio_mark_uptodate(folio);

	err = ssdfs_folio_array_set_folio_dirty(&fdesc->array,
						folio_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set folio %lu dirty: err %d\n",
			  folio_index, err);
	}

finish_folio_processing:
	flush_dcache_folio(folio);
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);
	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

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

	SSDFS_DBG("tbl %p, capacity %u, size %u, item_index %u\n",
		  tbl, array->capacity, array->size, *item_index);
#endif /* CONFIG_SSDFS_DEBUG */

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
		err = ssdfs_maptbl_correct_peb_state(tbl, fdesc,
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
	SSDFS_DBG("erased_pebs %d, min_pre_erase_pebs %d, "
		  "total_pre_erase_pebs %d\n",
		  erased_pebs,
		  atomic_read(&tbl->min_pre_erase_pebs),
		  atomic_read(&tbl->total_pre_erase_pebs));
#endif /* CONFIG_SSDFS_DEBUG */

	if (atomic_sub_return(erased_pebs, &tbl->min_pre_erase_pebs) < 0) {
		atomic_set(&tbl->min_pre_erase_pebs, 0);
	}

	if (atomic_sub_return(erased_pebs, &tbl->total_pre_erase_pebs) < 0) {
		SSDFS_WARN("erased_pebs %d, pre_erase_pebs %d\n",
			   erased_pebs,
			   atomic_read(&tbl->total_pre_erase_pebs));
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tbl->min_pre_erase_pebs %d, "
		  "tbl->total_pre_erase_pebs %d\n",
		  atomic_read(&tbl->min_pre_erase_pebs),
		  atomic_read(&tbl->total_pre_erase_pebs));
#endif /* CONFIG_SSDFS_DEBUG */

finish_fragment_correction:
	up_write(&fdesc->lock);

	if (!err) {
		if (is_ssdfs_maptbl_going_to_be_destroyed(tbl)) {
			SSDFS_WARN("maptbl %p, "
				  "fdesc %p, fragment_index %u, "
				  "start_leb %llu, lebs_count %u\n",
				  tbl, fdesc, fragment_index,
				  fdesc->start_leb, fdesc->lebs_count);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("maptbl %p, "
				  "fdesc %p, fragment_index %u, "
				  "start_leb %llu, lebs_count %u\n",
				  tbl, fdesc, fragment_index,
				  fdesc->start_leb, fdesc->lebs_count);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		mutex_lock(&tbl->bmap_lock);
		atomic_set(&fdesc->state, SSDFS_MAPTBL_FRAG_DIRTY);
		bitmap_set(tbl->dirty_bmap, fragment_index, 1);
		mutex_unlock(&tbl->bmap_lock);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment_index %u, state %#x\n",
			  fragment_index,
			  atomic_read(&fdesc->state));
#endif /* CONFIG_SSDFS_DEBUG */
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

	SSDFS_DBG("tbl %p, capacity %u, size %u\n",
		  tbl, array->capacity, array->size);
#endif /* CONFIG_SSDFS_DEBUG */

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
 * ssdfs_maptbl_correct_dirty_peb() - correct PEB's state in fragment
 * @tbl: mapping table object
 * @fdesc: fragment descriptor
 * @result: erase operation result
 *
 * This method corrects PEB's state in fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL  - invalid input.
 * %-ERANGE  - internal error.
 */
int ssdfs_maptbl_correct_dirty_peb(struct ssdfs_peb_mapping_table *tbl,
				   struct ssdfs_maptbl_fragment_desc *fdesc,
				   struct ssdfs_erase_result *result)
{
	int state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc || !result);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	SSDFS_DBG("peb_id %llu\n", result->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED ||
	    state == SSDFS_MAPTBL_FRAG_CREATED) {
		SSDFS_ERR("fail to correct fragment: "
			  "fragment_id %u, state %#x\n",
			  fdesc->fragment_id, state);
		return -ERANGE;
	}

	if (fdesc->pre_erase_pebs == 0) {
		SSDFS_ERR("fdesc->pre_erase_pebs == 0\n");
		return -ERANGE;
	}

	err = ssdfs_maptbl_correct_peb_state(tbl, fdesc, result);
	if (unlikely(err)) {
		SSDFS_ERR("fail to correct PEB state: "
			  "peb_id %llu, err %d\n",
			  result->peb_id, err);
		return err;
	}

	if (result->state == SSDFS_IGNORE_ERASE) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("ignore erase operation: "
			  "peb_id %llu\n",
			  result->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	if (atomic_dec_return(&tbl->min_pre_erase_pebs) < 0) {
		atomic_set(&tbl->min_pre_erase_pebs, 0);
	}

	if (atomic_dec_return(&tbl->total_pre_erase_pebs) < 0) {
		SSDFS_WARN("pre_erase_pebs %d\n",
			   atomic_read(&tbl->total_pre_erase_pebs));
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tbl->min_pre_erase_pebs %d, "
		  "tbl->total_pre_erase_pebs %d\n",
		  atomic_read(&tbl->min_pre_erase_pebs),
		  atomic_read(&tbl->total_pre_erase_pebs));
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_ssdfs_maptbl_going_to_be_destroyed(tbl)) {
		SSDFS_WARN("maptbl %p, "
			  "fdesc %p, fragment_id %u, "
			  "start_leb %llu, lebs_count %u\n",
			  tbl, fdesc, fdesc->fragment_id,
			  fdesc->start_leb, fdesc->lebs_count);
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("maptbl %p, "
			  "fdesc %p, fragment_id %u, "
			  "start_leb %llu, lebs_count %u\n",
			  tbl, fdesc, fdesc->fragment_id,
			  fdesc->start_leb, fdesc->lebs_count);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	mutex_lock(&tbl->bmap_lock);
	atomic_set(&fdesc->state, SSDFS_MAPTBL_FRAG_DIRTY);
	bitmap_set(tbl->dirty_bmap, fdesc->fragment_id, 1);
	mutex_unlock(&tbl->bmap_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("fragment_id %u, state %#x\n",
		  fdesc->fragment_id,
		  atomic_read(&fdesc->state));
#endif /* CONFIG_SSDFS_DEBUG */

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

	SSDFS_DBG("tbl %p\n", tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	upper_bound_cno = atomic64_read(&tbl->last_peb_recover_cno);
	upper_bound_cno += month_ns;

	current_cno = ssdfs_current_cno(tbl->fsi->sb);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("current_cno %llu, upper_bound_cno %llu\n",
		  current_cno, upper_bound_cno);
#endif /* CONFIG_SSDFS_DEBUG */

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

	SSDFS_DBG("tbl %p\n", tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	atomic64_set(&tbl->last_peb_recover_cno,
			ssdfs_current_cno(tbl->fsi->sb));
}

/*
 * ssdfs_maptbl_find_folio_recovering_pebs() - finds recovering PEBs in a folio
 * @fdesc: fragment descriptor
 * @fragment_index: fragment index
 * @folio_index: folio index
 * @max_erases: upper bound of erase operations
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
ssdfs_maptbl_find_folio_recovering_pebs(struct ssdfs_maptbl_fragment_desc *fdesc,
					u32 fragment_index,
					pgoff_t folio_index,
					int max_erases,
					int stage,
					struct ssdfs_erase_result_array *array)
{
	struct ssdfs_peb_table_fragment_header *hdr;
	bool need_mark_peb_bad = false;
	unsigned long *recover_bmap;
	int recovering_pebs;
	u16 pebs_count;
	struct folio *folio;
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

	SSDFS_DBG("fdesc %p, fragment_index %u, folio_index %lu, "
		  "max_erases %d, stage %#x\n",
		  fdesc, fragment_index, folio_index,
		  max_erases, stage);
#endif /* CONFIG_SSDFS_DEBUG */

	folio = ssdfs_folio_array_get_folio_locked(&fdesc->array, folio_index);
	if (IS_ERR_OR_NULL(folio)) {
		err = folio == NULL ? -ERANGE : PTR_ERR(folio);
		SSDFS_ERR("fail to find folio: folio_index %lu\n",
			  folio_index);
		return err;
	}

	kaddr = kmap_local_folio(folio, 0);

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;

	switch (stage) {
	case SSDFS_CHECK_RECOVERABILITY:
		if (!(hdr->flags & SSDFS_PEBTBL_FIND_RECOVERING_PEBS)) {
			/* no PEBs for recovering */
			goto finish_folio_processing;
		}
		break;

	case SSDFS_MAKE_RECOVERING:
		if (!(hdr->flags & SSDFS_PEBTBL_TRY_CORRECT_PEBS_AGAIN)) {
			/* no PEBs for recovering */
			goto finish_folio_processing;
		} else if (!(hdr->flags & SSDFS_PEBTBL_FIND_RECOVERING_PEBS)) {
			err = -ERANGE;
			SSDFS_WARN("invalid flags combination: %#x\n",
				   hdr->flags);
			goto finish_folio_processing;
		}
		break;

	default:
		BUG();
	};

	if (hdr->recover_months > 0) {
		hdr->recover_months--;
		goto finish_folio_processing;
	}

	pebs_count = le16_to_cpu(hdr->pebs_count);
	recover_bmap =
		(unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_RECOVER_BMAP][0];
	recovering_pebs = bitmap_weight(recover_bmap, pebs_count);

	if (unlikely(recovering_pebs == 0)) {
		err = -ERANGE;
		SSDFS_ERR("recovering_pebs == 0\n");
		goto finish_folio_processing;
	} else if (hdr->recover_threshold == SSDFS_PEBTBL_BADBLK_THRESHOLD) {
		/* simply reserve PEBs for marking as bad */
		need_mark_peb_bad = true;
	} else if (((recovering_pebs * 100) / pebs_count) < 20) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("leave folio %lu untouched: "
			  "recovering_pebs %d, pebs_count %u\n",
			  folio_index, recovering_pebs, pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */
		hdr->recover_months++;
		goto finish_folio_processing;
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
			goto finish_folio_processing;
		}

		array->ptr[array->size].fragment_index = fragment_index;
		peb_index = DEFINE_PEB_INDEX_IN_FRAGMENT(fdesc, folio_index,
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

finish_folio_processing:
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);
	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	if (array->size >= array->capacity) {
		err = -ENOSPC;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("array->size %u, max_erases %d\n",
			  array->size, max_erases);
#endif /* CONFIG_SSDFS_DEBUG */
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

	SSDFS_DBG("tbl %p, fragment_index %u, "
		  "erases_per_fragment %d, stage %#x\n",
		  tbl, fragment_index,
		  erases_per_fragment, stage);
#endif /* CONFIG_SSDFS_DEBUG */

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
		err = ssdfs_maptbl_find_folio_recovering_pebs(fdesc,
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
				  "fragment_index %u, folio_index %lu, "
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

	SSDFS_DBG("hdr %p, recover_threshold %u\n",
		  hdr, hdr->recover_threshold);
#endif /* CONFIG_SSDFS_DEBUG */

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

	SSDFS_DBG("hdr %p, recover_threshold %u\n",
		  hdr, hdr->recover_threshold);
#endif /* CONFIG_SSDFS_DEBUG */

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
 * ssdfs_maptbl_correct_folio_recovered_pebs() - correct state of PEBs in folio
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
ssdfs_maptbl_correct_folio_recovered_pebs(struct ssdfs_peb_mapping_table *tbl,
					  struct ssdfs_maptbl_fragment_desc *ptr,
					  struct ssdfs_erase_result_array *array,
					  u32 *item_index)
{
	struct ssdfs_peb_table_fragment_header *hdr;
	struct ssdfs_peb_descriptor *peb_desc;
	struct ssdfs_erase_result *res;
	pgoff_t folio_index, next_folio;
	struct folio *folio;
	void *kaddr;
	unsigned long *dirty_bmap, *used_bmap, *recover_bmap, *bad_bmap;
	u32 recovered_pebs = 0, failed_pebs = 0, bad_pebs = 0;
	u16 peb_index_offset;
	u16 reserved_pebs;
	u16 pebs_count;
	int used_pebs, unused_pebs;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !ptr || !array || !array->ptr || !item_index);
	BUG_ON(array->capacity == 0);
	BUG_ON(array->capacity < array->size);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));
	BUG_ON(!rwsem_is_locked(&ptr->lock));

	SSDFS_DBG("fdesc %p, capacity %u, size %u, item_index %u\n",
		  ptr, array->capacity, array->size, *item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (*item_index >= array->size) {
		SSDFS_ERR("item_index %u >= array->size %u\n",
			  *item_index, array->size);
		return -EINVAL;
	}

	res = &array->ptr[*item_index];
	folio_index = PEBTBL_FOLIO_INDEX(ptr, res->peb_index);

	folio = ssdfs_folio_array_get_folio_locked(&ptr->array, folio_index);
	if (IS_ERR_OR_NULL(folio)) {
		err = folio == NULL ? -ERANGE : PTR_ERR(folio);
		SSDFS_ERR("fail to find folio: folio_index %lu\n",
			  folio_index);
		return err;
	}

	kaddr = kmap_local_folio(folio, 0);

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;
	dirty_bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_DIRTY_BMAP][0];
	used_bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_USED_BMAP][0];
	recover_bmap =
		(unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_RECOVER_BMAP][0];
	bad_bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_BADBLK_BMAP][0];

	if (!(hdr->flags & SSDFS_PEBTBL_UNDER_RECOVERING)) {
		err = -ERANGE;
		SSDFS_ERR("folio %lu isn't recovering\n", folio_index);
		goto finish_folio_processing;
	}

	do {
		res = &array->ptr[*item_index];
		peb_index_offset = res->peb_index % ptr->pebs_per_page;

		peb_desc = GET_PEB_DESCRIPTOR(hdr, peb_index_offset);
		if (IS_ERR_OR_NULL(peb_desc)) {
			err = IS_ERR(peb_desc) ? PTR_ERR(peb_desc) : -ERANGE;
			SSDFS_ERR("fail to get peb_descriptor: "
				  "peb_index %u, err %d\n",
				  res->peb_index, err);
			goto finish_folio_processing;
		}

		if (peb_desc->state != SSDFS_MAPTBL_RECOVERING_STATE) {
			err = -ERANGE;
			SSDFS_ERR("invalid PEB state: "
				  "peb_id %llu, peb_index %u, state %#x\n",
				  res->peb_id, res->peb_index, res->state);
			goto finish_folio_processing;
		}

		if (res->state == SSDFS_BAD_BLOCK_DETECTED) {
			peb_desc->state = SSDFS_MAPTBL_BAD_PEB_STATE;
			bitmap_clear(dirty_bmap, peb_index_offset, 1);
			bitmap_set(bad_bmap, peb_index_offset, 1);
			ptr->recovering_pebs--;

			bad_pebs++;
		} else if (res->state != SSDFS_ERASE_DONE) {
			/* do nothing */
			failed_pebs++;
		} else {
			peb_desc->state = SSDFS_MAPTBL_UNKNOWN_PEB_STATE;
			bitmap_clear(recover_bmap, peb_index_offset, 1);
			bitmap_clear(used_bmap, peb_index_offset, 1);

			pebs_count = le16_to_cpu(hdr->pebs_count);
			used_pebs = bitmap_weight(used_bmap, pebs_count);
			unused_pebs = pebs_count - used_pebs;

			WARN_ON(unused_pebs < 0);

			reserved_pebs = le16_to_cpu(hdr->reserved_pebs);
			if (reserved_pebs < unused_pebs) {
				le16_add_cpu(&hdr->reserved_pebs, 1);
				ptr->reserved_pebs++;
			}

			ptr->recovering_pebs--;

			recovered_pebs++;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("hdr->reserved_pebs %u\n",
				  le16_to_cpu(hdr->reserved_pebs));
			BUG_ON(ptr->reserved_pebs > ptr->lebs_count);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		++*item_index;

		res->peb_index = array->ptr[*item_index].peb_index;
		next_folio = PEBTBL_FOLIO_INDEX(ptr, res->peb_index);
	} while (*item_index < array->size && folio_index == next_folio);

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

	if (!err) {
		folio_mark_uptodate(folio);

		err = ssdfs_folio_array_set_folio_dirty(&ptr->array,
							folio_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set folio %lu dirty: err %d\n",
				  folio_index, err);
		}
	}

finish_folio_processing:
	flush_dcache_folio(folio);
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);
	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

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

	SSDFS_DBG("tbl %p, capacity %u, size %u, item_index %u\n",
		  tbl, array->capacity, array->size, *item_index);
#endif /* CONFIG_SSDFS_DEBUG */

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
		err = ssdfs_maptbl_correct_folio_recovered_pebs(tbl, fdesc,
								array,
								item_index);
		if (err == -EAGAIN) {
			err2 = -EAGAIN;
			err = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to correct folio's PEB state: "
				  "item_index %u, err %d\n",
				  *item_index, err);
			goto finish_fragment_correction;
		}
	} while (*item_index < array->size &&
		 fragment_index == array->ptr[*item_index].fragment_index);

finish_fragment_correction:
	up_write(&fdesc->lock);

	if (!err) {
		if (is_ssdfs_maptbl_going_to_be_destroyed(tbl)) {
			SSDFS_WARN("maptbl %p, "
				  "fdesc %p, fragment_index %u, "
				  "start_leb %llu, lebs_count %u\n",
				  tbl, fdesc, fragment_index,
				  fdesc->start_leb, fdesc->lebs_count);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("maptbl %p, "
				  "fdesc %p, fragment_index %u, "
				  "start_leb %llu, lebs_count %u\n",
				  tbl, fdesc, fragment_index,
				  fdesc->start_leb, fdesc->lebs_count);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		mutex_lock(&tbl->bmap_lock);
		atomic_set(&fdesc->state, SSDFS_MAPTBL_FRAG_DIRTY);
		bitmap_set(tbl->dirty_bmap, fragment_index, 1);
		mutex_unlock(&tbl->bmap_lock);
		err = err2;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment_index %u, state %#x\n",
			  fragment_index,
			  atomic_read(&fdesc->state));
#endif /* CONFIG_SSDFS_DEBUG */
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

	SSDFS_DBG("tbl %p, capacity %u, size %u\n",
		  tbl, array->capacity, array->size);
#endif /* CONFIG_SSDFS_DEBUG */

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

#define SSDFS_MAPTBL_IO_RANGE		(10)

/*
 * ssdfs_maptbl_correct_max_erase_ops() - correct max erase operations
 * @fsi: file system info object
 * @max_erase_ops: max number of erase operations
 */
static
int ssdfs_maptbl_correct_max_erase_ops(struct ssdfs_fs_info *fsi,
					int max_erase_ops)
{
	s64 reqs_count;
	s64 factor;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p, max_erase_ops %d\n",
		  fsi, max_erase_ops);
#endif /* CONFIG_SSDFS_DEBUG */

	if (max_erase_ops <= 0)
		return 0;

	reqs_count = atomic64_read(&fsi->flush_reqs);
	reqs_count += atomic_read(&fsi->pending_bios);

	if (reqs_count <= SSDFS_MAPTBL_IO_RANGE)
		return max_erase_ops;

	factor = reqs_count / SSDFS_MAPTBL_IO_RANGE;
	max_erase_ops /= factor;

	if (max_erase_ops == 0)
		max_erase_ops = 1;

	return max_erase_ops;
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
	struct ssdfs_fs_info *fsi;
	u32 fragments_count;
	int max_erase_ops;
	int erases_per_fragment;
	int state = SSDFS_MAPTBL_NO_ERASE;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !array || !array->ptr);
	BUG_ON(array->capacity == 0);

	SSDFS_DBG("tbl %p, capacity %u\n",
		  tbl, array->capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = tbl->fsi;

	max_erase_ops = atomic_read(&tbl->max_erase_ops);
	max_erase_ops = min_t(int, max_erase_ops, array->capacity);
	max_erase_ops = ssdfs_maptbl_correct_max_erase_ops(fsi, max_erase_ops);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("max_erase_ops %d\n", max_erase_ops);
#endif /* CONFIG_SSDFS_DEBUG */

	if (max_erase_ops == 0) {
		SSDFS_WARN("max_erase_ops == 0\n");
		return 0;
	}

	down_read(&tbl->tbl_lock);

	if (is_ssdfs_maptbl_under_flush(fsi)) {
		err = -EBUSY;
		SSDFS_DBG("mapping table is under flush\n");
		goto finish_collect_dirty_pebs;
	}

	state = atomic_cmpxchg(&tbl->erase_op_state,
				SSDFS_MAPTBL_NO_ERASE,
				SSDFS_MAPTBL_ERASE_IN_PROGRESS);
	if (state != SSDFS_MAPTBL_NO_ERASE) {
		err = -EBUSY;
		SSDFS_DBG("erase operation is in progress\n");
		goto finish_collect_dirty_pebs;
	} else
		state = SSDFS_MAPTBL_ERASE_IN_PROGRESS;

	fragments_count = tbl->fragments_count;
	erases_per_fragment = max_erase_ops / fragments_count;
	if (erases_per_fragment == 0)
		erases_per_fragment = 1;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("erases_per_fragment %d\n", erases_per_fragment);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < fragments_count; i++) {
		err = ssdfs_maptbl_collect_dirty_pebs(tbl, i,
					erases_per_fragment, array);
		if (err == -ENOENT) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fragment %d has no dirty PEBs\n",
				  i);
#endif /* CONFIG_SSDFS_DEBUG */
			continue;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to collect dirty pebs: "
				  "fragment_index %d, err %d\n",
				  i, err);
			goto finish_collect_dirty_pebs;
		}

		up_read(&tbl->tbl_lock);

		if (is_ssdfs_maptbl_under_flush(fsi)) {
			err = -EBUSY;
			SSDFS_DBG("mapping table is under flush\n");
			goto finish_dirty_pebs_processing;
		}

		err = ssdfs_maptbl_erase_pebs_array(tbl->fsi, array);
		if (err == -EROFS) {
			err = 0;
			SSDFS_DBG("file system has READ-ONLY state\n");
			goto finish_dirty_pebs_processing;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to erase PEBs in array: err %d\n", err);
			goto finish_dirty_pebs_processing;
		}

		wake_up_all(&tbl->erase_ops_end_wq);

		down_read(&tbl->tbl_lock);

		err = ssdfs_maptbl_correct_dirty_pebs(tbl, array);
		if (unlikely(err)) {
			SSDFS_ERR("fail to correct erased PEBs state: err %d\n",
				  err);
			goto finish_collect_dirty_pebs;
		}
	}

finish_collect_dirty_pebs:
	up_read(&tbl->tbl_lock);

finish_dirty_pebs_processing:
	if (state == SSDFS_MAPTBL_ERASE_IN_PROGRESS) {
		state = SSDFS_MAPTBL_NO_ERASE;
		atomic_set(&tbl->erase_op_state, SSDFS_MAPTBL_NO_ERASE);
	}

	wake_up_all(&tbl->erase_ops_end_wq);

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
 * %-EBUSY   - mapping table is under flush.
 */
static
int __ssdfs_maptbl_recover_pebs(struct ssdfs_peb_mapping_table *tbl,
				struct ssdfs_erase_result_array *array,
				int stage)
{
	struct ssdfs_fs_info *fsi;
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

	SSDFS_DBG("tbl %p, capacity %u, stage %#x\n",
		  tbl, array->capacity, stage);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = tbl->fsi;

	max_erase_ops = atomic_read(&tbl->max_erase_ops);
	max_erase_ops = min_t(int, max_erase_ops, array->capacity);
	max_erase_ops = ssdfs_maptbl_correct_max_erase_ops(fsi, max_erase_ops);

	if (max_erase_ops == 0) {
		SSDFS_WARN("max_erase_ops == 0\n");
		return 0;
	}

	down_read(&tbl->tbl_lock);

	if (is_ssdfs_maptbl_under_flush(fsi)) {
		err = -EBUSY;
		SSDFS_DBG("mapping table is under flush\n");
		goto finish_collect_recovering_pebs;
	}

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

		if (kthread_should_stop()) {
			err = -EAGAIN;
			goto finish_collect_recovering_pebs;
		}
	}

finish_collect_recovering_pebs:
	up_read(&tbl->tbl_lock);

	if (err)
		goto finish_pebs_recovering;

	if (is_ssdfs_maptbl_under_flush(fsi)) {
		err = -EBUSY;
		SSDFS_DBG("mapping table is under flush\n");
		goto finish_pebs_recovering;
	}

	if (kthread_should_stop()) {
		err = -EAGAIN;
		goto finish_pebs_recovering;
	}

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
 * %-EBUSY   - mapping table is under flush.
 */
static inline int
ssdfs_maptbl_check_pebs_recoverability(struct ssdfs_peb_mapping_table *tbl,
					struct ssdfs_erase_result_array *array)
{
	int stage = SSDFS_CHECK_RECOVERABILITY;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !array || !array->ptr);
	BUG_ON(array->capacity == 0);

	SSDFS_DBG("tbl %p, capacity %u\n",
		  tbl, array->capacity);
#endif /* CONFIG_SSDFS_DEBUG */

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
 * %-EBUSY   - mapping table is under flush.
 */
static
int ssdfs_maptbl_recover_pebs(struct ssdfs_peb_mapping_table *tbl,
			      struct ssdfs_erase_result_array *array)
{
	int stage = SSDFS_MAKE_RECOVERING;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !array || !array->ptr);
	BUG_ON(array->capacity == 0);

	SSDFS_DBG("tbl %p, capacity %u\n",
		  tbl, array->capacity);
#endif /* CONFIG_SSDFS_DEBUG */

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
 *  %-EBUSY   - mapping table is under flush.
 */
static
int ssdfs_maptbl_resolve_peb_mapping(struct ssdfs_peb_mapping_table *tbl,
				     struct ssdfs_maptbl_cache *cache,
				     struct ssdfs_peb_mapping_info *pmi)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_maptbl_peb_relation pebr;
	int consistency = SSDFS_PEB_STATE_UNKNOWN;
	struct ssdfs_maptbl_fragment_desc *fdesc;
	int state;
	u64 peb_id;
	u8 peb_state;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !cache || !pmi);

	SSDFS_DBG("leb_id %llu, peb_id %llu, consistency %#x\n",
		  pmi->leb_id, pmi->peb_id, pmi->consistency);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = tbl->fsi;

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

	err = __ssdfs_maptbl_cache_convert_leb2peb(cache,
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
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("peb_id %llu isn't be found\n", pmi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	switch (consistency) {
	case SSDFS_PEB_STATE_CONSISTENT:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("peb_id %llu has consistent state already\n",
			  pmi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;

	default:
		if (consistency != pmi->consistency) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("consistency1 %#x != consistency2 %#x\n",
				  consistency, pmi->consistency);
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;
	}

	down_read(&tbl->tbl_lock);

	if (is_ssdfs_maptbl_under_flush(fsi)) {
		err = -EBUSY;
		SSDFS_DBG("mapping table is under flush\n");
		goto finish_resolving;
	}

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

		up_read(&tbl->tbl_lock);
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("maptbl's fragment init failed: "
				  "leb_id %llu, err %d\n",
				  pmi->leb_id, err);
			goto finish_resolving_no_lock;
		}
		down_read(&tbl->tbl_lock);
	}

	if (is_ssdfs_maptbl_under_flush(fsi)) {
		err = -EBUSY;
		SSDFS_DBG("mapping table is under flush\n");
		goto finish_resolving;
	}

	switch (consistency) {
	case SSDFS_PEB_STATE_INCONSISTENT:
		down_write(&cache->lock);
		down_write(&fdesc->lock);

		err = ssdfs_maptbl_cache_convert_leb2peb_nolock(cache,
								pmi->leb_id,
								&pebr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert LEB to PEB: "
				  "leb_id %llu, err %d\n",
				  pmi->leb_id, err);
			goto finish_inconsistent_case;
		}

		err = ssdfs_maptbl_solve_inconsistency(tbl, fdesc,
							pmi->leb_id,
							&pebr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to resolve inconsistency: "
				  "leb_id %llu, err %d\n",
				  pmi->leb_id, err);
			goto finish_inconsistent_case;
		}

		peb_id = pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id;
		peb_state = pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].state;
		if (peb_id != U64_MAX) {
			consistency = SSDFS_PEB_STATE_CONSISTENT;
			err = ssdfs_maptbl_cache_change_peb_state_nolock(cache,
								  pmi->leb_id,
								  peb_state,
								  consistency);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change PEB state: "
					  "leb_id %llu, peb_state %#x, "
					  "err %d\n",
					  pmi->leb_id, peb_state, err);
				goto finish_inconsistent_case;
			}
		}

		peb_id = pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].peb_id;
		peb_state = pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].state;
		if (peb_id != U64_MAX) {
			consistency = SSDFS_PEB_STATE_CONSISTENT;
			err = ssdfs_maptbl_cache_change_peb_state_nolock(cache,
								  pmi->leb_id,
								  peb_state,
								  consistency);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change PEB state: "
					  "leb_id %llu, peb_state %#x, "
					  "err %d\n",
					  pmi->leb_id, peb_state, err);
				goto finish_inconsistent_case;
			}
		}

finish_inconsistent_case:
		up_write(&fdesc->lock);
		up_write(&cache->lock);

		if (!err) {
			ssdfs_maptbl_set_fragment_dirty(tbl, fdesc, pmi->leb_id,
						SSDFS_MAPTBL_UNKNOWN_PEB_TYPE);
		}
		break;

	case SSDFS_PEB_STATE_PRE_DELETED:
		down_write(&cache->lock);
		down_write(&fdesc->lock);

		err = ssdfs_maptbl_cache_convert_leb2peb_nolock(cache,
								pmi->leb_id,
								&pebr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert LEB to PEB: "
				  "leb_id %llu, err %d\n",
				  pmi->leb_id, err);
			goto finish_pre_deleted_case;
		}

		err = ssdfs_maptbl_solve_pre_deleted_state(tbl, fdesc,
							   pmi->leb_id,
							   &pebr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to resolve pre-deleted state: "
				  "leb_id %llu, err %d\n",
				  pmi->leb_id, err);
			goto finish_pre_deleted_case;
		}

		consistency = SSDFS_PEB_STATE_CONSISTENT;
		err = ssdfs_maptbl_cache_forget_leb2peb_nolock(cache,
								pmi->leb_id,
								consistency);
		if (unlikely(err)) {
			SSDFS_ERR("fail to exclude migration PEB: "
				  "leb_id %llu, err %d\n",
				  pmi->leb_id, err);
			goto finish_pre_deleted_case;
		}

finish_pre_deleted_case:
		up_write(&fdesc->lock);
		up_write(&cache->lock);

		if (!err) {
			ssdfs_maptbl_set_fragment_dirty(tbl, fdesc, pmi->leb_id,
						SSDFS_MAPTBL_UNKNOWN_PEB_TYPE);
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
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

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

	SSDFS_DBG("min_pre_erase_pebs %d, total_pre_erase_pebs %d\n",
		  atomic_read(&tbl->min_pre_erase_pebs),
		  atomic_read(&tbl->total_pre_erase_pebs));
#endif /* CONFIG_SSDFS_DEBUG */

	return atomic_read(&tbl->min_pre_erase_pebs) > 0 ||
		atomic_read(&tbl->total_pre_erase_pebs) > 0;
}

int ssdfs_maptbl_erase_dirty_pebs_now(struct ssdfs_peb_mapping_table *tbl)
{
	struct ssdfs_erase_result_array array = {NULL, 0, 0};
	int err = 0;

	down_read(&tbl->tbl_lock);
	array.capacity = (u32)tbl->fragments_count *
				SSDFS_ERASE_RESULTS_PER_FRAGMENT;
	up_read(&tbl->tbl_lock);

	array.size = 0;
	array.ptr = ssdfs_map_thread_kcalloc(array.capacity,
				  sizeof(struct ssdfs_erase_result),
				  GFP_KERNEL);
	if (!array.ptr) {
		SSDFS_ERR("fail to allocate erase_results array\n");
		return -ENOMEM;
	}

	if (has_maptbl_pre_erase_pebs(tbl)) {
		err = ssdfs_maptbl_process_dirty_pebs(tbl, &array);
		if (err == -EBUSY || err == -EAGAIN) {
			err = 0;
			goto finish_erase_dirty_pebs;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to process dirty PEBs: err %d\n",
				  err);
			goto finish_erase_dirty_pebs;
		}
	}

finish_erase_dirty_pebs:
	if (array.ptr)
		ssdfs_map_thread_kfree(array.ptr);

	return err;
}

#define MAPTBL_PTR(tbl) \
	((struct ssdfs_peb_mapping_table *)(tbl))
#define MAPTBL_THREAD_WAKE_CONDITION(tbl, cache) \
	(kthread_should_stop() || \
	 has_maptbl_pre_erase_pebs(MAPTBL_PTR(tbl)) || \
	 !is_ssdfs_peb_mapping_queue_empty(&cache->pm_queue))
#define MAPTBL_FAILED_THREAD_WAKE_CONDITION() \
	(kthread_should_stop())

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
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!tbl) {
		SSDFS_ERR("pointer on mapping table object is NULL\n");
		BUG();
	}

	SSDFS_DBG("MAPTBL thread\n");
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = tbl->fsi;
	cache = &fsi->maptbl_cache;
	wait_queue = &tbl->wait_queue;

	down_read(&tbl->tbl_lock);
	array.capacity = (u32)tbl->fragments_count *
				SSDFS_ERASE_RESULTS_PER_FRAGMENT;
	up_read(&tbl->tbl_lock);

	array.size = 0;
	array.ptr = ssdfs_map_thread_kcalloc(array.capacity,
				  sizeof(struct ssdfs_erase_result),
				  GFP_KERNEL);
	if (!array.ptr) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate erase_results array\n");
		goto sleep_maptbl_thread;
	}

	down_read(&tbl->tbl_lock);
	for (i = 0; i < tbl->fragments_count; i++) {
		struct completion *init_end = &tbl->desc_array[i].init_end;

		up_read(&tbl->tbl_lock);

		wait_for_completion_timeout(init_end, HZ);
		if (kthread_should_stop())
			goto repeat;

		down_read(&tbl->tbl_lock);
	}
	up_read(&tbl->tbl_lock);

repeat:
	if (kthread_should_stop()) {
		wake_up_all(&tbl->erase_ops_end_wq);
		complete_all(&tbl->thread.full_stop);
		if (array.ptr)
			ssdfs_map_thread_kfree(array.ptr);

		if (unlikely(err)) {
			SSDFS_ERR("thread function had some issue: err %d\n",
				  err);
		}

		return err;
	}

	if (unlikely(err))
		goto sleep_failed_maptbl_thread;

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR)
		err = -EFAULT;

	if (unlikely(err)) {
		SSDFS_ERR("fail to continue activity: err %d\n", err);
		goto sleep_failed_maptbl_thread;
	}

	if (fsi->sb->s_flags & SB_RDONLY)
		goto sleep_maptbl_thread;

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
		if (err == -EBUSY) {
			err = 0;
			ssdfs_peb_mapping_queue_add_tail(&cache->pm_queue,
							 pmi);
			goto sleep_maptbl_thread;
		} else if (err == -EAGAIN) {
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

		if (kthread_should_stop())
			goto repeat;
	}

	if (has_maptbl_pre_erase_pebs(tbl)) {
		err = ssdfs_maptbl_process_dirty_pebs(tbl, &array);
		if (err == -EBUSY || err == -EAGAIN) {
			err = 0;
			wait_event_interruptible_timeout(*wait_queue,
					kthread_should_stop(), HZ);
			goto sleep_maptbl_thread;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to process dirty PEBs: err %d\n",
				  err);
		}

		wait_event_interruptible_timeout(*wait_queue,
					kthread_should_stop(), HZ);
	}

check_next_step:
	if (kthread_should_stop())
		goto repeat;

	if (unlikely(err))
		goto sleep_failed_maptbl_thread;

	if (is_time_to_recover_pebs(tbl)) {
		err = ssdfs_maptbl_check_pebs_recoverability(tbl, &array);
		if (err == -EBUSY) {
			err = 0;
			goto sleep_maptbl_thread;
		} else if (err && err != -EAGAIN) {
			SSDFS_ERR("fail to check PEBs recoverability: "
				  "err %d\n",
				  err);
			goto sleep_failed_maptbl_thread;
		}

		set_last_recovering_cno(tbl);

		wait_event_interruptible_timeout(*wait_queue,
					kthread_should_stop(), HZ);
	} else
		goto sleep_maptbl_thread;

	if (kthread_should_stop())
		goto repeat;

	while (err == -EAGAIN) {
		err = ssdfs_maptbl_recover_pebs(tbl, &array);
		if (err == -EBUSY) {
			err = 0;
			goto sleep_maptbl_thread;
		} else if (err && err != -EAGAIN) {
			SSDFS_ERR("fail to recover PEBs: err %d\n",
				  err);
			goto sleep_failed_maptbl_thread;
		}

		set_last_recovering_cno(tbl);

		wait_event_interruptible_timeout(*wait_queue,
					kthread_should_stop(), HZ);

		if (kthread_should_stop())
			goto repeat;
	}

sleep_maptbl_thread:
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	add_wait_queue(wait_queue, &wait);
	while (!MAPTBL_THREAD_WAKE_CONDITION(tbl, cache)) {
		if (signal_pending(current)) {
			err = -ERESTARTSYS;
			break;
		}
		wait_woken(&wait, TASK_INTERRUPTIBLE, SSDFS_DEFAULT_TIMEOUT);
	}
	remove_wait_queue(wait_queue, &wait);
	goto repeat;

sleep_failed_maptbl_thread:
	wake_up_all(&tbl->erase_ops_end_wq);
	wait_event_interruptible(*wait_queue,
				 MAPTBL_FAILED_THREAD_WAKE_CONDITION());
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

	SSDFS_DBG("tbl %p\n", tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	threadfn = maptbl_thread.threadfn;
	fmt = maptbl_thread.fmt;

	tbl->thread.task = kthread_create(threadfn, tbl, fmt);
	if (IS_ERR_OR_NULL(tbl->thread.task)) {
		err = PTR_ERR(tbl->thread.task);
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
		} else {
			if (err == 0)
				err = -ERANGE;
			SSDFS_ERR("fail to start mapping table's thread: "
				  "err %d\n", err);
		}

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
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!tbl->thread.task)
		return 0;

	wake_up(&tbl->wait_queue);

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

	err = SSDFS_WAIT_COMPLETION(&tbl->thread.full_stop);
	if (unlikely(err)) {
		SSDFS_ERR("stop thread fails: err %d\n", err);
		return err;
	}

	return 0;
}
