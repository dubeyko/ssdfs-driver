// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_mapping_table.c - PEB mapping table implementation.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * Copyright (c) 2022-2023 Bytedance Ltd. and/or its affiliates.
 *              https://www.bytedance.com/
 *
 * (C) Copyright 2014-2019, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot
 *                  Zvonimir Bandic
 *                  Cong Wang
 */

#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/pagevec.h>
#include <linux/delay.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "page_vector.h"
#include "ssdfs.h"
#include "segment_bitmap.h"
#include "page_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "extents_tree.h"
#include "extents_queue.h"
#include "shared_extents_tree.h"
#include "snapshots_tree.h"
#include "peb_mapping_table.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_map_tbl_page_leaks;
atomic64_t ssdfs_map_tbl_memory_leaks;
atomic64_t ssdfs_map_tbl_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_map_tbl_cache_leaks_increment(void *kaddr)
 * void ssdfs_map_tbl_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_map_tbl_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_map_tbl_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_map_tbl_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_map_tbl_kfree(void *kaddr)
 * struct page *ssdfs_map_tbl_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_map_tbl_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_map_tbl_free_page(struct page *page)
 * void ssdfs_map_tbl_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(map_tbl)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(map_tbl)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_map_tbl_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_map_tbl_page_leaks, 0);
	atomic64_set(&ssdfs_map_tbl_memory_leaks, 0);
	atomic64_set(&ssdfs_map_tbl_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_map_tbl_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_map_tbl_page_leaks) != 0) {
		SSDFS_ERR("MAPPING TABLE: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_map_tbl_page_leaks));
	}

	if (atomic64_read(&ssdfs_map_tbl_memory_leaks) != 0) {
		SSDFS_ERR("MAPPING TABLE: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_map_tbl_memory_leaks));
	}

	if (atomic64_read(&ssdfs_map_tbl_cache_leaks) != 0) {
		SSDFS_ERR("MAPPING TABLE: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_map_tbl_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * ssdfs_unused_lebs_in_fragment() - calculate unused LEBs in fragment
 * @fdesc: fragment descriptor
 */
static inline
u32 ssdfs_unused_lebs_in_fragment(struct ssdfs_maptbl_fragment_desc *fdesc)
{
	u32 unused_lebs;
	u32 reserved_pool;

	reserved_pool = fdesc->reserved_pebs + fdesc->pre_erase_pebs;

	unused_lebs = fdesc->lebs_count;
	unused_lebs -= fdesc->mapped_lebs + fdesc->migrating_lebs;
	unused_lebs -= reserved_pool;

	return unused_lebs;
}

static inline
u32 ssdfs_lebs_reservation_threshold(struct ssdfs_maptbl_fragment_desc *fdesc)
{
	u32 expected2migrate = 0;
	u32 reserved_pool = 0;
	u32 migration_NOT_guaranted = 0;
	u32 threshold;

	expected2migrate = fdesc->mapped_lebs - fdesc->migrating_lebs;
	reserved_pool = fdesc->reserved_pebs + fdesc->pre_erase_pebs;

	if (expected2migrate > reserved_pool)
		migration_NOT_guaranted = expected2migrate - reserved_pool;
	else
		migration_NOT_guaranted = 0;

	threshold = migration_NOT_guaranted / 10;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("lebs_count %u, mapped_lebs %u, "
		  "migrating_lebs %u, reserved_pebs %u, "
		  "pre_erase_pebs %u, expected2migrate %u, "
		  "reserved_pool %u, migration_NOT_guaranted %u, "
		  "threshold %u\n",
		  fdesc->lebs_count, fdesc->mapped_lebs,
		  fdesc->migrating_lebs, fdesc->reserved_pebs,
		  fdesc->pre_erase_pebs, expected2migrate,
		  reserved_pool, migration_NOT_guaranted,
		  threshold);
#endif /* CONFIG_SSDFS_DEBUG */

	return threshold;
}

int ssdfs_maptbl_define_fragment_info(struct ssdfs_fs_info *fsi,
				      u64 leb_id,
				      u16 *pebs_per_fragment,
				      u16 *pebs_per_stripe,
				      u16 *stripes_per_fragment)
{
	struct ssdfs_peb_mapping_table *tbl;
	u32 fragments_count;
	u64 lebs_count;
	u16 pebs_per_fragment_default;
	u16 pebs_per_stripe_default;
	u16 stripes_per_fragment_default;
	u64 fragment_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->maptbl);

	SSDFS_DBG("leb_id %llu\n", leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	tbl = fsi->maptbl;

	*pebs_per_fragment = U16_MAX;
	*pebs_per_stripe = U16_MAX;
	*stripes_per_fragment = U16_MAX;

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"maptbl has corrupted state\n");
		return -EFAULT;
	}

	down_read(&tbl->tbl_lock);
	fragments_count = tbl->fragments_count;
	lebs_count = tbl->lebs_count;
	pebs_per_fragment_default = tbl->pebs_per_fragment;
	pebs_per_stripe_default = tbl->pebs_per_stripe;
	stripes_per_fragment_default = tbl->stripes_per_fragment;
	up_read(&tbl->tbl_lock);

	if (leb_id >= lebs_count) {
		SSDFS_ERR("invalid request: "
			  "leb_id %llu, lebs_count %llu\n",
			  leb_id, lebs_count);
		return -EINVAL;
	}

	fragment_index = div_u64(leb_id, (u32)pebs_per_fragment_default);

	if ((fragment_index + 1) < fragments_count) {
		*pebs_per_fragment = pebs_per_fragment_default;
		*pebs_per_stripe = pebs_per_stripe_default;
		*stripes_per_fragment = stripes_per_fragment_default;
	} else {
		u64 rest_pebs;

		rest_pebs = (u64)fragment_index * pebs_per_fragment_default;
		rest_pebs = lebs_count - rest_pebs;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(rest_pebs >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		*pebs_per_fragment = (u16)rest_pebs;
		*stripes_per_fragment = stripes_per_fragment_default;

		*pebs_per_stripe = *pebs_per_fragment / *stripes_per_fragment;
		if (*pebs_per_fragment % *stripes_per_fragment)
			*pebs_per_stripe += 1;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("leb_id %llu, pebs_per_fragment %u, "
		  "pebs_per_stripe %u, stripes_per_fragment %u\n",
		  leb_id, *pebs_per_fragment,
		  *pebs_per_stripe, *stripes_per_fragment);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_check_maptbl_sb_header() - check mapping table's sb_header
 * @fsi: file system info object
 *
 * This method checks mapping table description in volume header.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO     - maptbl_sb_header is corrupted.
 * %-EROFS   - mapping table has corrupted state.
 */
static
int ssdfs_check_maptbl_sb_header(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_peb_mapping_table *ptr;
	u64 calculated;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->maptbl);

	SSDFS_DBG("fsi %p, maptbl %p\n", fsi, fsi->maptbl);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr = fsi->maptbl;

	if (atomic_read(&ptr->flags) & ~SSDFS_MAPTBL_FLAGS_MASK) {
		SSDFS_CRIT("maptbl header corrupted: "
			   "unknown flags %#x\n",
			   atomic_read(&ptr->flags));
		return -EIO;
	}

	if (atomic_read(&ptr->flags) & SSDFS_MAPTBL_ERROR) {
		SSDFS_NOTICE("mapping table has corrupted state: "
			     "Please, run fsck utility\n");
		return -EROFS;
	}

	calculated = (u64)ptr->fragments_per_seg * ptr->fragment_bytes;
	if (calculated > fsi->segsize) {
		SSDFS_CRIT("mapping table has corrupted state: "
			   "fragments_per_seg %u, fragment_bytes %u, "
			   "segsize %u\n",
			   ptr->fragments_per_seg,
			   ptr->fragment_bytes,
			   fsi->segsize);
		return -EIO;
	}

	calculated = (u64)ptr->fragments_per_peb * ptr->fragment_bytes;
	if (calculated > fsi->erasesize) {
		SSDFS_CRIT("mapping table has corrupted state: "
			   "fragments_per_peb %u, fragment_bytes %u, "
			   "erasesize %u\n",
			   ptr->fragments_per_peb,
			   ptr->fragment_bytes,
			   fsi->erasesize);
		return -EIO;
	}

	calculated = (u64)ptr->fragments_per_peb * fsi->pebs_per_seg;
	if (calculated != ptr->fragments_per_seg) {
		SSDFS_CRIT("mapping table has corrupted state: "
			   "fragments_per_peb %u, fragments_per_seg %u, "
			   "pebs_per_seg %u\n",
			   ptr->fragments_per_peb,
			   ptr->fragments_per_seg,
			   fsi->pebs_per_seg);
		return -EIO;
	}

	calculated = fsi->nsegs * fsi->pebs_per_seg;
	if (ptr->lebs_count != calculated || ptr->pebs_count != calculated) {
		SSDFS_CRIT("mapping table has corrupted state: "
			   "lebs_count %llu, pebs_count %llu, "
			   "nsegs %llu, pebs_per_seg %u\n",
			   ptr->lebs_count, ptr->pebs_count,
			   fsi->nsegs, fsi->pebs_per_seg);
		return -EIO;
	}

	calculated = (u64)ptr->fragments_count * ptr->lebs_per_fragment;
	if (ptr->lebs_count > calculated ||
	    calculated > (ptr->lebs_count + (2 * ptr->lebs_per_fragment))) {
		SSDFS_CRIT("mapping table has corrupted state: "
			   "lebs_per_fragment %u, fragments_count %u, "
			   "lebs_per_fragment %u\n",
			   ptr->lebs_per_fragment,
			   ptr->fragments_count,
			   ptr->lebs_per_fragment);
		return -EIO;
	}

	calculated = (u64)ptr->fragments_count * ptr->pebs_per_fragment;
	if (ptr->pebs_count > calculated ||
	    calculated > (ptr->pebs_count + (2 * ptr->pebs_per_fragment))) {
		SSDFS_CRIT("mapping table has corrupted state: "
			   "pebs_per_fragment %u, fragments_count %u, "
			   "pebs_per_fragment %u\n",
			   ptr->pebs_per_fragment,
			   ptr->fragments_count,
			   ptr->pebs_per_fragment);
		return -EIO;
	}

	calculated = (u64)ptr->pebs_per_stripe * ptr->stripes_per_fragment;
	if (ptr->pebs_per_fragment != calculated) {
		SSDFS_CRIT("mapping table has corrupted state: "
			   "pebs_per_stripe %u, stripes_per_fragment %u, "
			   "pebs_per_fragment %u\n",
			   ptr->pebs_per_stripe,
			   ptr->stripes_per_fragment,
			   ptr->pebs_per_fragment);
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_maptbl_create_fragment() - initial fragment preparation.
 * @fsi: file system info object
 * @index: fragment index
 */
static
int ssdfs_maptbl_create_fragment(struct ssdfs_fs_info *fsi, u32 index)
{
	struct ssdfs_maptbl_fragment_desc *ptr;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->maptbl || !fsi->maptbl->desc_array);
	BUG_ON(index >= fsi->maptbl->fragments_count);

	SSDFS_DBG("fsi %p, index %u\n", fsi, index);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr = &fsi->maptbl->desc_array[index];

	init_rwsem(&ptr->lock);
	ptr->fragment_id = index;
	ptr->fragment_pages = fsi->maptbl->fragment_pages;
	ptr->start_leb = U64_MAX;
	ptr->lebs_count = U32_MAX;
	ptr->lebs_per_page = U16_MAX;
	ptr->lebtbl_pages = U16_MAX;
	ptr->pebs_per_page = U16_MAX;
	ptr->stripe_pages = U16_MAX;
	ptr->mapped_lebs = 0;
	ptr->migrating_lebs = 0;
	ptr->reserved_pebs = 0;
	ptr->pre_erase_pebs = 0;
	ptr->recovering_pebs = 0;

	err = ssdfs_create_page_array(ptr->fragment_pages, &ptr->array);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create page array: "
			  "capacity %u, err %d\n",
			  ptr->fragment_pages, err);
		return err;
	}

	init_completion(&ptr->init_end);

	ptr->flush_req1 = NULL;
	ptr->flush_req2 = NULL;
	ptr->flush_req_count = 0;

	ptr->flush_seq_size = min_t(u32, ptr->fragment_pages, PAGEVEC_SIZE);
	ptr->flush_req1 = ssdfs_map_tbl_kcalloc(ptr->flush_seq_size,
					sizeof(struct ssdfs_segment_request),
					GFP_KERNEL);
	if (!ptr->flush_req1) {
		ssdfs_destroy_page_array(&ptr->array);
		SSDFS_ERR("fail to allocate flush requests array: "
			  "array_size %u\n",
			  ptr->flush_seq_size);
		return -ENODATA;
	}

	ptr->flush_req2 = ssdfs_map_tbl_kcalloc(ptr->flush_seq_size,
					sizeof(struct ssdfs_segment_request),
					GFP_KERNEL);
	if (!ptr->flush_req2) {
		ssdfs_destroy_page_array(&ptr->array);
		ssdfs_map_tbl_kfree(ptr->flush_req1);
		ptr->flush_req1 = NULL;
		SSDFS_ERR("fail to allocate flush requests array: "
			  "array_size %u\n",
			  ptr->flush_seq_size);
		return -ENODATA;
	}

	atomic_set(&ptr->state, SSDFS_MAPTBL_FRAG_CREATED);

	return 0;
}

/*
 * CHECK_META_EXTENT_TYPE() - check type of metadata area's extent
 */
static
int CHECK_META_EXTENT_TYPE(struct ssdfs_meta_area_extent *extent)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!extent);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (le16_to_cpu(extent->type)) {
	case SSDFS_EMPTY_EXTENT_TYPE:
		return -ENODATA;

	case SSDFS_SEG_EXTENT_TYPE:
		return 0;
	}

	return -EOPNOTSUPP;
}

/*
 * ssdfs_maptbl_define_segment_counts() - define total maptbl's segments count
 * @tbl: mapping table object
 *
 * This method determines total count of segments that are allocated
 * for mapping table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO     - extents are corrupted.
 */
static
int ssdfs_maptbl_define_segment_counts(struct ssdfs_peb_mapping_table *tbl)
{
	u32 segs_count1 = 0, segs_count2 = 0;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);

	SSDFS_DBG("tbl %p\n", tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < SSDFS_MAPTBL_RESERVED_EXTENTS; i++) {
		struct ssdfs_meta_area_extent *extent;
		u32 len1 = 0, len2 = 0;

		extent = &tbl->extents[i][SSDFS_MAIN_MAPTBL_SEG];

		err = CHECK_META_EXTENT_TYPE(extent);
		if (err == -ENODATA) {
			/* do nothing */
			break;
		} else if (unlikely(err)) {
			SSDFS_WARN("invalid meta area extent: "
				   "index %d, err %d\n",
				   i, err);
			return err;
		}

		len1 = le32_to_cpu(extent->len);

		if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_HAS_COPY) {
			extent = &tbl->extents[i][SSDFS_COPY_MAPTBL_SEG];

			err = CHECK_META_EXTENT_TYPE(extent);
			if (err == -ENODATA) {
				SSDFS_ERR("empty copy meta area extent: "
					  "index %d\n", i);
				return -EIO;
			} else if (unlikely(err)) {
				SSDFS_WARN("invalid meta area extent: "
					   "index %d, err %d\n",
					   i, err);
				return err;
			}

			len2 = le32_to_cpu(extent->len);

			if (len1 != len2) {
				SSDFS_ERR("different main and copy extents: "
					  "index %d, len1 %u, len2 %u\n",
					  i, len1, len2);
				return -EIO;
			}
		}

		segs_count1 += len1;
		segs_count2 += len2;
	}

	if (segs_count1 == 0) {
		SSDFS_CRIT("empty maptbl extents\n");
		return -EIO;
	} else if (segs_count1 >= U16_MAX) {
		SSDFS_CRIT("invalid segment count %u\n",
			   segs_count1);
		return -EIO;
	}

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_HAS_COPY &&
	    segs_count1 != segs_count2) {
		SSDFS_ERR("segs_count1 %u != segs_count2 %u\n",
			  segs_count1, segs_count2);
		return -EIO;
	}

	tbl->segs_count = (u16)segs_count1;
	return 0;
}

/*
 * ssdfs_maptbl_create_segments() - create mapping table's segment objects
 * @fsi: file system info object
 * @array_type: main/backup segments chain
 * @tbl: mapping table object
 *
 * This method tries to create mapping table's segment objects.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_create_segments(struct ssdfs_fs_info *fsi,
				 int array_type,
				 struct ssdfs_peb_mapping_table *tbl)
{
	u64 seg;
	int seg_type = SSDFS_MAPTBL_SEG_TYPE;
	int seg_state = SSDFS_SEG_LEAF_NODE_USING;
	u16 log_pages;
	u8 create_threads;
	struct ssdfs_segment_info **kaddr = NULL;
	int i, j;
	u32 created_segs = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !tbl);
	BUG_ON(array_type >= SSDFS_MAPTBL_SEG_COPY_MAX);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));

	SSDFS_DBG("fsi %p, array_type %#x, tbl %p, segs_count %u\n",
		  fsi, array_type, tbl, tbl->segs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	log_pages = le16_to_cpu(fsi->vh->maptbl_log_pages);
	create_threads = fsi->create_threads_per_seg;

	tbl->segs[array_type] = ssdfs_map_tbl_kcalloc(tbl->segs_count,
					sizeof(struct ssdfs_segment_info *),
					GFP_KERNEL);
	if (!tbl->segs[array_type]) {
		SSDFS_ERR("fail to allocate segment array\n");
		return -ENOMEM;
	}

	for (i = 0; i < SSDFS_MAPTBL_RESERVED_EXTENTS; i++) {
		struct ssdfs_meta_area_extent *extent;
		u64 start_seg;
		u32 len;

		extent = &tbl->extents[i][array_type];

		err = CHECK_META_EXTENT_TYPE(extent);
		if (err == -ENODATA) {
			/* do nothing */
			break;
		} else if (unlikely(err)) {
			SSDFS_WARN("invalid meta area extent: "
				   "index %d, err %d\n",
				   i, err);
			return err;
		}

		start_seg = le64_to_cpu(extent->start_id);
		len = le32_to_cpu(extent->len);

		for (j = 0; j < len; j++) {
			if (created_segs >= tbl->segs_count) {
				SSDFS_ERR("created_segs %u >= segs_count %u\n",
					  created_segs, tbl->segs_count);
				return -ERANGE;
			}

			seg = start_seg + j;
			BUG_ON(!tbl->segs[array_type]);
			kaddr = &tbl->segs[array_type][created_segs];
			BUG_ON(*kaddr != NULL);

			*kaddr = ssdfs_segment_allocate_object(seg);
			if (IS_ERR_OR_NULL(*kaddr)) {
				err = !*kaddr ? -ENOMEM : PTR_ERR(*kaddr);
				*kaddr = NULL;
				SSDFS_ERR("fail to allocate segment object: "
					  "seg %llu, err %d\n",
					  seg, err);
				return err;
			}

			err = ssdfs_segment_create_object(fsi, seg, seg_state,
							  seg_type, log_pages,
							  create_threads,
							  *kaddr);
			if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
				return err;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to create segment: "
					  "seg %llu, err %d\n",
					  seg, err);
				return err;
			}

			ssdfs_segment_get_object(*kaddr);
			created_segs++;
		}
	}

	if (created_segs != tbl->segs_count) {
		SSDFS_ERR("created_segs %u != tbl->segs_count %u\n",
			  created_segs, tbl->segs_count);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_maptbl_destroy_segments() - destroy mapping table's segment objects
 * @tbl: mapping table object
 */
static
void ssdfs_maptbl_destroy_segments(struct ssdfs_peb_mapping_table *tbl)
{
	struct ssdfs_segment_info *si;
	int i, j;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);

	SSDFS_DBG("maptbl %p\n", tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < tbl->segs_count; i++) {
		for (j = 0; j < SSDFS_MAPTBL_SEG_COPY_MAX; j++) {
			if (tbl->segs[j] == NULL)
				continue;

			si = tbl->segs[j][i];

			ssdfs_segment_put_object(si);
			err = ssdfs_segment_destroy_object(si);
			if (unlikely(err == -EBUSY))
				BUG();
			else if (unlikely(err)) {
				SSDFS_WARN("issue during segment destroy: "
					   "err %d\n",
					   err);
			}
		}
	}

	for (i = 0; i < SSDFS_MAPTBL_SEG_COPY_MAX; i++) {
		ssdfs_map_tbl_kfree(tbl->segs[i]);
		tbl->segs[i] = NULL;
	}
}

/*
 * ssdfs_maptbl_destroy_fragment() - destroy mapping table's fragment
 * @fsi: file system info object
 * @index: fragment index
 */
inline
void ssdfs_maptbl_destroy_fragment(struct ssdfs_fs_info *fsi, u32 index)
{
	struct ssdfs_maptbl_fragment_desc *ptr;
	int state;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->maptbl || !fsi->maptbl->desc_array);
	BUG_ON(index >= fsi->maptbl->fragments_count);

	SSDFS_DBG("fsi %p, index %u\n", fsi, index);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr = &fsi->maptbl->desc_array[index];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(rwsem_is_locked(&ptr->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&ptr->state);

	if (state == SSDFS_MAPTBL_FRAG_DIRTY)
		SSDFS_WARN("fragment %u is dirty\n", index);
	else if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
		SSDFS_DBG("fragment %u init was failed\n", index);
		return;
	} else if (state >= SSDFS_MAPTBL_FRAG_STATE_MAX)
		BUG();

	if (ptr->flush_req1) {
		ssdfs_map_tbl_kfree(ptr->flush_req1);
		ptr->flush_req1 = NULL;
	}

	if (ptr->flush_req2) {
		ssdfs_map_tbl_kfree(ptr->flush_req2);
		ptr->flush_req2 = NULL;
	}

	ssdfs_destroy_page_array(&ptr->array);
	complete_all(&ptr->init_end);
}

/*
 * ssdfs_maptbl_segment_init() - initiate mapping table's segment init
 * @tbl: mapping table object
 * @si: segment object
 * @seg_index: index of segment in the sequence
 */
static
int ssdfs_maptbl_segment_init(struct ssdfs_peb_mapping_table *tbl,
			      struct ssdfs_segment_info *si,
			      int seg_index)
{
	u32 page_size;
	u64 logical_offset;
	u64 logical_blk;
	u32 blks_count;
	u32 fragment_bytes = tbl->fragment_bytes;
	u64 bytes_per_peb = (u64)tbl->fragments_per_peb * fragment_bytes;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);

	SSDFS_DBG("si %p, seg %llu, seg_index %d\n",
		  si, si->seg_id, seg_index);
#endif /* CONFIG_SSDFS_DEBUG */

	page_size = si->fsi->pagesize;
	logical_offset = bytes_per_peb * si->pebs_count * seg_index;

	for (i = 0; i < si->pebs_count; i++) {
		struct ssdfs_peb_container *pebc = &si->peb_array[i];
		struct ssdfs_segment_request *req;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!pebc);
#endif /* CONFIG_SSDFS_DEBUG */

		if (is_peb_container_empty(pebc)) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("PEB container empty: "
				  "seg %llu, peb_index %d\n",
				  si->seg_id, i);
#endif /* CONFIG_SSDFS_DEBUG */
			continue;
		}

		req = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(req)) {
			err = (req == NULL ? -ENOMEM : PTR_ERR(req));
			req = NULL;
			SSDFS_ERR("fail to allocate segment request: err %d\n",
				  err);
			return err;
		}

		ssdfs_request_init(req);
		ssdfs_get_request(req);

		logical_offset += bytes_per_peb * i;

		ssdfs_request_prepare_logical_extent(SSDFS_MAPTBL_INO,
						     logical_offset,
						     fragment_bytes,
						     0, 0, req);
		ssdfs_request_define_segment(si->seg_id, req);

		logical_blk = (u64)i * fragment_bytes;
		logical_blk = div64_u64(logical_blk, si->fsi->pagesize);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(logical_blk >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		blks_count = (fragment_bytes + page_size - 1) / page_size;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(blks_count >= U16_MAX);

		SSDFS_DBG("seg %llu, peb_index %d, "
			  "logical_blk %llu, blks_count %u, "
			  "fragment_bytes %u, page_size %u, "
			  "logical_offset %llu\n",
			  si->seg_id, i,
			  logical_blk, blks_count,
			  fragment_bytes, page_size,
			  logical_offset);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_request_define_volume_extent((u16)logical_blk,
						   (u16) blks_count,
						   req);

		ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
						    SSDFS_READ_INIT_MAPTBL,
						    SSDFS_REQ_ASYNC,
						    req);
		ssdfs_peb_read_request_cno(pebc);
		ssdfs_requests_queue_add_tail(&pebc->read_rq, req);
	}

	wake_up_all(&si->wait_queue[SSDFS_PEB_READ_THREAD]);

	return 0;
}

/*
 * ssdfs_maptbl_init() - initiate mapping table's initialization procedure
 * @tbl: mapping table object
 */
static
int ssdfs_maptbl_init(struct ssdfs_peb_mapping_table *tbl)
{
	struct ssdfs_segment_info *si;
	int i, j;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);

	SSDFS_DBG("maptbl %p\n", tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < tbl->segs_count; i++) {
		for (j = 0; j < SSDFS_MAPTBL_SEG_COPY_MAX; j++) {
			if (tbl->segs[j] == NULL)
				continue;

			si = tbl->segs[j][i];

			if (!si)
				continue;

			err = ssdfs_maptbl_segment_init(tbl, si, i);
			if (unlikely(err)) {
				SSDFS_ERR("fail to init segment: "
					  "seg %llu, err %d\n",
					  si->seg_id, err);
				return err;
			}
		}
	}

	return 0;
}

/*
 * ssdfs_maptbl_create() - create mapping table object
 * @fsi: file system info object
 */
int ssdfs_maptbl_create(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_peb_mapping_table *ptr;
	size_t maptbl_obj_size = sizeof(struct ssdfs_peb_mapping_table);
	size_t frag_desc_size = sizeof(struct ssdfs_maptbl_fragment_desc);
	void *kaddr;
	size_t bytes_count;
	size_t bmap_bytes;
	int array_type;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("fsi %p, segs_count %llu\n", fsi, fsi->nsegs);
#else
	SSDFS_DBG("fsi %p, segs_count %llu\n", fsi, fsi->nsegs);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	kaddr = ssdfs_map_tbl_kzalloc(maptbl_obj_size, GFP_KERNEL);
	if (!kaddr) {
		SSDFS_ERR("fail to allocate mapping table object\n");
		return -ENOMEM;
	}

	fsi->maptbl = ptr = (struct ssdfs_peb_mapping_table *)kaddr;

	ptr->fsi = fsi;

	init_rwsem(&ptr->tbl_lock);

	atomic_set(&ptr->flags, le16_to_cpu(fsi->vh->maptbl.flags));
	ptr->fragments_count = le32_to_cpu(fsi->vh->maptbl.fragments_count);
	ptr->fragment_bytes = le32_to_cpu(fsi->vh->maptbl.fragment_bytes);
	ptr->fragment_pages = (ptr->fragment_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
	ptr->fragments_per_seg = le16_to_cpu(fsi->vh->maptbl.fragments_per_seg);
	ptr->fragments_per_peb = le16_to_cpu(fsi->vh->maptbl.fragments_per_peb);
	ptr->lebs_count = le64_to_cpu(fsi->vh->maptbl.lebs_count);
	ptr->pebs_count = le64_to_cpu(fsi->vh->maptbl.pebs_count);
	ptr->lebs_per_fragment = le16_to_cpu(fsi->vh->maptbl.lebs_per_fragment);
	ptr->pebs_per_fragment = le16_to_cpu(fsi->vh->maptbl.pebs_per_fragment);
	ptr->pebs_per_stripe = le16_to_cpu(fsi->vh->maptbl.pebs_per_stripe);
	ptr->stripes_per_fragment =
		le16_to_cpu(fsi->vh->maptbl.stripes_per_fragment);

	atomic_set(&ptr->erase_op_state, SSDFS_MAPTBL_NO_ERASE);
	atomic_set(&ptr->pre_erase_pebs,
		   le16_to_cpu(fsi->vh->maptbl.pre_erase_pebs));
	/*
	 * TODO: the max_erase_ops field should be used by GC or
	 *       special management thread for determination of
	 *       upper bound of erase operations for one iteration
	 *       with the goal to orchestrate I/O load with
	 *       erasing load. But if it will be used TRIM command
	 *       for erasing then maybe the erasing load will be
	 *       no so sensitive.
	 */
	atomic_set(&ptr->max_erase_ops, ptr->pebs_count);

	init_waitqueue_head(&ptr->erase_ops_end_wq);

	atomic64_set(&ptr->last_peb_recover_cno,
		     le64_to_cpu(fsi->vh->maptbl.last_peb_recover_cno));

	bytes_count = sizeof(struct ssdfs_meta_area_extent);
	bytes_count *= SSDFS_MAPTBL_RESERVED_EXTENTS;
	bytes_count *= SSDFS_MAPTBL_SEG_COPY_MAX;
	ssdfs_memcpy(ptr->extents, 0, bytes_count,
		     fsi->vh->maptbl.extents, 0, bytes_count,
		     bytes_count);

	mutex_init(&ptr->bmap_lock);
	bmap_bytes = ptr->fragments_count + BITS_PER_LONG - 1;
	bmap_bytes /= BITS_PER_BYTE;
	ptr->dirty_bmap = ssdfs_map_tbl_kzalloc(bmap_bytes, GFP_KERNEL);
	if (!ptr->dirty_bmap) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate dirty_bmap\n");
		goto free_maptbl_object;
	}

	init_waitqueue_head(&ptr->wait_queue);

	err = ssdfs_check_maptbl_sb_header(fsi);
	if (unlikely(err)) {
		SSDFS_ERR("mapping table is corrupted: err %d\n", err);
		goto free_dirty_bmap;
	}

	kaddr = ssdfs_map_tbl_kcalloc(ptr->fragments_count,
					frag_desc_size, GFP_KERNEL);
	if (!kaddr) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate fragment descriptors array\n");
		goto free_dirty_bmap;
	}

	ptr->desc_array = (struct ssdfs_maptbl_fragment_desc *)kaddr;

	for (i = 0; i < ptr->fragments_count; i++) {
		err = ssdfs_maptbl_create_fragment(fsi, i);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create fragment: "
				  "index %d, err %d\n",
				  i, err);

			for (--i; i >= 0; i--) {
				/* Destroy created fragments */
				ssdfs_maptbl_destroy_fragment(fsi, i);
			}

			goto free_fragment_descriptors;
		}
	}

	err = ssdfs_maptbl_define_segment_counts(ptr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define segments count: err %d\n", err);
		goto free_fragment_descriptors;
	}

	array_type = SSDFS_MAIN_MAPTBL_SEG;
	err = ssdfs_maptbl_create_segments(fsi, array_type, ptr);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		goto destroy_seg_objects;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to create maptbl's segment objects: "
			  "err %d\n", err);
		goto destroy_seg_objects;
	}

	if (atomic_read(&ptr->flags) & SSDFS_MAPTBL_HAS_COPY) {
		array_type = SSDFS_COPY_MAPTBL_SEG;
		err = ssdfs_maptbl_create_segments(fsi, array_type, ptr);
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
			goto destroy_seg_objects;
		} if (unlikely(err)) {
			SSDFS_ERR("fail to create segbmap's segment objects: "
				  "err %d\n", err);
			goto destroy_seg_objects;
		}
	}

	err = ssdfs_maptbl_init(ptr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init mapping table: err %d\n",
			  err);
		goto destroy_seg_objects;
	}

	err = ssdfs_maptbl_start_thread(ptr);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		goto destroy_seg_objects;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to start mapping table's thread: "
			  "err %d\n", err);
		goto destroy_seg_objects;
	}

	atomic_set(&ptr->state, SSDFS_MAPTBL_CREATED);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("DONE: create mapping table\n");
#else
	SSDFS_DBG("DONE: create mapping table\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;

destroy_seg_objects:
	ssdfs_maptbl_destroy_segments(ptr);

free_fragment_descriptors:
	ssdfs_map_tbl_kfree(ptr->desc_array);

free_dirty_bmap:
	ssdfs_map_tbl_kfree(fsi->maptbl->dirty_bmap);
	fsi->maptbl->dirty_bmap = NULL;

free_maptbl_object:
	ssdfs_map_tbl_kfree(fsi->maptbl);
	fsi->maptbl = NULL;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(err == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_maptbl_destroy() - destroy mapping table object
 * @fsi: file system info object
 */
void ssdfs_maptbl_destroy(struct ssdfs_fs_info *fsi)
{
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("maptbl %p\n", fsi->maptbl);
#else
	SSDFS_DBG("maptbl %p\n", fsi->maptbl);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (!fsi->maptbl)
		return;

	ssdfs_maptbl_destroy_segments(fsi->maptbl);

	for (i = 0; i < fsi->maptbl->fragments_count; i++)
		ssdfs_maptbl_destroy_fragment(fsi, i);

	ssdfs_map_tbl_kfree(fsi->maptbl->desc_array);
	ssdfs_map_tbl_kfree(fsi->maptbl->dirty_bmap);
	fsi->maptbl->dirty_bmap = NULL;
	ssdfs_map_tbl_kfree(fsi->maptbl);
	fsi->maptbl = NULL;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */
}

/*
 * ssdfs_maptbl_fragment_desc_init() - prepare fragment descriptor
 * @tbl: mapping table object
 * @area: mapping table's area descriptor
 * @fdesc: mapping table's fragment descriptor
 */
static
void ssdfs_maptbl_fragment_desc_init(struct ssdfs_peb_mapping_table *tbl,
				     struct ssdfs_maptbl_area *area,
				     struct ssdfs_maptbl_fragment_desc *fdesc)
{
	u32 aligned_lebs_count;
	u16 lebs_per_page;
	u32 pebs_count;
	u32 aligned_pebs_count, aligned_stripe_pebs;
	u16 pebs_per_page;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !area || !fdesc);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	SSDFS_DBG("portion_id %u, tbl %p, "
		  "area %p, fdesc %p\n",
		  area->portion_id, tbl, area, fdesc);
#endif /* CONFIG_SSDFS_DEBUG */

	fdesc->start_leb = (u64)area->portion_id * tbl->lebs_per_fragment;
	fdesc->lebs_count = (u32)min_t(u64, (u64)tbl->lebs_per_fragment,
					tbl->lebs_count - fdesc->start_leb);

	lebs_per_page = SSDFS_LEB_DESC_PER_FRAGMENT(PAGE_SIZE);
	aligned_lebs_count = fdesc->lebs_count + lebs_per_page - 1;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON((aligned_lebs_count / lebs_per_page) >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	fdesc->lebtbl_pages = (u16)(aligned_lebs_count / lebs_per_page);

	fdesc->lebs_per_page = lebs_per_page;

	pebs_count = fdesc->lebs_count;
	pebs_per_page = SSDFS_PEB_DESC_PER_FRAGMENT(PAGE_SIZE);

	aligned_pebs_count = pebs_count +
				(pebs_count % tbl->stripes_per_fragment);
	aligned_stripe_pebs = aligned_pebs_count / tbl->stripes_per_fragment;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(((aligned_stripe_pebs + pebs_per_page - 1) /
		pebs_per_page) >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	fdesc->stripe_pages = (aligned_stripe_pebs + pebs_per_page - 1) /
				pebs_per_page;

	fdesc->pebs_per_page = pebs_per_page;
}

/*
 * ssdfs_maptbl_check_lebtbl_page() - check LEB table's page
 * @page: memory page with LEB table's fragment
 * @portion_id: portion identification number
 * @fragment_id: portion's fragment identification number
 * @fdesc: mapping table's fragment descriptor
 * @page_index: index of page inside of LEB table
 * @lebs_per_fragment: pointer on counter of LEBs in fragment [in|out]
 *
 * This method checks LEB table's page.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EIO        - fragment's LEB table is corrupted.
 */
static
int ssdfs_maptbl_check_lebtbl_page(struct page *page,
				   u16 portion_id, u16 fragment_id,
				   struct ssdfs_maptbl_fragment_desc *fdesc,
				   int page_index,
				   u16 *lebs_per_fragment)
{
	void *kaddr;
	struct ssdfs_leb_table_fragment_header *hdr;
	u32 bytes_count;
	__le32 csum;
	u64 start_leb;
	u16 lebs_count, mapped_lebs, migrating_lebs;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page || !fdesc || !lebs_per_fragment);
	BUG_ON(*lebs_per_fragment == U16_MAX);

	if (page_index >= fdesc->lebtbl_pages) {
		SSDFS_ERR("page_index %d >= fdesc->lebtbl_pages %u\n",
			  page_index, fdesc->lebtbl_pages);
		return -EINVAL;
	}

	SSDFS_DBG("page %p, portion_id %u, fragment_id %u, "
		  "fdesc %p, page_index %d, "
		  "lebs_per_fragment %u\n",
		  page, portion_id, fragment_id,
		  fdesc, page_index,
		  *lebs_per_fragment);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_lock_page(page);
	kaddr = kmap_local_page(page);
	hdr = (struct ssdfs_leb_table_fragment_header *)kaddr;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("PAGE DUMP: page_index %u\n",
		  page_index);
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     kaddr,
			     PAGE_SIZE);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	if (le16_to_cpu(hdr->magic) != SSDFS_LEB_TABLE_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid LEB table's magic signature: "
			  "page_index %d\n",
			  page_index);
		goto finish_lebtbl_check;
	}

	bytes_count = le32_to_cpu(hdr->bytes_count);
	if (bytes_count > PAGE_SIZE) {
		err = -EIO;
		SSDFS_ERR("invalid bytes_count %u\n",
			  bytes_count);
		goto finish_lebtbl_check;
	}

	csum = hdr->checksum;
	hdr->checksum = 0;
	hdr->checksum = ssdfs_crc32_le(kaddr, bytes_count);
	if (hdr->checksum != csum) {
		err = -EIO;
		SSDFS_ERR("hdr->checksum %u != csum %u\n",
			  le32_to_cpu(hdr->checksum),
			  le32_to_cpu(csum));
		hdr->checksum = csum;
		goto finish_lebtbl_check;
	}

	if (le16_to_cpu(hdr->portion_id) != portion_id ||
	    le16_to_cpu(hdr->fragment_id) != fragment_id) {
		err = -EIO;
		SSDFS_ERR("hdr->portion_id %u != portion_id %u OR "
			  "hdr->fragment_id %u != fragment_id %u\n",
			  le16_to_cpu(hdr->portion_id),
			  portion_id,
			  le16_to_cpu(hdr->fragment_id),
			  fragment_id);
		goto finish_lebtbl_check;
	}

	if (hdr->flags != 0) {
		err = -EIO;
		SSDFS_ERR("unsupported flags %#x\n",
			  le16_to_cpu(hdr->flags));
		goto finish_lebtbl_check;
	}

	start_leb = fdesc->start_leb + ((u64)fdesc->lebs_per_page * page_index);
	if (start_leb != le64_to_cpu(hdr->start_leb)) {
		err = -EIO;
		SSDFS_ERR("hdr->start_leb %llu != start_leb %llu\n",
			  le64_to_cpu(hdr->start_leb),
			  start_leb);
		goto finish_lebtbl_check;
	}

	lebs_count = le16_to_cpu(hdr->lebs_count);
	mapped_lebs = le16_to_cpu(hdr->mapped_lebs);
	migrating_lebs = le16_to_cpu(hdr->migrating_lebs);

	if (lebs_count > fdesc->lebs_per_page) {
		err = -EIO;
		SSDFS_ERR("lebs_count %u > fdesc->lebs_per_page %u\n",
			  lebs_count, fdesc->lebs_per_page);
		goto finish_lebtbl_check;
	}

	if (lebs_count < (mapped_lebs + migrating_lebs)) {
		err = -EIO;
		SSDFS_ERR("lebs_count %u, mapped_lebs %u, migrating_lebs %u\n",
			  lebs_count, mapped_lebs, migrating_lebs);
		goto finish_lebtbl_check;
	}

	fdesc->mapped_lebs += mapped_lebs;
	fdesc->migrating_lebs += migrating_lebs;

	*lebs_per_fragment += lebs_count;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("mapped_lebs %u, migrating_lebs %u\n",
		  fdesc->mapped_lebs, fdesc->migrating_lebs);
#endif /* CONFIG_SSDFS_DEBUG */

finish_lebtbl_check:
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);

	return err;
}

/*
 * ssdfs_maptbl_check_pebtbl_page() - check page in stripe of PEB table
 * @pebc: pointer on PEB container
 * @page: memory page with PEB table's fragment
 * @portion_id: portion identification number
 * @fragment_id: portion's fragment identification number
 * @fdesc: mapping table's fragment descriptor
 * @stripe_id: PEB table's stripe identification number
 * @page_index: index of page inside of PEB table's stripe
 * @pebs_per_fragment: pointer on counter of PEBs in fragment [in|out]
 *
 * This method checks PEB table's page.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EIO        - fragment's PEB table is corrupted.
 */
static
int ssdfs_maptbl_check_pebtbl_page(struct ssdfs_peb_container *pebc,
				   struct page *page,
				   u16 portion_id, u16 fragment_id,
				   struct ssdfs_maptbl_fragment_desc *fdesc,
				   int stripe_id,
				   int page_index,
				   u16 *pebs_per_fragment)
{
	struct ssdfs_fs_info *fsi;
	void *kaddr;
	struct ssdfs_peb_table_fragment_header *hdr;
	u32 bytes_count;
	__le32 csum;
	u16 pebs_count;
	u16 reserved_pebs;
	u16 used_pebs;
	u16 unused_pebs = 0;
	unsigned long *bmap;
	int pre_erase_pebs, recovering_pebs;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !page || !fdesc || !pebs_per_fragment);
	BUG_ON(*pebs_per_fragment == U16_MAX);

	if (page_index >= fdesc->stripe_pages) {
		SSDFS_ERR("page_index %d >= fdesc->stripe_pages %u\n",
			  page_index, fdesc->stripe_pages);
		return -EINVAL;
	}

	SSDFS_DBG("seg %llu, peb_index %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index);
	SSDFS_DBG("page %p, portion_id %u, fragment_id %u, "
		  "fdesc %p, stripe_id %d, page_index %d, "
		  "pebs_per_fragment %u\n",
		  page, portion_id, fragment_id,
		  fdesc, stripe_id, page_index,
		  *pebs_per_fragment);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebc->parent_si->fsi;

	ssdfs_lock_page(page);
	kaddr = kmap_local_page(page);
	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("PAGE DUMP: page_index %u\n",
		  page_index);
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     kaddr,
			     PAGE_SIZE);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	if (le16_to_cpu(hdr->magic) != SSDFS_PEB_TABLE_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid PEB table's magic signature: "
			  "stripe_id %d, page_index %d\n",
			  stripe_id, page_index);
		goto finish_pebtbl_check;
	}

	bytes_count = le32_to_cpu(hdr->bytes_count);
	if (bytes_count > PAGE_SIZE) {
		err = -EIO;
		SSDFS_ERR("invalid bytes_count %u\n",
			  bytes_count);
		goto finish_pebtbl_check;
	}

	csum = hdr->checksum;
	hdr->checksum = 0;
	hdr->checksum = ssdfs_crc32_le(kaddr, bytes_count);
	if (hdr->checksum != csum) {
		err = -EIO;
		SSDFS_ERR("hdr->checksum %u != csum %u\n",
			  le32_to_cpu(hdr->checksum),
			  le32_to_cpu(csum));
		hdr->checksum = csum;
		goto finish_pebtbl_check;
	}

	if (le16_to_cpu(hdr->portion_id) != portion_id ||
	    le16_to_cpu(hdr->fragment_id) != fragment_id) {
		err = -EIO;
		SSDFS_ERR("hdr->portion_id %u != portion_id %u OR "
			  "hdr->fragment_id %u != fragment_id %u\n",
			  le16_to_cpu(hdr->portion_id),
			  portion_id,
			  le16_to_cpu(hdr->fragment_id),
			  fragment_id);
		goto finish_pebtbl_check;
	}

	if (hdr->flags != 0) {
		err = -EIO;
		SSDFS_ERR("unsupported flags %#x\n",
			  hdr->flags);
		goto finish_pebtbl_check;
	}

	if (le16_to_cpu(hdr->stripe_id) != stripe_id) {
		err = -EIO;
		SSDFS_ERR("hdr->stripe_id %u != stripe_id %d\n",
			  le16_to_cpu(hdr->stripe_id),
			  stripe_id);
		goto finish_pebtbl_check;
	}

	pebs_count = le16_to_cpu(hdr->pebs_count);
	reserved_pebs = le16_to_cpu(hdr->reserved_pebs);
	fdesc->reserved_pebs += reserved_pebs;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("hdr->start_peb %llu, hdr->pebs_count %u\n",
		  le64_to_cpu(hdr->start_peb), pebs_count);
	SSDFS_DBG("hdr->reserved_pebs %u\n", reserved_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pebs_count > fdesc->pebs_per_page) {
		err = -EIO;
		SSDFS_ERR("pebs_count %u > fdesc->pebs_per_page %u\n",
			  pebs_count, fdesc->pebs_per_page);
		goto finish_pebtbl_check;
	}

	bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_USED_BMAP][0];
	used_pebs = bitmap_weight(bmap, pebs_count);

	if (used_pebs > pebs_count) {
		err = -EIO;
		SSDFS_ERR("used_pebs %u > pebs_count %u\n",
			  used_pebs, pebs_count);
		goto finish_pebtbl_check;
	}

	bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_DIRTY_BMAP][0];
	pre_erase_pebs = bitmap_weight(bmap, pebs_count);
	fdesc->pre_erase_pebs += pre_erase_pebs;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("fragment_id %u, stripe_id %u, pre_erase_pebs %u\n",
		  fragment_id, stripe_id, fdesc->pre_erase_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

	bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_RECOVER_BMAP][0];
	recovering_pebs = bitmap_weight(bmap, pebs_count);
	fdesc->recovering_pebs += recovering_pebs;

	*pebs_per_fragment += pebs_count;

	unused_pebs = pebs_count - used_pebs;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pebs_count %u, used_pebs %u, "
		  "unused_pebs %u, reserved_pebs %u\n",
		  pebs_count, used_pebs,
		  unused_pebs, reserved_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

	if (unused_pebs < reserved_pebs) {
		err = -EIO;
		SSDFS_ERR("unused_pebs %u < reserved_pebs %u\n",
			  unused_pebs, reserved_pebs);
		goto finish_pebtbl_check;
	}

	unused_pebs -= reserved_pebs;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pebs_count %u, used_pebs %u, "
		  "reserved_pebs %u, unused_pebs %u\n",
		  pebs_count, used_pebs,
		  reserved_pebs, unused_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

finish_pebtbl_check:
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);

	if (!err) {
		u32 unused_lebs;
		u64 free_pages;
		u64 unused_pages = 0;
		u32 threshold;

		unused_lebs = ssdfs_unused_lebs_in_fragment(fdesc);
		threshold = ssdfs_lebs_reservation_threshold(fdesc);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unused_pebs %u, unused_lebs %u, threshold %u\n",
			  unused_pebs, unused_lebs, threshold);
#endif /* CONFIG_SSDFS_DEBUG */

		if (unused_lebs > threshold) {
			unused_pages = (u64)unused_pebs * fsi->pages_per_peb;

			spin_lock(&fsi->volume_state_lock);
			fsi->free_pages += unused_pages;
			free_pages = fsi->free_pages;
			spin_unlock(&fsi->volume_state_lock);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			spin_lock(&fsi->volume_state_lock);
			free_pages = fsi->free_pages;
			spin_unlock(&fsi->volume_state_lock);
#endif /* CONFIG_SSDFS_DEBUG */
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg %llu, peb_index %u, "
			  "free_pages %llu, unused_pages %llu\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, free_pages, unused_pages);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return err;
}

/*
 * ssdfs_maptbl_move_fragment_pages() - move fragment's pages
 * @req: segment request
 * @area: fragment's pages
 * @pages_count: pages count in area
 */
void ssdfs_maptbl_move_fragment_pages(struct ssdfs_segment_request *req,
				      struct ssdfs_maptbl_area *area,
				      u16 pages_count)
{
	struct page *page;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req || !area);

	SSDFS_DBG("req %p, area %p\n",
		  req, area);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < pages_count; i++) {
		page = req->result.pvec.pages[i];
		area->pages[area->pages_count] = page;
		area->pages_count++;
		ssdfs_map_tbl_account_page(page);
		ssdfs_request_unlock_and_remove_page(req, i);
	}

#ifdef CONFIG_SSDFS_DEBUG
	for (i = 0; i < pagevec_count(&req->result.pvec); i++) {
		page = req->result.pvec.pages[i];

		if (page) {
			SSDFS_ERR("page %d is valid\n", i);
			BUG_ON(page);
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */

	pagevec_reinit(&req->result.pvec);
}

/*
 * ssdfs_maptbl_fragment_init() - init mapping table's fragment
 * @pebc: pointer on PEB container
 * @area: mapping table's area descriptor
 *
 * This method tries to initialize mapping table's fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EIO        - fragment is corrupted.
 */
int ssdfs_maptbl_fragment_init(struct ssdfs_peb_container *pebc,
				struct ssdfs_maptbl_area *area)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_mapping_table *tbl;
	struct ssdfs_maptbl_fragment_desc *fdesc;
	int state;
	u16 lebs_per_fragment = 0, pebs_per_fragment = 0;
	u32 calculated;
	int page_index;
	int fragment_id;
	int i, j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!pebc->parent_si->fsi->maptbl || !area);
	BUG_ON(!rwsem_is_locked(&pebc->parent_si->fsi->maptbl->tbl_lock));
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg %llu, peb_index %u, portion_id %u, "
		  "pages_count %zu, pages_capacity %zu\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index, area->portion_id,
		  area->pages_count, area->pages_capacity);
#else
	SSDFS_DBG("seg %llu, peb_index %u, portion_id %u, "
		  "pages_count %zu, pages_capacity %zu\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index, area->portion_id,
		  area->pages_count, area->pages_capacity);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi = pebc->parent_si->fsi;
	tbl = fsi->maptbl;

	if (area->pages_count > area->pages_capacity) {
		SSDFS_ERR("area->pages_count %zu > area->pages_capacity %zu\n",
			  area->pages_count,
			  area->pages_capacity);
		return -EINVAL;
	}

	if (area->pages_count > tbl->fragment_pages) {
		SSDFS_ERR("area->pages_count %zu > tbl->fragment_pages %u\n",
			  area->pages_count,
			  tbl->fragment_pages);
		return -EINVAL;
	}

	if (area->portion_id >= tbl->fragments_count) {
		SSDFS_ERR("invalid index: "
			  "portion_id %u, fragment_count %u\n",
			  area->portion_id,
			  tbl->fragments_count);
		return -EINVAL;
	}

	fdesc = &tbl->desc_array[area->portion_id];

	state = atomic_read(&fdesc->state);
	if (state != SSDFS_MAPTBL_FRAG_CREATED) {
		SSDFS_ERR("invalid fragment state %#x\n", state);
		return -ERANGE;
	}

	down_write(&fdesc->lock);

	ssdfs_maptbl_fragment_desc_init(tbl, area, fdesc);

	calculated = fdesc->lebtbl_pages;
	calculated += fdesc->stripe_pages * tbl->stripes_per_fragment;
	if (calculated != area->pages_count) {
		err = -EIO;
		SSDFS_ERR("calculated %u != area->pages_count %zu\n",
			  calculated, area->pages_count);
		goto finish_fragment_init;
	}

	page_index = 0;

	for (i = 0; i < fdesc->lebtbl_pages; i++) {
		struct page *page;

		if (page_index >= area->pages_count) {
			err = -ERANGE;
			SSDFS_ERR("page_index %d >= pages_count %zu\n",
				  page_index, area->pages_count);
			goto finish_fragment_init;
		}

		page = area->pages[page_index];
		if (!page) {
			err = -ERANGE;
			SSDFS_ERR("page %d is absent\n", i);
			goto finish_fragment_init;
		}

		err = ssdfs_maptbl_check_lebtbl_page(page,
						     area->portion_id, i,
						     fdesc, i,
						     &lebs_per_fragment);
		if (unlikely(err)) {
			SSDFS_ERR("maptbl's page %d is corrupted: "
				  "err %d\n",
				  page_index, err);
			goto finish_fragment_init;
		}

		page_index++;
	}

	if (fdesc->lebs_count < (fdesc->mapped_lebs + fdesc->migrating_lebs)) {
		err = -EIO;
		SSDFS_ERR("lebs_count %u, mapped_lebs %u, migratind_lebs %u\n",
			  fdesc->lebs_count,
			  fdesc->mapped_lebs,
			  fdesc->migrating_lebs);
		goto finish_fragment_init;
	}

	if (fdesc->lebs_count < fdesc->pre_erase_pebs) {
		err = -EIO;
		SSDFS_ERR("lebs_count %u, pre_erase_pebs %u\n",
			  fdesc->lebs_count,
			  fdesc->pre_erase_pebs);
		goto finish_fragment_init;
	}

	for (i = 0, fragment_id = 0; i < tbl->stripes_per_fragment; i++) {
		for (j = 0; j < fdesc->stripe_pages; j++) {
			struct page *page;

			if (page_index >= area->pages_count) {
				err = -ERANGE;
				SSDFS_ERR("page_index %d >= pages_count %zu\n",
					  page_index, area->pages_count);
				goto finish_fragment_init;
			}

			page = area->pages[page_index];
			if (!page) {
				err = -ERANGE;
				SSDFS_ERR("page %d is absent\n", i);
				goto finish_fragment_init;
			}

			err = ssdfs_maptbl_check_pebtbl_page(pebc, page,
							    area->portion_id,
							    fragment_id,
							    fdesc, i, j,
							    &pebs_per_fragment);
			if (unlikely(err)) {
				SSDFS_ERR("maptbl's page %d is corrupted: "
					  "err %d\n",
					  page_index, err);
				goto finish_fragment_init;
			}

			page_index++;
			fragment_id++;
		}
	}

	if (lebs_per_fragment > pebs_per_fragment) {
		err = -EIO;
		SSDFS_ERR("lebs_per_fragment %u > pebs_per_fragment %u\n",
			  lebs_per_fragment, pebs_per_fragment);
		goto finish_fragment_init;
	} else if (lebs_per_fragment < pebs_per_fragment) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("lebs_per_fragment %u < pebs_per_fragment %u\n",
			  lebs_per_fragment, pebs_per_fragment);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	if (lebs_per_fragment > tbl->lebs_per_fragment ||
	    lebs_per_fragment != fdesc->lebs_count) {
		err = -EIO;
		SSDFS_ERR("lebs_per_fragment %u, tbl->lebs_per_fragment %u, "
			  "fdesc->lebs_count %u\n",
			  lebs_per_fragment,
			  tbl->lebs_per_fragment,
			  fdesc->lebs_count);
		goto finish_fragment_init;
	}

	if (pebs_per_fragment > tbl->pebs_per_fragment ||
	    fdesc->lebs_count > pebs_per_fragment) {
		err = -EIO;
		SSDFS_ERR("pebs_per_fragment %u, tbl->pebs_per_fragment %u, "
			  "fdesc->lebs_count %u\n",
			  pebs_per_fragment,
			  tbl->pebs_per_fragment,
			  fdesc->lebs_count);
		goto finish_fragment_init;
	}

	for (i = 0; i < area->pages_count; i++) {
		struct page *page;

		if (i >= area->pages_count) {
			err = -ERANGE;
			SSDFS_ERR("page_index %d >= pages_count %zu\n",
				  i, area->pages_count);
			goto finish_fragment_init;
		}

		page = area->pages[i];
		if (!page) {
			err = -ERANGE;
			SSDFS_ERR("page %d is absent\n", i);
			goto finish_fragment_init;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page_index %d, page %p\n",
			  i, page);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_lock_page(page);
		ssdfs_set_page_private(page, 0);
		SetPageUptodate(page);
		err = ssdfs_page_array_add_page(&fdesc->array,
						page, i);
		ssdfs_unlock_page(page);

		if (unlikely(err)) {
			SSDFS_ERR("fail to add page %d: err %d\n",
				  i, err);
			goto finish_fragment_init;
		}

		ssdfs_map_tbl_forget_page(page);
		area->pages[i] = NULL;
	}

finish_fragment_init:
	if (err) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment init failed: "
			  "portion_id %u, fdesc->fragment_id %u\n",
			  area->portion_id, fdesc->fragment_id);
#endif /* CONFIG_SSDFS_DEBUG */

		state = atomic_cmpxchg(&fdesc->state,
					SSDFS_MAPTBL_FRAG_CREATED,
					SSDFS_MAPTBL_FRAG_INIT_FAILED);
		if (state != SSDFS_MAPTBL_FRAG_CREATED) {
			/* don't change error code */
			SSDFS_WARN("invalid fragment state %#x\n", state);
		}
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment init finished: "
			  "portion_id %u, fdesc->fragment_id %u\n",
			  area->portion_id, fdesc->fragment_id);
#endif /* CONFIG_SSDFS_DEBUG */

		state = atomic_cmpxchg(&fdesc->state,
					SSDFS_MAPTBL_FRAG_CREATED,
					SSDFS_MAPTBL_FRAG_INITIALIZED);
		if (state != SSDFS_MAPTBL_FRAG_CREATED) {
			err = -ERANGE;
			SSDFS_ERR("invalid fragment state %#x\n", state);
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment: fdesc->fragment_id %u, state %#x\n",
			  fdesc->fragment_id,
			  atomic_read(&fdesc->state));
#endif /* CONFIG_SSDFS_DEBUG */

	}

	up_write(&fdesc->lock);

	complete_all(&fdesc->init_end);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_sb_maptbl_header_correct_state() - save maptbl's state in superblock
 * @tbl: mapping table object
 */
static
void ssdfs_sb_maptbl_header_correct_state(struct ssdfs_peb_mapping_table *tbl)
{
	struct ssdfs_maptbl_sb_header *hdr;
	size_t bytes_count;
	u32 flags = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));
	BUG_ON(!rwsem_is_locked(&tbl->fsi->volume_sem));

	SSDFS_DBG("maptbl %p\n", tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = &tbl->fsi->vh->maptbl;

	hdr->fragments_count = cpu_to_le32(tbl->fragments_count);
	hdr->fragment_bytes = cpu_to_le32(tbl->fragment_bytes);
	hdr->last_peb_recover_cno =
		cpu_to_le64(atomic64_read(&tbl->last_peb_recover_cno));
	hdr->lebs_count = cpu_to_le64(tbl->lebs_count);
	hdr->pebs_count = cpu_to_le64(tbl->pebs_count);
	hdr->fragments_per_seg = cpu_to_le16(tbl->fragments_per_seg);
	hdr->fragments_per_peb = cpu_to_le16(tbl->fragments_per_peb);

	flags = atomic_read(&tbl->flags);
	/* exclude run-time flags*/
	flags &= ~SSDFS_MAPTBL_UNDER_FLUSH;
	hdr->flags = cpu_to_le16(flags);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(atomic_read(&tbl->pre_erase_pebs) >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	hdr->pre_erase_pebs = le16_to_cpu(atomic_read(&tbl->pre_erase_pebs));

	hdr->lebs_per_fragment = cpu_to_le16(tbl->lebs_per_fragment);
	hdr->pebs_per_fragment = cpu_to_le16(tbl->pebs_per_fragment);
	hdr->pebs_per_stripe = cpu_to_le16(tbl->pebs_per_stripe);
	hdr->stripes_per_fragment = cpu_to_le16(tbl->stripes_per_fragment);

	bytes_count = sizeof(struct ssdfs_meta_area_extent);
	bytes_count *= SSDFS_MAPTBL_RESERVED_EXTENTS;
	bytes_count *= SSDFS_MAPTBL_SEG_COPY_MAX;
	ssdfs_memcpy(hdr->extents, 0, bytes_count,
		     tbl->fsi->vh->maptbl.extents, 0, bytes_count,
		     bytes_count);
}

/*
 * ssdfs_maptbl_copy_dirty_page() - copy dirty page into request
 * @tbl: mapping table object
 * @pvec: pagevec with dirty pages
 * @spage_index: index of page in pagevec
 * @dpage_index: index of page in request
 * @req: segment request
 *
 * This method tries to copy dirty page into request.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_copy_dirty_page(struct ssdfs_peb_mapping_table *tbl,
				 struct pagevec *pvec,
				 int spage_index, int dpage_index,
				 struct ssdfs_segment_request *req)
{
	struct page *spage, *dpage;
	void *kaddr1, *kaddr2;
	struct ssdfs_leb_table_fragment_header *lhdr;
	struct ssdfs_peb_table_fragment_header *phdr;
	__le16 *magic;
	__le32 csum;
	u32 bytes_count;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !pvec || !req);
	BUG_ON(spage_index >= pagevec_count(pvec));

	SSDFS_DBG("maptbl %p, pvec %p, spage_index %d, "
		  "dpage_index %d, req %p\n",
		  tbl, pvec, spage_index, dpage_index, req);
#endif /* CONFIG_SSDFS_DEBUG */

	spage = pvec->pages[spage_index];

	ssdfs_lock_page(spage);
	kaddr1 = kmap_local_page(spage);

	magic = (__le16 *)kaddr1;
	if (*magic == cpu_to_le16(SSDFS_LEB_TABLE_MAGIC)) {
		lhdr = (struct ssdfs_leb_table_fragment_header *)kaddr1;
		bytes_count = le32_to_cpu(lhdr->bytes_count);
		csum = lhdr->checksum;
		lhdr->checksum = 0;
		lhdr->checksum = ssdfs_crc32_le(kaddr1, bytes_count);
		if (csum != lhdr->checksum) {
			err = -ERANGE;
			SSDFS_ERR("csum %#x != lhdr->checksum %#x\n",
				  le16_to_cpu(csum),
				  le16_to_cpu(lhdr->checksum));
			lhdr->checksum = csum;
			goto end_copy_dirty_page;
		}
	} else if (*magic == cpu_to_le16(SSDFS_PEB_TABLE_MAGIC)) {
		phdr = (struct ssdfs_peb_table_fragment_header *)kaddr1;
		bytes_count = le32_to_cpu(phdr->bytes_count);
		csum = phdr->checksum;
		phdr->checksum = 0;
		phdr->checksum = ssdfs_crc32_le(kaddr1, bytes_count);
		if (csum != phdr->checksum) {
			err = -ERANGE;
			SSDFS_ERR("csum %#x != phdr->checksum %#x\n",
				  le16_to_cpu(csum),
				  le16_to_cpu(phdr->checksum));
			phdr->checksum = csum;
			goto end_copy_dirty_page;
		}
	} else {
		err = -ERANGE;
		SSDFS_ERR("corrupted maptbl's page: index %lu\n",
			  spage->index);
		goto end_copy_dirty_page;
	}

	dpage = req->result.pvec.pages[dpage_index];

	if (!dpage) {
		err = -ERANGE;
		SSDFS_ERR("invalid page: page_index %u\n",
			  dpage_index);
		goto end_copy_dirty_page;
	}

	kaddr2 = kmap_local_page(dpage);
	ssdfs_memcpy(kaddr2, 0, PAGE_SIZE,
		     kaddr1, 0, PAGE_SIZE,
		     PAGE_SIZE);
	flush_dcache_page(dpage);
	kunmap_local(kaddr2);

	SetPageUptodate(dpage);
	if (!PageDirty(dpage))
		SetPageDirty(dpage);
	set_page_writeback(dpage);

end_copy_dirty_page:
	flush_dcache_page(spage);
	kunmap_local(kaddr1);
	ssdfs_unlock_page(spage);

	return err;
}

/*
 * ssdfs_maptbl_replicate_dirty_page() - replicate dirty page content
 * @req1: source request
 * @page_index: index of replicated page in @req1
 * @req2: destination request
 */
static
void ssdfs_maptbl_replicate_dirty_page(struct ssdfs_segment_request *req1,
					int page_index,
					struct ssdfs_segment_request *req2)
{
	struct page *spage, *dpage;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req1 || !req2);
	BUG_ON(page_index >= pagevec_count(&req1->result.pvec));
	BUG_ON(page_index >= pagevec_count(&req2->result.pvec));

	SSDFS_DBG("req1 %p, req2 %p, page_index %d\n",
		  req1, req2, page_index);
#endif /* CONFIG_SSDFS_DEBUG */

	spage = req1->result.pvec.pages[page_index];
	dpage = req2->result.pvec.pages[page_index];

	ssdfs_memcpy_page(dpage, 0, PAGE_SIZE,
			  spage, 0, PAGE_SIZE,
			  PAGE_SIZE);

	SetPageUptodate(dpage);
	if (!PageDirty(dpage))
		SetPageDirty(dpage);
	set_page_writeback(dpage);
}

/*
 * ssdfs_check_portion_id() - check portion_id in the pagevec
 * @pvec: checking pagevec
 */
static inline
int ssdfs_check_portion_id(struct pagevec *pvec)
{
	struct ssdfs_leb_table_fragment_header *lhdr;
	struct ssdfs_peb_table_fragment_header *phdr;
	u32 portion_id = U32_MAX;
	void *kaddr;
	__le16 *magic;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec);

	SSDFS_DBG("pvec %p\n", pvec);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pagevec_count(pvec) == 0) {
		SSDFS_ERR("empty pagevec\n");
		return -EINVAL;
	}

	for (i = 0; i < pagevec_count(pvec); i++) {
		kaddr = kmap_local_page(pvec->pages[i]);
		magic = (__le16 *)kaddr;
		if (le16_to_cpu(*magic) == SSDFS_LEB_TABLE_MAGIC) {
			lhdr = (struct ssdfs_leb_table_fragment_header *)kaddr;
			if (portion_id == U32_MAX)
				portion_id = le32_to_cpu(lhdr->portion_id);
			else if (portion_id != le32_to_cpu(lhdr->portion_id))
				err = -ERANGE;
		} else if (le16_to_cpu(*magic) == SSDFS_PEB_TABLE_MAGIC) {
			phdr = (struct ssdfs_peb_table_fragment_header *)kaddr;
			if (portion_id == U32_MAX)
				portion_id = le32_to_cpu(phdr->portion_id);
			else if (portion_id != le32_to_cpu(phdr->portion_id))
				err = -ERANGE;
		} else {
			err = -ERANGE;
			SSDFS_ERR("corrupted maptbl's page: index %d\n",
				  i);
		}
		kunmap_local(kaddr);

		if (unlikely(err))
			return err;
	}

	return 0;
}

/*
 * ssdfs_maptbl_define_volume_extent() - define volume extent for request
 * @tbl: mapping table object
 * @req: segment request
 * @fragment: pointer on raw fragment
 * @area_start: index of memeory page inside of fragment
 * @pages_count: number of memory pages in the area
 * @seg_index: index of segment in maptbl's array [out]
 */
static
int ssdfs_maptbl_define_volume_extent(struct ssdfs_peb_mapping_table *tbl,
					struct ssdfs_segment_request *req,
					void *fragment,
					pgoff_t area_start,
					u32 pages_count,
					u16 *seg_index)
{
	struct ssdfs_leb_table_fragment_header *lhdr;
	struct ssdfs_peb_table_fragment_header *phdr;
	u32 portion_id = U32_MAX;
	__le16 *magic;
	u64 fragment_offset;
	u16 item_index;
	u32 pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !req || !fragment || !seg_index);

	SSDFS_DBG("maptbl %p, req %p, fragment %p, "
		  "area_start %lu, pages_count %u, "
		  "seg_index %p\n",
		  tbl, req, fragment, area_start,
		  pages_count, seg_index);
#endif /* CONFIG_SSDFS_DEBUG */

	pagesize = tbl->fsi->pagesize;

	magic = (__le16 *)fragment;
	if (le16_to_cpu(*magic) == SSDFS_LEB_TABLE_MAGIC) {
		lhdr = (struct ssdfs_leb_table_fragment_header *)fragment;
		portion_id = le32_to_cpu(lhdr->portion_id);
	} else if (le16_to_cpu(*magic) == SSDFS_PEB_TABLE_MAGIC) {
		phdr = (struct ssdfs_peb_table_fragment_header *)fragment;
		portion_id = le32_to_cpu(phdr->portion_id);
	} else {
		SSDFS_ERR("corrupted maptbl's page\n");
		return -ERANGE;
	}

	if (portion_id >= tbl->fragments_count) {
		SSDFS_ERR("portion_id %u >= tbl->fragments_count %u\n",
			  portion_id, tbl->fragments_count);
		return -ERANGE;
	}

	*seg_index = portion_id / tbl->fragments_per_seg;

	fragment_offset = portion_id % tbl->fragments_per_seg;
	fragment_offset *= tbl->fragment_bytes;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(div_u64(fragment_offset, PAGE_SIZE) >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	item_index = (u16)div_u64(fragment_offset, PAGE_SIZE);
	item_index += area_start;

	if (tbl->fsi->pagesize < PAGE_SIZE) {
		u32 pages_per_item;
		u32 items_count = pages_count;

		pages_per_item = PAGE_SIZE + pagesize - 1;
		pages_per_item /= pagesize;
		req->place.start.blk_index = item_index * pages_per_item;
		req->place.len = items_count * pages_per_item;
	} else if (tbl->fsi->pagesize > PAGE_SIZE) {
		u32 items_per_page;
		u32 items_count = pages_count;

		items_per_page = pagesize + PAGE_SIZE - 1;
		items_per_page /= PAGE_SIZE;
		req->place.start.blk_index = item_index / items_per_page;
		req->place.len = items_count + items_per_page - 1;
		req->place.len /= items_per_page;
	} else {
		req->place.start.blk_index = item_index;
		req->place.len = pages_count;
	}

	return 0;
}

/*
 * ssdfs_maptbl_set_fragment_checksum() - calculate checksum of dirty fragment
 * @pvec: pagevec with dirty pages
 *
 * This method tries to calculate checksum of dirty fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_set_fragment_checksum(struct pagevec *pvec)
{
	struct ssdfs_leb_table_fragment_header *lhdr;
	struct ssdfs_peb_table_fragment_header *phdr;
	struct page *page;
	void *kaddr;
	__le16 *magic;
	u32 bytes_count;
	unsigned count;
	unsigned i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec);
#endif /* CONFIG_SSDFS_DEBUG */

	count = pagevec_count(pvec);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pvec %p, pages_count %u\n",
		  pvec, count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (count == 0) {
		SSDFS_WARN("empty pagevec\n");
		return -ERANGE;
	}

	for (i = 0; i < count; i++) {
		page = pvec->pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		kaddr = kmap_local_page(page);
		magic = (__le16 *)kaddr;
		if (le16_to_cpu(*magic) == SSDFS_LEB_TABLE_MAGIC) {
			lhdr = (struct ssdfs_leb_table_fragment_header *)kaddr;
			bytes_count = le32_to_cpu(lhdr->bytes_count);
			lhdr->checksum = 0;
			lhdr->checksum = ssdfs_crc32_le(kaddr, bytes_count);
		} else if (le16_to_cpu(*magic) == SSDFS_PEB_TABLE_MAGIC) {
			phdr = (struct ssdfs_peb_table_fragment_header *)kaddr;
			bytes_count = le32_to_cpu(phdr->bytes_count);
			phdr->checksum = 0;
			phdr->checksum = ssdfs_crc32_le(kaddr, bytes_count);
		} else {
			err = -ERANGE;
			SSDFS_ERR("corrupted maptbl's page: index %d\n",
				  i);
		}
		flush_dcache_page(page);
		kunmap_local(kaddr);

		if (unlikely(err))
			return err;
	}

	return 0;
}

/*
 * ssdfs_realloc_flush_reqs_array() - check necessity to realloc reqs array
 * @fdesc: pointer on fragment descriptor
 *
 * This method checks the necessity to realloc the flush
 * requests array. Finally, it tries to realloc the memory
 * for the flush requests array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
static inline
int ssdfs_realloc_flush_reqs_array(struct ssdfs_maptbl_fragment_desc *fdesc)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);
	BUG_ON(!rwsem_is_locked(&fdesc->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	if (fdesc->flush_req_count > fdesc->flush_seq_size) {
		SSDFS_ERR("request_index %u > flush_seq_size %u\n",
			  fdesc->flush_req_count, fdesc->flush_seq_size);
		return -ERANGE;
	} else if (fdesc->flush_req_count == fdesc->flush_seq_size) {
		size_t seg_req_size = sizeof(struct ssdfs_segment_request);

		fdesc->flush_seq_size *= 2;

		fdesc->flush_req1 = krealloc(fdesc->flush_req1,
					fdesc->flush_seq_size * seg_req_size,
					GFP_KERNEL | __GFP_ZERO);
		if (!fdesc->flush_req1) {
			SSDFS_ERR("fail to reallocate buffer\n");
			return -ENOMEM;
		}

		fdesc->flush_req2 = krealloc(fdesc->flush_req2,
					fdesc->flush_seq_size * seg_req_size,
					GFP_KERNEL | __GFP_ZERO);
		if (!fdesc->flush_req2) {
			SSDFS_ERR("fail to reallocate buffer\n");
			return -ENOMEM;
		}
	}

	return 0;
}

/*
 * ssdfs_maptbl_update_fragment() - update dirty fragment
 * @tbl: mapping table object
 * @fragment_index: index of fragment in the array
 *
 * This method tries to update dirty fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_maptbl_update_fragment(struct ssdfs_peb_mapping_table *tbl,
				 u32 fragment_index)
{
	struct ssdfs_maptbl_fragment_desc *fdesc;
	struct ssdfs_segment_request *req1 = NULL, *req2 = NULL;
	struct ssdfs_segment_info *si;
	int state;
	struct pagevec pvec;
	bool has_backup;
	pgoff_t page_index, end, range_len;
	int i, j;
	pgoff_t area_start;
	unsigned area_size;
	u64 ino = SSDFS_MAPTBL_INO;
	u64 offset;
	u32 size;
	u16 seg_index;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));
	BUG_ON(fragment_index >= tbl->fragments_count);

	SSDFS_DBG("maptbl %p, fragment_index %u\n",
		  tbl, fragment_index);
#endif /* CONFIG_SSDFS_DEBUG */

	fdesc = &tbl->desc_array[fragment_index];
	has_backup = atomic_read(&tbl->flags) & SSDFS_MAPTBL_HAS_COPY;

	state = atomic_read(&fdesc->state);
	if (state != SSDFS_MAPTBL_FRAG_DIRTY) {
		SSDFS_ERR("fragment %u hasn't dirty state: state %#x\n",
			  fragment_index, state);
		return -ERANGE;
	}

	page_index = 0;
	range_len = min_t(pgoff_t,
			  (pgoff_t)PAGEVEC_SIZE,
			  (pgoff_t)(tbl->fragment_pages - page_index));
	end = page_index + range_len - 1;

	down_write(&fdesc->lock);

	fdesc->flush_req_count = 0;

retrive_dirty_pages:
	pagevec_init(&pvec);

	err = ssdfs_page_array_lookup_range(&fdesc->array,
					    &page_index, end,
					    SSDFS_DIRTY_PAGE_TAG,
					    tbl->fragment_pages,
					    &pvec);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find dirty pages: "
			  "fragment_index %u, start %lu, "
			  "end %lu, err %d\n",
			  fragment_index, page_index, end, err);
		goto finish_fragment_update;
	}

	if (pagevec_count(&pvec) == 0) {
		page_index += range_len;

		if (page_index >= tbl->fragment_pages)
			goto finish_fragment_update;

		range_len = min_t(pgoff_t,
			  (pgoff_t)PAGEVEC_SIZE,
			  (pgoff_t)(tbl->fragment_pages - page_index));
		end = page_index + range_len - 1;
		goto retrive_dirty_pages;
	}

	err = ssdfs_page_array_clear_dirty_range(&fdesc->array,
						 page_index, end);
	if (unlikely(err)) {
		SSDFS_ERR("fail to clear dirty range: "
			  "start %lu, end %lu, err %d\n",
			  page_index, end, err);
		goto finish_fragment_update;
	}

	err = ssdfs_maptbl_set_fragment_checksum(&pvec);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set fragment checksum: "
			  "fragment_index %u, err %d\n",
			  fragment_index, err);
		goto finish_fragment_update;
	}

	i = 0;

define_update_area:
	area_start = pvec.pages[i]->index;
	area_size = 0;
	for (; i < pagevec_count(&pvec); i++) {
		if ((area_start + area_size) != pvec.pages[i]->index)
			break;
		else
			area_size++;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("fragment_index %u, area_start %lu, area_size %u\n",
		  fragment_index, area_start, area_size);

	BUG_ON(area_size == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_realloc_flush_reqs_array(fdesc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to realloc the reqs array\n");
		goto finish_fragment_update;
	}

	req1 = &fdesc->flush_req1[fdesc->flush_req_count];
	req2 = &fdesc->flush_req2[fdesc->flush_req_count];
	fdesc->flush_req_count++;

	ssdfs_request_init(req1);
	ssdfs_get_request(req1);
	if (has_backup) {
		ssdfs_request_init(req2);
		ssdfs_get_request(req2);
	}

	for (j = 0; j < area_size; j++) {
		err = ssdfs_request_add_allocated_page_locked(req1);
		if (!err && has_backup)
			err = ssdfs_request_add_allocated_page_locked(req2);
		if (unlikely(err)) {
			SSDFS_ERR("fail allocate memory page: err %d\n", err);
			goto fail_issue_fragment_updates;
		}

		err = ssdfs_maptbl_copy_dirty_page(tbl, &pvec,
						   (i - area_size) + j,
						   j, req1);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy dirty page: "
				  "spage_index %d, dpage_index %d, err %d\n",
				  (i - area_size) + j, j, err);
			goto fail_issue_fragment_updates;
		}

		if (has_backup)
			ssdfs_maptbl_replicate_dirty_page(req1, j, req2);
	}

	offset = area_start * PAGE_SIZE;
	offset += fragment_index * tbl->fragment_bytes;
	size = area_size * PAGE_SIZE;

	ssdfs_request_prepare_logical_extent(ino, offset, size, 0, 0, req1);
	if (has_backup) {
		ssdfs_request_prepare_logical_extent(ino, offset, size,
						     0, 0, req2);
	}

	err = ssdfs_check_portion_id(&req1->result.pvec);
	if (unlikely(err)) {
		SSDFS_ERR("corrupted maptbl's page was found: "
			  "err %d\n", err);
		goto fail_issue_fragment_updates;
	}

	kaddr = kmap_local_page(req1->result.pvec.pages[0]);
	err = ssdfs_maptbl_define_volume_extent(tbl, req1, kaddr,
						area_start, area_size,
						&seg_index);
	kunmap_local(kaddr);

	if (unlikely(err)) {
		SSDFS_ERR("fail to define volume extent: "
			  "err %d\n",
			  err);
		goto fail_issue_fragment_updates;
	}

	if (has_backup) {
		ssdfs_memcpy(&req2->place,
			     0, sizeof(struct ssdfs_volume_extent),
			     &req1->place,
			     0, sizeof(struct ssdfs_volume_extent),
			     sizeof(struct ssdfs_volume_extent));
	}

	si = tbl->segs[SSDFS_MAIN_MAPTBL_SEG][seg_index];
	err = ssdfs_segment_update_extent_async(si,
						SSDFS_REQ_ASYNC_NO_FREE,
						req1);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("update extent async: seg %llu\n", si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!err && has_backup) {
		if (!tbl->segs[SSDFS_COPY_MAPTBL_SEG]) {
			err = -ERANGE;
			SSDFS_ERR("copy of maptbl doesn't exist\n");
			goto fail_issue_fragment_updates;
		}

		si = tbl->segs[SSDFS_COPY_MAPTBL_SEG][seg_index];
		err = ssdfs_segment_update_extent_async(si,
						SSDFS_REQ_ASYNC_NO_FREE,
						req2);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to update extent: "
			  "seg_index %u, err %d\n",
			  seg_index, err);
		goto fail_issue_fragment_updates;
	}

	if (err) {
fail_issue_fragment_updates:
		ssdfs_request_unlock_and_remove_pages(req1);
		ssdfs_put_request(req1);
		if (has_backup) {
			ssdfs_request_unlock_and_remove_pages(req2);
			ssdfs_put_request(req2);
		}
		goto finish_fragment_update;
	}

	if (i < pagevec_count(&pvec))
		goto define_update_area;

	for (j = 0; j < pagevec_count(&pvec); j++) {
		ssdfs_put_page(pvec.pages[j]);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  pvec.pages[j],
			  page_ref_count(pvec.pages[j]));
#endif /* CONFIG_SSDFS_DEBUG */
	}

	page_index += range_len;

	if (page_index < tbl->fragment_pages) {
		range_len = min_t(pgoff_t,
			  (pgoff_t)PAGEVEC_SIZE,
			  (pgoff_t)(tbl->fragment_pages - page_index));
		end = page_index + range_len - 1;
		pagevec_reinit(&pvec);
		goto retrive_dirty_pages;
	}

finish_fragment_update:
	if (!err) {
		state = atomic_cmpxchg(&fdesc->state,
					SSDFS_MAPTBL_FRAG_DIRTY,
					SSDFS_MAPTBL_FRAG_TOWRITE);
		if (state != SSDFS_MAPTBL_FRAG_DIRTY) {
			err = -ERANGE;
			SSDFS_ERR("invalid fragment state %#x\n", state);
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment_index %u, state %#x\n",
			  fragment_index,
			  atomic_read(&fdesc->state));
#endif /* CONFIG_SSDFS_DEBUG */
	} else {
		for (j = 0; j < pagevec_count(&pvec); j++) {
			ssdfs_put_page(pvec.pages[j]);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  pvec.pages[j],
				  page_ref_count(pvec.pages[j]));
#endif /* CONFIG_SSDFS_DEBUG */
		}
	}

	up_write(&fdesc->lock);

	pagevec_reinit(&pvec);
	return err;
}

/*
 * ssdfs_maptbl_issue_fragments_update() - issue update of fragments
 * @tbl: mapping table object
 * @start_fragment: index of start fragment in the dirty bmap
 * @dirty_bmap: bmap of dirty fragments
 *
 * This method tries to find the dirty fragments in @dirty_bmap.
 * It updates the state of every found dirty fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA     - @dirty_bmap doesn't contain the dirty fragments.
 */
static
int ssdfs_maptbl_issue_fragments_update(struct ssdfs_peb_mapping_table *tbl,
					u32 start_fragment,
					unsigned long dirty_bmap)
{
	bool is_bit_found;
	int i = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));

	SSDFS_DBG("maptbl %p, start_fragment %u, dirty_bmap %#lx\n",
		  tbl, start_fragment, dirty_bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	if (dirty_bmap == 0) {
		SSDFS_DBG("bmap doesn't contain dirty bits\n");
		return -ENODATA;
	}

	for (i = 0; i < BITS_PER_LONG; i++) {
		is_bit_found = test_bit(i, &dirty_bmap);

		if (!is_bit_found)
			continue;

		err = ssdfs_maptbl_update_fragment(tbl, start_fragment + i);
		if (unlikely(err)) {
			SSDFS_ERR("fail to update fragment: "
				  "fragment_index %u, err %d\n",
				  start_fragment + i, err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_maptbl_flush_dirty_fragments() - find and flush dirty fragments
 * @tbl: mapping table object
 *
 * This method tries to find and to flush all dirty fragments.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_flush_dirty_fragments(struct ssdfs_peb_mapping_table *tbl)
{
	unsigned long *bmap;
	int size;
	unsigned long *found;
	u32 start_fragment;
#ifdef CONFIG_SSDFS_DEBUG
	size_t bytes_count;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));

	SSDFS_DBG("maptbl %p\n", tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_debug_maptbl_object(tbl);

	mutex_lock(&tbl->bmap_lock);

	bmap = tbl->dirty_bmap;

#ifdef CONFIG_SSDFS_DEBUG
	bytes_count = tbl->fragments_count + BITS_PER_LONG - 1;
	bytes_count /= BITS_PER_BYTE;
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				tbl->dirty_bmap, bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	size = tbl->fragments_count;
	err = ssdfs_find_first_dirty_fragment(bmap, size, &found);
	if (err == -ENODATA) {
		SSDFS_DBG("maptbl hasn't dirty fragments\n");
		goto finish_flush_dirty_fragments;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find dirty fragments: "
			  "err %d\n",
			  err);
		goto finish_flush_dirty_fragments;
	} else if (!found) {
		err = -ERANGE;
		SSDFS_ERR("invalid bitmap pointer\n");
		goto finish_flush_dirty_fragments;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("bmap %p, found %p\n", bmap, found);

	BUG_ON(((found - bmap) * BITS_PER_LONG) >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	start_fragment = (u32)((found - bmap) * BITS_PER_LONG);

	err = ssdfs_maptbl_issue_fragments_update(tbl, start_fragment,
						  *found);
	if (unlikely(err)) {
		SSDFS_ERR("fail to issue fragments update: "
			  "start_fragment %u, found %#lx, err %d\n",
			  start_fragment, *found, err);
		goto finish_flush_dirty_fragments;
	}

	err = ssdfs_clear_dirty_state(found);
	if (unlikely(err)) {
		SSDFS_ERR("fail to clear dirty state: "
			  "err %d\n",
			  err);
		goto finish_flush_dirty_fragments;
	}

	if ((start_fragment + BITS_PER_LONG) >= tbl->fragments_count)
		goto finish_flush_dirty_fragments;

	size = tbl->fragments_count - (start_fragment + BITS_PER_LONG);
	while (size > 0) {
		err = ssdfs_find_first_dirty_fragment(++found, size, &found);
		if (err == -ENODATA) {
			err = 0;
			goto finish_flush_dirty_fragments;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find dirty fragments: "
				  "err %d\n",
				  err);
			goto finish_flush_dirty_fragments;
		} else if (!found) {
			err = -ERANGE;
			SSDFS_ERR("invalid bitmap pointer\n");
			goto finish_flush_dirty_fragments;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(((found - bmap) * BITS_PER_LONG) >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		start_fragment = (u32)((found - bmap) * BITS_PER_LONG);

		err = ssdfs_maptbl_issue_fragments_update(tbl, start_fragment,
							  *found);
		if (unlikely(err)) {
			SSDFS_ERR("fail to issue fragments update: "
				  "start_fragment %u, found %#lx, err %d\n",
				  start_fragment, *found, err);
			goto finish_flush_dirty_fragments;
		}

		err = ssdfs_clear_dirty_state(found);
		if (unlikely(err)) {
			SSDFS_ERR("fail to clear dirty state: "
				  "err %d\n",
				  err);
			goto finish_flush_dirty_fragments;
		}

		size = tbl->fragments_count - (start_fragment + BITS_PER_LONG);
	}

finish_flush_dirty_fragments:
	mutex_unlock(&tbl->bmap_lock);
	return err;
}

/*
 * ssdfs_maptbl_check_request() - check request
 * @fdesc: pointer on fragment descriptor
 * @req: segment request
 *
 * This method tries to check the state of request.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_check_request(struct ssdfs_maptbl_fragment_desc *fdesc,
				struct ssdfs_segment_request *req)
{
	wait_queue_head_t *wq = NULL;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc || !req);
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	SSDFS_DBG("fdesc %p, req %p\n", fdesc, req);
#endif /* CONFIG_SSDFS_DEBUG */

check_req_state:
	switch (atomic_read(&req->result.state)) {
	case SSDFS_REQ_CREATED:
	case SSDFS_REQ_STARTED:
		wq = &req->private.wait_queue;

		up_write(&fdesc->lock);
		err = wait_event_killable_timeout(*wq,
					has_request_been_executed(req),
					SSDFS_DEFAULT_TIMEOUT);
		down_write(&fdesc->lock);

		if (err < 0)
			WARN_ON(err < 0);
		else
			err = 0;

		goto check_req_state;
		break;

	case SSDFS_REQ_FINISHED:
		/* do nothing */
		break;

	case SSDFS_REQ_FAILED:
		err = req->result.err;

		if (!err) {
			SSDFS_ERR("error code is absent: "
				  "req %p, err %d\n",
				  req, err);
			err = -ERANGE;
		}

		SSDFS_ERR("flush request is failed: "
			  "err %d\n", err);
		return err;

	default:
		SSDFS_ERR("invalid result's state %#x\n",
		    atomic_read(&req->result.state));
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_maptbl_wait_flush_end() - wait flush ending
 * @tbl: mapping table object
 *
 * This method is waiting the end of flush operation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_wait_flush_end(struct ssdfs_peb_mapping_table *tbl)
{
	struct ssdfs_maptbl_fragment_desc *fdesc;
	struct ssdfs_segment_request *req1 = NULL, *req2 = NULL;
	bool has_backup;
	u32 fragments_count;
	u32 i, j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));

	SSDFS_DBG("maptbl %p\n", tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	fragments_count = tbl->fragments_count;
	has_backup = atomic_read(&tbl->flags) & SSDFS_MAPTBL_HAS_COPY;

	for (i = 0; i < fragments_count; i++) {
		fdesc = &tbl->desc_array[i];

		down_write(&fdesc->lock);

		switch (atomic_read(&fdesc->state)) {
		case SSDFS_MAPTBL_FRAG_DIRTY:
			err = -ERANGE;
			SSDFS_ERR("found unprocessed dirty fragment: "
				  "index %d\n", i);
			goto finish_fragment_processing;

		case SSDFS_MAPTBL_FRAG_TOWRITE:
			for (j = 0; j < fdesc->flush_req_count; j++) {
				req1 = &fdesc->flush_req1[j];
				req2 = &fdesc->flush_req2[j];

				err = ssdfs_maptbl_check_request(fdesc, req1);
				if (unlikely(err)) {
					SSDFS_ERR("flush request failed: "
						  "err %d\n", err);
					goto finish_fragment_processing;
				}

				if (!has_backup)
					continue;

				err = ssdfs_maptbl_check_request(fdesc, req2);
				if (unlikely(err)) {
					SSDFS_ERR("flush request failed: "
						  "err %d\n", err);
					goto finish_fragment_processing;
				}
			}
			break;

		default:
			/* do nothing */
			break;
		}

finish_fragment_processing:
		up_write(&fdesc->lock);

		if (unlikely(err))
			return err;
	}

	return 0;
}

/*
 * __ssdfs_maptbl_commit_logs() - issue commit log requests
 * @tbl: mapping table object
 * @fdesc: pointer on fragment descriptor
 * @fragment_index: index of fragment in the array
 *
 * This method tries to issue the commit log requests.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_maptbl_commit_logs(struct ssdfs_peb_mapping_table *tbl,
				struct ssdfs_maptbl_fragment_desc *fdesc,
				u32 fragment_index)
{
	struct ssdfs_segment_request *req1 = NULL, *req2 = NULL;
	struct ssdfs_segment_info *si;
	u64 ino = SSDFS_MAPTBL_INO;
	int state;
	bool has_backup;
	pgoff_t area_start;
	pgoff_t area_size, processed_pages;
	u64 offset;
	u16 seg_index;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !fdesc);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	SSDFS_DBG("maptbl %p, fragment_index %u\n",
		  tbl, fragment_index);
#endif /* CONFIG_SSDFS_DEBUG */

	has_backup = atomic_read(&tbl->flags) & SSDFS_MAPTBL_HAS_COPY;

	state = atomic_read(&fdesc->state);
	if (state != SSDFS_MAPTBL_FRAG_TOWRITE) {
		SSDFS_ERR("fragment isn't under flush: state %#x\n",
			  state);
		return -ERANGE;
	}

	area_start = 0;
	area_size = min_t(pgoff_t,
			  (pgoff_t)PAGEVEC_SIZE,
			  (pgoff_t)tbl->fragment_pages);
	processed_pages = 0;

	fdesc->flush_req_count = 0;

	do {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(area_size == 0);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_realloc_flush_reqs_array(fdesc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to realloc the reqs array\n");
			goto finish_issue_commit_request;
		}

		req1 = &fdesc->flush_req1[fdesc->flush_req_count];
		req2 = &fdesc->flush_req2[fdesc->flush_req_count];
		fdesc->flush_req_count++;

		ssdfs_request_init(req1);
		ssdfs_get_request(req1);
		if (has_backup) {
			ssdfs_request_init(req2);
			ssdfs_get_request(req2);
		}

		offset = area_start * PAGE_SIZE;
		offset += fragment_index * tbl->fragment_bytes;

		ssdfs_request_prepare_logical_extent(ino, offset,
						     0, 0, 0, req1);
		if (has_backup) {
			ssdfs_request_prepare_logical_extent(ino,
							     offset,
							     0, 0, 0,
							     req2);
		}

		page = ssdfs_page_array_get_page_locked(&fdesc->array,
							area_start);
		if (IS_ERR_OR_NULL(page)) {
			err = page == NULL ? -ERANGE : PTR_ERR(page);
			SSDFS_ERR("fail to get page: "
				  "index %lu, err %d\n",
				  area_start, err);
			goto finish_issue_commit_request;
		}

		kaddr = kmap_local_page(page);
		err = ssdfs_maptbl_define_volume_extent(tbl, req1, kaddr,
							area_start, area_size,
							&seg_index);
		kunmap_local(kaddr);

		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

		if (unlikely(err)) {
			SSDFS_ERR("fail to define volume extent: "
				  "err %d\n",
				  err);
			goto finish_issue_commit_request;
		}

		if (has_backup) {
			ssdfs_memcpy(&req2->place,
				     0, sizeof(struct ssdfs_volume_extent),
				     &req1->place,
				     0, sizeof(struct ssdfs_volume_extent),
				     sizeof(struct ssdfs_volume_extent));
		}

		si = tbl->segs[SSDFS_MAIN_MAPTBL_SEG][seg_index];
		err = ssdfs_segment_commit_log_async(si,
						SSDFS_REQ_ASYNC_NO_FREE,
						req1);

		if (!err && has_backup) {
			if (!tbl->segs[SSDFS_COPY_MAPTBL_SEG]) {
				err = -ERANGE;
				SSDFS_ERR("copy of maptbl doesn't exist\n");
				goto finish_issue_commit_request;
			}

			si = tbl->segs[SSDFS_COPY_MAPTBL_SEG][seg_index];
			err = ssdfs_segment_commit_log_async(si,
						SSDFS_REQ_ASYNC_NO_FREE,
						req2);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to update extent: "
				  "seg_index %u, err %d\n",
				  seg_index, err);
			goto finish_issue_commit_request;
		}

		area_start += area_size;
		processed_pages += area_size;
		area_size = min_t(pgoff_t,
				  (pgoff_t)PAGEVEC_SIZE,
				  (pgoff_t)(tbl->fragment_pages -
					    processed_pages));
	} while (processed_pages < tbl->fragment_pages);

finish_issue_commit_request:
	if (err) {
		ssdfs_put_request(req1);
		if (has_backup)
			ssdfs_put_request(req2);
	}

	return err;
}

/*
 * ssdfs_maptbl_commit_logs() - issue commit log requests
 * @tbl: mapping table object
 *
 * This method tries to issue the commit log requests.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_commit_logs(struct ssdfs_peb_mapping_table *tbl)
{
	struct ssdfs_maptbl_fragment_desc *fdesc;
	u32 fragments_count;
	bool has_backup;
	u32 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));

	SSDFS_DBG("maptbl %p\n", tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	fragments_count = tbl->fragments_count;
	has_backup = atomic_read(&tbl->flags) & SSDFS_MAPTBL_HAS_COPY;

	for (i = 0; i < fragments_count; i++) {
		fdesc = &tbl->desc_array[i];

		down_write(&fdesc->lock);

		switch (atomic_read(&fdesc->state)) {
		case SSDFS_MAPTBL_FRAG_DIRTY:
			err = -ERANGE;
			SSDFS_ERR("found unprocessed dirty fragment: "
				  "index %d\n", i);
			goto finish_fragment_processing;

		case SSDFS_MAPTBL_FRAG_TOWRITE:
			err = __ssdfs_maptbl_commit_logs(tbl, fdesc, i);
			if (unlikely(err)) {
				SSDFS_ERR("fail to commit logs: "
					  "fragment_index %u, err %d\n",
					  i, err);
				goto finish_fragment_processing;
			}
			break;

		default:
			/* do nothing */
			break;
		}

finish_fragment_processing:
		up_write(&fdesc->lock);

		if (unlikely(err))
			return err;
	}

	return 0;
}

/*
 * ssdfs_maptbl_wait_commit_logs_end() - wait commit logs ending
 * @tbl: mapping table object
 *
 * This method is waiting the end of commit logs operation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_wait_commit_logs_end(struct ssdfs_peb_mapping_table *tbl)
{
	struct ssdfs_maptbl_fragment_desc *fdesc;
	struct ssdfs_segment_request *req1 = NULL, *req2 = NULL;
	bool has_backup;
	u32 fragments_count;
	int state;
	u32 i, j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));

	SSDFS_DBG("maptbl %p\n", tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	fragments_count = tbl->fragments_count;
	has_backup = atomic_read(&tbl->flags) & SSDFS_MAPTBL_HAS_COPY;

	for (i = 0; i < fragments_count; i++) {
		fdesc = &tbl->desc_array[i];

		down_write(&fdesc->lock);

		switch (atomic_read(&fdesc->state)) {
		case SSDFS_MAPTBL_FRAG_DIRTY:
			err = -ERANGE;
			SSDFS_ERR("found unprocessed dirty fragment: "
				  "index %d\n", i);
			goto finish_fragment_processing;

		case SSDFS_MAPTBL_FRAG_TOWRITE:
			for (j = 0; j < fdesc->flush_req_count; j++) {
				req1 = &fdesc->flush_req1[j];
				req2 = &fdesc->flush_req2[j];

				err = ssdfs_maptbl_check_request(fdesc, req1);
				if (unlikely(err)) {
					SSDFS_ERR("flush request failed: "
						  "err %d\n", err);
					goto finish_fragment_processing;
				}

				if (!has_backup)
					continue;

				err = ssdfs_maptbl_check_request(fdesc, req2);
				if (unlikely(err)) {
					SSDFS_ERR("flush request failed: "
						  "err %d\n", err);
					goto finish_fragment_processing;
				}
			}

			state = atomic_cmpxchg(&fdesc->state,
						SSDFS_MAPTBL_FRAG_TOWRITE,
						SSDFS_MAPTBL_FRAG_INITIALIZED);
			if (state != SSDFS_MAPTBL_FRAG_TOWRITE) {
				err = -ERANGE;
				SSDFS_ERR("invalid fragment state %#x\n",
					  state);
				goto finish_fragment_processing;;
			}

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fragment_index %u, state %#x\n",
				  i,
				  atomic_read(&fdesc->state));
#endif /* CONFIG_SSDFS_DEBUG */
			break;

		default:
			/* do nothing */
			break;
		}

finish_fragment_processing:
		up_write(&fdesc->lock);

		if (unlikely(err))
			return err;
	}

	return 0;
}

/*
 * __ssdfs_maptbl_prepare_migration() - issue prepare migration requests
 * @tbl: mapping table object
 * @fdesc: pointer on fragment descriptor
 * @fragment_index: index of fragment in the array
 *
 * This method tries to issue prepare migration requests.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_maptbl_prepare_migration(struct ssdfs_peb_mapping_table *tbl,
				     struct ssdfs_maptbl_fragment_desc *fdesc,
				     u32 fragment_index)
{
	struct ssdfs_segment_request *req1 = NULL, *req2 = NULL;
	struct ssdfs_segment_info *si;
	u64 ino = SSDFS_MAPTBL_INO;
	bool has_backup;
	pgoff_t area_start;
	pgoff_t area_size, processed_pages;
	u64 offset;
	u16 seg_index;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !fdesc);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	SSDFS_DBG("maptbl %p, fragment_index %u\n",
		  tbl, fragment_index);
#endif /* CONFIG_SSDFS_DEBUG */

	has_backup = atomic_read(&tbl->flags) & SSDFS_MAPTBL_HAS_COPY;

	area_start = 0;
	area_size = min_t(pgoff_t,
			  (pgoff_t)PAGEVEC_SIZE,
			  (pgoff_t)tbl->fragment_pages);
	processed_pages = 0;

	fdesc->flush_req_count = 0;

	do {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(area_size == 0);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_realloc_flush_reqs_array(fdesc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to realloc the reqs array\n");
			goto finish_issue_prepare_migration_request;
		}

		req1 = &fdesc->flush_req1[fdesc->flush_req_count];
		req2 = &fdesc->flush_req2[fdesc->flush_req_count];
		fdesc->flush_req_count++;

		ssdfs_request_init(req1);
		ssdfs_get_request(req1);
		if (has_backup) {
			ssdfs_request_init(req2);
			ssdfs_get_request(req2);
		}

		offset = area_start * PAGE_SIZE;
		offset += fragment_index * tbl->fragment_bytes;

		ssdfs_request_prepare_logical_extent(ino, offset,
						     0, 0, 0, req1);
		if (has_backup) {
			ssdfs_request_prepare_logical_extent(ino,
							     offset,
							     0, 0, 0,
							     req2);
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("area_start %lu, area_size %lu, "
			  "processed_pages %lu, tbl->fragment_pages %u\n",
			  area_start, area_size, processed_pages,
			  tbl->fragment_pages);
#endif /* CONFIG_SSDFS_DEBUG */

		page = ssdfs_page_array_get_page_locked(&fdesc->array,
							area_start);
		if (IS_ERR_OR_NULL(page)) {
			err = page == NULL ? -ERANGE : PTR_ERR(page);
			SSDFS_ERR("fail to get page: "
				  "index %lu, err %d\n",
				  area_start, err);
			goto finish_issue_prepare_migration_request;
		}

		kaddr = kmap_local_page(page);
		err = ssdfs_maptbl_define_volume_extent(tbl, req1, kaddr,
							area_start, area_size,
							&seg_index);
		kunmap_local(kaddr);

		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

		if (unlikely(err)) {
			SSDFS_ERR("fail to define volume extent: "
				  "err %d\n",
				  err);
			goto finish_issue_prepare_migration_request;
		}

		if (has_backup) {
			ssdfs_memcpy(&req2->place,
				     0, sizeof(struct ssdfs_volume_extent),
				     &req1->place,
				     0, sizeof(struct ssdfs_volume_extent),
				     sizeof(struct ssdfs_volume_extent));
		}

		si = tbl->segs[SSDFS_MAIN_MAPTBL_SEG][seg_index];

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start migration now: seg %llu\n", si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_segment_prepare_migration_async(si,
						SSDFS_REQ_ASYNC_NO_FREE,
						req1);
		if (!err && has_backup) {
			if (!tbl->segs[SSDFS_COPY_MAPTBL_SEG]) {
				err = -ERANGE;
				SSDFS_ERR("copy of maptbl doesn't exist\n");
				goto finish_issue_prepare_migration_request;
			}

			si = tbl->segs[SSDFS_COPY_MAPTBL_SEG][seg_index];
			err = ssdfs_segment_prepare_migration_async(si,
						SSDFS_REQ_ASYNC_NO_FREE,
						req2);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to update extent: "
				  "seg_index %u, err %d\n",
				  seg_index, err);
			goto finish_issue_prepare_migration_request;
		}

		area_start += area_size;
		processed_pages += area_size;
		area_size = min_t(pgoff_t,
				  (pgoff_t)PAGEVEC_SIZE,
				  (pgoff_t)(tbl->fragment_pages -
					    processed_pages));
	} while (processed_pages < tbl->fragment_pages);

finish_issue_prepare_migration_request:
	if (err) {
		ssdfs_put_request(req1);
		if (has_backup)
			ssdfs_put_request(req2);
	}

	return err;
}

/*
 * ssdfs_maptbl_prepare_migration() - issue prepare migration requests
 * @tbl: mapping table object
 *
 * This method tries to issue prepare migration requests.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_prepare_migration(struct ssdfs_peb_mapping_table *tbl)
{
	struct ssdfs_maptbl_fragment_desc *fdesc;
	u32 fragments_count;
	int state;
	u32 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));

	SSDFS_DBG("maptbl %p\n", tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	fragments_count = tbl->fragments_count;

	for (i = 0; i < fragments_count; i++) {
		fdesc = &tbl->desc_array[i];

		state = atomic_read(&fdesc->state);
		if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
			SSDFS_ERR("fragment is corrupted: index %u\n",
				  i);
			return -EFAULT;
		} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
			struct completion *end = &fdesc->init_end;

			up_read(&tbl->tbl_lock);

			err = SSDFS_WAIT_COMPLETION(end);
			if (unlikely(err)) {
				SSDFS_ERR("maptbl's fragment init failed: "
					  "index %u\n", i);
				return -ERANGE;
			}

			down_read(&tbl->tbl_lock);
		}

		state = atomic_read(&fdesc->state);
		switch (state) {
		case SSDFS_MAPTBL_FRAG_INITIALIZED:
		case SSDFS_MAPTBL_FRAG_DIRTY:
			/* expected state */
			break;

		case SSDFS_MAPTBL_FRAG_CREATED:
		case SSDFS_MAPTBL_FRAG_INIT_FAILED:
			SSDFS_WARN("fragment is not initialized: "
				   "index %u, state %#x\n",
				   i, state);
			return -EFAULT;

		default:
			SSDFS_WARN("unexpected fragment state: "
				   "index %u, state %#x\n",
				   i, atomic_read(&fdesc->state));
			return -ERANGE;
		}

		down_write(&fdesc->lock);
		err = __ssdfs_maptbl_prepare_migration(tbl, fdesc, i);
		up_write(&fdesc->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare migration: "
				  "fragment_index %u, err %d\n",
				  i, err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_maptbl_wait_prepare_migration_end() - wait migration preparation ending
 * @tbl: mapping table object
 *
 * This method is waiting the end of migration preparation operation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_wait_prepare_migration_end(struct ssdfs_peb_mapping_table *tbl)
{
	struct ssdfs_maptbl_fragment_desc *fdesc;
	struct ssdfs_segment_request *req1 = NULL, *req2 = NULL;
	bool has_backup;
	u32 fragments_count;
	u32 i, j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));

	SSDFS_DBG("maptbl %p\n", tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	fragments_count = tbl->fragments_count;
	has_backup = atomic_read(&tbl->flags) & SSDFS_MAPTBL_HAS_COPY;

	for (i = 0; i < fragments_count; i++) {
		fdesc = &tbl->desc_array[i];

		down_write(&fdesc->lock);

		for (j = 0; j < fdesc->flush_req_count; j++) {
			req1 = &fdesc->flush_req1[j];
			req2 = &fdesc->flush_req2[j];

			err = ssdfs_maptbl_check_request(fdesc, req1);
			if (unlikely(err)) {
				SSDFS_ERR("flush request failed: "
					  "err %d\n", err);
				goto finish_fragment_processing;
			}

			if (!has_backup)
				continue;

			err = ssdfs_maptbl_check_request(fdesc, req2);
			if (unlikely(err)) {
				SSDFS_ERR("flush request failed: "
					  "err %d\n", err);
				goto finish_fragment_processing;
			}
		}

finish_fragment_processing:
		up_write(&fdesc->lock);

		if (unlikely(err))
			return err;
	}

	return 0;
}

static
int ssdfs_maptbl_create_checkpoint(struct ssdfs_peb_mapping_table *tbl)
{
#ifdef CONFIG_SSDFS_DEBUG
	/* TODO: implement */
	SSDFS_DBG("TODO: implement %s\n", __func__);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_maptbl_flush() - flush dirty mapping table object
 * @tbl: mapping table object
 *
 * This method tries to flush dirty mapping table object.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - mapping table is corrupted.
 */
int ssdfs_maptbl_flush(struct ssdfs_peb_mapping_table *tbl)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("maptbl %p\n", tbl);
#else
	SSDFS_DBG("maptbl %p\n", tbl);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"maptbl has corrupted state\n");
		return -EFAULT;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("prepare migration\n");
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&tbl->tbl_lock);

	err = ssdfs_maptbl_prepare_migration(tbl);
	if (unlikely(err)) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to prepare migration: err %d\n",
				err);
		goto finish_prepare_migration;
	}

	err = ssdfs_maptbl_wait_prepare_migration_end(tbl);
	if (unlikely(err)) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to prepare migration: err %d\n",
				err);
		goto finish_prepare_migration;
	}

finish_prepare_migration:
	up_read(&tbl->tbl_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finish prepare migration\n");
#endif /* CONFIG_SSDFS_DEBUG */

	if (unlikely(err))
		return err;

	/*
	 * This flag should be not included into the header.
	 * The flag is used only during flush operation.
	 * The inclusion of the flag in the on-disk layout's
	 * state means the volume corruption.
	 */
	atomic_or(SSDFS_MAPTBL_UNDER_FLUSH, &tbl->flags);

	down_write(&tbl->tbl_lock);

	ssdfs_sb_maptbl_header_correct_state(tbl);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("flush dirty fragments\n");
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_maptbl_flush_dirty_fragments(tbl);
	if (err == -ENODATA) {
		err = 0;
		up_write(&tbl->tbl_lock);
		SSDFS_DBG("maptbl hasn't dirty fragments\n");
		goto finish_maptbl_flush;
	} else if (unlikely(err)) {
		up_write(&tbl->tbl_lock);
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to flush maptbl: err %d\n",
				err);
		goto finish_maptbl_flush;
	}

	err = ssdfs_maptbl_wait_flush_end(tbl);
	if (unlikely(err)) {
		up_write(&tbl->tbl_lock);
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to flush maptbl: err %d\n",
				err);
		goto finish_maptbl_flush;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finish flush dirty fragments\n");

	SSDFS_DBG("commit logs\n");
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_maptbl_commit_logs(tbl);
	if (unlikely(err)) {
		up_write(&tbl->tbl_lock);
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to flush maptbl: err %d\n",
				err);
		goto finish_maptbl_flush;
	}

	err = ssdfs_maptbl_wait_commit_logs_end(tbl);
	if (unlikely(err)) {
		up_write(&tbl->tbl_lock);
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to flush maptbl: err %d\n",
				err);
		goto finish_maptbl_flush;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finish commit logs\n");
#endif /* CONFIG_SSDFS_DEBUG */

	downgrade_write(&tbl->tbl_lock);

	err = ssdfs_maptbl_create_checkpoint(tbl);
	if (unlikely(err)) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to create maptbl's checkpoint: "
				"err %d\n",
				err);
	}

	up_read(&tbl->tbl_lock);

finish_maptbl_flush:
	atomic_and(~SSDFS_MAPTBL_UNDER_FLUSH, &tbl->flags);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

int ssdfs_maptbl_resize(struct ssdfs_peb_mapping_table *tbl,
			u64 new_pebs_count)
{
	/* TODO: implement */
	SSDFS_WARN("TODO: implement %s\n", __func__);
	return -ENOSYS;
}

/*
 * ssdfs_maptbl_get_peb_descriptor() - retrieve PEB descriptor
 * @fdesc: fragment descriptor
 * @index: index of PEB descriptor in the PEB table
 * @peb_id: pointer on PEB ID value [out]
 * @peb_desc: pointer on PEB descriptor value [out]
 *
 * This method tries to extract PEB ID and PEB descriptor
 * for the index of PEB descriptor in the PEB table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_get_peb_descriptor(struct ssdfs_maptbl_fragment_desc *fdesc,
				    u16 index, u64 *peb_id,
				    struct ssdfs_peb_descriptor *peb_desc)
{
	struct ssdfs_peb_descriptor *ptr;
	pgoff_t page_index;
	u16 item_index;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc || !peb_id || !peb_desc);
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	SSDFS_DBG("fdesc %p, index %u, peb_id %p, peb_desc %p\n",
		  fdesc, index, peb_id, peb_desc);
#endif /* CONFIG_SSDFS_DEBUG */

	*peb_id = U64_MAX;
	page_index = PEBTBL_PAGE_INDEX(fdesc, index);
	item_index = index % fdesc->pebs_per_page;

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap_local_page(page);

	*peb_id = GET_PEB_ID(kaddr, item_index);
	if (*peb_id == U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("fail to define peb_id: "
			  "page_index %lu, item_index %u\n",
			  page_index, item_index);
		goto finish_page_processing;
	}

	ptr = GET_PEB_DESCRIPTOR(kaddr, item_index);
	if (IS_ERR_OR_NULL(ptr)) {
		err = IS_ERR(ptr) ? PTR_ERR(ptr) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "page_index %lu, item_index %u, err %d\n",
			  page_index, item_index, err);
		goto finish_page_processing;
	}

	ssdfs_memcpy(peb_desc,
		     0, sizeof(struct ssdfs_peb_descriptor),
		     ptr,
		     0, sizeof(struct ssdfs_peb_descriptor),
		     sizeof(struct ssdfs_peb_descriptor));

finish_page_processing:
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * GET_LEB_DESCRIPTOR() - retrieve LEB descriptor
 * @kaddr: pointer on memory page's content
 * @leb_id: LEB ID number
 *
 * This method tries to return the pointer on
 * LEB descriptor for @leb_id.
 *
 * RETURN:
 * [success] - pointer on LEB descriptor
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static inline
struct ssdfs_leb_descriptor *GET_LEB_DESCRIPTOR(void *kaddr, u64 leb_id)
{
	struct ssdfs_leb_table_fragment_header *hdr;
	u64 start_leb;
	u16 lebs_count;
	u64 leb_id_diff;
	u32 leb_desc_off;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);

	SSDFS_DBG("kaddr %p, leb_id %llu\n",
		  kaddr, leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = (struct ssdfs_leb_table_fragment_header *)kaddr;

	if (le16_to_cpu(hdr->magic) != SSDFS_LEB_TABLE_MAGIC) {
		SSDFS_ERR("corrupted page\n");
		return ERR_PTR(-ERANGE);
	}

	start_leb = le64_to_cpu(hdr->start_leb);
	lebs_count = le16_to_cpu(hdr->lebs_count);

	if (leb_id < start_leb ||
	    leb_id >= (start_leb + lebs_count)) {
		SSDFS_ERR("corrupted page: "
			  "leb_id %llu, start_leb %llu, lebs_count %u\n",
			  leb_id, start_leb, lebs_count);
		return ERR_PTR(-ERANGE);
	}

	leb_id_diff = leb_id - start_leb;
	leb_desc_off = SSDFS_LEBTBL_FRAGMENT_HDR_SIZE;
	leb_desc_off += leb_id_diff * sizeof(struct ssdfs_leb_descriptor);

	if (leb_desc_off >= PAGE_SIZE) {
		SSDFS_ERR("invalid offset %u\n", leb_desc_off);
		return ERR_PTR(-ERANGE);
	}

	return (struct ssdfs_leb_descriptor *)((u8 *)kaddr + leb_desc_off);
}

/*
 * LEBTBL_PAGE_INDEX() - define LEB table's page index
 * @fdesc: fragment descriptor
 * @leb_id: LEB identification number
 *
 * RETURN:
 * [success] - page index.
 * [failure] - ULONG_MAX.
 */
static inline
pgoff_t LEBTBL_PAGE_INDEX(struct ssdfs_maptbl_fragment_desc *fdesc,
			  u64 leb_id)
{
	u64 leb_id_diff;
	pgoff_t page_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);

	SSDFS_DBG("fdesc %p, leb_id %llu\n",
		  fdesc, leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (leb_id < fdesc->start_leb ||
	    leb_id >= (fdesc->start_leb + fdesc->lebs_count)) {
		SSDFS_ERR("invalid leb_id: leb_id %llu, "
			  "start_leb %llu, lebs_count %u\n",
			  leb_id, fdesc->start_leb, fdesc->lebs_count);
		return ULONG_MAX;
	}

	leb_id_diff = leb_id - fdesc->start_leb;
	page_index = (pgoff_t)(leb_id_diff / fdesc->lebs_per_page);

	if (page_index >= fdesc->lebtbl_pages) {
		SSDFS_ERR("page_index %lu >= fdesc->lebtbl_pages %u\n",
			  page_index, fdesc->lebtbl_pages);
		return ULONG_MAX;
	}

	return page_index;
}

/*
 * ssdfs_maptbl_get_leb_descriptor() - retrieve LEB descriptor
 * @fdesc: fragment descriptor
 * @leb_id: LEB ID number
 * @leb_desc: pointer on LEB descriptor value [out]
 *
 * This method tries to extract LEB descriptor
 * for the LEB ID number.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_get_leb_descriptor(struct ssdfs_maptbl_fragment_desc *fdesc,
				    u64 leb_id,
				    struct ssdfs_leb_descriptor *leb_desc)
{
	struct ssdfs_leb_descriptor *ptr;
	pgoff_t page_index;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc || !leb_desc);
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	SSDFS_DBG("fdesc %p, leb_id %llu, leb_desc %p\n",
		  fdesc, leb_id, leb_desc);
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = LEBTBL_PAGE_INDEX(fdesc, leb_id);
	if (page_index == ULONG_MAX) {
		SSDFS_ERR("fail to define page_index: "
			  "leb_id %llu\n",
			  leb_id);
		return -ERANGE;
	}

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap_local_page(page);

	ptr = GET_LEB_DESCRIPTOR(kaddr, leb_id);
	if (IS_ERR_OR_NULL(ptr)) {
		err = IS_ERR(ptr) ? PTR_ERR(ptr) : -ERANGE;
		SSDFS_ERR("fail to get leb_descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_page_processing;
	}

	ssdfs_memcpy(leb_desc,
		     0, sizeof(struct ssdfs_leb_descriptor),
		     ptr,
		     0, sizeof(struct ssdfs_leb_descriptor),
		     sizeof(struct ssdfs_leb_descriptor));

finish_page_processing:
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * FRAGMENT_INDEX() - define fragment index
 * @tbl: pointer on mapping table object
 * @leb_id: LEB ID number
 *
 * RETURN:
 * [success] - fragment index.
 * [failure] - U32_MAX.
 */
static inline
u32 FRAGMENT_INDEX(struct ssdfs_peb_mapping_table *tbl, u64 leb_id)
{
	u32 fragment_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));

	SSDFS_DBG("maptbl %p, leb_id %llu\n",
		  tbl, leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (leb_id >= tbl->lebs_count) {
		SSDFS_ERR("leb_id %llu >= tbl->lebs_count %llu\n",
			  leb_id, tbl->lebs_count);
		return U32_MAX;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(div_u64(leb_id, tbl->lebs_per_fragment) >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	fragment_index = (u32)div_u64(leb_id, tbl->lebs_per_fragment);
	if (fragment_index >= tbl->fragments_count) {
		SSDFS_ERR("fragment_index %u >= tbl->fragments_count %u\n",
			  fragment_index, tbl->fragments_count);
		return U32_MAX;
	}

	return fragment_index;
}

/*
 * ssdfs_maptbl_get_fragment_descriptor() - get fragment descriptor
 * @tbl: pointer on mapping table object
 * @leb_id: LEB ID number
 *
 * RETURN:
 * [success] - pointer on fragment descriptor.
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
struct ssdfs_maptbl_fragment_desc *
ssdfs_maptbl_get_fragment_descriptor(struct ssdfs_peb_mapping_table *tbl,
				     u64 leb_id)
{
	u32 fragment_index = FRAGMENT_INDEX(tbl, leb_id);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("leb_id %llu, fragment index %u\n",
		  leb_id, fragment_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (fragment_index == U32_MAX) {
		SSDFS_ERR("invalid fragment_index: leb_id %llu\n",
			  leb_id);
		return ERR_PTR(-ERANGE);
	}

	return &tbl->desc_array[fragment_index];
}

/*
 * ssdfs_maptbl_get_peb_relation() - retrieve PEB relation
 * @fdesc: fragment descriptor
 * @leb_desc: LEB descriptor
 * @pebr: PEB relation [out]
 *
 * This method tries to retrieve PEB relation for @leb_desc.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - unitialized LEB descriptor.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_get_peb_relation(struct ssdfs_maptbl_fragment_desc *fdesc,
				  struct ssdfs_leb_descriptor *leb_desc,
				  struct ssdfs_maptbl_peb_relation *pebr)
{
	u16 physical_index, relation_index;
	u64 peb_id;
	struct ssdfs_peb_descriptor peb_desc;
	struct ssdfs_maptbl_peb_descriptor *ptr;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc || !leb_desc || !pebr);
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	SSDFS_DBG("fdesc %p, leb_desc %p, pebr %p\n",
		  fdesc, leb_desc, pebr);
#endif /* CONFIG_SSDFS_DEBUG */

	physical_index = le16_to_cpu(leb_desc->physical_index);
	relation_index = le16_to_cpu(leb_desc->relation_index);

	if (physical_index == U16_MAX) {
		SSDFS_DBG("unitialized leb descriptor\n");
		return -ENODATA;
	}

	err = ssdfs_maptbl_get_peb_descriptor(fdesc, physical_index,
					      &peb_id, &peb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get peb descriptor: "
			  "physical_index %u, err %d\n",
			  physical_index, err);
		return err;
	}

	ptr = &pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX];

	if (peb_id == U64_MAX) {
		SSDFS_ERR("invalid peb_id\n");
		return -ERANGE;
	}

	ptr->peb_id = peb_id;
	ptr->shared_peb_index = peb_desc.shared_peb_index;
	ptr->erase_cycles = le32_to_cpu(peb_desc.erase_cycles);
	ptr->type = peb_desc.type;
	ptr->state = peb_desc.state;
	ptr->flags = peb_desc.flags;

	if (relation_index == U16_MAX) {
		SSDFS_DBG("relation peb_id is absent\n");
		return 0;
	}

	err = ssdfs_maptbl_get_peb_descriptor(fdesc, relation_index,
					      &peb_id, &peb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get peb descriptor: "
			  "relation_index %u, err %d\n",
			  relation_index, err);
		return err;
	}

	ptr = &pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX];

	if (peb_id == U64_MAX) {
		SSDFS_ERR("invalid peb_id\n");
		return -ERANGE;
	}

	ptr->peb_id = peb_id;
	ptr->erase_cycles = le32_to_cpu(peb_desc.erase_cycles);
	ptr->type = peb_desc.type;
	ptr->state = peb_desc.state;
	ptr->flags = le16_to_cpu(peb_desc.flags);

	return 0;
}

/*
 * should_cache_peb_info() - check that PEB info is cached
 * @peb_type: PEB type
 */
static inline
bool should_cache_peb_info(u8 peb_type)
{
	return peb_type == SSDFS_MAPTBL_SBSEG_PEB_TYPE ||
		peb_type == SSDFS_MAPTBL_SEGBMAP_PEB_TYPE ||
		peb_type == SSDFS_MAPTBL_MAPTBL_PEB_TYPE;
}

/*
 * ssdfs_maptbl_define_pebtbl_page() - define PEB table's page index
 * @tbl: pointer on mapping table object
 * @desc: fragment descriptor
 * @leb_id: LEB ID number
 * @peb_desc_index: PEB descriptor index
 *
 * RETURN:
 * [success] - page index.
 * [failure] - ULONG_MAX.
 */
static
pgoff_t ssdfs_maptbl_define_pebtbl_page(struct ssdfs_peb_mapping_table *tbl,
					struct ssdfs_maptbl_fragment_desc *desc,
					u64 leb_id,
					u16 peb_desc_index)
{
	u64 leb_id_diff;
	u64 stripe_index;
	u64 page_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !desc);

	if (leb_id < desc->start_leb ||
	    leb_id >= (desc->start_leb + desc->lebs_count)) {
		SSDFS_ERR("invalid leb_id: leb_id %llu, "
			  "start_leb %llu, lebs_count %u\n",
			  leb_id, desc->start_leb, desc->lebs_count);
		return ULONG_MAX;
	}

	if (peb_desc_index != U16_MAX) {
		if (peb_desc_index >= tbl->pebs_per_fragment) {
			SSDFS_ERR("peb_desc_index %u >= pebs_per_fragment %u\n",
				  peb_desc_index, tbl->pebs_per_fragment);
			return ULONG_MAX;
		}
	}

	SSDFS_DBG("tbl %p, desc %p, leb_id %llu\n", tbl, desc, leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (peb_desc_index >= U16_MAX) {
		leb_id_diff = leb_id - desc->start_leb;
		stripe_index = div_u64(leb_id_diff, tbl->pebs_per_stripe);
		page_index = leb_id_diff -
				(stripe_index * tbl->pebs_per_stripe);
		page_index = div_u64(page_index, desc->pebs_per_page);
		page_index += stripe_index * desc->stripe_pages;
		page_index += desc->lebtbl_pages;
	} else {
		page_index = PEBTBL_PAGE_INDEX(desc, peb_desc_index);
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(page_index > ULONG_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	return (pgoff_t)page_index;
}

/*
 * is_pebtbl_stripe_recovering() - check that PEB is under recovering
 * @hdr: PEB table fragment's header
 */
static inline
bool is_pebtbl_stripe_recovering(struct ssdfs_peb_table_fragment_header *hdr)
{
	u16 flags;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr);

	SSDFS_DBG("pebtbl_hdr %p\n", hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	flags = hdr->flags;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(flags & ~SSDFS_PEBTBL_FLAGS_MASK);
#endif /* CONFIG_SSDFS_DEBUG */

	return flags & SSDFS_PEBTBL_UNDER_RECOVERING;
}

/*
 * ssdfs_maptbl_solve_inconsistency() - resolve PEB state inconsistency
 * @tbl: pointer on mapping table object
 * @fdesc: fragment descriptor
 * @leb_id: LEB ID number
 * @pebr: cached PEB relation
 *
 * This method tries to change the PEB state in the mapping table
 * for the case if cached PEB state is inconsistent.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - unitialized leb descriptor.
 */
int ssdfs_maptbl_solve_inconsistency(struct ssdfs_peb_mapping_table *tbl,
				     struct ssdfs_maptbl_fragment_desc *fdesc,
				     u64 leb_id,
				     struct ssdfs_maptbl_peb_relation *pebr)
{
	struct ssdfs_leb_descriptor leb_desc;
	pgoff_t page_index;
	struct page *page;
	void *kaddr;
	struct ssdfs_peb_table_fragment_header *hdr;
	u16 physical_index, relation_index;
	struct ssdfs_peb_descriptor *peb_desc;
	struct ssdfs_maptbl_peb_descriptor *cached;
	u16 item_index;
	u64 peb_id;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !fdesc || !pebr);
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	SSDFS_DBG("fdesc %p, leb_id %llu\n",
		  fdesc, leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		return err;
	}

	physical_index = le16_to_cpu(leb_desc.physical_index);

	if (physical_index == U16_MAX) {
		SSDFS_ERR("unitialized leb descriptor: "
			  "leb_id %llu\n", leb_id);
		return -ENODATA;
	}

	page_index = ssdfs_maptbl_define_pebtbl_page(tbl, fdesc,
						     leb_id, physical_index);
	if (page_index == ULONG_MAX) {
		SSDFS_ERR("fail to define PEB table's page_index: "
			  "leb_id %llu, physical_index %u\n",
			  leb_id, physical_index);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("leb_id %llu, physical_index %u, page_index %lu\n",
		  leb_id, physical_index, page_index);
#endif /* CONFIG_SSDFS_DEBUG */

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap_local_page(page);

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;

	if (is_pebtbl_stripe_recovering(hdr)) {
		err = -EACCES;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to change the PEB state: "
			  "leb_id %llu: "
			  "stripe %u is under recovering\n",
			  leb_id,
			  le16_to_cpu(hdr->stripe_id));
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_physical_index_processing;
	}

	item_index = physical_index % fdesc->pebs_per_page;

	peb_id = GET_PEB_ID(kaddr, item_index);
	if (peb_id == U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("fail to define peb_id: "
			  "page_index %lu, item_index %u\n",
			  page_index, item_index);
		goto finish_physical_index_processing;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("physical_index %u, item_index %u, "
		  "pebs_per_page %u, peb_id %llu\n",
		  physical_index, item_index,
		  fdesc->pebs_per_page, peb_id);

	SSDFS_DBG("PAGE DUMP: page_index %lu\n",
		  page_index);
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     kaddr,
			     PAGE_SIZE);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	peb_desc = GET_PEB_DESCRIPTOR(kaddr, item_index);
	if (IS_ERR_OR_NULL(peb_desc)) {
		err = IS_ERR(peb_desc) ? PTR_ERR(peb_desc) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "page_index %lu, item_index %u, err %d\n",
			  page_index, item_index, err);
		goto finish_physical_index_processing;
	}

	cached = &pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX];

	if (cached->peb_id != peb_id) {
		err = -ERANGE;
		SSDFS_ERR("invalid main index: "
			  "cached->peb_id %llu, peb_id %llu\n",
			  cached->peb_id, peb_id);
		goto finish_physical_index_processing;
	}

	peb_desc->state = cached->state;
	peb_desc->flags = cached->flags;
	peb_desc->shared_peb_index = cached->shared_peb_index;

finish_physical_index_processing:
	kunmap_local(kaddr);

	if (!err) {
		ssdfs_set_page_private(page, 0);
		SetPageUptodate(page);
		err = ssdfs_page_array_set_page_dirty(&fdesc->array,
						      page_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu dirty: err %d\n",
				  page_index, err);
		}
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	if (err)
		return err;

	cached = &pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX];
	relation_index = le16_to_cpu(leb_desc.relation_index);

	if (cached->peb_id >= U64_MAX && relation_index == U16_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("LEB %llu hasn't relation\n", leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	} else if (relation_index == U16_MAX) {
		SSDFS_ERR("unitialized leb descriptor: "
			  "leb_id %llu\n", leb_id);
		return -ENODATA;
	}

	page_index = ssdfs_maptbl_define_pebtbl_page(tbl, fdesc,
						     leb_id, relation_index);
	if (page_index == ULONG_MAX) {
		SSDFS_ERR("fail to define PEB table's page_index: "
			  "leb_id %llu, relation_index %u\n",
			  leb_id, relation_index);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("leb_id %llu, relation_index %u, page_index %lu\n",
		  leb_id, relation_index, page_index);
#endif /* CONFIG_SSDFS_DEBUG */

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap_local_page(page);

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;

	if (is_pebtbl_stripe_recovering(hdr)) {
		err = -EACCES;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to change the PEB state: "
			  "leb_id %llu: "
			  "stripe %u is under recovering\n",
			  leb_id,
			  le16_to_cpu(hdr->stripe_id));
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_relation_index_processing;
	}

	item_index = relation_index % fdesc->pebs_per_page;

	peb_id = GET_PEB_ID(kaddr, item_index);
	if (peb_id == U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("fail to define peb_id: "
			  "page_index %lu, item_index %u\n",
			  page_index, item_index);
		goto finish_relation_index_processing;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("relation_index %u, item_index %u, "
		  "pebs_per_page %u, peb_id %llu\n",
		  relation_index, item_index,
		  fdesc->pebs_per_page, peb_id);

	SSDFS_DBG("PAGE DUMP: page_index %lu\n",
		  page_index);
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     kaddr,
			     PAGE_SIZE);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	peb_desc = GET_PEB_DESCRIPTOR(kaddr, item_index);
	if (IS_ERR_OR_NULL(peb_desc)) {
		err = IS_ERR(peb_desc) ? PTR_ERR(peb_desc) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "page_index %lu, item_index %u, err %d\n",
			  page_index, item_index, err);
		goto finish_relation_index_processing;
	}

	if (cached->peb_id != peb_id) {
		err = -ERANGE;
		SSDFS_ERR("invalid main index: "
			  "cached->peb_id %llu, peb_id %llu\n",
			  cached->peb_id, peb_id);
		goto finish_relation_index_processing;
	}

	peb_desc->state = cached->state;
	peb_desc->flags = cached->flags;
	peb_desc->shared_peb_index = cached->shared_peb_index;

finish_relation_index_processing:
	kunmap_local(kaddr);

	if (!err) {
		ssdfs_set_page_private(page, 0);
		SetPageUptodate(page);
		err = ssdfs_page_array_set_page_dirty(&fdesc->array,
						      page_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu dirty: err %d\n",
				  page_index, err);
		}
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * __is_mapped_leb2peb() - check that LEB is mapped
 * @leb_desc: LEB descriptor
 */
static inline
bool __is_mapped_leb2peb(struct ssdfs_leb_descriptor *leb_desc)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!leb_desc);

	SSDFS_DBG("physical_index %u, relation_index %u\n",
		  le16_to_cpu(leb_desc->physical_index),
		  le16_to_cpu(leb_desc->relation_index));
#endif /* CONFIG_SSDFS_DEBUG */

	return le16_to_cpu(leb_desc->physical_index) != U16_MAX;
}

/*
 * is_leb_migrating() - check that LEB is migrating
 * @leb_desc: LEB descriptor
 */
static inline
bool is_leb_migrating(struct ssdfs_leb_descriptor *leb_desc)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!leb_desc);

	SSDFS_DBG("physical_index %u, relation_index %u\n",
		  le16_to_cpu(leb_desc->physical_index),
		  le16_to_cpu(leb_desc->relation_index));
#endif /* CONFIG_SSDFS_DEBUG */

	return le16_to_cpu(leb_desc->relation_index) != U16_MAX;
}

/*
 * ssdfs_maptbl_set_under_erase_state() - set source PEB as under erase
 * @fdesc: fragment descriptor
 * @index: PEB index in the fragment
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_set_under_erase_state(struct ssdfs_maptbl_fragment_desc *fdesc,
					u16 index)
{
	struct ssdfs_peb_descriptor *ptr;
	pgoff_t page_index;
	u16 item_index;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);

	SSDFS_DBG("fdesc %p, index %u\n",
		  fdesc, index);
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = PEBTBL_PAGE_INDEX(fdesc, index);
	item_index = index % fdesc->pebs_per_page;

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap_local_page(page);

	ptr = GET_PEB_DESCRIPTOR(kaddr, item_index);
	if (IS_ERR_OR_NULL(ptr)) {
		err = IS_ERR(ptr) ? PTR_ERR(ptr) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "page_index %lu, item_index %u, err %d\n",
			  page_index, item_index, err);
		goto finish_page_processing;
	}

	ptr->state = SSDFS_MAPTBL_UNDER_ERASE_STATE;

finish_page_processing:
	kunmap_local(kaddr);

	if (!err) {
		ssdfs_set_page_private(page, 0);
		SetPageUptodate(page);
		err = ssdfs_page_array_set_page_dirty(&fdesc->array,
						      page_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu dirty: err %d\n",
				  page_index, err);
		}
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_maptbl_set_pre_erase_state() - set source PEB as pre-erased
 * @fdesc: fragment descriptor
 * @index: PEB index in the fragment
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_set_pre_erase_state(struct ssdfs_maptbl_fragment_desc *fdesc,
				     u16 index)
{
	struct ssdfs_peb_table_fragment_header *hdr;
	struct ssdfs_peb_descriptor *ptr;
	pgoff_t page_index;
	u16 item_index;
	struct page *page;
	void *kaddr;
	unsigned long *bmap;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);

	SSDFS_DBG("fdesc %p, index %u\n",
		  fdesc, index);
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = PEBTBL_PAGE_INDEX(fdesc, index);
	item_index = index % fdesc->pebs_per_page;

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap_local_page(page);

	ptr = GET_PEB_DESCRIPTOR(kaddr, item_index);
	if (IS_ERR_OR_NULL(ptr)) {
		err = IS_ERR(ptr) ? PTR_ERR(ptr) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "page_index %lu, item_index %u, err %d\n",
			  page_index, item_index, err);
		goto finish_page_processing;
	}

	ptr->state = SSDFS_MAPTBL_PRE_ERASE_STATE;

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;
	bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_DIRTY_BMAP][0];
	bitmap_set(bmap, item_index, 1);

finish_page_processing:
	kunmap_local(kaddr);

	if (!err) {
		ssdfs_set_page_private(page, 0);
		SetPageUptodate(page);
		err = ssdfs_page_array_set_page_dirty(&fdesc->array,
						      page_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu dirty: err %d\n",
				  page_index, err);
		}
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_maptbl_set_snapshot_state() - set PEB in snapshot state
 * @fdesc: fragment descriptor
 * @index: PEB index in the fragment
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_set_snapshot_state(struct ssdfs_maptbl_fragment_desc *fdesc,
				    u16 index)
{
	struct ssdfs_peb_table_fragment_header *hdr;
	struct ssdfs_peb_descriptor *ptr;
	pgoff_t page_index;
	u16 item_index;
	struct page *page;
	void *kaddr;
	unsigned long *bmap;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);

	SSDFS_DBG("fdesc %p, index %u\n",
		  fdesc, index);
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = PEBTBL_PAGE_INDEX(fdesc, index);
	item_index = index % fdesc->pebs_per_page;

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap_local_page(page);

	ptr = GET_PEB_DESCRIPTOR(kaddr, item_index);
	if (IS_ERR_OR_NULL(ptr)) {
		err = IS_ERR(ptr) ? PTR_ERR(ptr) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "page_index %lu, item_index %u, err %d\n",
			  page_index, item_index, err);
		goto finish_page_processing;
	}

	ptr->state = SSDFS_MAPTBL_SNAPSHOT_STATE;

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;
	bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_DIRTY_BMAP][0];
	bitmap_set(bmap, item_index, 1);

finish_page_processing:
	kunmap_local(kaddr);

	if (!err) {
		ssdfs_set_page_private(page, 0);
		SetPageUptodate(page);
		err = ssdfs_page_array_set_page_dirty(&fdesc->array,
						      page_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu dirty: err %d\n",
				  page_index, err);
		}
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_maptbl_set_source_state() - set destination PEB as source
 * @fdesc: fragment descriptor
 * @index: PEB index in the fragment
 * @peb_state: PEB's state
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_set_source_state(struct ssdfs_maptbl_fragment_desc *fdesc,
				  u16 index, u8 peb_state)
{
	struct ssdfs_peb_descriptor *ptr;
	pgoff_t page_index;
	u16 item_index;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);

	SSDFS_DBG("fdesc %p, index %u\n",
		  fdesc, index);
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = PEBTBL_PAGE_INDEX(fdesc, index);
	item_index = index % fdesc->pebs_per_page;

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap_local_page(page);

	ptr = GET_PEB_DESCRIPTOR(kaddr, item_index);
	if (IS_ERR_OR_NULL(ptr)) {
		err = IS_ERR(ptr) ? PTR_ERR(ptr) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "page_index %lu, item_index %u, err %d\n",
			  page_index, item_index, err);
		goto finish_page_processing;
	}

	if (peb_state == SSDFS_MAPTBL_UNKNOWN_PEB_STATE) {
		switch (ptr->state) {
		case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
			ptr->state = SSDFS_MAPTBL_CLEAN_PEB_STATE;
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
			ptr->state = SSDFS_MAPTBL_USING_PEB_STATE;
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
			ptr->state = SSDFS_MAPTBL_USED_PEB_STATE;
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
			ptr->state = SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE;
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_DIRTY_STATE:
			ptr->state = SSDFS_MAPTBL_DIRTY_PEB_STATE;
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid PEB state: "
				  "state %#x\n",
				  ptr->state);
			goto finish_page_processing;
		}
	} else {
		switch (ptr->state) {
		case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
		case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
		case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
		case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
		case SSDFS_MAPTBL_MIGRATION_DST_DIRTY_STATE:
			ptr->state = peb_state;
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid PEB state: "
				  "state %#x\n",
				  ptr->state);
			goto finish_page_processing;
			break;
		}
	}

finish_page_processing:
	kunmap_local(kaddr);

	if (!err) {
		ssdfs_set_page_private(page, 0);
		SetPageUptodate(page);
		err = ssdfs_page_array_set_page_dirty(&fdesc->array,
						      page_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu dirty: err %d\n",
				  page_index, err);
		}
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * __ssdfs_maptbl_exclude_migration_peb() - correct LEB table state
 * @ptr: fragment descriptor
 * @leb_id: LEB ID number
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_maptbl_exclude_migration_peb(struct ssdfs_maptbl_fragment_desc *ptr,
					 u64 leb_id)
{
	struct ssdfs_leb_table_fragment_header *hdr;
	struct ssdfs_leb_descriptor *leb_desc;
	pgoff_t page_index;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);

	SSDFS_DBG("fdesc %p, leb_id %llu\n",
		  ptr, leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = LEBTBL_PAGE_INDEX(ptr, leb_id);
	if (page_index == ULONG_MAX) {
		SSDFS_ERR("fail to define page_index: "
			  "leb_id %llu\n",
			  leb_id);
		return -ERANGE;
	}

	page = ssdfs_page_array_get_page_locked(&ptr->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap_local_page(page);

	leb_desc = GET_LEB_DESCRIPTOR(kaddr, leb_id);
	if (IS_ERR_OR_NULL(leb_desc)) {
		err = IS_ERR(leb_desc) ? PTR_ERR(leb_desc) : -ERANGE;
		SSDFS_ERR("fail to get leb_descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_page_processing;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("INITIAL: page_index %lu, "
		  "physical_index %u, relation_index %u\n",
		  page_index,
		  le16_to_cpu(leb_desc->physical_index),
		  le16_to_cpu(leb_desc->relation_index));
#endif /* CONFIG_SSDFS_DEBUG */

	leb_desc->physical_index = leb_desc->relation_index;
	leb_desc->relation_index = cpu_to_le16(U16_MAX);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("MODIFIED: page_index %lu, "
		  "physical_index %u, relation_index %u\n",
		  page_index,
		  le16_to_cpu(leb_desc->physical_index),
		  le16_to_cpu(leb_desc->relation_index));
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = (struct ssdfs_leb_table_fragment_header *)kaddr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(le16_to_cpu(hdr->migrating_lebs) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	le16_add_cpu(&hdr->migrating_lebs, -1);

finish_page_processing:
	kunmap_local(kaddr);

	if (!err) {
		ssdfs_set_page_private(page, 0);
		SetPageUptodate(page);
		err = ssdfs_page_array_set_page_dirty(&ptr->array,
						      page_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu dirty: err %d\n",
				  page_index, err);
		}
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_maptbl_solve_pre_deleted_state() - exclude pre-deleted migration PEB
 * @tbl: pointer on mapping table object
 * @fdesc: fragment descriptor
 * @leb_id: LEB ID number
 * @pebr: cached PEB relation
 *
 * This method tries to exclude the pre-deleted migration PEB
 * from the relation by means of mapping table modification if
 * the migration PEB is marked as pre-deleted in the mapping
 * table cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int
ssdfs_maptbl_solve_pre_deleted_state(struct ssdfs_peb_mapping_table *tbl,
				     struct ssdfs_maptbl_fragment_desc *fdesc,
				     u64 leb_id,
				     struct ssdfs_maptbl_peb_relation *pebr)
{
	struct ssdfs_leb_descriptor leb_desc;
	u16 physical_index, relation_index;
	int peb_state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !fdesc);
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	SSDFS_DBG("fdesc %p, leb_id %llu\n",
		  fdesc, leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		return err;
	}

	if (!__is_mapped_leb2peb(&leb_desc)) {
		SSDFS_ERR("leb %llu doesn't be mapped yet\n",
			  leb_id);
		return -ERANGE;
	}

	if (!is_leb_migrating(&leb_desc)) {
		SSDFS_ERR("leb %llu isn't under migration\n",
			  leb_id);
		return -ERANGE;
	}

	physical_index = le16_to_cpu(leb_desc.physical_index);
	relation_index = le16_to_cpu(leb_desc.relation_index);

	peb_state = pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].state;

	switch (peb_state) {
	case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid state %#x of source PEB\n",
			  peb_state);
		return -ERANGE;
	}

	err = ssdfs_maptbl_set_pre_erase_state(fdesc, physical_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move PEB into pre-erase state: "
			  "index %u, err %d\n",
			  physical_index, err);
		return err;
	}

	peb_state = pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].state;

	err = ssdfs_maptbl_set_source_state(fdesc, relation_index,
					    (u8)peb_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move PEB into source state: "
			  "index %u, peb_state %#x, err %d\n",
			  relation_index, peb_state, err);
		return err;
	}

	err = __ssdfs_maptbl_exclude_migration_peb(fdesc, leb_id);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(fdesc->migrating_lebs == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	fdesc->migrating_lebs--;
	fdesc->pre_erase_pebs++;
	atomic_inc(&tbl->pre_erase_pebs);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("mapped_lebs %u, migrating_lebs %u\n",
		  fdesc->mapped_lebs, fdesc->migrating_lebs);
	SSDFS_DBG("fdesc->pre_erase_pebs %u, tbl->pre_erase_pebs %d\n",
		  fdesc->pre_erase_pebs,
		  atomic_read(&tbl->pre_erase_pebs));
#endif /* CONFIG_SSDFS_DEBUG */

	wake_up(&tbl->wait_queue);

	return 0;
}

/*
 * ssdfs_maptbl_set_fragment_dirty() - set fragment as dirty
 * @tbl: pointer on mapping table object
 * @fdesc: fragment descriptor
 * @leb_id: LEB ID number
 */
void ssdfs_maptbl_set_fragment_dirty(struct ssdfs_peb_mapping_table *tbl,
				     struct ssdfs_maptbl_fragment_desc *fdesc,
				     u64 leb_id)
{
	u32 fragment_index;
#ifdef CONFIG_SSDFS_DEBUG
	size_t bytes_count;
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !fdesc);
#endif /* CONFIG_SSDFS_DEBUG */

	fragment_index = FRAGMENT_INDEX(tbl, leb_id);

	if (is_ssdfs_maptbl_going_to_be_destroyed(tbl)) {
		SSDFS_WARN("maptbl %p, leb_id %llu, "
			  "fdesc %p, fragment_index %u, "
			  "start_leb %llu, lebs_count %u\n",
			  tbl, leb_id,
			  fdesc, fragment_index,
			  fdesc->start_leb, fdesc->lebs_count);
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("maptbl %p, leb_id %llu, "
			  "fdesc %p, fragment_index %u, "
			  "start_leb %llu, lebs_count %u\n",
			  tbl, leb_id,
			  fdesc, fragment_index,
			  fdesc->start_leb, fdesc->lebs_count);
#endif /* CONFIG_SSDFS_DEBUG */
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(fragment_index == U32_MAX);
	BUG_ON(fragment_index >= tbl->fragments_count);
#endif /* CONFIG_SSDFS_DEBUG */

	mutex_lock(&tbl->bmap_lock);
#ifdef CONFIG_SSDFS_DEBUG
	bytes_count = tbl->fragments_count + BITS_PER_LONG - 1;
	bytes_count /= BITS_PER_BYTE;
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			tbl->dirty_bmap, bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */
	atomic_set(&fdesc->state, SSDFS_MAPTBL_FRAG_DIRTY);
	bitmap_set(tbl->dirty_bmap, fragment_index, 1);
	mutex_unlock(&tbl->bmap_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("fragment_index %u, state %#x\n",
		  fragment_index,
		  atomic_read(&fdesc->state));
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * ssdfs_maptbl_convert_leb2peb() - get description of PEBs
 * @fsi: file system info object
 * @leb_id: LEB ID number
 * @peb_type: PEB type
 * @pebr: description of PEBs relation [out]
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to get description of PEBs for the
 * LEB ID number.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EFAULT     - maptbl has inconsistent state.
 * %-ENODATA    - LEB doesn't mapped to PEB yet.
 * %-ERANGE     - internal error.
 */
int ssdfs_maptbl_convert_leb2peb(struct ssdfs_fs_info *fsi,
				 u64 leb_id,
				 u8 peb_type,
				 struct ssdfs_maptbl_peb_relation *pebr,
				 struct completion **end)
{
	struct ssdfs_peb_mapping_table *tbl;
	struct ssdfs_maptbl_cache *cache;
	struct ssdfs_maptbl_fragment_desc *fdesc;
	struct ssdfs_leb_descriptor leb_desc;
	struct ssdfs_maptbl_peb_relation cached_pebr;
	size_t peb_relation_size = sizeof(struct ssdfs_maptbl_peb_relation);
	u8 consistency = SSDFS_PEB_STATE_CONSISTENT;
	int state;
	u64 peb_id;
	u8 peb_state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebr || !end);

	SSDFS_DBG("fsi %p, leb_id %llu, peb_type %#x, "
		  "pebr %p, init_end %p\n",
		  fsi, leb_id, peb_type, pebr, end);
#endif /* CONFIG_SSDFS_DEBUG */

	*end = NULL;
	memset(pebr, 0xFF, peb_relation_size);

	tbl = fsi->maptbl;
	cache = &tbl->fsi->maptbl_cache;

	if (!tbl) {
		err = 0;

		if (should_cache_peb_info(peb_type)) {
			err = ssdfs_maptbl_cache_convert_leb2peb(cache, leb_id,
								 pebr);
			if (unlikely(err)) {
				SSDFS_ERR("fail to convert LEB to PEB: "
					  "leb_id %llu, err %d\n",
					  leb_id, err);
			}
		} else {
			err = -ERANGE;
			SSDFS_CRIT("mapping table is absent\n");
		}

		return err;
	}

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"maptbl has corrupted state\n");
		return -EFAULT;
	}

	if (rwsem_is_locked(&tbl->tbl_lock) &&
	    atomic_read(&tbl->flags) & SSDFS_MAPTBL_UNDER_FLUSH) {
		if (should_cache_peb_info(peb_type)) {
			err = ssdfs_maptbl_cache_convert_leb2peb(cache, leb_id,
								 pebr);
			if (unlikely(err)) {
				SSDFS_ERR("fail to convert LEB to PEB: "
					  "leb_id %llu, err %d\n",
					  leb_id, err);
			}

			return err;
		}
	}

	down_read(&tbl->tbl_lock);

	if (peb_type == SSDFS_MAPTBL_UNKNOWN_PEB_TYPE) {
		/*
		 * GC thread requested the conversion
		 * without the knowledge of PEB's type.
		 */
		goto start_convert_leb2peb;
	}

	if (should_cache_peb_info(peb_type)) {
		struct ssdfs_maptbl_peb_descriptor *peb_desc;

		err = __ssdfs_maptbl_cache_convert_leb2peb(cache, leb_id,
							   &cached_pebr);
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to convert LEB to PEB: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_conversion;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to convert LEB to PEB: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_conversion;
		}

		peb_desc = &cached_pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX];
		consistency = peb_desc->consistency;

		switch (consistency) {
		case SSDFS_PEB_STATE_CONSISTENT:
			peb_desc =
				&cached_pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX];
			switch (peb_desc->consistency) {
			case SSDFS_PEB_STATE_INCONSISTENT:
				consistency = peb_desc->consistency;
				break;

			default:
				/* do nothing */
				break;
			}
			break;

		default:
			/* do nothing */
			break;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("MAIN_INDEX: peb_id %llu, type %#x, "
			  "state %#x, consistency %#x; "
			  "RELATION_INDEX: peb_id %llu, type %#x, "
			  "state %#x, consistency %#x\n",
		    cached_pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id,
		    cached_pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].type,
		    cached_pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
		    cached_pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].consistency,
		    cached_pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].peb_id,
		    cached_pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].type,
		    cached_pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].state,
		    cached_pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].consistency);
#endif /* CONFIG_SSDFS_DEBUG */
	}

start_convert_leb2peb:
	fdesc = ssdfs_maptbl_get_fragment_descriptor(tbl, leb_id);
	if (IS_ERR_OR_NULL(fdesc)) {
		err = IS_ERR(fdesc) ? PTR_ERR(fdesc) : -ERANGE;
		SSDFS_ERR("fail to get fragment descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_conversion;
	}

	*end = &fdesc->init_end;

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
		err = -EFAULT;
		SSDFS_ERR("fragment is corrupted: leb_id %llu\n",
			  leb_id);
		goto finish_conversion;
	} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: "
			  "leb_id %llu, fragment_id %u, state %#x\n",
			  leb_id, fdesc->fragment_id,
			  atomic_read(&fdesc->state));
#endif /* CONFIG_SSDFS_DEBUG */
		err = -EAGAIN;
		goto finish_conversion;
	}

	switch (consistency) {
	case SSDFS_PEB_STATE_CONSISTENT:
		down_read(&fdesc->lock);

		err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get leb descriptor: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_consistent_case;
		}

		err = ssdfs_maptbl_get_peb_relation(fdesc, &leb_desc, pebr);
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to get peb relation: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_consistent_case;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get peb relation: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_consistent_case;
		}

finish_consistent_case:
		up_read(&fdesc->lock);
		break;

	case SSDFS_PEB_STATE_INCONSISTENT:
		down_write(&cache->lock);
		down_write(&fdesc->lock);

		err = ssdfs_maptbl_cache_convert_leb2peb_nolock(cache,
								leb_id,
								&cached_pebr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert LEB to PEB: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_inconsistent_case;
		}

		err = ssdfs_maptbl_solve_inconsistency(tbl, fdesc, leb_id,
							&cached_pebr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to resolve inconsistency: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_inconsistent_case;
		}

		err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get leb descriptor: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_inconsistent_case;
		}

		err = ssdfs_maptbl_get_peb_relation(fdesc, &leb_desc, pebr);
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to get peb relation: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_inconsistent_case;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get peb relation: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_inconsistent_case;
		}

		peb_id = cached_pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id;
		peb_state = cached_pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].state;
		if (peb_id != U64_MAX) {
			consistency = SSDFS_PEB_STATE_CONSISTENT;
			err = ssdfs_maptbl_cache_change_peb_state_nolock(cache,
								  leb_id,
								  peb_state,
								  consistency);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change PEB state: "
					  "leb_id %llu, peb_state %#x, "
					  "err %d\n",
					  leb_id, peb_state, err);
				goto finish_inconsistent_case;
			}
		}

		peb_id = cached_pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].peb_id;
		peb_state = cached_pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].state;
		if (peb_id != U64_MAX) {
			consistency = SSDFS_PEB_STATE_CONSISTENT;
			err = ssdfs_maptbl_cache_change_peb_state_nolock(cache,
								  leb_id,
								  peb_state,
								  consistency);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change PEB state: "
					  "leb_id %llu, peb_state %#x, "
					  "err %d\n",
					  leb_id, peb_state, err);
				goto finish_inconsistent_case;
			}
		}

finish_inconsistent_case:
		up_write(&fdesc->lock);
		up_write(&cache->lock);

		if (!err) {
			ssdfs_maptbl_set_fragment_dirty(tbl, fdesc,
							leb_id);
		}
		break;

	case SSDFS_PEB_STATE_PRE_DELETED:
		down_write(&cache->lock);
		down_write(&fdesc->lock);

		err = ssdfs_maptbl_cache_convert_leb2peb_nolock(cache,
								leb_id,
								&cached_pebr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert LEB to PEB: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_pre_deleted_case;
		}

		err = ssdfs_maptbl_solve_pre_deleted_state(tbl, fdesc, leb_id,
							   &cached_pebr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to resolve pre-deleted state: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_pre_deleted_case;
		}

		err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get leb descriptor: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_pre_deleted_case;
		}

		err = ssdfs_maptbl_get_peb_relation(fdesc, &leb_desc, pebr);
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to get peb relation: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_pre_deleted_case;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get peb relation: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_pre_deleted_case;
		}

		consistency = SSDFS_PEB_STATE_CONSISTENT;
		err = ssdfs_maptbl_cache_forget_leb2peb_nolock(cache,
								leb_id,
								consistency);
		if (unlikely(err)) {
			SSDFS_ERR("fail to exclude migration PEB: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_pre_deleted_case;
		}

finish_pre_deleted_case:
		up_write(&fdesc->lock);
		up_write(&cache->lock);

		if (!err) {
			ssdfs_maptbl_set_fragment_dirty(tbl, fdesc,
							leb_id);
		}
		break;

	default:
		err = -EFAULT;
		SSDFS_ERR("invalid consistency %#x\n",
			  consistency);
		goto finish_conversion;
	}

finish_conversion:
	up_read(&tbl->tbl_lock);

	if (!err && peb_type == SSDFS_MAPTBL_UNKNOWN_PEB_TYPE) {
		peb_type = pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].type;

		if (should_cache_peb_info(peb_type)) {
			err = ssdfs_maptbl_cache_convert_leb2peb(cache, leb_id,
								 &cached_pebr);
			if (err == -ENODATA) {
				err = 0;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("cache has nothing for leb_id %llu\n",
					  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to convert LEB to PEB: "
					  "leb_id %llu, err %d\n",
					  leb_id, err);
				return err;
			} else {
				/* use the cached value */
				ssdfs_memcpy(pebr, 0, peb_relation_size,
					     &cached_pebr, 0, peb_relation_size,
					     peb_relation_size);
			}
		}
	} else if (err == -EAGAIN && should_cache_peb_info(peb_type)) {
		err = ssdfs_maptbl_cache_convert_leb2peb(cache, leb_id,
							 pebr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert LEB to PEB: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			return err;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
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

	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * is_mapped_leb2peb() - check that LEB is mapped
 * @fdesc: fragment descriptor
 * @leb_id: LEB ID number
 */
static inline
bool is_mapped_leb2peb(struct ssdfs_maptbl_fragment_desc *fdesc,
			u64 leb_id)
{
	struct ssdfs_leb_descriptor leb_desc;
	bool is_mapped;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);

	SSDFS_DBG("leb_id %llu, fdesc %p\n",
		  leb_id, fdesc);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		return false;
	}

	is_mapped = __is_mapped_leb2peb(&leb_desc);

	if (!is_mapped) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unitialized leb descriptor: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return is_mapped;
}

static inline
bool need_try2reserve_peb(struct ssdfs_fs_info *fsi)
{
#define SSDFS_PEB_RESERVATION_THRESHOLD		1
	return fsi->pebs_per_seg == SSDFS_PEB_RESERVATION_THRESHOLD;
}

/*
 * can_be_mapped_leb2peb() - check that LEB can be mapped
 * @tbl: pointer on mapping table object
 * @fdesc: fragment descriptor
 * @leb_id: LEB ID number
 */
static inline
bool can_be_mapped_leb2peb(struct ssdfs_peb_mapping_table *tbl,
			   struct ssdfs_maptbl_fragment_desc *fdesc,
			   u64 leb_id)
{
	u32 unused_lebs;
	u32 expected2migrate = 0;
	u32 reserved_pool = 0;
	u32 migration_NOT_guaranted = 0;
	u32 threshold;
	bool is_mapping_possible = false;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !fdesc);
	BUG_ON(!tbl->fsi);

	SSDFS_DBG("maptbl %p, leb_id %llu, fdesc %p\n",
		  tbl, leb_id, fdesc);
#endif /* CONFIG_SSDFS_DEBUG */

	expected2migrate = fdesc->mapped_lebs - fdesc->migrating_lebs;
	reserved_pool = fdesc->reserved_pebs + fdesc->pre_erase_pebs;

	if (expected2migrate > reserved_pool)
		migration_NOT_guaranted = expected2migrate - reserved_pool;
	else
		migration_NOT_guaranted = 0;

	unused_lebs = ssdfs_unused_lebs_in_fragment(fdesc);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("lebs_count %u, mapped_lebs %u, "
		  "migrating_lebs %u, reserved_pebs %u, "
		  "pre_erase_pebs %u, expected2migrate %u, "
		  "reserved_pool %u, migration_NOT_guaranted %u, "
		  "unused_lebs %u\n",
		  fdesc->lebs_count, fdesc->mapped_lebs,
		  fdesc->migrating_lebs, fdesc->reserved_pebs,
		  fdesc->pre_erase_pebs, expected2migrate,
		  reserved_pool, migration_NOT_guaranted,
		  unused_lebs);
#endif /* CONFIG_SSDFS_DEBUG */

	threshold = ssdfs_lebs_reservation_threshold(fdesc);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("unused_lebs %u, migration_NOT_guaranted %u, "
		  "threshold %u, stripe_pages %u\n",
		  unused_lebs,
		  migration_NOT_guaranted,
		  threshold,
		  fdesc->stripe_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	if ((reserved_pool + 1) >= unused_lebs) {
		is_mapping_possible = false;
		goto finish_check;
	}

	if (need_try2reserve_peb(tbl->fsi)) {
		threshold = max_t(u32, threshold,
				  (u32)tbl->stripes_per_fragment);

		if (unused_lebs > threshold) {
			is_mapping_possible = true;
			goto finish_check;
		}

		if (migration_NOT_guaranted == 0 &&
		    unused_lebs > tbl->stripes_per_fragment) {
			is_mapping_possible = true;
			goto finish_check;
		}
	} else {
		if (unused_lebs > threshold) {
			is_mapping_possible = true;
			goto finish_check;
		}

		if (migration_NOT_guaranted == 0 && unused_lebs > 0) {
			is_mapping_possible = true;
			goto finish_check;
		}
	}

finish_check:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("is_mapping_possible %#x\n",
		  is_mapping_possible);
#endif /* CONFIG_SSDFS_DEBUG */

	return is_mapping_possible;
}

/*
 * has_fragment_unused_pebs() - check that fragment has unused PEBs
 * @hdr: PEB table fragment's header
 */
static inline
bool has_fragment_unused_pebs(struct ssdfs_peb_table_fragment_header *hdr)
{
	unsigned long *bmap;
	u16 pebs_count;
	int used_pebs, unused_pebs;
	u16 reserved_pebs;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	pebs_count = le16_to_cpu(hdr->pebs_count);

	bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_USED_BMAP][0];
	used_pebs = bitmap_weight(bmap, pebs_count);
	unused_pebs = pebs_count - used_pebs;

	WARN_ON(unused_pebs < 0);

	reserved_pebs = le16_to_cpu(hdr->reserved_pebs);

	if (reserved_pebs > unused_pebs) {
		SSDFS_ERR("reserved_pebs %u > unused_pebs %u\n",
			  reserved_pebs, unused_pebs);
		return false;
	}

	unused_pebs -= reserved_pebs;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("hdr %p, unused_pebs %d, reserved_pebs %u\n",
		  hdr, unused_pebs, reserved_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

	return unused_pebs > 0;
}

/*
 * ssdfs_maptbl_decrease_reserved_pebs() - decrease amount of reserved PEBs
 * @fsi: file system info object
 * @desc: fragment descriptor
 * @hdr: PEB table fragment's header
 *
 * This method tries to move some amount of reserved PEBs into
 * unused state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - unable to decrease amount of reserved PEBs.
 */
static
int ssdfs_maptbl_decrease_reserved_pebs(struct ssdfs_fs_info *fsi,
				    struct ssdfs_maptbl_fragment_desc *desc,
				    struct ssdfs_peb_table_fragment_header *hdr)
{
	unsigned long *bmap;
	u32 expected2migrate;
	u16 pebs_count;
	u16 reserved_pebs;
	u16 used_pebs;
	u16 unused_pebs;
	u16 new_reservation;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	pebs_count = le16_to_cpu(hdr->pebs_count);
	reserved_pebs = le16_to_cpu(hdr->reserved_pebs);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("desc %p, hdr %p\n", desc, hdr);
	SSDFS_DBG("mapped_lebs %u, migrating_lebs %u, "
		  "pebs_count %u, reserved_pebs %u\n",
		  desc->mapped_lebs, desc->migrating_lebs,
		  pebs_count, reserved_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

	expected2migrate = (desc->mapped_lebs - desc->migrating_lebs);
	expected2migrate /= desc->stripe_pages;

	bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_USED_BMAP][0];
	used_pebs = bitmap_weight(bmap, pebs_count);
	unused_pebs = pebs_count - used_pebs;

	if (reserved_pebs > unused_pebs) {
		SSDFS_ERR("reserved_pebs %u > unused_pebs %u\n",
			  reserved_pebs, unused_pebs);
		return -ERANGE;
	}

	unused_pebs -= reserved_pebs;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pebs_count %u, used_pebs %u, unused_pebs %u, "
		  "expected2migrate %u\n",
		  pebs_count, used_pebs,
		  unused_pebs, expected2migrate);
#endif /* CONFIG_SSDFS_DEBUG */

	if (unused_pebs > reserved_pebs) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("no necessity to decrease: "
			  "unused_pebs %u, reserved_pebs %u\n",
			  unused_pebs, reserved_pebs);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	new_reservation = max_t(u16, expected2migrate,
				(unused_pebs * 20) / 100);

	if (reserved_pebs > new_reservation) {
		u64 free_pages;
		u64 new_free_pages;
		u16 new_unused_pebs = reserved_pebs - new_reservation;

		hdr->reserved_pebs = cpu_to_le16(new_reservation);
		desc->reserved_pebs -= new_unused_pebs;

		spin_lock(&fsi->volume_state_lock);
		new_free_pages = (u64)new_unused_pebs * fsi->pages_per_peb;
		fsi->free_pages += new_free_pages;
		free_pages = fsi->free_pages;
		spin_unlock(&fsi->volume_state_lock);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("free_pages %llu, new_free_pages %llu\n",
			  free_pages, new_free_pages);
		SSDFS_DBG("reserved_pebs %u, new_reservation %u, "
			  "desc->reserved_pebs %u\n",
			  reserved_pebs, new_reservation,
			  desc->reserved_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

		return 0;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("unable to decrease reserved PEBs\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return -ENOSPC;
}

static inline
u32 ssdfs_mandatory_reserved_pebs_pct(struct ssdfs_fs_info *fsi)
{
	u32 percentage = 50;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	percentage /= fsi->pebs_per_seg;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pebs_per_seg %u, percentage %u\n",
		  fsi->pebs_per_seg, percentage);
#endif /* CONFIG_SSDFS_DEBUG */

	return percentage;
}

/*
 * ssdfs_maptbl_increase_reserved_pebs() - increase amount of reserved PEBs
 * @fsi: file system info object
 * @desc: fragment descriptor
 * @hdr: PEB table fragment's header
 *
 * This method tries to move some amount of unused PEBs into
 * reserved state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - unable to increase amount of reserved PEBs.
 */
static
int ssdfs_maptbl_increase_reserved_pebs(struct ssdfs_fs_info *fsi,
				    struct ssdfs_maptbl_fragment_desc *desc,
				    struct ssdfs_peb_table_fragment_header *hdr)
{
	unsigned long *bmap;
	u32 expected2migrate;
	u16 pebs_count;
	u16 reserved_pebs;
	u16 used_pebs;
	u16 unused_pebs;
	u64 free_pages = 0;
	u64 free_pebs = 0;
	u64 reserved_pages = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !hdr);

	if (desc->migrating_lebs > desc->mapped_lebs) {
		SSDFS_ERR("fragment is corrupted: "
			  "migrating_lebs %u, mapped_lebs %u\n",
			  desc->migrating_lebs,
			  desc->mapped_lebs);
		return -ERANGE;
	}

	SSDFS_DBG("desc %p, hdr %p\n", desc, hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	pebs_count = le16_to_cpu(hdr->pebs_count);
	reserved_pebs = le16_to_cpu(hdr->reserved_pebs);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("mapped_lebs %u, migrating_lebs %u, "
		  "pebs_count %u, reserved_pebs %u\n",
		  desc->mapped_lebs, desc->migrating_lebs,
		  pebs_count, reserved_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

	expected2migrate = desc->mapped_lebs - desc->migrating_lebs;

	bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_USED_BMAP][0];
	used_pebs = bitmap_weight(bmap, pebs_count);
	unused_pebs = pebs_count - used_pebs;

	if (reserved_pebs > unused_pebs) {
		SSDFS_ERR("reserved_pebs %u > unused_pebs %u\n",
			  reserved_pebs, unused_pebs);
		return -ERANGE;
	}

	unused_pebs -= reserved_pebs;

	if (need_try2reserve_peb(fsi)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("used_pebs %u, unused_pebs %u, "
			  "reserved_pebs %u\n",
			  used_pebs, unused_pebs, reserved_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

		if (reserved_pebs < used_pebs && unused_pebs >= used_pebs) {
			reserved_pebs = used_pebs;

			spin_lock(&fsi->volume_state_lock);
			free_pages = fsi->free_pages;
			free_pebs = div64_u64(free_pages, fsi->pages_per_peb);
			if (reserved_pebs <= free_pebs) {
				reserved_pages = (u64)reserved_pebs *
							fsi->pages_per_peb;
				fsi->free_pages -= reserved_pages;
				free_pages = fsi->free_pages;
				hdr->reserved_pebs = cpu_to_le16(reserved_pebs);
				desc->reserved_pebs += reserved_pebs;
			} else
				err = -ENOSPC;
			spin_unlock(&fsi->volume_state_lock);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("free_pages %llu, reserved_pages %llu, "
				  "reserved_pebs %u, err %d\n",
				  free_pages, reserved_pages,
				  reserved_pebs, err);
			SSDFS_DBG("hdr->reserved_pebs %u\n",
				  le16_to_cpu(hdr->reserved_pebs));
#endif /* CONFIG_SSDFS_DEBUG */

			return err;
		}
	}

	if (reserved_pebs > 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("no need to increase reserved pebs: "
			  "reserved_pebs %u\n",
			  reserved_pebs);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	reserved_pebs = min_t(u16, unused_pebs / 2, expected2migrate);

	if (reserved_pebs == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("reserved_pebs %u, unused_pebs %u, "
			  "expected2migrate %u\n",
			  reserved_pebs, unused_pebs,
			  expected2migrate);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOSPC;
	}

	spin_lock(&fsi->volume_state_lock);
	free_pages = fsi->free_pages;
	free_pebs = div64_u64(free_pages, fsi->pages_per_peb);
	if (reserved_pebs <= free_pebs) {
		reserved_pages = (u64)reserved_pebs * fsi->pages_per_peb;
		fsi->free_pages -= reserved_pages;
		free_pages = fsi->free_pages;
		le16_add_cpu(&hdr->reserved_pebs, reserved_pebs);
		desc->reserved_pebs += reserved_pebs;
	} else
		err = -ENOSPC;
	spin_unlock(&fsi->volume_state_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("free_pages %llu, reserved_pages %llu, "
		  "reserved_pebs %u, err %d\n",
		  free_pages, reserved_pages,
		  reserved_pebs, err);
	SSDFS_DBG("hdr->reserved_pebs %u\n",
		  le16_to_cpu(hdr->reserved_pebs));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_maptbl_get_erase_threshold() - detect erase threshold for fragment
 * @hdr: PEB table fragment's header
 * @start: start item for search
 * @max: upper bound for the search
 * @used_pebs: number of used PEBs
 * @found: found item index [out]
 * @erase_cycles: erase cycles for found item [out]
 *
 * This method tries to detect the erase threshold of
 * PEB table's fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENODATA    - unable to detect the erase threshold.
 */
static int
ssdfs_maptbl_get_erase_threshold(struct ssdfs_peb_table_fragment_header *hdr,
				 unsigned long start, unsigned long max,
				 unsigned long used_pebs,
				 unsigned long *found, u32 *threshold)
{
	struct ssdfs_peb_descriptor *desc;
	unsigned long *bmap;
	unsigned long index, index1;
	u32 found_cycles;
	int step = 1;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr || !found || !threshold);

	SSDFS_DBG("hdr %p, start_peb %llu, pebs_count %u, "
		  "start %lu, max %lu, used_pebs %lu\n",
		  hdr,
		  le64_to_cpu(hdr->start_peb),
		  le16_to_cpu(hdr->pebs_count),
		  start, max, used_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

	bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_USED_BMAP][0];

	*found = ULONG_MAX;
	*threshold = U32_MAX;

	index = max - 1;
	while (index > 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index %lu, used_pebs %lu\n",
			  index, used_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

		index1 = bitmap_find_next_zero_area(bmap,
						    max, index,
						    1, 0);
		if (index1 >= max) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("try next: index1 %lu >= max %lu\n",
				  index1, max);
#endif /* CONFIG_SSDFS_DEBUG */

			desc = GET_PEB_DESCRIPTOR(hdr, (u16)index);
			if (IS_ERR_OR_NULL(desc)) {
				err = IS_ERR(desc) ? PTR_ERR(desc) : -ERANGE;
				SSDFS_ERR("fail to get peb_descriptor: "
					  "index %lu, err %d\n",
					  index, err);
				return err;
			}

			if (desc->state != SSDFS_MAPTBL_BAD_PEB_STATE) {
				found_cycles = le32_to_cpu(desc->erase_cycles);

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("index %lu, found_cycles %u, "
					  "threshold %u\n",
					  index, found_cycles, *threshold);
#endif /* CONFIG_SSDFS_DEBUG */

				if (*threshold > found_cycles)
					*threshold = found_cycles;
			}

			goto try_next_index;
		} else
			index = index1;

		if (index == *found)
			goto finish_search;

		desc = GET_PEB_DESCRIPTOR(hdr, (u16)index);
		if (IS_ERR_OR_NULL(desc)) {
			err = IS_ERR(desc) ? PTR_ERR(desc) : -ERANGE;
			SSDFS_ERR("fail to get peb_descriptor: "
				  "index %lu, err %d\n",
				  index, err);
			return err;
		}

		if (desc->state != SSDFS_MAPTBL_BAD_PEB_STATE) {
			found_cycles = le32_to_cpu(desc->erase_cycles);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("index %lu, found_cycles %u, threshold %u\n",
				  index, found_cycles, *threshold);
#endif /* CONFIG_SSDFS_DEBUG */

			if (*found >= ULONG_MAX) {
				*threshold = found_cycles;
				*found = index;
			} else if (*threshold > found_cycles) {
				*threshold = found_cycles;
				*found = index;
			} else if (*threshold == found_cycles) {
				/* continue search */
				*found = index;
			} else if ((*threshold + 1) <= found_cycles) {
				*found = index;
				goto finish_search;
			}
		}

try_next_index:
		if (index <= step)
			break;

		index -= step;
		step *= 2;

		while ((index - start) < step && step >= 2)
			step /= 2;
	}

	if (*found >= ULONG_MAX) {
		index = bitmap_find_next_zero_area(bmap,
						   max, 0,
						   1, 0);
		if (index < max) {
			desc = GET_PEB_DESCRIPTOR(hdr, (u16)index);
			if (IS_ERR_OR_NULL(desc)) {
				err = IS_ERR(desc) ? PTR_ERR(desc) : -ERANGE;
				SSDFS_ERR("fail to get peb_descriptor: "
					  "index %lu, err %d\n",
					  index, err);
				return err;
			}

			if (desc->state != SSDFS_MAPTBL_BAD_PEB_STATE) {
				found_cycles = le32_to_cpu(desc->erase_cycles);
				*threshold = found_cycles;
				*found = index;
			}
		}
	}

finish_search:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("found %lu, threshold %u\n",
		  *found, *threshold);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * __ssdfs_maptbl_find_unused_peb() - find unused PEB
 * @hdr: PEB table fragment's header
 * @start: start item for search
 * @max: upper bound for the search
 * @threshold: erase threshold for fragment
 * @found: found item index [out]
 *
 * This method tries to find unused PEB in the bitmap of
 * PEB table's fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENODATA    - unable to find unused PEB.
 */
static
int __ssdfs_maptbl_find_unused_peb(struct ssdfs_peb_table_fragment_header *hdr,
				   unsigned long start, unsigned long max,
				   u32 threshold, unsigned long *found)
{
	struct ssdfs_peb_descriptor *desc;
	unsigned long *bmap;
	unsigned long index;
	int err = -ENODATA;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr || !found);

	SSDFS_DBG("hdr %p, start %lu, max %lu, threshold %u\n",
		  hdr, start, max, threshold);
#endif /* CONFIG_SSDFS_DEBUG */

	bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_USED_BMAP][0];

	*found = ULONG_MAX;

	if (start >= max) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start %lu >= max %lu\n",
			  start, max);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	do {
		index = bitmap_find_next_zero_area(bmap, max, start, 1, 0);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start %lu, max %lu, index %lu\n",
			  start, max, index);
#endif /* CONFIG_SSDFS_DEBUG */

		if (index >= max) {
			SSDFS_DBG("unable to find the unused peb\n");
			return -ENODATA;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(index >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		desc = GET_PEB_DESCRIPTOR(hdr, (u16)index);
		if (IS_ERR_OR_NULL(desc)) {
			err = IS_ERR(desc) ? PTR_ERR(desc) : -ERANGE;
			SSDFS_ERR("fail to get peb_descriptor: "
				  "index %lu, err %d\n",
				  index, err);
			return err;
		}

		if (desc->state != SSDFS_MAPTBL_BAD_PEB_STATE) {
			u32 found_cycles = le32_to_cpu(desc->erase_cycles);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("index %lu, found_cycles %u, threshold %u\n",
				  index, found_cycles, threshold);
#endif /* CONFIG_SSDFS_DEBUG */

			if (found_cycles <= threshold) {
				*found = index;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("found: index %lu, "
					  "found_cycles %u, threshold %u\n",
					  *found, found_cycles, threshold);
#endif /* CONFIG_SSDFS_DEBUG */
				return 0;
			} else {
				/* continue to search */
				*found = ULONG_MAX;
			}
		}

		start = index + 1;
	} while (start < max);

	return err;
}

/*
 * ssdfs_maptbl_find_unused_peb() - find unused PEB
 * @hdr: PEB table fragment's header
 * @start: start item for search
 * @max: upper bound for the search
 * @used_pebs: number of used PEBs
 * @found: found item index [out]
 * @erase_cycles: erase cycles for found item [out]
 *
 * This method tries to find unused PEB in the bitmap of
 * PEB table's fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENODATA    - unable to find unused PEB.
 */
static
int ssdfs_maptbl_find_unused_peb(struct ssdfs_peb_table_fragment_header *hdr,
				 unsigned long start, unsigned long max,
				 unsigned long used_pebs,
				 unsigned long *found, u32 *erase_cycles)
{
	u32 threshold = U32_MAX;
	unsigned long found_for_threshold;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr || !found || !erase_cycles);

	SSDFS_DBG("hdr %p, start %lu, max %lu\n",
		  hdr, start, max);
#endif /* CONFIG_SSDFS_DEBUG */

	if (start >= max) {
		SSDFS_ERR("start %lu >= max %lu\n",
			  start, max);
		return -EINVAL;
	}

	err = ssdfs_maptbl_get_erase_threshold(hdr, 0, max, used_pebs,
						found, &threshold);
	if (unlikely(err)) {
		SSDFS_ERR("fail to detect erase threshold: err %d\n", err);
		return err;
	} else if (threshold >= U32_MAX) {
		SSDFS_ERR("invalid erase threshold %u\n", threshold);
		return -ERANGE;
	}

	*erase_cycles = threshold;
	found_for_threshold = *found;

	err = __ssdfs_maptbl_find_unused_peb(hdr, start, max,
					     threshold, found);
	if (err == -ENODATA) {
		err = __ssdfs_maptbl_find_unused_peb(hdr,
						     0, start,
						     threshold, found);
	}

	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		struct ssdfs_peb_descriptor *desc;
		unsigned long *bmap;
		u64 start_peb;
		u16 pebs_count;
		u16 reserved_pebs;
		u16 last_selected_peb;
		unsigned long used_pebs;
		u32 found_cycles;
		int i;

		SSDFS_DBG("unable to find unused PEB: "
			  "found_for_threshold %lu, threshold %u\n",
			  found_for_threshold, threshold);

		bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_USED_BMAP][0];
		start_peb = le64_to_cpu(hdr->start_peb);
		pebs_count = le16_to_cpu(hdr->pebs_count);
		reserved_pebs = le16_to_cpu(hdr->reserved_pebs);
		last_selected_peb = le16_to_cpu(hdr->last_selected_peb);
		used_pebs = bitmap_weight(bmap, pebs_count);

		SSDFS_DBG("hdr %p, start_peb %llu, pebs_count %u, "
			  "last_selected_peb %u, "
			  "reserved_pebs %u, used_pebs %lu\n",
			  hdr, start_peb, pebs_count, last_selected_peb,
			  reserved_pebs, used_pebs);

		for (i = 0; i < max; i++) {
			desc = GET_PEB_DESCRIPTOR(hdr, (u16)i);
			if (IS_ERR_OR_NULL(desc))
				continue;

			found_cycles = le32_to_cpu(desc->erase_cycles);

			SSDFS_DBG("index %d, found_cycles %u\n",
				  i, found_cycles);
		}
#endif /* CONFIG_SSDFS_DEBUG */

		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find unused PEB: err %d\n", err);
		return err;
	}

	return 0;
}

enum {
	SSDFS_MAPTBL_MAPPING_PEB,
	SSDFS_MAPTBL_MIGRATING_PEB,
	SSDFS_MAPTBL_PEB_PURPOSE_MAX
};

/*
 * ssdfs_maptbl_select_unused_peb() - select unused PEB
 * @fdesc: fragment descriptor
 * @hdr: PEB table fragment's header
 * @pebs_per_volume: number of PEBs per whole volume
 * @peb_goal: PEB purpose
 *
 * This method tries to find unused PEB and to set this
 * PEB as used.
 *
 * RETURN:
 * [success] - item index.
 * [failure] - U16_MAX.
 */
static
u16 ssdfs_maptbl_select_unused_peb(struct ssdfs_maptbl_fragment_desc *fdesc,
				   struct ssdfs_peb_table_fragment_header *hdr,
				   u64 pebs_per_volume,
				   int peb_goal)
{
	unsigned long *bmap;
	u64 start_peb;
	u16 pebs_count;
	u16 unused_pebs;
	u16 reserved_pebs;
	u16 last_selected_peb;
	unsigned long used_pebs;
	unsigned long start = 0;
	unsigned long found = ULONG_MAX;
	u32 erase_cycles = U32_MAX;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr || !fdesc);
	BUG_ON(peb_goal >= SSDFS_MAPTBL_PEB_PURPOSE_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_USED_BMAP][0];
	start_peb = le64_to_cpu(hdr->start_peb);
	pebs_count = le16_to_cpu(hdr->pebs_count);
	reserved_pebs = le16_to_cpu(hdr->reserved_pebs);
	last_selected_peb = le16_to_cpu(hdr->last_selected_peb);
	used_pebs = bitmap_weight(bmap, pebs_count);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("hdr %p, start_peb %llu, pebs_count %u, "
		  "last_selected_peb %u, "
		  "reserved_pebs %u, used_pebs %lu\n",
		  hdr, start_peb, pebs_count, last_selected_peb,
		  reserved_pebs, used_pebs);
	SSDFS_DBG("mapped_lebs %u, migrating_lebs %u, "
		  "pre_erase_pebs %u, recovering_pebs %u\n",
		  fdesc->mapped_lebs, fdesc->migrating_lebs,
		  fdesc->pre_erase_pebs, fdesc->recovering_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

	if ((start_peb + pebs_count) > pebs_per_volume) {
		/* correct value */
		pebs_count = (u16)(pebs_per_volume - start_peb);
	}

	if (used_pebs > pebs_count) {
		SSDFS_ERR("used_pebs %lu > pebs_count %u\n",
			  used_pebs, pebs_count);
		return -ERANGE;
	}

	unused_pebs = pebs_count - used_pebs;

	switch (peb_goal) {
	case SSDFS_MAPTBL_MAPPING_PEB:
		if (unused_pebs <= reserved_pebs) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unused_pebs %u, reserved_pebs %u\n",
				  unused_pebs, reserved_pebs);
#endif /* CONFIG_SSDFS_DEBUG */
			return U16_MAX;
		}
		break;

	case SSDFS_MAPTBL_MIGRATING_PEB:
		if (reserved_pebs == 0 && unused_pebs == 0) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("reserved_pebs %u, unused_pebs %u\n",
				  reserved_pebs, unused_pebs);
#endif /* CONFIG_SSDFS_DEBUG */
			return U16_MAX;
		}
		break;

	default:
		BUG();
	};

	if ((last_selected_peb + 1) >= pebs_count)
		last_selected_peb = 0;

	err = ssdfs_maptbl_find_unused_peb(hdr, last_selected_peb,
					   pebs_count, used_pebs,
					   &found, &erase_cycles);
	if (err == -ENODATA) {
		SSDFS_DBG("unable to find the unused peb\n");
		return U16_MAX;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find unused peb: "
			  "start %lu, pebs_count %u, err %d\n",
			  start, pebs_count, err);
		return U16_MAX;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(found >= U16_MAX);
	BUG_ON(erase_cycles >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	bitmap_set(bmap, found, 1);
	hdr->last_selected_peb = cpu_to_le16((u16)found);

	switch (peb_goal) {
	case SSDFS_MAPTBL_MAPPING_PEB:
		/* do nothing */
		break;

	case SSDFS_MAPTBL_MIGRATING_PEB:
		if (reserved_pebs > 0) {
			le16_add_cpu(&hdr->reserved_pebs, -1);
			fdesc->reserved_pebs--;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("hdr->reserved_pebs %u\n",
				  le16_to_cpu(hdr->reserved_pebs));
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	default:
		BUG();
	};

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("found %lu, erase_cycles %u\n",
		  found, erase_cycles);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u16)found;
}

/*
 * __ssdfs_maptbl_map_leb2peb() - map LEB into PEB
 * @fdesc: fragment descriptor
 * @hdr: PEB table fragment's header
 * @leb_id: LEB ID number
 * @page_index: page index in the fragment
 * @peb_type: type of the PEB
 * @pebr: description of PEBs relation [out]
 *
 * This method sets mapping association between LEB and PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - unable to select unused PEB.
 */
static
int __ssdfs_maptbl_map_leb2peb(struct ssdfs_peb_mapping_table *tbl,
				struct ssdfs_maptbl_fragment_desc *fdesc,
				struct ssdfs_peb_table_fragment_header *hdr,
				u64 leb_id, pgoff_t page_index, u8 peb_type,
				struct ssdfs_maptbl_peb_relation *pebr)
{
	struct ssdfs_peb_descriptor *peb_desc;
	struct ssdfs_leb_table_fragment_header *lebtbl_hdr;
	struct ssdfs_leb_descriptor *leb_desc;
	struct ssdfs_maptbl_peb_descriptor *ptr = NULL;
	u16 item_index;
	u16 peb_index = 0;
	pgoff_t lebtbl_page;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc || !hdr || !pebr);

	if (peb_type >= SSDFS_MAPTBL_PEB_TYPE_MAX) {
		SSDFS_ERR("invalid peb_type %#x\n",
			  peb_type);
		return -EINVAL;
	}

	SSDFS_DBG("fdesc %p, hdr %p, leb_id %llu, peb_type %#x, pebr %p\n",
		  fdesc, hdr, leb_id, peb_type, pebr);
#endif /* CONFIG_SSDFS_DEBUG */

	item_index = ssdfs_maptbl_select_unused_peb(fdesc, hdr,
						    tbl->pebs_count,
						    SSDFS_MAPTBL_MAPPING_PEB);
	if (item_index == U16_MAX) {
		SSDFS_DBG("unable to select unused peb\n");
		return -ENOENT;
	}

	memset(pebr, 0xFF, sizeof(struct ssdfs_maptbl_peb_relation));

	peb_desc = GET_PEB_DESCRIPTOR(hdr, item_index);
	if (IS_ERR_OR_NULL(peb_desc)) {
		err = IS_ERR(peb_desc) ? PTR_ERR(peb_desc) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "index %u, err %d\n",
			  item_index, err);
		return err;
	}

	peb_desc->type = peb_type;
	peb_desc->state = SSDFS_MAPTBL_CLEAN_PEB_STATE;

	lebtbl_page = LEBTBL_PAGE_INDEX(fdesc, leb_id);
	if (lebtbl_page == ULONG_MAX) {
		SSDFS_ERR("fail to define page_index: "
			  "leb_id %llu\n",
			  leb_id);
		return -ERANGE;
	}

	page = ssdfs_page_array_get_page_locked(&fdesc->array, lebtbl_page);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  lebtbl_page);
		return err;
	}

	kaddr = kmap_local_page(page);

	leb_desc = GET_LEB_DESCRIPTOR(kaddr, leb_id);
	if (IS_ERR_OR_NULL(leb_desc)) {
		err = IS_ERR(leb_desc) ? PTR_ERR(leb_desc) : -ERANGE;
		SSDFS_ERR("fail to get leb_descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_page_processing;
	}

	peb_index = DEFINE_PEB_INDEX_IN_FRAGMENT(fdesc, page_index, item_index);
	if (peb_index == U16_MAX) {
		err = -ERANGE;
		SSDFS_ERR("fail to define peb index\n");
		goto finish_page_processing;
	}

	leb_desc->physical_index = cpu_to_le16(peb_index);
	leb_desc->relation_index = U16_MAX;

	lebtbl_hdr = (struct ssdfs_leb_table_fragment_header *)kaddr;
	le16_add_cpu(&lebtbl_hdr->mapped_lebs, 1);

	ptr = &pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX];
	ptr->peb_id = le64_to_cpu(hdr->start_peb) + item_index;
	ptr->shared_peb_index = peb_desc->shared_peb_index;
	ptr->erase_cycles = le32_to_cpu(peb_desc->erase_cycles);
	ptr->type = peb_desc->type;
	ptr->state = peb_desc->state;
	ptr->flags = peb_desc->flags;

finish_page_processing:
	kunmap_local(kaddr);

	if (!err) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("leb_id %llu, item_index %u, peb_index %u, "
			  "start_peb %llu, peb_id %llu\n",
			  leb_id, item_index, peb_index,
			  le64_to_cpu(hdr->start_peb),
			  ptr->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_set_page_private(page, 0);
		SetPageUptodate(page);
		err = ssdfs_page_array_set_page_dirty(&fdesc->array,
						      lebtbl_page);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu dirty: err %d\n",
				  lebtbl_page, err);
		}
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

static
int ssdfs_maptbl_reserve_free_pages(struct ssdfs_fs_info *fsi)
{
	u64 free_pebs = 0;
	u64 free_pages = 0;
	u64 reserved_pages = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&fsi->volume_state_lock);
	free_pages = fsi->free_pages;
	free_pebs = div64_u64(free_pages, fsi->pages_per_peb);
	if (free_pebs >= 1) {
		reserved_pages = fsi->pages_per_peb;
		if (fsi->free_pages >= reserved_pages) {
			fsi->free_pages -= reserved_pages;
			free_pages = fsi->free_pages;
		} else
			err = -ERANGE;
	} else
		err = -ENOSPC;
	spin_unlock(&fsi->volume_state_lock);

	if (unlikely(err)) {
		SSDFS_WARN("fail to reserve PEB: "
			  "free_pages %llu, err %d\n",
			  free_pages, err);
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("free_pages %llu, reserved_pages %llu\n",
			  free_pages, reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return err;
}

static
void ssdfs_maptbl_free_reserved_pages(struct ssdfs_fs_info *fsi)
{
	u64 free_pages = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&fsi->volume_state_lock);
	fsi->free_pages += fsi->pages_per_peb;
	free_pages = fsi->free_pages;
	spin_unlock(&fsi->volume_state_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("free_pages %llu\n",
		  free_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	return;
}

static inline
bool can_peb_be_reserved(struct ssdfs_fs_info *fsi,
			 struct ssdfs_peb_table_fragment_header *hdr)
{
	unsigned long *bmap;
	u16 pebs_count;
	u16 used_pebs;
	u16 unused_pebs;
	u16 reserved_pebs;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	pebs_count = le16_to_cpu(hdr->pebs_count);
	reserved_pebs = le16_to_cpu(hdr->reserved_pebs);

	bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_USED_BMAP][0];
	used_pebs = bitmap_weight(bmap, pebs_count);
	unused_pebs = pebs_count - used_pebs;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pebs_count %u, used_pebs %u, "
		  "unused_pebs %u, reserved_pebs %u\n",
		  pebs_count, used_pebs,
		  unused_pebs, reserved_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

	if (unused_pebs == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to reserve PEB: "
			  "pebs_count %u, used_pebs %u, "
			  "unused_pebs %u, reserved_pebs %u\n",
			  pebs_count, used_pebs,
			  unused_pebs, reserved_pebs);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	} else if ((reserved_pebs + 1) >= unused_pebs) {
		/*
		 * Mapping operation takes one PEB +
		 * reservation needs another one.
		 */
		if (reserved_pebs > unused_pebs) {
			SSDFS_WARN("fail to reserve PEB: "
				  "pebs_count %u, used_pebs %u, "
				  "unused_pebs %u, reserved_pebs %u\n",
				  pebs_count, used_pebs,
				  unused_pebs, reserved_pebs);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to reserve PEB: "
				  "pebs_count %u, used_pebs %u, "
				  "unused_pebs %u, reserved_pebs %u\n",
				  pebs_count, used_pebs,
				  unused_pebs, reserved_pebs);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		return false;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("PEB can be reserved\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return true;
}

/*
 * __ssdfs_maptbl_try_map_leb2peb() - try to map LEB into PEB
 * @tbl: pointer on mapping table object
 * @fdesc: fragment descriptor
 * @leb_id: LEB ID number
 * @peb_type: type of the PEB
 * @pebr: description of PEBs relation [out]
 *
 * This method tries to set association between LEB identification
 * number and PEB identification number.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EACCES     - PEB stripe is under recovering.
 * %-ENOENT     - provided @leb_id cannot be mapped.
 */
static
int __ssdfs_maptbl_try_map_leb2peb(struct ssdfs_peb_mapping_table *tbl,
				   struct ssdfs_maptbl_fragment_desc *fdesc,
				   u64 leb_id, u64 start_peb_id, u8 peb_type,
				   struct ssdfs_maptbl_peb_relation *pebr)
{
	struct ssdfs_fs_info *fsi;
	pgoff_t page_index;
	struct page *page;
	void *kaddr;
	struct ssdfs_peb_table_fragment_header *hdr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !fdesc || !pebr);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	if (peb_type >= SSDFS_MAPTBL_PEB_TYPE_MAX) {
		SSDFS_ERR("invalid peb_type %#x\n",
			  peb_type);
		return -EINVAL;
	}

	SSDFS_DBG("tbl %p, fdesc %p, leb_id %llu, "
		  "start_peb_id %llu, peb_type %#x\n",
		  tbl, fdesc, leb_id, start_peb_id, peb_type);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = tbl->fsi;

	page_index = ssdfs_maptbl_define_pebtbl_page(tbl, fdesc,
						     start_peb_id,
						     U16_MAX);
	if (page_index == ULONG_MAX) {
		err = -ERANGE;
		SSDFS_ERR("fail to define PEB table's page_index: "
			  "start_peb_id %llu\n", start_peb_id);
		goto finish_fragment_change;
	}

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		goto finish_fragment_change;
	}

	kaddr = kmap_local_page(page);

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;

	if (is_pebtbl_stripe_recovering(hdr)) {
		err = -EACCES;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to map leb_id %llu: "
			  "stripe %u is under recovering\n",
			  leb_id,
			  le16_to_cpu(hdr->stripe_id));
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_page_processing;
	}

	if (!can_be_mapped_leb2peb(tbl, fdesc, leb_id)) {
		err = ssdfs_maptbl_decrease_reserved_pebs(fsi, fdesc, hdr);
		if (err == -ENOSPC) {
			err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to decrease reserved_pebs %u\n",
				  le16_to_cpu(hdr->reserved_pebs));
			SSDFS_DBG("unable to map leb_id %llu: "
				  "value is out of threshold\n",
				  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_page_processing;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to decrease reserved_pebs: err %d\n",
				  err);
			goto finish_page_processing;
		}
	}

	if (!has_fragment_unused_pebs(hdr)) {
		err = ssdfs_maptbl_decrease_reserved_pebs(fsi, fdesc, hdr);
		if (err == -ENOSPC) {
			err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to decrease reserved_pebs %u\n",
				  le16_to_cpu(hdr->reserved_pebs));
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_page_processing;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to decrease reserved_pebs: err %d\n",
				  err);
			goto finish_page_processing;
		}
	}

	if (!has_fragment_unused_pebs(hdr)) {
		err = -ERANGE;
		SSDFS_ERR("fail to map leb_id %llu\n", leb_id);
		goto finish_page_processing;
	}

	if (need_try2reserve_peb(fsi)) {
		/*
		 * Reservation could be not aligned with
		 * already mapped PEBs. Simply, try to align
		 * the number of reserved PEBs.
		 */
		err = ssdfs_maptbl_increase_reserved_pebs(fsi, fdesc, hdr);
		if (err == -ENOSPC) {
			err = 0;
			SSDFS_DBG("no space to reserve PEBs\n");
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to increase reserved PEBs: "
				  "err %d\n", err);
			goto finish_page_processing;
		}

		if (can_peb_be_reserved(fsi, hdr)) {
			err = ssdfs_maptbl_reserve_free_pages(fsi);
			if (err == -ENOSPC) {
				err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to reserve PEB: "
					  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_page_processing;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to reserve PEB: "
					  "err %d\n", err);
				goto finish_page_processing;
			}
		} else {
			err = -ENOENT;
			SSDFS_DBG("unable to reserve PEB\n");
			goto finish_page_processing;
		}
	}

	err = __ssdfs_maptbl_map_leb2peb(tbl, fdesc, hdr, leb_id,
					 page_index, peb_type, pebr);
	if (err == -ENOENT) {
		if (need_try2reserve_peb(fsi)) {
			ssdfs_maptbl_free_reserved_pages(fsi);
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to map: leb_id %llu, page_index %lu\n",
			  leb_id, page_index);
#endif /* CONFIG_SSDFS_DEBUG */

		goto finish_page_processing;
	} else if (unlikely(err)) {
		if (need_try2reserve_peb(fsi)) {
			ssdfs_maptbl_free_reserved_pages(fsi);
		}

		SSDFS_ERR("fail to map leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_page_processing;
	}

	fdesc->mapped_lebs++;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("mapped_lebs %u, migrating_lebs %u\n",
		  fdesc->mapped_lebs, fdesc->migrating_lebs);
#endif /* CONFIG_SSDFS_DEBUG */

	if (need_try2reserve_peb(fsi)) {
		le16_add_cpu(&hdr->reserved_pebs, 1);
		fdesc->reserved_pebs++;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("reserved_pebs %u\n",
		  le16_to_cpu(hdr->reserved_pebs));
#endif /* CONFIG_SSDFS_DEBUG */

finish_page_processing:
	flush_dcache_page(page);
	kunmap_local(kaddr);

	if (!err) {
		ssdfs_set_page_private(page, 0);
		SetPageUptodate(page);
		err = ssdfs_page_array_set_page_dirty(&fdesc->array,
						      page_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu dirty: err %d\n",
				  page_index, err);
		}
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

finish_fragment_change:
	return err;
}

/*
 * ssdfs_maptbl_try_map_leb2peb() - try to map LEB into PEB
 * @tbl: pointer on mapping table object
 * @fdesc: fragment descriptor
 * @leb_id: LEB ID number
 * @peb_type: type of the PEB
 * @pebr: description of PEBs relation [out]
 *
 * This method tries to set association between LEB identification
 * number and PEB identification number.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EACCES     - PEB stripe is under recovering.
 * %-ENOENT     - provided @leb_id cannot be mapped.
 */
static
int ssdfs_maptbl_try_map_leb2peb(struct ssdfs_peb_mapping_table *tbl,
				 struct ssdfs_maptbl_fragment_desc *fdesc,
				 u64 leb_id, u8 peb_type,
				 struct ssdfs_maptbl_peb_relation *pebr)
{
	u64 start_peb;
	u64 end_peb;
	int err = -ENOENT;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !fdesc || !pebr);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	if (peb_type >= SSDFS_MAPTBL_PEB_TYPE_MAX) {
		SSDFS_ERR("invalid peb_type %#x\n",
			  peb_type);
		return -EINVAL;
	}

	SSDFS_DBG("tbl %p, fdesc %p, leb_id %llu, peb_type %#x\n",
		  tbl, fdesc, leb_id, peb_type);
#endif /* CONFIG_SSDFS_DEBUG */

	start_peb = fdesc->start_leb;
	end_peb = fdesc->start_leb + fdesc->lebs_count;

	while (start_peb < end_peb) {
		err = __ssdfs_maptbl_try_map_leb2peb(tbl, fdesc,
						     leb_id, start_peb,
						     peb_type, pebr);
		if (err == -ENOENT) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to map: "
				  "leb_id %llu, start_peb %llu\n",
				  leb_id, start_peb);
#endif /* CONFIG_SSDFS_DEBUG */
			start_peb += fdesc->pebs_per_page;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to map: leb_id %llu, err %d\n",
				  leb_id, err);
			return err;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("leb_id %llu has been mapped\n", leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return 0;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("unable to map: leb_id %llu\n", leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	return -ENOENT;
}

/*
 * ssdfs_maptbl_map_leb2peb() - map LEB into PEB
 * @fsi: file system info object
 * @leb_id: LEB ID number
 * @peb_type: type of the PEB
 * @pebr: description of PEBs relation [out]
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to set association between LEB identification
 * number and PEB identification number.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EACCES     - PEB stripe is under recovering.
 * %-ENOENT     - provided @leb_id cannot be mapped.
 * %-EEXIST     - LEB is mapped yet.
 */
int ssdfs_maptbl_map_leb2peb(struct ssdfs_fs_info *fsi,
			     u64 leb_id, u8 peb_type,
			     struct ssdfs_maptbl_peb_relation *pebr,
			     struct completion **end)
{
	struct ssdfs_peb_mapping_table *tbl;
	struct ssdfs_maptbl_cache *cache;
	struct ssdfs_maptbl_fragment_desc *fdesc;
	int state;
	struct ssdfs_leb_descriptor leb_desc;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebr || !end);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("fsi %p, leb_id %llu, pebr %p, init_end %p\n",
		  fsi, leb_id, pebr, end);
#else
	SSDFS_DBG("fsi %p, leb_id %llu, pebr %p, init_end %p\n",
		  fsi, leb_id, pebr, end);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	*end = NULL;
	memset(pebr, 0xFF, sizeof(struct ssdfs_maptbl_peb_relation));

	tbl = fsi->maptbl;
	cache = &tbl->fsi->maptbl_cache;

	if (!tbl) {
		SSDFS_CRIT("mapping table is absent\n");
		return -ERANGE;
	}

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"maptbl has corrupted state\n");
		return -EFAULT;
	}

	down_read(&tbl->tbl_lock);

	fdesc = ssdfs_maptbl_get_fragment_descriptor(tbl, leb_id);
	if (IS_ERR_OR_NULL(fdesc)) {
		err = IS_ERR(fdesc) ? PTR_ERR(fdesc) : -ERANGE;
		SSDFS_ERR("fail to get fragment descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_mapping;
	}

	*end = &fdesc->init_end;

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
		err = -EFAULT;
		SSDFS_ERR("fragment is corrupted: leb_id %llu\n", leb_id);
		goto finish_mapping;
	} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
		err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_mapping;
	}

	down_write(&fdesc->lock);

	err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
	}

	err = ssdfs_maptbl_get_peb_relation(fdesc, &leb_desc, pebr);
	if (err != -ENODATA) {
		if (unlikely(err)) {
			SSDFS_ERR("fail to get peb relation: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_fragment_change;
		} else {
			err = -EEXIST;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("leb_id %llu is mapped yet\n", leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_fragment_change;
		}
	} else
		err = 0;

	err = ssdfs_maptbl_try_map_leb2peb(tbl, fdesc, leb_id, peb_type, pebr);
	if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to map: leb_id %llu, peb_type %#x\n",
			  leb_id, peb_type);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_fragment_change;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to map: leb_id %llu, peb_type %#x, err %d\n",
			  leb_id, peb_type, err);
		goto finish_fragment_change;
	}

finish_fragment_change:
	up_write(&fdesc->lock);

	if (!err)
		ssdfs_maptbl_set_fragment_dirty(tbl, fdesc, leb_id);

finish_mapping:
	up_read(&tbl->tbl_lock);

	if (err == -EAGAIN && should_cache_peb_info(peb_type)) {
		err = ssdfs_maptbl_cache_convert_leb2peb(cache, leb_id,
							 pebr);
		if (err == -ENODATA) {
			err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to convert LEB to PEB: "
				  "leb_id %llu\n",
				  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to convert LEB to PEB: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
		} else {
			err = -EEXIST;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("leb_id %llu is mapped yet\n",
				  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		}
	} else if (!err && should_cache_peb_info(peb_type)) {
		err = ssdfs_maptbl_cache_map_leb2peb(cache, leb_id, pebr,
						SSDFS_PEB_STATE_CONSISTENT);
		if (unlikely(err)) {
			SSDFS_ERR("fail to cache LEB/PEB mapping: "
				  "leb_id %llu, peb_id %llu, err %d\n",
				  leb_id,
				  pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id,
				  err);
			err = -EFAULT;
		}
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("leb_id %llu, pebs_count %llu\n",
		  leb_id, tbl->pebs_count);
	SSDFS_ERR("MAIN_INDEX: peb_id %llu, type %#x, "
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
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("leb_id %llu, pebs_count %llu\n",
		  leb_id, tbl->pebs_count);
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
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (!err) {
		u64 peb_id = pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id;
		loff_t offset = peb_id * fsi->erasesize;

		err = fsi->devops->open_zone(fsi->sb, offset);
		if (err == -EOPNOTSUPP && !fsi->is_zns_device) {
			/* ignore error */
			err = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to open zone: "
				  "offset %llu, err %d\n",
				  offset, err);
			return err;
		}
	}

	return err;
}

/*
 * ssdfs_maptbl_find_pebtbl_page() - find next page of PEB table
 * @tbl: pointer on mapping table object
 * @fdesc: fragment descriptor
 * @cur_index: current page index
 * @start_index: page index in the start of searching
 *
 * This method tries to find a next page of PEB table.
 */
static
pgoff_t ssdfs_maptbl_find_pebtbl_page(struct ssdfs_peb_mapping_table *tbl,
				      struct ssdfs_maptbl_fragment_desc *fdesc,
				      pgoff_t cur_index,
				      pgoff_t start_index)
{
	pgoff_t index;
	u32 pebtbl_pages, fragment_pages;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("maptbl %p, fdesc %p, cur_index %lu, start_index %lu\n",
		  tbl, fdesc, cur_index, start_index);

	BUG_ON(!tbl || !fdesc);
	BUG_ON((tbl->stripes_per_fragment * fdesc->stripe_pages) < cur_index);
	BUG_ON((tbl->stripes_per_fragment * fdesc->stripe_pages) < start_index);
	BUG_ON(cur_index < fdesc->lebtbl_pages);
	BUG_ON(start_index < fdesc->lebtbl_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	pebtbl_pages = tbl->stripes_per_fragment * fdesc->stripe_pages;
	fragment_pages = (u32)fdesc->lebtbl_pages + pebtbl_pages;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(cur_index >= fragment_pages);
	BUG_ON(start_index >= fragment_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	index = cur_index + fdesc->stripe_pages;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pebtbl_pages %u, fragment_pages %u, "
		  "fdesc->stripe_pages %u, cur_index %lu, "
		  "index %lu\n",
		  pebtbl_pages, fragment_pages,
		  fdesc->stripe_pages, cur_index,
		  index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (index >= fragment_pages)
		index = ULONG_MAX;

	return index;
}

/*
 * ssdfs_maptbl_try_decrease_reserved_pebs() - try decrease reserved PEBs
 * @tbl: pointer on mapping table object
 * @fdesc: fragment descriptor
 *
 * This method tries to decrease number of reserved PEBs.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EACCES     - fragment is recovering.
 * %-ENOENT     - unable to decrease the number of reserved PEBs.
 * %-ERANGE     - internal error.
 */
static int
ssdfs_maptbl_try_decrease_reserved_pebs(struct ssdfs_peb_mapping_table *tbl,
				    struct ssdfs_maptbl_fragment_desc *fdesc)
{
	struct ssdfs_fs_info *fsi;
	pgoff_t start_page;
	pgoff_t page_index;
	struct page *page;
	void *kaddr;
	struct ssdfs_peb_table_fragment_header *hdr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !fdesc);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	SSDFS_DBG("start_leb %llu, end_leb %llu\n",
		  fdesc->start_leb,
		  fdesc->start_leb + fdesc->lebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = tbl->fsi;

	start_page = ssdfs_maptbl_define_pebtbl_page(tbl, fdesc,
						     fdesc->start_leb,
						     U16_MAX);
	if (start_page == ULONG_MAX) {
		err = -ERANGE;
		SSDFS_ERR("fail to define PEB table's page_index: "
			  "start_peb_id %llu\n", fdesc->start_leb);
		goto finish_fragment_change;
	}

	page_index = start_page;

try_next_page:
	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		goto finish_fragment_change;
	}

	kaddr = kmap_local_page(page);

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;

	if (is_pebtbl_stripe_recovering(hdr)) {
		err = -EACCES;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to decrease reserved_pebs: "
			  "stripe %u is under recovering\n",
			  le16_to_cpu(hdr->stripe_id));
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_page_processing;
	}

	err = ssdfs_maptbl_decrease_reserved_pebs(fsi, fdesc, hdr);
	if (err == -ENOSPC) {
		err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to decrease reserved_pebs %u\n",
			  le16_to_cpu(hdr->reserved_pebs));
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_page_processing;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to decrease reserved_pebs: err %d\n",
			  err);
		goto finish_page_processing;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("mapped_lebs %u, migrating_lebs %u, "
		  "reserved_pebs %u, pre_erase_pebs %u, "
		  "recovering_pebs %u\n",
		  fdesc->mapped_lebs, fdesc->migrating_lebs,
		  fdesc->reserved_pebs, fdesc->pre_erase_pebs,
		  fdesc->recovering_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

finish_page_processing:
	flush_dcache_page(page);
	kunmap_local(kaddr);

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

	if (err == -EACCES || err == -ENOENT) {
		page_index = ssdfs_maptbl_find_pebtbl_page(tbl, fdesc,
							   page_index,
							   start_page);
		if (page_index == ULONG_MAX)
			goto finish_fragment_change;
		else
			goto try_next_page;
	}

finish_fragment_change:
	return err;
}

/*
 * ssdfs_maptbl_recommend_search_range() - recommend search range
 * @fsi: file system info object
 * @start_leb: recommended start LEB ID [in|out]
 * @end_leb: recommended end LEB ID [out]
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to find not exhausted fragment and
 * to share the starting/ending LEB ID of this fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - all fragments have been exhausted.
 */
int ssdfs_maptbl_recommend_search_range(struct ssdfs_fs_info *fsi,
					u64 *start_leb,
					u64 *end_leb,
					struct completion **end)
{
	struct ssdfs_peb_mapping_table *tbl;
	struct ssdfs_maptbl_fragment_desc *fdesc;
	int state;
	u64 start_search_leb;
	u64 found_start_leb = 0;
	u64 found_end_leb = 0;
	int start_index;
	bool is_found = false;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !start_leb || !end_leb || !end);

	SSDFS_DBG("fsi %p, start_leb %llu, end_leb %p, init_end %p\n",
		  fsi, *start_leb, end_leb, end);
#endif /* CONFIG_SSDFS_DEBUG */

	if (*start_leb >= fsi->nsegs) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start_leb %llu >= nsegs %llu",
			  *start_leb, fsi->nsegs);
#endif /* CONFIG_SSDFS_DEBUG */
		*start_leb = U64_MAX;
		*end_leb = U64_MAX;
		return -ENOENT;
	}

	start_search_leb = *start_leb;

	*start_leb = U64_MAX;
	*end_leb = U64_MAX;
	*end = NULL;

	tbl = fsi->maptbl;
	if (!tbl) {
		SSDFS_CRIT("mapping table is absent\n");
		return -ERANGE;
	}

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"maptbl has corrupted state\n");
		return -EFAULT;
	}

	err = -ENOENT;

	down_read(&tbl->tbl_lock);

	start_index = FRAGMENT_INDEX(tbl, start_search_leb);

	for (i = start_index; i < tbl->fragments_count; i++) {
		fdesc = &tbl->desc_array[i];

		*end = &fdesc->init_end;

		state = atomic_read(&fdesc->state);
		if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
			err = -EFAULT;
			SSDFS_ERR("fragment is corrupted: index %d\n", i);
			goto finish_check;
		} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
			err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fragment is under initialization: "
				  "index %d\n", i);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_check;
		}

		down_read(&fdesc->lock);

		found_start_leb = fdesc->start_leb;
		found_end_leb = fdesc->start_leb + fdesc->lebs_count;
		is_found = can_be_mapped_leb2peb(tbl, fdesc, found_start_leb);

		if (!is_found) {
			err = ssdfs_maptbl_try_decrease_reserved_pebs(tbl,
								      fdesc);
			if (err == -ENOENT) {
				err = 0;
				SSDFS_DBG("unable to decrease reserved pebs\n");
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to decrease reserved pebs: "
					  "err %d\n", err);
				goto finish_fragment_processing;
			}

			is_found = can_be_mapped_leb2peb(tbl, fdesc,
							 found_start_leb);
		}

finish_fragment_processing:
		up_read(&fdesc->lock);

		*start_leb = max_t(u64, start_search_leb, found_start_leb);
		*end_leb = found_end_leb;

		if (is_found) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("recommend: start_leb %llu, end_leb %llu\n",
				  *start_leb, *end_leb);
#endif /* CONFIG_SSDFS_DEBUG */
			break;
		} else {
			err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fragment %d (leb_id %llu) is exhausted\n",
				  i, found_start_leb);
#endif /* CONFIG_SSDFS_DEBUG */
		}
	}

finish_check:
	up_read(&tbl->tbl_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished: start_leb %llu, end_leb %llu, err %d\n",
		  *start_leb, *end_leb, err);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * __ssdfs_maptbl_change_peb_state() - change PEB state
 * @tbl: pointer on mapping table object
 * @fdesc: fragment descriptor
 * @leb_id: LEB ID number
 * @selected_index: index of item in the whole fragment
 * @new_peb_state: new state of the PEB
 * @old_peb_state: old state of the PEB [out]
 *
 * This method tries to change the state of the PEB
 * in the mapping table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EACCES     - PEB stripe is under recovering.
 * %-EEXIST     - PEB has this state already.
 */
static
int __ssdfs_maptbl_change_peb_state(struct ssdfs_peb_mapping_table *tbl,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    u64 leb_id,
				    u16 selected_index,
				    int new_peb_state,
				    int *old_peb_state)
{
	struct ssdfs_peb_table_fragment_header *hdr;
	struct ssdfs_peb_descriptor *peb_desc;
	pgoff_t page_index;
	struct page *page;
	void *kaddr;
	u16 item_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tbl %p, fdesc %p, leb_id %llu, "
		  "selected_index %u, new_peb_state %#x\n",
		  tbl, fdesc, leb_id,
		  selected_index, new_peb_state);

	BUG_ON(!tbl || !fdesc || !old_peb_state);
	BUG_ON(selected_index >= U16_MAX);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));
	BUG_ON(!rwsem_is_locked(&fdesc->lock));

	if (new_peb_state <= SSDFS_MAPTBL_UNKNOWN_PEB_STATE ||
	    new_peb_state >= SSDFS_MAPTBL_PEB_STATE_MAX) {
		SSDFS_ERR("invalid PEB state %#x\n",
			  new_peb_state);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	*old_peb_state = SSDFS_MAPTBL_PEB_STATE_MAX;

	page_index = ssdfs_maptbl_define_pebtbl_page(tbl, fdesc,
						     leb_id, selected_index);
	if (page_index == ULONG_MAX) {
		err = -ERANGE;
		SSDFS_ERR("fail to define PEB table's page_index: "
			  "leb_id %llu\n", leb_id);
		goto finish_fragment_change;
	}

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		goto finish_fragment_change;
	}

	kaddr = kmap_local_page(page);

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;

	if (is_pebtbl_stripe_recovering(hdr)) {
		err = -EACCES;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to change the PEB state: "
			  "leb_id %llu: "
			  "stripe %u is under recovering\n",
			  leb_id,
			  le16_to_cpu(hdr->stripe_id));
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_page_processing;
	}

	item_index = selected_index % fdesc->pebs_per_page;

	peb_desc = GET_PEB_DESCRIPTOR(kaddr, item_index);
	if (IS_ERR_OR_NULL(peb_desc)) {
		err = IS_ERR(peb_desc) ? PTR_ERR(peb_desc) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "page_index %lu, item_index %u, err %d\n",
			  page_index, item_index, err);
		goto finish_page_processing;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("leb_id %llu, item_index %u, "
		  "old_peb_state %#x, new_peb_state %#x\n",
		  leb_id, item_index, peb_desc->state, new_peb_state);
#endif /* CONFIG_SSDFS_DEBUG */

	*old_peb_state = peb_desc->state;

	if (peb_desc->state == (u8)new_peb_state) {
		err = -EEXIST;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("peb_state1 %#x == peb_state2 %#x\n",
			  peb_desc->state,
			  (u8)new_peb_state);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_page_processing;
	} else
		peb_desc->state = (u8)new_peb_state;

finish_page_processing:
	flush_dcache_page(page);
	kunmap_local(kaddr);

	if (!err) {
		ssdfs_set_page_private(page, 0);
		SetPageUptodate(page);
		err = ssdfs_page_array_set_page_dirty(&fdesc->array,
						      page_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu dirty: err %d\n",
				  page_index, err);
		}
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

finish_fragment_change:
	return err;
}

/*
 * ssdfs_maptbl_change_peb_state() - change PEB state
 * @fsi: file system info object
 * @leb_id: LEB ID number
 * @peb_type: type of the PEB
 * @peb_state: new state of the PEB
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to change the state of the PEB
 * in the mapping table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EACCES     - PEB stripe is under recovering.
 * %-ENODATA    - uninitialized LEB descriptor.
 */
int ssdfs_maptbl_change_peb_state(struct ssdfs_fs_info *fsi,
				  u64 leb_id, u8 peb_type, int peb_state,
				  struct completion **end)
{
	struct ssdfs_peb_mapping_table *tbl;
	struct ssdfs_maptbl_cache *cache;
	struct ssdfs_maptbl_fragment_desc *fdesc;
	struct ssdfs_leb_descriptor leb_desc;
	struct ssdfs_maptbl_peb_relation pebr;
	int state;
	u16 selected_index;
	int consistency;
	int old_peb_state = SSDFS_MAPTBL_PEB_STATE_MAX;
	int err = 0;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("fsi %p, leb_id %llu, peb_type %#x, "
		  "peb_state %#x, init_end %p\n",
		  fsi, leb_id, peb_type, peb_state, end);
#else
	SSDFS_DBG("fsi %p, leb_id %llu, peb_type %#x, "
		  "peb_state %#x, init_end %p\n",
		  fsi, leb_id, peb_type, peb_state, end);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !end);
#endif /* CONFIG_SSDFS_DEBUG */

	tbl = fsi->maptbl;
	cache = &tbl->fsi->maptbl_cache;
	*end = NULL;

	if (peb_state <= SSDFS_MAPTBL_UNKNOWN_PEB_STATE ||
	    peb_state >= SSDFS_MAPTBL_PEB_STATE_MAX) {
		SSDFS_ERR("invalid PEB state %#x\n",
			  peb_state);
		return -EINVAL;
	}

	if (!tbl) {
		err = 0;

		if (should_cache_peb_info(peb_type)) {
			consistency = SSDFS_PEB_STATE_INCONSISTENT;
			err = ssdfs_maptbl_cache_change_peb_state(cache,
								  leb_id,
								  peb_state,
								  consistency);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change PEB state: "
					  "leb_id %llu, peb_state %#x, "
					  "err %d\n",
					  leb_id, peb_state, err);
			}
		} else {
			err = -ERANGE;
			SSDFS_CRIT("mapping table is absent\n");
		}

		return err;
	}

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"maptbl has corrupted state\n");
		return -EFAULT;
	}

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_UNDER_FLUSH) {
		if (should_cache_peb_info(peb_type)) {
			consistency = SSDFS_PEB_STATE_INCONSISTENT;
			err = ssdfs_maptbl_cache_change_peb_state(cache,
								  leb_id,
								  peb_state,
								  consistency);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change PEB state: "
					  "leb_id %llu, peb_state %#x, "
					  "err %d\n",
					  leb_id, peb_state, err);
			}

			return err;
		}
	}

	if (should_cache_peb_info(peb_type)) {
		/* resolve potential inconsistency */
		err = ssdfs_maptbl_convert_leb2peb(fsi, leb_id, peb_type,
						   &pebr, end);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fragment is under initialization: "
				  "leb_id %llu\n",
				  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to resolve inconsistency: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			return err;
		}
	}

	if (rwsem_is_locked(&tbl->tbl_lock) &&
	    atomic_read(&tbl->flags) & SSDFS_MAPTBL_UNDER_FLUSH) {
		if (should_cache_peb_info(peb_type)) {
			consistency = SSDFS_PEB_STATE_INCONSISTENT;
			err = ssdfs_maptbl_cache_change_peb_state(cache,
								  leb_id,
								  peb_state,
								  consistency);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change PEB state: "
					  "leb_id %llu, peb_state %#x, "
					  "err %d\n",
					  leb_id, peb_state, err);
			}

			return err;
		}
	}

	down_read(&tbl->tbl_lock);

	fdesc = ssdfs_maptbl_get_fragment_descriptor(tbl, leb_id);
	if (IS_ERR_OR_NULL(fdesc)) {
		err = IS_ERR(fdesc) ? PTR_ERR(fdesc) : -ERANGE;
		SSDFS_ERR("fail to get fragment descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_change_state;
	}

	*end = &fdesc->init_end;

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
		err = -EFAULT;
		SSDFS_ERR("fragment is corrupted: leb_id %llu\n",
			  leb_id);
		goto finish_change_state;
	} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
		err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_change_state;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (rwsem_is_locked(&fdesc->lock)) {
		SSDFS_DBG("fragment is locked -> lock fragment: "
			  "leb_id %llu\n", leb_id);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&fdesc->lock);

	err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
	}

	err = ssdfs_maptbl_get_peb_relation(fdesc, &leb_desc, &pebr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get peb relation: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
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
		selected_index = le16_to_cpu(leb_desc.physical_index);
		break;

	case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_DIRTY_STATE:
		selected_index = le16_to_cpu(leb_desc.relation_index);
		break;

	default:
		BUG();
	}

	if (selected_index == U16_MAX) {
		err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unitialized leb descriptor: "
			  "leb_id %llu\n", leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_fragment_change;
	}

	err = __ssdfs_maptbl_change_peb_state(tbl, fdesc, leb_id,
					      selected_index,
					      peb_state,
					      &old_peb_state);
	if (err == -EEXIST) {
		/*
		 * PEB has this state already.
		 * Don't set fragment dirty!!!
		 */
		goto finish_fragment_change;
	} else if (err == -EACCES) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to change the PEB state: "
			  "leb_id %llu: "
			  "stripe is under recovering\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_fragment_change;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to change the PEB state: "
			  "leb_id %llu, peb_state %#x, err %d\n",
			  leb_id, peb_state, err);
		goto finish_fragment_change;
	}

finish_fragment_change:
	up_write(&fdesc->lock);

	if (!err)
		ssdfs_maptbl_set_fragment_dirty(tbl, fdesc, leb_id);

finish_change_state:
	up_read(&tbl->tbl_lock);

	if (err == -EAGAIN && should_cache_peb_info(peb_type)) {
		consistency = SSDFS_PEB_STATE_INCONSISTENT;
		err = ssdfs_maptbl_cache_change_peb_state(cache,
							  leb_id,
							  peb_state,
							  consistency);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change PEB state: "
				  "leb_id %llu, peb_state %#x, "
				  "err %d\n",
				  leb_id, peb_state, err);
		}
	} else if (!err && should_cache_peb_info(peb_type)) {
		consistency = SSDFS_PEB_STATE_CONSISTENT;
		err = ssdfs_maptbl_cache_change_peb_state(cache,
							  leb_id,
							  peb_state,
							  consistency);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change PEB state: "
				  "leb_id %llu, peb_state %#x, "
				  "err %d\n",
				  leb_id, peb_state, err);
		}
	} else if (err == -EEXIST) {
		/* PEB has this state already */
		err = 0;

		if (should_cache_peb_info(peb_type)) {
			consistency = SSDFS_PEB_STATE_CONSISTENT;
			err = ssdfs_maptbl_cache_change_peb_state(cache,
								  leb_id,
								  peb_state,
								  consistency);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change PEB state: "
					  "leb_id %llu, peb_state %#x, "
					  "err %d\n",
					  leb_id, peb_state, err);
			}
		}
	}

	if (!err && fsi->is_zns_device) {
		u64 peb_id = U64_MAX;

		err = -ENODATA;

		switch (old_peb_state) {
		case SSDFS_MAPTBL_CLEAN_PEB_STATE:
		case SSDFS_MAPTBL_USING_PEB_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_USED_PEB_STATE:
			case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
			case SSDFS_MAPTBL_PRE_ERASE_STATE:
			case SSDFS_MAPTBL_RECOVERING_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
				err = 0;
				selected_index = SSDFS_MAPTBL_MAIN_INDEX;
				peb_id = pebr.pebs[selected_index].peb_id;
				break;

			default:
				/* do nothing */
				break;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
		case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
			switch (peb_state) {
			case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
			case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
			case SSDFS_MAPTBL_MIGRATION_DST_DIRTY_STATE:
				err = 0;
				selected_index = SSDFS_MAPTBL_RELATION_INDEX;
				peb_id = pebr.pebs[selected_index].peb_id;
				break;

			default:
				/* do nothing */
				break;
			}

		default:
			/* do nothing */
			break;
		};

		if (!err) {
			loff_t offset = peb_id * fsi->erasesize;

			err = fsi->devops->close_zone(fsi->sb, offset);
			if (unlikely(err)) {
				SSDFS_ERR("fail to close zone: "
					  "offset %llu, err %d\n",
					  offset, err);
				return err;
			}
		} else
			err = 0;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * __ssdfs_maptbl_unmap_dirty_peb() - unmap dirty PEB
 * @ptr: fragment descriptor
 * @leb_id: LEB ID number
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_maptbl_unmap_dirty_peb(struct ssdfs_maptbl_fragment_desc *ptr,
				   u64 leb_id)
{
	struct ssdfs_leb_table_fragment_header *hdr;
	struct ssdfs_leb_descriptor *leb_desc;
	pgoff_t page_index;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);

	SSDFS_DBG("fdesc %p, leb_id %llu\n",
		  ptr, leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = LEBTBL_PAGE_INDEX(ptr, leb_id);
	if (page_index == ULONG_MAX) {
		SSDFS_ERR("fail to define page_index: "
			  "leb_id %llu\n",
			  leb_id);
		return -ERANGE;
	}

	page = ssdfs_page_array_get_page_locked(&ptr->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap_local_page(page);

	leb_desc = GET_LEB_DESCRIPTOR(kaddr, leb_id);
	if (IS_ERR_OR_NULL(leb_desc)) {
		err = IS_ERR(leb_desc) ? PTR_ERR(leb_desc) : -ERANGE;
		SSDFS_ERR("fail to get leb_descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_page_processing;
	}

	leb_desc->physical_index = cpu_to_le16(U16_MAX);
	leb_desc->relation_index = cpu_to_le16(U16_MAX);

	hdr = (struct ssdfs_leb_table_fragment_header *)kaddr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(le16_to_cpu(hdr->mapped_lebs) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	le16_add_cpu(&hdr->mapped_lebs, -1);

finish_page_processing:
	kunmap_local(kaddr);

	if (!err) {
		ssdfs_set_page_private(page, 0);
		SetPageUptodate(page);
		err = ssdfs_page_array_set_page_dirty(&ptr->array,
						      page_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu dirty: err %d\n",
				  page_index, err);
		}
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_maptbl_prepare_pre_erase_state() - convert dirty PEB into pre-erased
 * @fsi: file system info object
 * @leb_id: LEB ID number
 * @peb_type: type of the PEB
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to convert dirty PEB into pre-erase state
 * in the mapping table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EACCES     - PEB stripe is under recovering.
 * %-ENODATA    - uninitialized LEB descriptor.
 * %-EBUSY      - maptbl is under flush operation.
 */
int ssdfs_maptbl_prepare_pre_erase_state(struct ssdfs_fs_info *fsi,
					 u64 leb_id, u8 peb_type,
					 struct completion **end)
{
	struct ssdfs_peb_mapping_table *tbl;
	struct ssdfs_maptbl_cache *cache;
	struct ssdfs_maptbl_fragment_desc *fdesc;
	struct ssdfs_leb_descriptor leb_desc;
	int state;
	u16 physical_index, relation_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !end);

	SSDFS_DBG("fsi %p, leb_id %llu, peb_type %#x, "
		  "init_end %p\n",
		  fsi, leb_id, peb_type, end);
#endif /* CONFIG_SSDFS_DEBUG */

	tbl = fsi->maptbl;
	cache = &tbl->fsi->maptbl_cache;
	*end = NULL;

	if (!tbl) {
		SSDFS_WARN("operation is not supported\n");
		return -EOPNOTSUPP;
	}

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"maptbl has corrupted state\n");
		return -EFAULT;
	}

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_UNDER_FLUSH) {
		SSDFS_DBG("maptbl is under flush\n");
		return -EBUSY;
	}

	down_read(&tbl->tbl_lock);

	fdesc = ssdfs_maptbl_get_fragment_descriptor(tbl, leb_id);
	if (IS_ERR_OR_NULL(fdesc)) {
		err = IS_ERR(fdesc) ? PTR_ERR(fdesc) : -ERANGE;
		SSDFS_ERR("fail to get fragment descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_change_state;
	}

	*end = &fdesc->init_end;

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
		err = -EFAULT;
		SSDFS_ERR("fragment is corrupted: leb_id %llu\n",
			  leb_id);
		goto finish_change_state;
	} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
		err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_change_state;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (rwsem_is_locked(&fdesc->lock)) {
		SSDFS_DBG("fragment is locked -> lock fragment: "
			  "leb_id %llu\n", leb_id);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&fdesc->lock);

	err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
	}

	if (!__is_mapped_leb2peb(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu doesn't be mapped yet\n",
			  leb_id);
		goto finish_fragment_change;
	}

	if (is_leb_migrating(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu is under migration\n",
			  leb_id);
		goto finish_fragment_change;
	}

	physical_index = le16_to_cpu(leb_desc.physical_index);
	relation_index = le16_to_cpu(leb_desc.relation_index);

	if (relation_index != U16_MAX) {
		err = -EFAULT;
		SSDFS_ERR("fragment is corrupted: leb_id %llu\n",
			  leb_id);
		goto finish_fragment_change;
	}

	err = ssdfs_maptbl_set_pre_erase_state(fdesc, physical_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move PEB into pre-erase state: "
			  "index %u, err %d\n",
			  physical_index, err);
		goto finish_fragment_change;
	}

	err = __ssdfs_maptbl_unmap_dirty_peb(fdesc, leb_id);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(fdesc->mapped_lebs == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	fdesc->mapped_lebs--;
	fdesc->pre_erase_pebs++;
	atomic_inc(&tbl->pre_erase_pebs);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("fdesc->pre_erase_pebs %u, tbl->pre_erase_pebs %d\n",
		  fdesc->pre_erase_pebs,
		  atomic_read(&tbl->pre_erase_pebs));
#endif /* CONFIG_SSDFS_DEBUG */

finish_fragment_change:
	up_write(&fdesc->lock);

	if (!err)
		ssdfs_maptbl_set_fragment_dirty(tbl, fdesc, leb_id);

	if (should_cache_peb_info(peb_type)) {
		err = ssdfs_maptbl_cache_forget_leb2peb(cache, leb_id,
						SSDFS_PEB_STATE_CONSISTENT);
		if (err == -ENODATA || err == -EFAULT) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("leb_id %llu is not in cache already\n",
				  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to forget leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_change_state;
		}
	}

finish_change_state:
	wake_up(&tbl->wait_queue);
	up_read(&tbl->tbl_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_maptbl_set_pre_erased_snapshot_peb() - set snapshot PEB as pre-erased
 * @fsi: file system info object
 * @peb_id: PEB ID number
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to convert snapshot PEB into pre-erase state
 * in the mapping table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EACCES     - PEB stripe is under recovering.
 * %-ENODATA    - uninitialized LEB descriptor.
 * %-EBUSY      - maptbl is under flush operation.
 */
int ssdfs_maptbl_set_pre_erased_snapshot_peb(struct ssdfs_fs_info *fsi,
					     u64 peb_id,
					     struct completion **end)
{
	struct ssdfs_peb_mapping_table *tbl;
	struct ssdfs_maptbl_fragment_desc *fdesc;
	struct ssdfs_peb_descriptor peb_desc;
	int state;
	u16 physical_index;
	u64 found_peb_id;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !end);

	SSDFS_DBG("fsi %p, peb_id %llu, init_end %p\n",
		  fsi, peb_id, end);
#endif /* CONFIG_SSDFS_DEBUG */

	tbl = fsi->maptbl;
	*end = NULL;

	if (!tbl) {
		SSDFS_WARN("operation is not supported\n");
		return -EOPNOTSUPP;
	}

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"maptbl has corrupted state\n");
		return -EFAULT;
	}

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_UNDER_FLUSH) {
		SSDFS_DBG("maptbl is under flush\n");
		return -EBUSY;
	}

	down_read(&tbl->tbl_lock);

	fdesc = ssdfs_maptbl_get_fragment_descriptor(tbl, peb_id);
	if (IS_ERR_OR_NULL(fdesc)) {
		err = IS_ERR(fdesc) ? PTR_ERR(fdesc) : -ERANGE;
		SSDFS_ERR("fail to get fragment descriptor: "
			  "peb_id %llu, err %d\n",
			  peb_id, err);
		goto finish_change_state;
	}

	*end = &fdesc->init_end;

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
		err = -EFAULT;
		SSDFS_ERR("fragment is corrupted: peb_id %llu\n",
			  peb_id);
		goto finish_change_state;
	} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
		err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: peb_id %llu\n",
			  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_change_state;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (rwsem_is_locked(&fdesc->lock)) {
		SSDFS_DBG("fragment is locked -> lock fragment: "
			  "peb_id %llu\n", peb_id);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&fdesc->lock);

	if (peb_id < fdesc->start_leb ||
	    peb_id > (fdesc->start_leb + fdesc->lebs_count)) {
		err = -ERANGE;
		SSDFS_ERR("peb_id %llu is out of range: "
			  "start_leb %llu, lebs_count %u\n",
			  peb_id, fdesc->start_leb, fdesc->lebs_count);
		goto finish_fragment_change;
	}

	physical_index = peb_id - fdesc->start_leb;

	err = ssdfs_maptbl_get_peb_descriptor(fdesc, physical_index,
					      &found_peb_id, &peb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get peb descriptor: "
			  "peb_id %llu, err %d\n",
			  peb_id, err);
		goto finish_fragment_change;
	}

	if (found_peb_id != peb_id) {
		err = -ERANGE;
		SSDFS_ERR("corrupted mapping table: "
			  "found_peb_id %llu != peb_id %llu\n",
			  found_peb_id, peb_id);
		goto finish_fragment_change;
	}

	if (peb_desc.state != SSDFS_MAPTBL_SNAPSHOT_STATE) {
		err = -ERANGE;
		SSDFS_ERR("unexpected PEB state: "
			  "peb_id %llu, state %#x\n",
			  peb_id, peb_desc.state);
		goto finish_fragment_change;
	}

	err = ssdfs_maptbl_set_pre_erase_state(fdesc, physical_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move PEB into pre-erase state: "
			  "index %u, err %d\n",
			  physical_index, err);
		goto finish_fragment_change;
	}

	fdesc->pre_erase_pebs++;
	atomic_inc(&tbl->pre_erase_pebs);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("fdesc->pre_erase_pebs %u, tbl->pre_erase_pebs %d\n",
		  fdesc->pre_erase_pebs,
		  atomic_read(&tbl->pre_erase_pebs));
#endif /* CONFIG_SSDFS_DEBUG */

finish_fragment_change:
	up_write(&fdesc->lock);

	if (!err)
		ssdfs_maptbl_set_fragment_dirty(tbl, fdesc, peb_id);

finish_change_state:
	wake_up(&tbl->wait_queue);
	up_read(&tbl->tbl_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * has_fragment_reserved_pebs() - check that fragment has reserved PEBs
 * @hdr: PEB table fragment's header
 */
static inline
bool has_fragment_reserved_pebs(struct ssdfs_peb_table_fragment_header *hdr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr);

	SSDFS_DBG("hdr %p, reserved_pebs %u\n",
		  hdr, le16_to_cpu(hdr->reserved_pebs));
#endif /* CONFIG_SSDFS_DEBUG */

	return le16_to_cpu(hdr->reserved_pebs) != 0;
}

/*
 * ssdfs_maptbl_select_pebtbl_page() - select page of PEB table
 * @tbl: pointer on mapping table object
 * @fdesc: fragment descriptor
 * @leb_id: LEB ID number
 *
 * This method tries to select a page of PEB table.
 */
static
int ssdfs_maptbl_select_pebtbl_page(struct ssdfs_peb_mapping_table *tbl,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    u64 leb_id, pgoff_t *page_index)
{
	pgoff_t start_page;
	pgoff_t first_valid_page = ULONG_MAX;
	struct page *page;
	void *kaddr;
	struct ssdfs_peb_table_fragment_header *hdr;
	unsigned long *bmap;
	u16 pebs_count, used_pebs;
	u16 unused_pebs, reserved_pebs;
	bool is_recovering = false;
	bool has_reserved_pebs = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("maptbl %p, fdesc %p, leb_id %llu\n",
		  tbl, fdesc, leb_id);

	BUG_ON(!tbl || !fdesc || !page_index);
#endif /* CONFIG_SSDFS_DEBUG */

	*page_index = ssdfs_maptbl_define_pebtbl_page(tbl, fdesc,
						      leb_id, U16_MAX);
	if (*page_index == ULONG_MAX) {
		SSDFS_ERR("fail to define PEB table's page_index: "
			  "leb_id %llu\n", leb_id);
		return -ERANGE;
	}

	start_page = *page_index;

try_next_page:
	page = ssdfs_page_array_get_page_locked(&fdesc->array, *page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: "
			  "page_index %lu, err %d\n",
			  *page_index, err);
		return -ERANGE;
	}

	kaddr = kmap_local_page(page);

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;
	bmap = (unsigned long *)&hdr->bmaps[SSDFS_PEBTBL_USED_BMAP][0];
	pebs_count = le16_to_cpu(hdr->pebs_count);
	used_pebs = bitmap_weight(bmap, pebs_count);
	unused_pebs = pebs_count - used_pebs;
	reserved_pebs = le16_to_cpu(hdr->reserved_pebs);
	is_recovering = is_pebtbl_stripe_recovering(hdr);

	has_reserved_pebs = has_fragment_reserved_pebs(hdr);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d, page_index %lu\n",
		  page, page_ref_count(page), *page_index);
	SSDFS_DBG("pebs_count %u, used_pebs %u, unused_pebs %u, "
		  "reserved_pebs %u, is_recovering %#x, "
		  "has_reserved_pebs %#x\n",
		  pebs_count, used_pebs, unused_pebs,
		  reserved_pebs, is_recovering,
		  has_reserved_pebs);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!has_reserved_pebs) {
		err = ssdfs_maptbl_increase_reserved_pebs(tbl->fsi, fdesc, hdr);
		if (!err) {
			reserved_pebs = le16_to_cpu(hdr->reserved_pebs);
			has_reserved_pebs = has_fragment_reserved_pebs(hdr);
		} else if (err == -ENOSPC && unused_pebs > 0) {
			/* we can take from the unused pool, anyway */
			err = 0;
		}
	}

	kunmap_local(kaddr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

	if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find PEB table page: "
			  "leb_id %llu, page_index %lu\n",
			  leb_id, *page_index);
#endif /* CONFIG_SSDFS_DEBUG */

		*page_index = ssdfs_maptbl_find_pebtbl_page(tbl, fdesc,
							    *page_index,
							    start_page);
		if (*page_index == ULONG_MAX)
			goto use_first_valid_page;
		else {
			err = 0;
			goto try_next_page;
		}
	} else if (unlikely(err)) {
		*page_index = ULONG_MAX;
		SSDFS_ERR("fail to increase reserved pebs: "
			  "err %d\n", err);
		goto finish_select_pebtbl_page;
	}

	if (is_recovering) {
		*page_index = ssdfs_maptbl_find_pebtbl_page(tbl, fdesc,
							    *page_index,
							    start_page);
		if (*page_index == ULONG_MAX)
			goto use_first_valid_page;
		else
			goto try_next_page;
	} else if (!has_reserved_pebs) {
		if (unused_pebs > 0) {
			first_valid_page = *page_index;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("take from unused pool: "
				  "leb_id %llu, unused_pebs %u, "
				  "reserved_pebs %u\n",
				  leb_id, unused_pebs, reserved_pebs);
#endif /* CONFIG_SSDFS_DEBUG */
		} else {
			*page_index = ULONG_MAX;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find PEB table page: "
				  "leb_id %llu\n",
				  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		goto finish_select_pebtbl_page;
	} else if (unused_pebs > 0) {
		first_valid_page = *page_index;

		if (unused_pebs < reserved_pebs) {
			*page_index = ssdfs_maptbl_find_pebtbl_page(tbl, fdesc,
								    *page_index,
								    start_page);
			if (*page_index == ULONG_MAX)
				goto use_first_valid_page;
			else
				goto try_next_page;
		} else
			goto finish_select_pebtbl_page;
	} else
		goto finish_select_pebtbl_page;

use_first_valid_page:
	if (first_valid_page >= ULONG_MAX) {
		if (fdesc->pre_erase_pebs > 0)
			err = -EBUSY;
		else
			err = -ENODATA;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find PEB table page: "
			  "leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	*page_index = first_valid_page;

finish_select_pebtbl_page:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page_index %lu\n", *page_index);
#endif /* CONFIG_SSDFS_DEBUG */
	return err;
}

/*
 * ssdfs_maptbl_set_peb_descriptor() - change PEB descriptor
 * @fdesc: fragment descriptor
 * @pebtbl_page: page index of PEB table
 * @peb_goal: PEB purpose
 * @peb_type: type of the PEB
 * @item_index: item index in the memory page [out]
 *
 * This method tries to change PEB descriptor in the PEB table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_set_peb_descriptor(struct ssdfs_peb_mapping_table *tbl,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    pgoff_t pebtbl_page,
				    int peb_goal,
				    u8 peb_type,
				    u16 *item_index)
{
	struct ssdfs_peb_table_fragment_header *hdr;
	struct ssdfs_peb_descriptor *peb_desc;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc || !item_index);

	SSDFS_DBG("fdesc %p, pebtbl_page %lu, "
		  "peb_goal %#x, peb_type %#x\n",
		  fdesc, pebtbl_page, peb_goal, peb_type);
#endif /* CONFIG_SSDFS_DEBUG */

	*item_index = U16_MAX;

	page = ssdfs_page_array_get_page_locked(&fdesc->array, pebtbl_page);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: "
			  "page_index %lu, err %d\n",
			  pebtbl_page, err);
		return err;
	}

	kaddr = kmap_local_page(page);

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;

	*item_index = ssdfs_maptbl_select_unused_peb(fdesc, hdr,
						     tbl->pebs_count,
						     peb_goal);
	if (*item_index >= U16_MAX) {
		err = -ERANGE;
		SSDFS_DBG("unable to select unused peb\n");
		goto finish_set_peb_descriptor;
	}

	peb_desc = GET_PEB_DESCRIPTOR(hdr, *item_index);
	if (IS_ERR_OR_NULL(peb_desc)) {
		err = IS_ERR(peb_desc) ? PTR_ERR(peb_desc) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "index %u, err %d\n",
			  *item_index, err);
		goto finish_set_peb_descriptor;
	}

	peb_desc->type = peb_type;
	peb_desc->state = SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE;

	ssdfs_set_page_private(page, 0);
	SetPageUptodate(page);
	err = ssdfs_page_array_set_page_dirty(&fdesc->array,
					      pebtbl_page);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page %lu dirty: err %d\n",
			  pebtbl_page, err);
	}

finish_set_peb_descriptor:
	flush_dcache_page(page);
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_maptbl_set_leb_descriptor() - change LEB descriptor
 * @fdesc: fragment descriptor
 * @leb_id: LEB ID number
 * @pebtbl_page: page index of PEB table
 * @item_index: item index in the memory page
 *
 * This method tries to change LEB descriptor in the LEB table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_set_leb_descriptor(struct ssdfs_maptbl_fragment_desc *fdesc,
				    u64 leb_id, pgoff_t pebtbl_page,
				    u16 item_index)
{
	struct ssdfs_leb_descriptor *leb_desc;
	struct ssdfs_leb_table_fragment_header *lebtbl_hdr;
	pgoff_t lebtbl_page;
	u16 peb_index;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);

	SSDFS_DBG("fdesc %p, leb_id %llu, pebtbl_page %lu, "
		  "item_index %u\n",
		  fdesc, leb_id, pebtbl_page, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	lebtbl_page = LEBTBL_PAGE_INDEX(fdesc, leb_id);
	if (lebtbl_page == ULONG_MAX) {
		SSDFS_ERR("fail to define page_index: "
			  "leb_id %llu\n",
			  leb_id);
		return -ERANGE;
	}

	page = ssdfs_page_array_get_page_locked(&fdesc->array, lebtbl_page);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  lebtbl_page);
		return err;
	}

	kaddr = kmap_local_page(page);

	leb_desc = GET_LEB_DESCRIPTOR(kaddr, leb_id);
	if (IS_ERR_OR_NULL(leb_desc)) {
		err = IS_ERR(leb_desc) ? PTR_ERR(leb_desc) : -ERANGE;
		SSDFS_ERR("fail to get leb_descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_page_processing;
	}

	peb_index = DEFINE_PEB_INDEX_IN_FRAGMENT(fdesc,
						 pebtbl_page,
						 item_index);
	if (peb_index == U16_MAX) {
		err = -ERANGE;
		SSDFS_ERR("fail to define peb index\n");
		goto finish_page_processing;
	}

	leb_desc->relation_index = cpu_to_le16(peb_index);

	lebtbl_hdr = (struct ssdfs_leb_table_fragment_header *)kaddr;
	le16_add_cpu(&lebtbl_hdr->migrating_lebs, 1);

	ssdfs_set_page_private(page, 0);
	SetPageUptodate(page);
	err = ssdfs_page_array_set_page_dirty(&fdesc->array,
					      lebtbl_page);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page %lu dirty: err %d\n",
			  lebtbl_page, err);
	}

finish_page_processing:
	flush_dcache_page(page);
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_maptbl_add_migration_peb() - associate PEB for migration
 * @fsi: file system info object
 * @leb_id: LEB ID number
 * @peb_type: type of the PEB
 * @pebr: description of PEBs relation [out]
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to add in the pair destination PEB for
 * data migration.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to find PEB for migration.
 * %-EEXIST     - LEB is under migration yet.
 */
int ssdfs_maptbl_add_migration_peb(struct ssdfs_fs_info *fsi,
				   u64 leb_id, u8 peb_type,
				   struct ssdfs_maptbl_peb_relation *pebr,
				   struct completion **end)
{
	struct ssdfs_peb_mapping_table *tbl;
	struct ssdfs_maptbl_cache *cache;
	struct ssdfs_maptbl_fragment_desc *fdesc;
	int state;
	struct ssdfs_leb_descriptor leb_desc;
	pgoff_t pebtbl_page = ULONG_MAX;
	u16 item_index;
	int consistency;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebr || !end);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("fsi %p, leb_id %llu, pebr %p, init_end %p\n",
		  fsi, leb_id, pebr, end);
#else
	SSDFS_DBG("fsi %p, leb_id %llu, pebr %p, init_end %p\n",
		  fsi, leb_id, pebr, end);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	tbl = fsi->maptbl;
	cache = &tbl->fsi->maptbl_cache;
	*end = NULL;

	memset(pebr, 0xFF, sizeof(struct ssdfs_maptbl_peb_relation));

	if (!tbl) {
		SSDFS_CRIT("mapping table is absent\n");
		return -ERANGE;
	}

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"maptbl has corrupted state\n");
		return -EFAULT;
	}

	if (should_cache_peb_info(peb_type)) {
		struct ssdfs_maptbl_peb_relation prev_pebr;

		/* resolve potential inconsistency */
		err = ssdfs_maptbl_convert_leb2peb(fsi, leb_id, peb_type,
						   &prev_pebr, end);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fragment is under initialization: "
				  "leb_id %llu\n",
				  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to resolve inconsistency: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			return err;
		}
	}

	down_read(&tbl->tbl_lock);

	fdesc = ssdfs_maptbl_get_fragment_descriptor(tbl, leb_id);
	if (IS_ERR_OR_NULL(fdesc)) {
		err = IS_ERR(fdesc) ? PTR_ERR(fdesc) : -ERANGE;
		SSDFS_ERR("fail to get fragment descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_add_migrating_peb;
	}

	*end = &fdesc->init_end;

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
		err = -EFAULT;
		SSDFS_ERR("fragment is corrupted: leb_id %llu\n", leb_id);
		goto finish_add_migrating_peb;
	} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
		err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_add_migrating_peb;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (rwsem_is_locked(&fdesc->lock)) {
		SSDFS_DBG("fragment is locked -> lock fragment: "
			  "leb_id %llu\n", leb_id);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&fdesc->lock);

	err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
	}

	if (!__is_mapped_leb2peb(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu doesn't be mapped yet\n",
			  leb_id);
		goto finish_fragment_change;
	}

	if (is_leb_migrating(&leb_desc)) {
		err = ssdfs_maptbl_get_peb_relation(fdesc, &leb_desc, pebr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get peb relation: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
		} else {
			err = -EEXIST;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("leb %llu is under migration yet\n",
				  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		}
		goto finish_fragment_change;
	}

	err = ssdfs_maptbl_select_pebtbl_page(tbl, fdesc, leb_id, &pebtbl_page);
	if (unlikely(err)) {
		SSDFS_DBG("unable to find the peb table's page\n");
		goto finish_fragment_change;
	}

	err = ssdfs_maptbl_set_peb_descriptor(tbl, fdesc, pebtbl_page,
						SSDFS_MAPTBL_MIGRATING_PEB,
						peb_type, &item_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set PEB descriptor: "
			  "pebtbl_page %lu, "
			  "peb_type %#x, err %d\n",
			  pebtbl_page,
			  peb_type, err);
		goto finish_fragment_change;
	}

	err = ssdfs_maptbl_set_leb_descriptor(fdesc, leb_id,
					      pebtbl_page,
					      item_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set LEB descriptor: "
			  "leb_id %llu, pebtbl_page %lu, "
			  "item_index %u, err %d\n",
			  leb_id, pebtbl_page,
			  item_index, err);
		goto finish_fragment_change;
	}

	fdesc->migrating_lebs++;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("mapped_lebs %u, migrating_lebs %u\n",
		  fdesc->mapped_lebs, fdesc->migrating_lebs);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
	}

	err = ssdfs_maptbl_get_peb_relation(fdesc, &leb_desc, pebr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get peb relation: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
	}

#ifdef CONFIG_SSDFS_DEBUG
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

finish_fragment_change:
	up_write(&fdesc->lock);

	if (!err)
		ssdfs_maptbl_set_fragment_dirty(tbl, fdesc, leb_id);

finish_add_migrating_peb:
	up_read(&tbl->tbl_lock);

	if (!err && should_cache_peb_info(peb_type)) {
		consistency = SSDFS_PEB_STATE_CONSISTENT;
		err = ssdfs_maptbl_cache_add_migration_peb(cache, leb_id,
							   pebr,
							   consistency);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add migration PEB: "
				  "leb_id %llu, peb_id %llu, err %d\n",
				leb_id,
				pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].peb_id,
				err);
			err = -EFAULT;
		}
	}

	if (!err) {
		u64 peb_id = pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX].peb_id;
		loff_t offset = peb_id * fsi->erasesize;

		err = fsi->devops->open_zone(fsi->sb, offset);
		if (err == -EOPNOTSUPP && !fsi->is_zns_device) {
			/* ignore error */
			err = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to open zone: "
				  "offset %llu, err %d\n",
				  offset, err);
			return err;
		}
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * need_erase_peb_now() - does it need to erase PEB now?
 * @fdesc: fragment descriptor
 */
static inline
bool need_erase_peb_now(struct ssdfs_maptbl_fragment_desc *fdesc)
{
	u32 percentage;
	u32 unused_lebs;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);
	BUG_ON(!rwsem_is_locked(&fdesc->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	percentage = (fdesc->pre_erase_pebs * 100) / fdesc->lebs_count;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("lebs_count %u, pre_erase_pebs %u, "
		  "percentage %u\n",
		  fdesc->lebs_count,
		  fdesc->pre_erase_pebs,
		  percentage);
#endif /* CONFIG_SSDFS_DEBUG */

	if (percentage > SSDFS_PRE_ERASE_PEB_THRESHOLD_PCT)
		return true;

	unused_lebs = fdesc->lebs_count;
	unused_lebs -= fdesc->mapped_lebs;
	unused_lebs -= fdesc->migrating_lebs;
	unused_lebs -= fdesc->pre_erase_pebs;
	unused_lebs -= fdesc->recovering_pebs;

	percentage = (unused_lebs * 100) / fdesc->lebs_count;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("lebs_count %u, mapped_lebs %u, "
		  "migrating_lebs %u, pre_erase_pebs %u, "
		  "recovering_pebs %u, reserved_pebs %u, "
		  "percentage %u\n",
		  fdesc->lebs_count, fdesc->mapped_lebs,
		  fdesc->migrating_lebs, fdesc->pre_erase_pebs,
		  fdesc->recovering_pebs, fdesc->reserved_pebs,
		  percentage);
#endif /* CONFIG_SSDFS_DEBUG */

	if (percentage <= SSDFS_UNUSED_LEB_THRESHOLD_PCT)
		return true;

	return false;
}

/*
 * ssdfs_maptbl_erase_reserved_peb_now() - erase reserved dirty PEB
 * @fsi: file system info object
 * @leb_id: LEB ID number
 * @peb_type: PEB type
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to erase a reserved dirty PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_maptbl_erase_reserved_peb_now(struct ssdfs_fs_info *fsi,
					u64 leb_id, u8 peb_type,
					struct completion **end)
{
	struct ssdfs_peb_mapping_table *tbl;
	struct ssdfs_maptbl_fragment_desc *fdesc;
	struct ssdfs_maptbl_peb_relation pebr;
	struct ssdfs_maptbl_peb_descriptor *ptr;
	struct ssdfs_erase_result res;
	int state;
	struct ssdfs_leb_descriptor leb_desc;
	u16 physical_index;
	u64 peb_id;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !end);

	SSDFS_DBG("fsi %p, leb_id %llu, init_end %p\n",
		  fsi, leb_id, end);
#endif /* CONFIG_SSDFS_DEBUG */

	tbl = fsi->maptbl;
	*end = NULL;

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"maptbl has corrupted state\n");
		return -EFAULT;
	}

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_UNDER_FLUSH)
		BUG();

	down_read(&tbl->tbl_lock);

	fdesc = ssdfs_maptbl_get_fragment_descriptor(tbl, leb_id);
	if (IS_ERR_OR_NULL(fdesc)) {
		err = IS_ERR(fdesc) ? PTR_ERR(fdesc) : -ERANGE;
		SSDFS_ERR("fail to get fragment descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_erase_reserved_peb;
	}

	*end = &fdesc->init_end;

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
		err = -EFAULT;
		SSDFS_ERR("fragment is corrupted: leb_id %llu\n", leb_id);
		goto finish_erase_reserved_peb;
	} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
		err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_erase_reserved_peb;
	}

	down_write(&fdesc->lock);

	err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
	}

	if (!__is_mapped_leb2peb(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu has not been mapped yet\n",
			  leb_id);
		goto finish_fragment_change;
	}

	physical_index = le16_to_cpu(leb_desc.physical_index);

	err = ssdfs_maptbl_get_peb_relation(fdesc, &leb_desc, &pebr);
	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to get peb relation: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_fragment_change;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to get peb relation: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
	}

	err = ssdfs_maptbl_set_under_erase_state(fdesc, physical_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set PEB as under erase state: "
			  "index %u, err %d\n",
			  physical_index, err);
		goto finish_fragment_change;
	}

	ptr = &pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX];
	peb_id = ptr->peb_id;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("erase peb_id %llu now\n",
		  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_ERASE_RESULT_INIT(fdesc->fragment_id, physical_index,
				peb_id, SSDFS_ERASE_RESULT_UNKNOWN,
				&res);

	up_write(&fdesc->lock);
	err = ssdfs_maptbl_erase_peb(fsi, &res);
	if (unlikely(err)) {
		SSDFS_ERR("fail to erase: "
			  "peb_id %llu, err %d\n",
			  peb_id, err);
		goto finish_erase_reserved_peb;
	}
	down_write(&fdesc->lock);

	switch (res.state) {
	case SSDFS_ERASE_DONE:
		res.state = SSDFS_ERASE_SB_PEB_DONE;
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to erase: peb_id %llu\n",
			  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		break;
	}

	fdesc->pre_erase_pebs++;
	atomic_inc(&tbl->pre_erase_pebs);

	err = ssdfs_maptbl_correct_dirty_peb(tbl, fdesc, &res);
	if (unlikely(err)) {
		SSDFS_ERR("fail to correct dirty PEB's state: "
			  "err %d\n", err);
		goto finish_fragment_change;
	}

finish_fragment_change:
	up_write(&fdesc->lock);

	if (!err)
		ssdfs_maptbl_set_fragment_dirty(tbl, fdesc, leb_id);

finish_erase_reserved_peb:
	up_read(&tbl->tbl_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * is_ssdfs_peb_contains_snapshot() - check that PEB contains snapshot
 * @fsi: file system info object
 * @peb_type: PEB type
 * @peb_create_time: PEB creation time
 * @last_log_time: last log creation time
 *
 * This method tries to check that PEB contains a snapshot.
 */
static
bool is_ssdfs_peb_contains_snapshot(struct ssdfs_fs_info *fsi,
				    u8 peb_type,
				    u64 peb_create_time,
				    u64 last_log_time)
{
	struct ssdfs_snapshots_btree_info *tree;
	struct ssdfs_btree_search *search = NULL;
	struct ssdfs_timestamp_range range;
	bool is_contains_snapshot = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("peb_type %#x, peb_create_time %llu, "
		  "last_log_time %llu\n",
		  peb_type, peb_create_time,
		  last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (peb_type) {
	case SSDFS_MAPTBL_DATA_PEB_TYPE:
	case SSDFS_MAPTBL_LNODE_PEB_TYPE:
	case SSDFS_MAPTBL_HNODE_PEB_TYPE:
	case SSDFS_MAPTBL_IDXNODE_PEB_TYPE:
		/* continue logic */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("PEB hasn't snapshot: "
			  "peb_type %#x\n",
			  peb_type);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	tree = fsi->snapshots.tree;

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto finish_search_snapshots_range;
	}

	range.start = peb_create_time;
	range.end = last_log_time;

	ssdfs_btree_search_init(search);
	err = ssdfs_snapshots_btree_check_range(tree, &range, search);
	if (err == -ENODATA) {
		err = 0;
		is_contains_snapshot = false;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find snapshot: "
			  "start_timestamp %llu, end_timestamp %llu\n",
			  peb_create_time, last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */
	} else if (err == -EAGAIN) {
		err = 0;
		is_contains_snapshot = true;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("snapshots have been found: "
			  "start_timestamp %llu, end_timestamp %llu\n",
			  peb_create_time, last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */
	} else if (unlikely(err)) {
		SSDFS_WARN("fail to find snapshot: "
			  "start_timestamp %llu, end_timestamp %llu, "
			  "err %d\n",
			  peb_create_time, last_log_time, err);
	} else {
		is_contains_snapshot = true;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("snapshots have been found: "
			  "start_timestamp %llu, end_timestamp %llu\n",
			  peb_create_time, last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */
	}

finish_search_snapshots_range:
	ssdfs_btree_search_free(search);

	if (unlikely(err))
		return false;

	return is_contains_snapshot;
}

/*
 * ssdfs_maptbl_exclude_migration_peb() - exclude PEB from migration
 * @fsi: file system info object
 * @leb_id: LEB ID number
 * @peb_type: PEB type
 * @peb_create_time: PEB creation time
 * @last_log_time: last log creation time
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to exclude PEB from migration association.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_maptbl_exclude_migration_peb(struct ssdfs_fs_info *fsi,
					u64 leb_id, u8 peb_type,
					u64 peb_create_time,
					u64 last_log_time,
					struct completion **end)
{
	struct ssdfs_peb_mapping_table *tbl;
	struct ssdfs_maptbl_cache *cache;
	struct ssdfs_snapshots_btree_info *snap_tree;
	struct ssdfs_maptbl_fragment_desc *fdesc;
	struct ssdfs_maptbl_peb_relation pebr;
	struct ssdfs_maptbl_peb_descriptor *ptr;
	struct ssdfs_erase_result res;
	int state;
	struct ssdfs_leb_descriptor leb_desc;
	u16 physical_index, relation_index;
	int consistency;
	u64 peb_id;
	bool need_erase = false;
	bool peb_contains_snapshot = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !end);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("fsi %p, leb_id %llu, init_end %p\n",
		  fsi, leb_id, end);
#else
	SSDFS_DBG("fsi %p, leb_id %llu, init_end %p\n",
		  fsi, leb_id, end);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	tbl = fsi->maptbl;
	cache = &tbl->fsi->maptbl_cache;
	snap_tree = fsi->snapshots.tree;
	*end = NULL;

	if (!tbl) {
		err = 0;

		if (should_cache_peb_info(peb_type)) {
			consistency = SSDFS_PEB_STATE_PRE_DELETED;
			err = ssdfs_maptbl_cache_exclude_migration_peb(cache,
								leb_id,
								consistency);
			if (unlikely(err)) {
				SSDFS_ERR("fail to exclude migration PEB: "
					  "leb_id %llu, err %d\n",
					  leb_id, err);
			}
		} else {
			err = -ERANGE;
			SSDFS_CRIT("mapping table is absent\n");
		}

		return err;
	}

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"maptbl has corrupted state\n");
		return -EFAULT;
	}

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_UNDER_FLUSH) {
		if (should_cache_peb_info(peb_type)) {
			consistency = SSDFS_PEB_STATE_PRE_DELETED;
			err = ssdfs_maptbl_cache_exclude_migration_peb(cache,
								leb_id,
								consistency);
			if (unlikely(err)) {
				SSDFS_ERR("fail to exclude migration PEB: "
					  "leb_id %llu, err %d\n",
					  leb_id, err);
			}

			return err;
		}
	}

	if (should_cache_peb_info(peb_type)) {
		struct ssdfs_maptbl_peb_relation prev_pebr;

		/* resolve potential inconsistency */
		err = ssdfs_maptbl_convert_leb2peb(fsi, leb_id, peb_type,
						   &prev_pebr, end);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fragment is under initialization: "
				  "leb_id %llu\n",
				  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to resolve inconsistency: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			return err;
		}
	}

	if (rwsem_is_locked(&tbl->tbl_lock) &&
	    atomic_read(&tbl->flags) & SSDFS_MAPTBL_UNDER_FLUSH) {
		if (should_cache_peb_info(peb_type)) {
			consistency = SSDFS_PEB_STATE_PRE_DELETED;
			err = ssdfs_maptbl_cache_exclude_migration_peb(cache,
								leb_id,
								consistency);
			if (unlikely(err)) {
				SSDFS_ERR("fail to exclude migration PEB: "
					  "leb_id %llu, err %d\n",
					  leb_id, err);
			}

			return err;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_create_time %llx, last_log_time %llx\n",
		  peb_create_time, last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */

	peb_contains_snapshot = is_ssdfs_peb_contains_snapshot(fsi, peb_type,
								peb_create_time,
								last_log_time);

	down_read(&tbl->tbl_lock);

	fdesc = ssdfs_maptbl_get_fragment_descriptor(tbl, leb_id);
	if (IS_ERR_OR_NULL(fdesc)) {
		err = IS_ERR(fdesc) ? PTR_ERR(fdesc) : -ERANGE;
		SSDFS_ERR("fail to get fragment descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_exclude_migrating_peb;
	}

	*end = &fdesc->init_end;

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
		err = -EFAULT;
		SSDFS_ERR("fragment is corrupted: leb_id %llu\n", leb_id);
		goto finish_exclude_migrating_peb;
	} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
		err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_exclude_migrating_peb;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (rwsem_is_locked(&fdesc->lock)) {
		SSDFS_DBG("fragment is locked -> lock fragment: "
			  "leb_id %llu\n", leb_id);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&fdesc->lock);

	err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
	}

	if (!__is_mapped_leb2peb(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu has not been mapped yet\n",
			  leb_id);
		goto finish_fragment_change;
	}

	if (!is_leb_migrating(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu isn't under migration\n",
			  leb_id);
		goto finish_fragment_change;
	}

	physical_index = le16_to_cpu(leb_desc.physical_index);
	relation_index = le16_to_cpu(leb_desc.relation_index);

	need_erase = need_erase_peb_now(fdesc);

	if (peb_contains_snapshot) {
		struct ssdfs_peb_timestamps peb2time;
		struct ssdfs_btree_search *search = NULL;

		need_erase = false;

		err = ssdfs_maptbl_get_peb_relation(fdesc, &leb_desc, &pebr);
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to get peb relation: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_fragment_change;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get peb relation: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_fragment_change;
		}

		err = ssdfs_maptbl_set_snapshot_state(fdesc, physical_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move PEB into snapshot state: "
				  "index %u, err %d\n",
				  physical_index, err);
			goto finish_fragment_change;
		}

		peb2time.peb_id = pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id;
		peb2time.create_time = peb_create_time;
		peb2time.last_log_time = last_log_time;

		search = ssdfs_btree_search_alloc();
		if (!search) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate btree search object\n");
			goto finish_fragment_change;
		}

		ssdfs_btree_search_init(search);
		err = ssdfs_snapshots_btree_add_peb2time(snap_tree, &peb2time,
							 search);
		ssdfs_btree_search_free(search);

		if (unlikely(err)) {
			SSDFS_ERR("fail to add peb2time: "
				  "peb_id %llu, peb_create_time %llu, "
				  "last_log_time %llu, err %d\n",
				  peb2time.peb_id, peb2time.create_time,
				  peb2time.last_log_time, err);
			goto finish_fragment_change;
		}

		err = ssdfs_maptbl_set_source_state(fdesc, relation_index,
					    SSDFS_MAPTBL_UNKNOWN_PEB_STATE);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move PEB into source state: "
				  "index %u, err %d\n",
				  relation_index, err);
			goto finish_fragment_change;
		}

		err = __ssdfs_maptbl_exclude_migration_peb(fdesc, leb_id);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change leb descriptor: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_fragment_change;
		}
	} else if (need_erase) {
		err = ssdfs_maptbl_get_peb_relation(fdesc, &leb_desc, &pebr);
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to get peb relation: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_fragment_change;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get peb relation: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_fragment_change;
		}

		err = ssdfs_maptbl_set_under_erase_state(fdesc, physical_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set PEB as under erase state: "
				  "index %u, err %d\n",
				  physical_index, err);
			goto finish_fragment_change;
		}

		err = ssdfs_maptbl_set_source_state(fdesc, relation_index,
					    SSDFS_MAPTBL_UNKNOWN_PEB_STATE);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move PEB into source state: "
				  "index %u, err %d\n",
				  relation_index, err);
			goto finish_fragment_change;
		}

		err = __ssdfs_maptbl_exclude_migration_peb(fdesc, leb_id);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change leb descriptor: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_fragment_change;
		}

		ptr = &pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX];
		peb_id = ptr->peb_id;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("erase peb_id %llu now\n",
			  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

		SSDFS_ERASE_RESULT_INIT(fdesc->fragment_id, physical_index,
					peb_id, SSDFS_ERASE_RESULT_UNKNOWN,
					&res);

		up_write(&fdesc->lock);
		err = ssdfs_maptbl_erase_peb(fsi, &res);
		if (unlikely(err)) {
			SSDFS_ERR("fail to erase: "
				  "peb_id %llu, err %d\n",
				  peb_id, err);
			goto finish_exclude_migrating_peb;
		}
		down_write(&fdesc->lock);

		switch (res.state) {
		case SSDFS_ERASE_DONE:
			/* expected state */
			break;

		default:
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to erase: peb_id %llu\n",
				  peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			break;
		}
	} else {
		err = ssdfs_maptbl_set_pre_erase_state(fdesc, physical_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move PEB into pre-erase state: "
				  "index %u, err %d\n",
				  physical_index, err);
			goto finish_fragment_change;
		}

		err = ssdfs_maptbl_set_source_state(fdesc, relation_index,
					    SSDFS_MAPTBL_UNKNOWN_PEB_STATE);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move PEB into source state: "
				  "index %u, err %d\n",
				  relation_index, err);
			goto finish_fragment_change;
		}

		err = __ssdfs_maptbl_exclude_migration_peb(fdesc, leb_id);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change leb descriptor: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_fragment_change;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(fdesc->migrating_lebs == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	fdesc->migrating_lebs--;
	fdesc->pre_erase_pebs++;
	atomic_inc(&tbl->pre_erase_pebs);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("mapped_lebs %u, migrating_lebs %u\n",
		  fdesc->mapped_lebs, fdesc->migrating_lebs);
	SSDFS_DBG("fdesc->pre_erase_pebs %u, tbl->pre_erase_pebs %d\n",
		  fdesc->pre_erase_pebs,
		  atomic_read(&tbl->pre_erase_pebs));
#endif /* CONFIG_SSDFS_DEBUG */

	if (need_erase) {
		err = ssdfs_maptbl_correct_dirty_peb(tbl, fdesc, &res);
		if (unlikely(err)) {
			SSDFS_ERR("fail to correct dirty PEB's state: "
				  "err %d\n", err);
			goto finish_fragment_change;
		}
	}

	wake_up(&tbl->wait_queue);

finish_fragment_change:
	up_write(&fdesc->lock);

	if (!err)
		ssdfs_maptbl_set_fragment_dirty(tbl, fdesc, leb_id);

finish_exclude_migrating_peb:
	up_read(&tbl->tbl_lock);

	if (err == -EAGAIN && should_cache_peb_info(peb_type)) {
		consistency = SSDFS_PEB_STATE_PRE_DELETED;
		err = ssdfs_maptbl_cache_exclude_migration_peb(cache,
								leb_id,
								consistency);
		if (unlikely(err)) {
			SSDFS_ERR("fail to exclude migration PEB: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
		}
	} else if (!err && should_cache_peb_info(peb_type)) {
		consistency = SSDFS_PEB_STATE_CONSISTENT;
		err = ssdfs_maptbl_cache_exclude_migration_peb(cache,
								leb_id,
								consistency);
		if (unlikely(err)) {
			SSDFS_ERR("fail to exclude migration PEB: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
		}
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_maptbl_set_peb_as_shared() - set destination PEB as shared
 * @fdesc: fragment descriptor
 * @index: PEB index in the fragment
 * @peb_type: PEB type
 *
 * This method tries to set SSDFS_MAPTBL_SHARED_DESTINATION_PEB flag
 * in destination PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_set_peb_as_shared(struct ssdfs_maptbl_fragment_desc *fdesc,
				   u16 index, u8 peb_type)
{
	struct ssdfs_peb_descriptor *ptr;
	pgoff_t page_index;
	u16 item_index;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);

	SSDFS_DBG("fdesc %p, index %u\n",
		  fdesc, index);
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = PEBTBL_PAGE_INDEX(fdesc, index);
	item_index = index % fdesc->pebs_per_page;

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap_local_page(page);

	ptr = GET_PEB_DESCRIPTOR(kaddr, item_index);
	if (IS_ERR_OR_NULL(ptr)) {
		err = IS_ERR(ptr) ? PTR_ERR(ptr) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "page_index %lu, item_index %u, err %d\n",
			  page_index, item_index, err);
		goto finish_page_processing;
	}

	if (peb_type != ptr->type) {
		err = -ERANGE;
		SSDFS_ERR("peb_type %#x != ptr->type %#x\n",
			  peb_type, ptr->type);
		goto finish_page_processing;
	}

	switch (ptr->state) {
	case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
		/* valid state */
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid PEB state %#x\n",
			  ptr->state);
		goto finish_page_processing;
	}

	if (ptr->flags & SSDFS_MAPTBL_SOURCE_PEB_HAS_EXT_PTR ||
	    ptr->shared_peb_index != U16_MAX) {
		err = -ERANGE;
		SSDFS_ERR("corrupted PEB desriptor\n");
		goto finish_page_processing;
	}

	ptr->flags |= SSDFS_MAPTBL_SHARED_DESTINATION_PEB;

finish_page_processing:
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_maptbl_set_shared_destination_peb() - set destination PEB as shared
 * @tbl: pointer on mapping table object
 * @leb_id: LEB ID number
 * @peb_type: PEB type
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to set SSDFS_MAPTBL_SHARED_DESTINATION_PEB flag
 * in destination PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_set_shared_destination_peb(struct ssdfs_peb_mapping_table *tbl,
					    u64 leb_id, u8 peb_type,
					    struct completion **end)
{
	struct ssdfs_maptbl_fragment_desc *fdesc;
	int state;
	struct ssdfs_leb_descriptor leb_desc;
	u16 relation_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !end);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));

	SSDFS_DBG("maptbl %p, leb_id %llu, peb_type %#x\n",
		  tbl, leb_id, peb_type);
#endif /* CONFIG_SSDFS_DEBUG */

	fdesc = ssdfs_maptbl_get_fragment_descriptor(tbl, leb_id);
	if (IS_ERR_OR_NULL(fdesc)) {
		err = IS_ERR(fdesc) ? PTR_ERR(fdesc) : -ERANGE;
		SSDFS_ERR("fail to get fragment descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		return err;
	}

	*end = &fdesc->init_end;

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
		err = -EFAULT;
		SSDFS_ERR("fragment is corrupted: leb_id %llu\n", leb_id);
		return err;
	} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
		err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	}

	down_write(&fdesc->lock);

	err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
	}

	if (!__is_mapped_leb2peb(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu doesn't be mapped yet\n",
			  leb_id);
		goto finish_fragment_change;
	}

	if (!is_leb_migrating(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu isn't under migration\n",
			  leb_id);
		goto finish_fragment_change;
	}

	relation_index = le16_to_cpu(leb_desc.relation_index);

	if (relation_index == U16_MAX) {
		err = -ENODATA;
		SSDFS_DBG("unitialized leb descriptor\n");
		goto finish_fragment_change;
	}

	err = ssdfs_maptbl_set_peb_as_shared(fdesc, relation_index,
					     peb_type);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set shared destination PEB: "
			  "relation_index %u, err %d\n",
			  relation_index, err);
		goto finish_fragment_change;
	}

finish_fragment_change:
	up_write(&fdesc->lock);

	if (!err)
		ssdfs_maptbl_set_fragment_dirty(tbl, fdesc, leb_id);

	return err;
}

/*
 * ssdfs_maptbl_set_external_peb_ptr() - define PEB as external pointer
 * @fdesc: fragment descriptor
 * @index: PEB index in the fragment
 * @peb_type: PEB type
 * @dst_peb_index: destination PEB index
 *
 * This method tries to define index of destination PEB and to set
 * SSDFS_MAPTBL_SOURCE_PEB_HAS_EXT_PTR flag.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_set_external_peb_ptr(struct ssdfs_maptbl_fragment_desc *fdesc,
				      u16 index, u8 peb_type,
				      u16 dst_peb_index)
{
	struct ssdfs_peb_descriptor *ptr;
	pgoff_t page_index;
	u16 item_index;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);

	SSDFS_DBG("fdesc %p, index %u\n",
		  fdesc, index);
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = PEBTBL_PAGE_INDEX(fdesc, index);
	item_index = index % fdesc->pebs_per_page;

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap_local_page(page);

	ptr = GET_PEB_DESCRIPTOR(kaddr, item_index);
	if (IS_ERR_OR_NULL(ptr)) {
		err = IS_ERR(ptr) ? PTR_ERR(ptr) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "page_index %lu, item_index %u, err %d\n",
			  page_index, item_index, err);
		goto finish_page_processing;
	}

	if (peb_type != ptr->type) {
		err = -ERANGE;
		SSDFS_ERR("peb_type %#x != ptr->type %#x\n",
			  peb_type, ptr->type);
		goto finish_page_processing;
	}

	if (ptr->flags & SSDFS_MAPTBL_SHARED_DESTINATION_PEB) {
		err = -ERANGE;
		SSDFS_ERR("corrupted PEB desriptor\n");
		goto finish_page_processing;
	}

	switch (ptr->state) {
	case SSDFS_MAPTBL_USED_PEB_STATE:
		ptr->state = SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE;
		break;

	case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
		ptr->state = SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE;
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid PEB state %#x\n",
			  ptr->state);
		goto finish_page_processing;
	}

	if (dst_peb_index >= U8_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid dst_peb_index %u\n",
			  dst_peb_index);
		goto finish_page_processing;
	}

	ptr->shared_peb_index = (u8)dst_peb_index;
	ptr->flags |= SSDFS_MAPTBL_SOURCE_PEB_HAS_EXT_PTR;

finish_page_processing:
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * __ssdfs_maptbl_set_indirect_relation() - set destination PEB as shared
 * @tbl: pointer on mapping table object
 * @leb_id: LEB ID number
 * @peb_type: PEB type
 * @dst_peb_index: destination PEB index
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to define index of destination PEB and to set
 * SSDFS_MAPTBL_SOURCE_PEB_HAS_EXT_PTR flag.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_maptbl_set_indirect_relation(struct ssdfs_peb_mapping_table *tbl,
					 u64 leb_id, u8 peb_type,
					 u16 dst_peb_index,
					 struct completion **end)
{
	struct ssdfs_maptbl_fragment_desc *fdesc;
	int state;
	struct ssdfs_leb_descriptor leb_desc;
	u16 physical_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !end);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));

	SSDFS_DBG("maptbl %p, leb_id %llu, peb_type %#x, "
		  "dst_peb_index %u\n",
		  tbl, leb_id, peb_type, dst_peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	fdesc = ssdfs_maptbl_get_fragment_descriptor(tbl, leb_id);
	if (IS_ERR_OR_NULL(fdesc)) {
		err = IS_ERR(fdesc) ? PTR_ERR(fdesc) : -ERANGE;
		SSDFS_ERR("fail to get fragment descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		return err;
	}

	*end = &fdesc->init_end;

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
		err = -EFAULT;
		SSDFS_ERR("fragment is corrupted: leb_id %llu\n", leb_id);
		return err;
	} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
		err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	}

	down_write(&fdesc->lock);

	err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
	}

	if (!__is_mapped_leb2peb(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu doesn't be mapped yet\n",
			  leb_id);
		goto finish_fragment_change;
	}

	if (is_leb_migrating(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu has direct relation\n",
			  leb_id);
		goto finish_fragment_change;
	}

	physical_index = le16_to_cpu(leb_desc.physical_index);

	if (physical_index == U16_MAX) {
		err = -ENODATA;
		SSDFS_DBG("unitialized leb descriptor\n");
		goto finish_fragment_change;
	}

	err = ssdfs_maptbl_set_external_peb_ptr(fdesc, physical_index,
						peb_type, dst_peb_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set external PEB pointer: "
			  "physical_index %u, err %d\n",
			  physical_index, err);
		goto finish_fragment_change;
	}

finish_fragment_change:
	up_write(&fdesc->lock);

	if (!err)
		ssdfs_maptbl_set_fragment_dirty(tbl, fdesc, leb_id);

	return err;
}

/*
 * ssdfs_maptbl_set_indirect_relation() - set PEBs indirect relation
 * @tbl: pointer on mapping table object
 * @leb_id: source LEB ID number
 * @peb_type: PEB type
 * @dst_leb_id: destination LEB ID number
 * @dst_peb_index: destination PEB index
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to set SSDFS_MAPTBL_SHARED_DESTINATION_PEB flag
 * in destination PEB. Then it tries to define index of destination PEB
 * and to set SSDFS_MAPTBL_SOURCE_PEB_HAS_EXT_PTR flag.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-ERANGE     - internal error.
 */
int ssdfs_maptbl_set_indirect_relation(struct ssdfs_peb_mapping_table *tbl,
					u64 leb_id, u8 peb_type,
					u64 dst_leb_id, u16 dst_peb_index,
					struct completion **end)
{
	struct ssdfs_fs_info *fsi;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !end);

	SSDFS_DBG("maptbl %p, leb_id %llu, "
		  "peb_type %#x, dst_peb_index %u\n",
		  tbl, leb_id, peb_type, dst_peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	*end = NULL;
	fsi = tbl->fsi;

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"maptbl has corrupted state\n");
		return -EFAULT;
	}

	if (should_cache_peb_info(peb_type)) {
		struct ssdfs_maptbl_peb_relation prev_pebr;

		/* resolve potential inconsistency */
		err = ssdfs_maptbl_convert_leb2peb(fsi, leb_id, peb_type,
						   &prev_pebr, end);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fragment is under initialization: "
				  "leb_id %llu\n",
				  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to resolve inconsistency: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			return err;
		}
	}

	down_read(&tbl->tbl_lock);

	err = ssdfs_maptbl_set_shared_destination_peb(tbl, dst_leb_id,
						      peb_type, end);
	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  dst_leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_set_indirect_relation;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to set shared destination PEB: "
			  "dst_leb_id %llu, err %u\n",
			  dst_leb_id, err);
		goto finish_set_indirect_relation;
	}

	err = __ssdfs_maptbl_set_indirect_relation(tbl, leb_id, peb_type,
						   dst_peb_index, end);
	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_set_indirect_relation;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to set indirect relation: "
			  "leb_id %llu, err %u\n",
			  leb_id, err);
		goto finish_set_indirect_relation;
	}

finish_set_indirect_relation:
	up_read(&tbl->tbl_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_maptbl_set_zns_external_peb_ptr() - define zone as external pointer
 * @fdesc: fragment descriptor
 * @index: PEB index in the fragment
 * @peb_type: PEB type
 *
 * This method tries to set SSDFS_MAPTBL_SOURCE_PEB_HAS_ZONE_PTR flag.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static int
ssdfs_maptbl_set_zns_external_peb_ptr(struct ssdfs_maptbl_fragment_desc *fdesc,
				      u16 index, u8 peb_type)
{
	struct ssdfs_peb_descriptor *ptr;
	pgoff_t page_index;
	u16 item_index;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);

	SSDFS_DBG("fdesc %p, index %u\n",
		  fdesc, index);
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = PEBTBL_PAGE_INDEX(fdesc, index);
	item_index = index % fdesc->pebs_per_page;

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap_local_page(page);

	ptr = GET_PEB_DESCRIPTOR(kaddr, item_index);
	if (IS_ERR_OR_NULL(ptr)) {
		err = IS_ERR(ptr) ? PTR_ERR(ptr) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "page_index %lu, item_index %u, err %d\n",
			  page_index, item_index, err);
		goto finish_page_processing;
	}

	if (peb_type != ptr->type) {
		err = -ERANGE;
		SSDFS_ERR("peb_type %#x != ptr->type %#x\n",
			  peb_type, ptr->type);
		goto finish_page_processing;
	}

	if (ptr->flags & SSDFS_MAPTBL_SHARED_DESTINATION_PEB) {
		err = -ERANGE;
		SSDFS_ERR("corrupted PEB desriptor\n");
		goto finish_page_processing;
	}

	switch (ptr->state) {
	case SSDFS_MAPTBL_USED_PEB_STATE:
		ptr->state = SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE;
		break;

	case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
		ptr->state = SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE;
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid PEB state %#x\n",
			  ptr->state);
		goto finish_page_processing;
	}

	ptr->shared_peb_index = U8_MAX;
	ptr->flags |= SSDFS_MAPTBL_SOURCE_PEB_HAS_ZONE_PTR;

finish_page_processing:
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * __ssdfs_maptbl_set_zns_indirect_relation() - set PEBs indirect relation
 * @tbl: pointer on mapping table object
 * @leb_id: LEB ID number
 * @peb_type: PEB type
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to set SSDFS_MAPTBL_SOURCE_PEB_HAS_ZONE_PTR flag.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-ERANGE     - internal error.
 */
static int
__ssdfs_maptbl_set_zns_indirect_relation(struct ssdfs_peb_mapping_table *tbl,
					 u64 leb_id, u8 peb_type,
					 struct completion **end)
{
	struct ssdfs_maptbl_fragment_desc *fdesc;
	int state;
	struct ssdfs_leb_descriptor leb_desc;
	u16 physical_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !end);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));

	SSDFS_DBG("maptbl %p, leb_id %llu, peb_type %#x\n",
		  tbl, leb_id, peb_type);
#endif /* CONFIG_SSDFS_DEBUG */

	fdesc = ssdfs_maptbl_get_fragment_descriptor(tbl, leb_id);
	if (IS_ERR_OR_NULL(fdesc)) {
		err = IS_ERR(fdesc) ? PTR_ERR(fdesc) : -ERANGE;
		SSDFS_ERR("fail to get fragment descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		return err;
	}

	*end = &fdesc->init_end;

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
		err = -EFAULT;
		SSDFS_ERR("fragment is corrupted: leb_id %llu\n", leb_id);
		return err;
	} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
		err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	}

	down_write(&fdesc->lock);

	err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
	}

	if (!__is_mapped_leb2peb(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu doesn't be mapped yet\n",
			  leb_id);
		goto finish_fragment_change;
	}

	if (is_leb_migrating(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu has direct relation\n",
			  leb_id);
		goto finish_fragment_change;
	}

	physical_index = le16_to_cpu(leb_desc.physical_index);

	if (physical_index == U16_MAX) {
		err = -ENODATA;
		SSDFS_DBG("unitialized leb descriptor\n");
		goto finish_fragment_change;
	}

	err = ssdfs_maptbl_set_zns_external_peb_ptr(fdesc, physical_index,
						    peb_type);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set external PEB pointer: "
			  "physical_index %u, err %d\n",
			  physical_index, err);
		goto finish_fragment_change;
	}

finish_fragment_change:
	up_write(&fdesc->lock);

	if (!err)
		ssdfs_maptbl_set_fragment_dirty(tbl, fdesc, leb_id);

	return err;
}

/*
 * ssdfs_maptbl_set_zns_indirect_relation() - set PEBs indirect relation
 * @tbl: pointer on mapping table object
 * @leb_id: source LEB ID number
 * @peb_type: PEB type
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to set SSDFS_MAPTBL_SOURCE_PEB_HAS_ZONE_PTR flag.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-ERANGE     - internal error.
 */
int ssdfs_maptbl_set_zns_indirect_relation(struct ssdfs_peb_mapping_table *tbl,
					   u64 leb_id, u8 peb_type,
					   struct completion **end)
{
	struct ssdfs_fs_info *fsi;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !end);

	SSDFS_DBG("maptbl %p, leb_id %llu, peb_type %#x\n",
		  tbl, leb_id, peb_type);
#endif /* CONFIG_SSDFS_DEBUG */

	*end = NULL;
	fsi = tbl->fsi;

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"maptbl has corrupted state\n");
		return -EFAULT;
	}

	if (should_cache_peb_info(peb_type)) {
		struct ssdfs_maptbl_peb_relation prev_pebr;

		/* resolve potential inconsistency */
		err = ssdfs_maptbl_convert_leb2peb(fsi, leb_id, peb_type,
						   &prev_pebr, end);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fragment is under initialization: "
				  "leb_id %llu\n",
				  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to resolve inconsistency: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			return err;
		}
	}

	down_read(&tbl->tbl_lock);

	err = __ssdfs_maptbl_set_zns_indirect_relation(tbl, leb_id,
							peb_type, end);
	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_set_indirect_relation;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to set indirect relation: "
			  "leb_id %llu, err %u\n",
			  leb_id, err);
		goto finish_set_indirect_relation;
	}

finish_set_indirect_relation:
	up_read(&tbl->tbl_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_maptbl_clear_peb_as_shared() - clear destination PEB as shared
 * @fdesc: fragment descriptor
 * @index: PEB index in the fragment
 * @peb_type: PEB type
 *
 * This method tries to clear SSDFS_MAPTBL_SHARED_DESTINATION_PEB flag
 * in destination PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_maptbl_clear_peb_as_shared(struct ssdfs_maptbl_fragment_desc *fdesc,
				     u16 index, u8 peb_type)
{
	struct ssdfs_peb_descriptor *ptr;
	pgoff_t page_index;
	u16 item_index;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);

	SSDFS_DBG("fdesc %p, index %u\n",
		  fdesc, index);
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = PEBTBL_PAGE_INDEX(fdesc, index);
	item_index = index % fdesc->pebs_per_page;

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap_local_page(page);

	ptr = GET_PEB_DESCRIPTOR(kaddr, item_index);
	if (IS_ERR_OR_NULL(ptr)) {
		err = IS_ERR(ptr) ? PTR_ERR(ptr) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "page_index %lu, item_index %u, err %d\n",
			  page_index, item_index, err);
		goto finish_page_processing;
	}

	if (peb_type != ptr->type) {
		err = -ERANGE;
		SSDFS_ERR("peb_type %#x != ptr->type %#x\n",
			  peb_type, ptr->type);
		goto finish_page_processing;
	}

	switch (ptr->state) {
	case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_DIRTY_STATE:
		/* valid state */
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid PEB state %#x\n",
			  ptr->state);
		goto finish_page_processing;
	}

	if (ptr->flags & SSDFS_MAPTBL_SOURCE_PEB_HAS_EXT_PTR ||
	    ptr->shared_peb_index != U16_MAX) {
		err = -ERANGE;
		SSDFS_ERR("corrupted PEB desriptor\n");
		goto finish_page_processing;
	}

	if (!(ptr->flags & SSDFS_MAPTBL_SHARED_DESTINATION_PEB))
		SSDFS_WARN("it is not shared destination PEB\n");

	ptr->flags &= ~SSDFS_MAPTBL_SHARED_DESTINATION_PEB;

finish_page_processing:
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_maptbl_clear_shared_destination_peb() - clear destination PEB as shared
 * @tbl: pointer on mapping table object
 * @leb_id: LEB ID number
 * @peb_type: PEB type
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to clear SSDFS_MAPTBL_SHARED_DESTINATION_PEB flag
 * in destination PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-ERANGE     - internal error.
 */
static int
ssdfs_maptbl_clear_shared_destination_peb(struct ssdfs_peb_mapping_table *tbl,
					  u64 leb_id, u8 peb_type,
					  struct completion **end)
{
	struct ssdfs_maptbl_fragment_desc *fdesc;
	int state;
	struct ssdfs_leb_descriptor leb_desc;
	u16 relation_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !end);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));

	SSDFS_DBG("maptbl %p, leb_id %llu, peb_type %#x\n",
		  tbl, leb_id, peb_type);
#endif /* CONFIG_SSDFS_DEBUG */

	fdesc = ssdfs_maptbl_get_fragment_descriptor(tbl, leb_id);
	if (IS_ERR_OR_NULL(fdesc)) {
		err = IS_ERR(fdesc) ? PTR_ERR(fdesc) : -ERANGE;
		SSDFS_ERR("fail to get fragment descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		return err;
	}

	*end = &fdesc->init_end;

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
		err = -EFAULT;
		SSDFS_ERR("fragment is corrupted: leb_id %llu\n", leb_id);
		return err;
	} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
		err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	}

	down_write(&fdesc->lock);

	err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
	}

	if (!__is_mapped_leb2peb(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu doesn't be mapped yet\n",
			  leb_id);
		goto finish_fragment_change;
	}

	if (!is_leb_migrating(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu isn't under migration\n",
			  leb_id);
		goto finish_fragment_change;
	}

	relation_index = le16_to_cpu(leb_desc.relation_index);

	if (relation_index == U16_MAX) {
		err = -ENODATA;
		SSDFS_DBG("unitialized leb descriptor\n");
		goto finish_fragment_change;
	}

	err = ssdfs_maptbl_clear_peb_as_shared(fdesc, relation_index,
						peb_type);
	if (unlikely(err)) {
		SSDFS_ERR("fail to clear PEB as shared: "
			  "relation_index %u, err %d\n",
			  relation_index, err);
		goto finish_fragment_change;
	}

finish_fragment_change:
	up_write(&fdesc->lock);

	if (!err)
		ssdfs_maptbl_set_fragment_dirty(tbl, fdesc, leb_id);

	return err;
}

/*
 * ssdfs_maptbl_break_external_peb_ptr() - forget PEB as external pointer
 * @fdesc: fragment descriptor
 * @index: PEB index in the fragment
 * @peb_type: PEB type
 * @peb_state: pointer on PEB state value [out]
 *
 * This method tries to forget index of destination PEB and to clear
 * SSDFS_MAPTBL_SOURCE_PEB_HAS_EXT_PTR flag.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static int
ssdfs_maptbl_break_external_peb_ptr(struct ssdfs_maptbl_fragment_desc *fdesc,
				    u16 index, u8 peb_type,
				    u8 *peb_state)
{
	struct ssdfs_peb_descriptor *ptr;
	pgoff_t page_index;
	u16 item_index;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc || !peb_state);

	SSDFS_DBG("fdesc %p, index %u\n",
		  fdesc, index);
#endif /* CONFIG_SSDFS_DEBUG */

	*peb_state = SSDFS_MAPTBL_UNKNOWN_PEB_STATE;

	page_index = PEBTBL_PAGE_INDEX(fdesc, index);
	item_index = index % fdesc->pebs_per_page;

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap_local_page(page);

	ptr = GET_PEB_DESCRIPTOR(kaddr, item_index);
	if (IS_ERR_OR_NULL(ptr)) {
		err = IS_ERR(ptr) ? PTR_ERR(ptr) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "page_index %lu, item_index %u, err %d\n",
			  page_index, item_index, err);
		goto finish_page_processing;
	}

	if (peb_type != ptr->type) {
		err = -ERANGE;
		SSDFS_ERR("peb_type %#x != ptr->type %#x\n",
			  peb_type, ptr->type);
		goto finish_page_processing;
	}

	if (ptr->flags & SSDFS_MAPTBL_SHARED_DESTINATION_PEB) {
		err = -ERANGE;
		SSDFS_ERR("corrupted PEB desriptor\n");
		goto finish_page_processing;
	}

	if (!(ptr->flags & SSDFS_MAPTBL_SOURCE_PEB_HAS_EXT_PTR))
		SSDFS_WARN("PEB hasn't indirect relation\n");

	switch (ptr->state) {
	case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
		ptr->state = SSDFS_MAPTBL_USED_PEB_STATE;
		*peb_state = SSDFS_MAPTBL_USED_PEB_STATE;
		break;

	case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
		ptr->state = SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE;
		*peb_state = SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE;
		break;

	case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
		ptr->state = SSDFS_MAPTBL_DIRTY_PEB_STATE;
		*peb_state = SSDFS_MAPTBL_DIRTY_PEB_STATE;
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid PEB state %#x\n",
			  ptr->state);
		goto finish_page_processing;
	}

	ptr->shared_peb_index = U8_MAX;
	ptr->flags &= ~SSDFS_MAPTBL_SOURCE_PEB_HAS_EXT_PTR;

finish_page_processing:
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * __ssdfs_maptbl_break_indirect_relation() - forget destination PEB as shared
 * @tbl: pointer on mapping table object
 * @leb_id: LEB ID number
 * @peb_type: PEB type
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to forget index of destination PEB and to clear
 * SSDFS_MAPTBL_SOURCE_PEB_HAS_EXT_PTR flag.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_maptbl_break_indirect_relation(struct ssdfs_peb_mapping_table *tbl,
					   u64 leb_id, u8 peb_type,
					   struct completion **end)
{
	struct ssdfs_maptbl_fragment_desc *fdesc;
	int state;
	struct ssdfs_leb_descriptor leb_desc;
	u16 physical_index;
	u8 peb_state = SSDFS_MAPTBL_UNKNOWN_PEB_STATE;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !end);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));

	SSDFS_DBG("maptbl %p, leb_id %llu, peb_type %#x\n",
		  tbl, leb_id, peb_type);
#endif /* CONFIG_SSDFS_DEBUG */

	fdesc = ssdfs_maptbl_get_fragment_descriptor(tbl, leb_id);
	if (IS_ERR_OR_NULL(fdesc)) {
		err = IS_ERR(fdesc) ? PTR_ERR(fdesc) : -ERANGE;
		SSDFS_ERR("fail to get fragment descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		return err;
	}

	*end = &fdesc->init_end;

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
		err = -EFAULT;
		SSDFS_ERR("fragment is corrupted: leb_id %llu\n", leb_id);
		return err;
	} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
		err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	}

	down_write(&fdesc->lock);

	err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
	}

	if (!__is_mapped_leb2peb(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu doesn't be mapped yet\n",
			  leb_id);
		goto finish_fragment_change;
	}

	if (is_leb_migrating(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu has direct relation\n",
			  leb_id);
		goto finish_fragment_change;
	}

	physical_index = le16_to_cpu(leb_desc.physical_index);

	if (physical_index == U16_MAX) {
		err = -ENODATA;
		SSDFS_DBG("unitialized leb descriptor\n");
		goto finish_fragment_change;
	}

	err = ssdfs_maptbl_break_external_peb_ptr(fdesc, physical_index,
						  peb_type, &peb_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to break external PEB pointer: "
			  "physical_index %u, err %d\n",
			  physical_index, err);
		goto finish_fragment_change;
	}

	if (peb_state == SSDFS_MAPTBL_DIRTY_PEB_STATE) {
		err = ssdfs_maptbl_set_pre_erase_state(fdesc, physical_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move PEB into pre-erase state: "
				  "index %u, err %d\n",
				  physical_index, err);
			goto finish_fragment_change;
		}

		fdesc->pre_erase_pebs++;
		atomic_inc(&tbl->pre_erase_pebs);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fdesc->pre_erase_pebs %u, tbl->pre_erase_pebs %d\n",
			  fdesc->pre_erase_pebs,
			  atomic_read(&tbl->pre_erase_pebs));
#endif /* CONFIG_SSDFS_DEBUG */

		wake_up(&tbl->wait_queue);
	}

finish_fragment_change:
	up_write(&fdesc->lock);

	if (!err)
		ssdfs_maptbl_set_fragment_dirty(tbl, fdesc, leb_id);

	return err;
}

/*
 * ssdfs_maptbl_break_indirect_relation() - break PEBs indirect relation
 * @tbl: pointer on mapping table object
 * @leb_id: source LEB ID number
 * @peb_type: PEB type
 * @dst_leb_id: destination LEB ID number
 * @dst_peb_refs: destination PEB reference counter
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to clear SSDFS_MAPTBL_SHARED_DESTINATION_PEB flag
 * in destination PEB. Then it tries to forget index of destination PEB
 * and to clear SSDFS_MAPTBL_SOURCE_PEB_HAS_EXT_PTR flag.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-ERANGE     - internal error.
 */
int ssdfs_maptbl_break_indirect_relation(struct ssdfs_peb_mapping_table *tbl,
					  u64 leb_id, u8 peb_type,
					  u64 dst_leb_id, int dst_peb_refs,
					  struct completion **end)
{
	struct ssdfs_fs_info *fsi;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !end);

	SSDFS_DBG("maptbl %p, leb_id %llu, "
		  "peb_type %#x, dst_leb_id %llu, "
		  "dst_peb_refs %d\n",
		  tbl, leb_id, peb_type,
		  dst_leb_id, dst_peb_refs);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = tbl->fsi;
	*end = NULL;

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"maptbl has corrupted state\n");
		return -EFAULT;
	}

	if (dst_peb_refs <= 0) {
		SSDFS_ERR("invalid dst_peb_refs\n");
		return -ERANGE;
	}

	if (should_cache_peb_info(peb_type)) {
		struct ssdfs_maptbl_peb_relation prev_pebr;

		/* resolve potential inconsistency */
		err = ssdfs_maptbl_convert_leb2peb(fsi, leb_id, peb_type,
						   &prev_pebr, end);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fragment is under initialization: "
				  "leb_id %llu\n",
				  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to resolve inconsistency: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			return err;
		}
	}

	down_read(&tbl->tbl_lock);

	if (dst_peb_refs > 1)
		goto break_indirect_relation;

	err = ssdfs_maptbl_clear_shared_destination_peb(tbl, dst_leb_id,
							peb_type, end);
	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  dst_leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_break_indirect_relation;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to clear shared destination PEB: "
			  "dst_leb_id %llu, err %u\n",
			  dst_leb_id, err);
		goto finish_break_indirect_relation;
	}

break_indirect_relation:
	err = __ssdfs_maptbl_break_indirect_relation(tbl, leb_id,
						     peb_type, end);
	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_break_indirect_relation;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to break indirect relation: "
			  "leb_id %llu, err %u\n",
			  leb_id, err);
		goto finish_break_indirect_relation;
	}

finish_break_indirect_relation:
	up_read(&tbl->tbl_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_maptbl_break_zns_external_peb_ptr() - forget shared zone
 * @fdesc: fragment descriptor
 * @index: PEB index in the fragment
 * @peb_type: PEB type
 * @peb_state: pointer on PEB state value [out]
 *
 * This method tries to clear SSDFS_MAPTBL_SOURCE_PEB_HAS_ZONE_PTR flag.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static int
ssdfs_maptbl_break_zns_external_peb_ptr(struct ssdfs_maptbl_fragment_desc *fdesc,
					u16 index, u8 peb_type,
					u8 *peb_state)
{
	struct ssdfs_peb_descriptor *ptr;
	pgoff_t page_index;
	u16 item_index;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc || !peb_state);

	SSDFS_DBG("fdesc %p, index %u\n",
		  fdesc, index);
#endif /* CONFIG_SSDFS_DEBUG */

	*peb_state = SSDFS_MAPTBL_UNKNOWN_PEB_STATE;

	page_index = PEBTBL_PAGE_INDEX(fdesc, index);
	item_index = index % fdesc->pebs_per_page;

	page = ssdfs_page_array_get_page_locked(&fdesc->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to find page: page_index %lu\n",
			  page_index);
		return err;
	}

	kaddr = kmap_local_page(page);

	ptr = GET_PEB_DESCRIPTOR(kaddr, item_index);
	if (IS_ERR_OR_NULL(ptr)) {
		err = IS_ERR(ptr) ? PTR_ERR(ptr) : -ERANGE;
		SSDFS_ERR("fail to get peb_descriptor: "
			  "page_index %lu, item_index %u, err %d\n",
			  page_index, item_index, err);
		goto finish_page_processing;
	}

	if (peb_type != ptr->type) {
		err = -ERANGE;
		SSDFS_ERR("peb_type %#x != ptr->type %#x\n",
			  peb_type, ptr->type);
		goto finish_page_processing;
	}

	if (ptr->flags & SSDFS_MAPTBL_SHARED_DESTINATION_PEB) {
		err = -ERANGE;
		SSDFS_ERR("corrupted PEB desriptor\n");
		goto finish_page_processing;
	}

	if (!(ptr->flags & SSDFS_MAPTBL_SOURCE_PEB_HAS_ZONE_PTR))
		SSDFS_WARN("PEB hasn't indirect relation\n");

	switch (ptr->state) {
	case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
		ptr->state = SSDFS_MAPTBL_USED_PEB_STATE;
		*peb_state = SSDFS_MAPTBL_USED_PEB_STATE;
		break;

	case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
		ptr->state = SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE;
		*peb_state = SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE;
		break;

	case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
		ptr->state = SSDFS_MAPTBL_DIRTY_PEB_STATE;
		*peb_state = SSDFS_MAPTBL_DIRTY_PEB_STATE;
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid PEB state %#x\n",
			  ptr->state);
		goto finish_page_processing;
	}

	ptr->shared_peb_index = U8_MAX;
	ptr->flags &= ~SSDFS_MAPTBL_SOURCE_PEB_HAS_ZONE_PTR;

finish_page_processing:
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * __ssdfs_maptbl_break_zns_indirect_relation() - forget shared zone
 * @tbl: pointer on mapping table object
 * @leb_id: LEB ID number
 * @peb_type: PEB type
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to clear SSDFS_MAPTBL_SOURCE_PEB_HAS_ZONE_PTR flag.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-ERANGE     - internal error.
 */
static int
__ssdfs_maptbl_break_zns_indirect_relation(struct ssdfs_peb_mapping_table *tbl,
					   u64 leb_id, u8 peb_type,
					   struct completion **end)
{
	struct ssdfs_maptbl_fragment_desc *fdesc;
	int state;
	struct ssdfs_leb_descriptor leb_desc;
	u16 physical_index;
	u8 peb_state = SSDFS_MAPTBL_UNKNOWN_PEB_STATE;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !end);
	BUG_ON(!rwsem_is_locked(&tbl->tbl_lock));

	SSDFS_DBG("maptbl %p, leb_id %llu, peb_type %#x\n",
		  tbl, leb_id, peb_type);
#endif /* CONFIG_SSDFS_DEBUG */

	fdesc = ssdfs_maptbl_get_fragment_descriptor(tbl, leb_id);
	if (IS_ERR_OR_NULL(fdesc)) {
		err = IS_ERR(fdesc) ? PTR_ERR(fdesc) : -ERANGE;
		SSDFS_ERR("fail to get fragment descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		return err;
	}

	*end = &fdesc->init_end;

	state = atomic_read(&fdesc->state);
	if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
		err = -EFAULT;
		SSDFS_ERR("fragment is corrupted: leb_id %llu\n", leb_id);
		return err;
	} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
		err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	}

	down_write(&fdesc->lock);

	err = ssdfs_maptbl_get_leb_descriptor(fdesc, leb_id, &leb_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get leb descriptor: "
			  "leb_id %llu, err %d\n",
			  leb_id, err);
		goto finish_fragment_change;
	}

	if (!__is_mapped_leb2peb(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu doesn't be mapped yet\n",
			  leb_id);
		goto finish_fragment_change;
	}

	if (is_leb_migrating(&leb_desc)) {
		err = -ERANGE;
		SSDFS_ERR("leb %llu has direct relation\n",
			  leb_id);
		goto finish_fragment_change;
	}

	physical_index = le16_to_cpu(leb_desc.physical_index);

	if (physical_index == U16_MAX) {
		err = -ENODATA;
		SSDFS_DBG("unitialized leb descriptor\n");
		goto finish_fragment_change;
	}

	err = ssdfs_maptbl_break_zns_external_peb_ptr(fdesc, physical_index,
							peb_type, &peb_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to break external PEB pointer: "
			  "physical_index %u, err %d\n",
			  physical_index, err);
		goto finish_fragment_change;
	}

	if (peb_state == SSDFS_MAPTBL_DIRTY_PEB_STATE) {
		err = ssdfs_maptbl_set_pre_erase_state(fdesc, physical_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move PEB into pre-erase state: "
				  "index %u, err %d\n",
				  physical_index, err);
			goto finish_fragment_change;
		}

		fdesc->pre_erase_pebs++;
		atomic_inc(&tbl->pre_erase_pebs);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fdesc->pre_erase_pebs %u, tbl->pre_erase_pebs %d\n",
			  fdesc->pre_erase_pebs,
			  atomic_read(&tbl->pre_erase_pebs));
#endif /* CONFIG_SSDFS_DEBUG */

		wake_up(&tbl->wait_queue);
	}

finish_fragment_change:
	up_write(&fdesc->lock);

	if (!err)
		ssdfs_maptbl_set_fragment_dirty(tbl, fdesc, leb_id);

	return err;
}

/*
 * ssdfs_maptbl_break_zns_indirect_relation() - break PEBs indirect relation
 * @tbl: pointer on mapping table object
 * @leb_id: source LEB ID number
 * @peb_type: PEB type
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to clear SSDFS_MAPTBL_SOURCE_PEB_HAS_ZONE_PTR flag.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - maptbl has inconsistent state.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-ERANGE     - internal error.
 */
int ssdfs_maptbl_break_zns_indirect_relation(struct ssdfs_peb_mapping_table *tbl,
					     u64 leb_id, u8 peb_type,
					     struct completion **end)
{
	struct ssdfs_fs_info *fsi;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !end);

	SSDFS_DBG("maptbl %p, leb_id %llu, "
		  "peb_type %#x\n",
		  tbl, leb_id, peb_type);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = tbl->fsi;
	*end = NULL;

	if (atomic_read(&tbl->flags) & SSDFS_MAPTBL_ERROR) {
		ssdfs_fs_error(tbl->fsi->sb,
				__FILE__, __func__, __LINE__,
				"maptbl has corrupted state\n");
		return -EFAULT;
	}

	if (should_cache_peb_info(peb_type)) {
		struct ssdfs_maptbl_peb_relation prev_pebr;

		/* resolve potential inconsistency */
		err = ssdfs_maptbl_convert_leb2peb(fsi, leb_id, peb_type,
						   &prev_pebr, end);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fragment is under initialization: "
				  "leb_id %llu\n",
				  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to resolve inconsistency: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			return err;
		}
	}

	down_read(&tbl->tbl_lock);

	err = __ssdfs_maptbl_break_zns_indirect_relation(tbl, leb_id,
							 peb_type, end);
	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment is under initialization: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_break_indirect_relation;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to break indirect relation: "
			  "leb_id %llu, err %u\n",
			  leb_id, err);
		goto finish_break_indirect_relation;
	}

finish_break_indirect_relation:
	up_read(&tbl->tbl_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

static inline
int __ssdfs_reserve_free_pages(struct ssdfs_fs_info *fsi, u32 count,
				int type, u64 *free_pages)
{
#ifdef CONFIG_SSDFS_DEBUG
	u64 reserved = 0;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(type <= SSDFS_UNKNOWN_PAGE_TYPE || type >= SSDFS_PAGES_TYPE_MAX);

	SSDFS_DBG("fsi %p, count %u, type %#x\n",
		  fsi, count, type);
#endif /* CONFIG_SSDFS_DEBUG */

	*free_pages = 0;

	spin_lock(&fsi->volume_state_lock);
	*free_pages = fsi->free_pages;
	if (fsi->free_pages >= count) {
		err = -EEXIST;
		fsi->free_pages -= count;
		switch (type) {
		case SSDFS_USER_DATA_PAGES:
			fsi->reserved_new_user_data_pages += count;
			break;

		default:
			/* do nothing */
			break;
		};
#ifdef CONFIG_SSDFS_DEBUG
		reserved = fsi->reserved_new_user_data_pages;
#endif /* CONFIG_SSDFS_DEBUG */
	} else
		err = -ENOSPC;
	spin_unlock(&fsi->volume_state_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("reserved %llu\n", reserved);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

static
int ssdfs_try2increase_free_pages(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_peb_mapping_table *tbl;
	struct ssdfs_maptbl_fragment_desc *fdesc;
	u32 fragments_count;
	int state;
	u32 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	tbl = fsi->maptbl;

	fragments_count = tbl->fragments_count;

	down_read(&tbl->tbl_lock);

	for (i = 0; i < fragments_count; i++) {
		fdesc = &tbl->desc_array[i];

		state = atomic_read(&fdesc->state);
		if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
			err = -EFAULT;
			SSDFS_ERR("fragment is corrupted: index %u\n",
				  i);
			goto finish_fragment_check;
		} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
			struct completion *end = &fdesc->init_end;

			up_read(&tbl->tbl_lock);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("wait fragment initialization end: "
				  "index %u, state %#x\n",
				  i, state);
#endif /* CONFIG_SSDFS_DEBUG */

			err = SSDFS_WAIT_COMPLETION(end);
			if (unlikely(err)) {
				SSDFS_ERR("fragment init failed: "
					  "index %u\n", i);
				err = -EFAULT;
				goto finish_try2increase_free_pages;
			}

			down_read(&tbl->tbl_lock);
		}

		down_read(&fdesc->lock);
		err = ssdfs_maptbl_try_decrease_reserved_pebs(tbl, fdesc);
		up_read(&fdesc->lock);

		if (err == -ENOENT) {
			err = -ENOSPC;
			SSDFS_DBG("unable to decrease reserved pebs\n");
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to decrease reserved pebs: "
				  "err %d\n", err);
			goto finish_fragment_check;
		}
	}

finish_fragment_check:
	up_read(&tbl->tbl_lock);

finish_try2increase_free_pages:
	return err;
}

static
int ssdfs_wait_maptbl_init_ending(struct ssdfs_fs_info *fsi, u32 count)
{
	struct ssdfs_peb_mapping_table *tbl;
	struct ssdfs_maptbl_fragment_desc *fdesc;
	u32 fragments_count;
	int state;
	u64 free_pages;
	u32 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	tbl = fsi->maptbl;

	fragments_count = tbl->fragments_count;

	down_read(&tbl->tbl_lock);

	for (i = 0; i < fragments_count; i++) {
		fdesc = &tbl->desc_array[i];

		state = atomic_read(&fdesc->state);
		if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
			err = -EFAULT;
			SSDFS_ERR("fragment is corrupted: index %u\n",
				  i);
			goto finish_fragment_check;
		} else if (state == SSDFS_MAPTBL_FRAG_CREATED) {
			struct completion *end = &fdesc->init_end;

			up_read(&tbl->tbl_lock);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("wait fragment initialization end: "
				  "index %u, state %#x\n",
				  i, state);
#endif /* CONFIG_SSDFS_DEBUG */

			err = SSDFS_WAIT_COMPLETION(end);
			if (unlikely(err)) {
				SSDFS_ERR("fragment init failed: "
					  "index %u\n", i);
				err = -EFAULT;
				goto finish_wait_init;
			}

			spin_lock(&fsi->volume_state_lock);
			free_pages = fsi->free_pages;
			spin_unlock(&fsi->volume_state_lock);

			if (free_pages >= count)
				goto finish_wait_init;

			down_read(&tbl->tbl_lock);
		}
	}

finish_fragment_check:
	up_read(&tbl->tbl_lock);

finish_wait_init:
	return err;
}

int ssdfs_reserve_free_pages(struct ssdfs_fs_info *fsi, u32 count, int type)
{
	u64 free_pages = 0;
	int state;
	u32 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(type <= SSDFS_UNKNOWN_PAGE_TYPE || type >= SSDFS_PAGES_TYPE_MAX);

	SSDFS_DBG("fsi %p, count %u, type %#x\n",
		  fsi, count, type);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&fsi->global_fs_state);

	err = __ssdfs_reserve_free_pages(fsi, count, type, &free_pages);
	if (err == -EEXIST) {
		err = 0;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("free pages %u have been reserved, free_pages %llu\n",
			  count, free_pages);
#endif /* CONFIG_SSDFS_DEBUG */
	} else if (err == -ENOSPC && state == SSDFS_UNKNOWN_GLOBAL_FS_STATE) {
		err = ssdfs_wait_maptbl_init_ending(fsi, count);
		if (unlikely(err)) {
			SSDFS_ERR("initialization has failed: "
				  "err %d\n", err);
			goto finish_reserve_free_pages;
		}

		err = __ssdfs_reserve_free_pages(fsi, count,
						 type, &free_pages);
		if (err == -EEXIST) {
			/* succesful reservation */
			err = 0;
			goto finish_reserve_free_pages;
		} else {
			/*
			 * finish logic
			 */
			goto finish_reserve_free_pages;
		}
	} else if (err == -ENOSPC) {
		DEFINE_WAIT(wait);
		err = 0;

		wake_up_all(&fsi->shextree->wait_queue);
		wake_up_all(&fsi->maptbl->wait_queue);

		for (i = 0; i < SSDFS_GC_THREAD_TYPE_MAX; i++) {
			wake_up_all(&fsi->gc_wait_queue[i]);
		}

		prepare_to_wait(&fsi->maptbl->erase_ops_end_wq, &wait,
				TASK_UNINTERRUPTIBLE);
		schedule();
		finish_wait(&fsi->maptbl->erase_ops_end_wq, &wait);

		err = ssdfs_try2increase_free_pages(fsi);
		if (err == -ENOSPC) {
			/*
			 * try to collect the dirty segments
			 */
			err = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to increase the free pages: "
				  "err %d\n", err);
			goto finish_reserve_free_pages;
		} else {
			err = __ssdfs_reserve_free_pages(fsi, count,
							 type, &free_pages);
			if (err == -EEXIST) {
				/* succesful reservation */
				err = 0;
				goto finish_reserve_free_pages;
			} else {
				/*
				 * try to collect the dirty segments
				 */
				err = 0;
			}
		}

		err = ssdfs_collect_dirty_segments_now(fsi);
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to collect the dirty segments: "
				  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_reserve_free_pages;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to collect the dirty segments: "
				  "err %d\n", err);
			goto finish_reserve_free_pages;
		}

		err = ssdfs_try2increase_free_pages(fsi);
		if (err == -ENOSPC) {
			/*
			 * finish logic
			 */
			goto finish_reserve_free_pages;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to increase the free pages: "
				  "err %d\n", err);
			goto finish_reserve_free_pages;
		} else {
			err = __ssdfs_reserve_free_pages(fsi, count,
							 type, &free_pages);
			if (err == -EEXIST) {
				/* succesful reservation */
				err = 0;
				goto finish_reserve_free_pages;
			} else {
				/*
				 * finish logic
				 */
				goto finish_reserve_free_pages;
			}
		}
	} else
		BUG();

finish_reserve_free_pages:
	if (err) {
		err = -ENOSPC;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to reserve, free_pages %llu\n",
			  free_pages);
#endif /* CONFIG_SSDFS_DEBUG */
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("free pages %u have been reserved, free_pages %llu\n",
			  count, free_pages);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return err;
}

void ssdfs_debug_maptbl_object(struct ssdfs_peb_mapping_table *tbl)
{
#ifdef CONFIG_SSDFS_DEBUG
	int i, j;
	size_t bytes_count;

	BUG_ON(!tbl);

	SSDFS_DBG("fragments_count %u, fragments_per_seg %u, "
		  "fragments_per_peb %u, fragment_bytes %u, "
		  "flags %#x, lebs_count %llu, pebs_count %llu, "
		  "lebs_per_fragment %u, pebs_per_fragment %u, "
		  "pebs_per_stripe %u, stripes_per_fragment %u\n",
		  tbl->fragments_count, tbl->fragments_per_seg,
		  tbl->fragments_per_peb, tbl->fragment_bytes,
		  atomic_read(&tbl->flags), tbl->lebs_count,
		  tbl->pebs_count, tbl->lebs_per_fragment,
		  tbl->pebs_per_fragment, tbl->pebs_per_stripe,
		  tbl->stripes_per_fragment);

	for (i = 0; i < MAPTBL_LIMIT1; i++) {
		for (j = 0; j < MAPTBL_LIMIT2; j++) {
			struct ssdfs_meta_area_extent *extent;
			extent = &tbl->extents[i][j];
			SSDFS_DBG("extent[%d][%d]: "
				  "start_id %llu, len %u, "
				  "type %#x, flags %#x\n",
				  i, j,
				  le64_to_cpu(extent->start_id),
				  le32_to_cpu(extent->len),
				  le16_to_cpu(extent->type),
				  le16_to_cpu(extent->flags));
		}
	}

	SSDFS_DBG("segs_count %u\n", tbl->segs_count);

	for (i = 0; i < SSDFS_MAPTBL_SEG_COPY_MAX; i++) {
		if (!tbl->segs[i])
			continue;

		for (j = 0; j < tbl->segs_count; j++)
			SSDFS_DBG("seg[%d][%d] %p\n", i, j, tbl->segs[i][j]);
	}

	SSDFS_DBG("pre_erase_pebs %u, max_erase_ops %u, "
		  "last_peb_recover_cno %llu\n",
		  atomic_read(&tbl->pre_erase_pebs),
		  atomic_read(&tbl->max_erase_ops),
		  (u64)atomic64_read(&tbl->last_peb_recover_cno));

	bytes_count = tbl->fragments_count + BITS_PER_LONG - 1;
	bytes_count /= BITS_PER_BYTE;
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				tbl->dirty_bmap, bytes_count);

	for (i = 0; i < tbl->fragments_count; i++) {
		struct ssdfs_maptbl_fragment_desc *desc;
		struct page *page;
		u32 pages_count;
		int state;

		desc = &tbl->desc_array[i];

		state = atomic_read(&desc->state);
		SSDFS_DBG("fragment #%d: "
			  "state %#x, start_leb %llu, lebs_count %u, "
			  "lebs_per_page %u, lebtbl_pages %u, "
			  "pebs_per_page %u, stripe_pages %u, "
			  "mapped_lebs %u, migrating_lebs %u, "
			  "pre_erase_pebs %u, recovering_pebs %u\n",
			  i, state,
			  desc->start_leb, desc->lebs_count,
			  desc->lebs_per_page, desc->lebtbl_pages,
			  desc->pebs_per_page, desc->stripe_pages,
			  desc->mapped_lebs, desc->migrating_lebs,
			  desc->pre_erase_pebs, desc->recovering_pebs);

		if (state == SSDFS_MAPTBL_FRAG_CREATED) {
			SSDFS_DBG("fragment #%d isn't initialized\n", i);
			continue;
		} else if (state == SSDFS_MAPTBL_FRAG_INIT_FAILED) {
			SSDFS_DBG("fragment #%d init was failed\n", i);
			continue;
		}

		pages_count = desc->lebtbl_pages +
			(desc->stripe_pages * tbl->stripes_per_fragment);

		for (j = 0; j < pages_count; j++) {
			void *kaddr;

			page = ssdfs_page_array_get_page_locked(&desc->array,
								j);

			SSDFS_DBG("page[%d] %p\n", j, page);
			if (IS_ERR_OR_NULL(page))
				continue;

			SSDFS_DBG("page_index %llu, flags %#lx\n",
				  (u64)page_index(page), page->flags);

			kaddr = kmap_local_page(page);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
						kaddr, PAGE_SIZE);
			kunmap_local(kaddr);

			ssdfs_unlock_page(page);
			ssdfs_put_page(page);

			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */
}
