//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/offset_translation_table.c - offset translation table functionality.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2019, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
 */

#include <linux/bitmap.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "offset_translation_table.h"
#include "page_array.h"
#include "peb.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"

#include <trace/events/ssdfs.h>

static struct kmem_cache *ssdfs_blk2off_frag_obj_cachep;

/******************************************************************************
 *                            BTREE NODE CACHE                                *
 ******************************************************************************/

static void ssdfs_init_blk2off_frag_object_once(void *obj)
{
	struct ssdfs_phys_offset_table_fragment *frag_obj = obj;

	memset(frag_obj, 0, sizeof(struct ssdfs_phys_offset_table_fragment));
}

void ssdfs_destroy_blk2off_frag_obj_cache(void)
{
	if (ssdfs_blk2off_frag_obj_cachep)
		kmem_cache_destroy(ssdfs_blk2off_frag_obj_cachep);
}

int ssdfs_init_blk2off_frag_obj_cache(void)
{
	size_t obj_size = sizeof(struct ssdfs_phys_offset_table_fragment);

	ssdfs_blk2off_frag_obj_cachep =
			kmem_cache_create("ssdfs_blk2off_frag_obj_cache",
					obj_size, 0,
					SLAB_RECLAIM_ACCOUNT |
					SLAB_MEM_SPREAD |
					SLAB_ACCOUNT,
					ssdfs_init_blk2off_frag_object_once);
	if (!ssdfs_blk2off_frag_obj_cachep) {
		SSDFS_ERR("unable to create blk2off fragments cache\n");
		return -ENOMEM;
	}

	return 0;
}

/*
 * ssdfs_blk2off_frag_alloc() - allocate memory for blk2off fragment
 */
static
struct ssdfs_phys_offset_table_fragment *ssdfs_blk2off_frag_alloc(void)
{
	struct ssdfs_phys_offset_table_fragment *ptr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_blk2off_frag_obj_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr = kmem_cache_alloc(ssdfs_blk2off_frag_obj_cachep, GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate memory for blk2off fragment\n");
		return ERR_PTR(-ENOMEM);
	}

	return ptr;
}

/*
 * ssdfs_blk2off_frag_free() - free memory for blk2off fragment
 */
static
void ssdfs_blk2off_frag_free(void *ptr)
{
	struct ssdfs_phys_offset_table_fragment *frag;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_blk2off_frag_obj_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!ptr)
		return;

	frag = (struct ssdfs_phys_offset_table_fragment *)ptr;

	WARN_ON(atomic_read(&frag->state) == SSDFS_BLK2OFF_FRAG_DIRTY);

	if (frag->buf) {
		kfree(frag->buf);
		frag->buf = NULL;
	}

	kmem_cache_free(ssdfs_blk2off_frag_obj_cachep, frag);
}

/******************************************************************************
 *                      BLK2OFF TABLE OBJECT FUNCTIONALITY                    *
 ******************************************************************************/

/*
 * struct ssdfs_blk2off_init - initialization environment
 * @table: pointer on translation table object
 * @source: portion's pagevec
 * @peb_index: PEB's index
 * @cno: checkpoint
 * @fragments_count: count of fragments in portion
 * @capacity: maximum amount of items
 * @tbl_hdr: portion header
 * @tbl_hdr_off: portion header's offset
 * @pot_hdr: fragment header
 * @pot_hdr_off: fragment header's offset
 * @bmap: temporary bitmap
 * @bmap_bytes: bytes in temporaray bitmap
 * @pos_array: offset positions temporary array
 * @pos_count: count of offset positions in array
 * @extent_array: translation extents temporary array
 * @extents_count: count of extents in array
 */
struct ssdfs_blk2off_init {
	struct ssdfs_blk2off_table *table;
	struct pagevec *source;
	u16 peb_index;
	u64 cno;
	u32 fragments_count;
	u16 capacity;

	struct ssdfs_blk2off_table_header tbl_hdr;
	u32 tbl_hdr_off;
	struct ssdfs_phys_offset_table_header pot_hdr;
	u32 pot_hdr_off;

	unsigned long *bmap;
	u32 bmap_bytes;

	struct ssdfs_offset_position *pos_array;
	u16 pos_count;

	struct ssdfs_translation_extent *extent_array;
	u16 extents_count;
};

/*
 * ssdfs_blk2off_table_init_fragment() - init PEB's fragment
 * @ptr: fragment pointer
 * @sequence_id: fragment's sequence ID
 * @start_id: fragment's start ID
 * @pages_per_peb: PEB's pages count
 * @state: fragment state after initialization
 * @buf_size: pointer on buffer size
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 */
static int
ssdfs_blk2off_table_init_fragment(struct ssdfs_phys_offset_table_fragment *ptr,
				  u16 sequence_id, u16 start_id,
				  u32 pages_per_peb, int state,
				  size_t *buf_size)
{
	size_t blk2off_tbl_hdr_size = sizeof(struct ssdfs_blk2off_table_header);
	size_t hdr_size = sizeof(struct ssdfs_phys_offset_table_header);
	size_t off_size = sizeof(struct ssdfs_phys_offset_descriptor);
	size_t fragment_size = 0;
	int err = 0;

	SSDFS_DBG("ptr %p, sequence_id %u, start_id %u, "
		  "pages_per_peb %u, state %#x, buf_size %p\n",
		  ptr, sequence_id, start_id, pages_per_peb,
		  state, buf_size);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);
	BUG_ON(sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD);
	BUG_ON(state < SSDFS_BLK2OFF_FRAG_CREATED ||
		state >= SSDFS_BLK2OFF_FRAG_STATE_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	init_rwsem(&ptr->lock);

	down_write(&ptr->lock);

	if (buf_size) {
		fragment_size = min_t(size_t, *buf_size, PAGE_SIZE);
	} else {
		fragment_size += blk2off_tbl_hdr_size;
		fragment_size += hdr_size + (off_size * pages_per_peb);
		fragment_size = min_t(size_t, fragment_size, PAGE_SIZE);
	}

	ptr->buf_size = fragment_size;
	ptr->buf = kzalloc(ptr->buf_size, GFP_KERNEL);
	if (!ptr->buf) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate table buffer\n");
		goto finish_fragment_init;
	}

	ptr->start_id = start_id;
	ptr->sequence_id = sequence_id;
	atomic_set(&ptr->id_count, 0);

	ptr->hdr = SSDFS_POFFTH(ptr->buf);
	ptr->phys_offs = SSDFS_PHYSOFFD(ptr->buf + hdr_size);

	atomic_set(&ptr->state, state);

	SSDFS_DBG("FRAGMENT: sequence_id %u, start_id %u, id_count %d\n",
		  sequence_id, start_id, atomic_read(&ptr->id_count));

finish_fragment_init:
	up_write(&ptr->lock);
	return err;
}

/*
 * ssdfs_blk2off_table_create() - create translation table object
 * @fsi: pointer on shared file system object
 * @items_count: table's capacity
 * @type: table's type
 * @state: initial state of object
 *
 * This method tries to create translation table object.
 *
 * RETURN:
 * [success] - pointer on created object.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid value.
 * %-ENOMEM     - fail to allocate memory.
 */
struct ssdfs_blk2off_table *
ssdfs_blk2off_table_create(struct ssdfs_fs_info *fsi,
			   u16 items_count, u8 type,
			   int state)
{
	struct ssdfs_blk2off_table *ptr;
	size_t table_size = sizeof(struct ssdfs_blk2off_table);
	size_t off_pos_size = sizeof(struct ssdfs_offset_position);
	size_t blk_desc_size = sizeof(struct ssdfs_migrating_block);
	u32 bytes;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(state <= SSDFS_BLK2OFF_OBJECT_UNKNOWN ||
		state >= SSDFS_BLK2OFF_OBJECT_STATE_MAX);
	BUG_ON(items_count > (2 * fsi->pages_per_seg));
	BUG_ON(type <= SSDFS_UNKNOWN_OFF_TABLE_TYPE ||
		type >= SSDFS_OFF_TABLE_MAX_TYPE);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, items_count %u, type %u, state %#x\n",
		  fsi, items_count, type,  state);

	ptr = (struct ssdfs_blk2off_table *)kzalloc(table_size, GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate translation table\n");
		return ERR_PTR(-ENOMEM);
	}

	ptr->fsi = fsi;

	atomic_set(&ptr->flags, 0);
	atomic_set(&ptr->state, SSDFS_BLK2OFF_OBJECT_UNKNOWN);

	ptr->pages_per_peb = fsi->pages_per_peb;
	ptr->pages_per_seg = fsi->pages_per_seg;
	ptr->type = type;

	init_rwsem(&ptr->translation_lock);

	ptr->init_cno = U64_MAX;
	ptr->used_logical_blks = 0;
	ptr->free_logical_blks = items_count;
	ptr->last_allocated_blk = U16_MAX;

	bytes = ssdfs_blk2off_table_bmap_bytes(items_count);
	for (i = 0; i < SSDFS_LBMAP_ARRAY_MAX; i++) {
		ptr->lbmap[i] = (unsigned long *)kzalloc(bytes, GFP_KERNEL);
		if (!ptr->lbmap[i]) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate bitmaps\n");
			goto free_bmap;
		}
	}

	ptr->lblk2off_capacity = items_count;

	ptr->lblk2off = kzalloc(off_pos_size * items_count, GFP_KERNEL);
	if (!ptr->lblk2off) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate translation array\n");
		goto free_bmap;
	}
	memset(ptr->lblk2off, 0xFF, off_pos_size * items_count);

	ptr->migrating_blks = kzalloc(blk_desc_size * items_count, GFP_KERNEL);
	if (!ptr->migrating_blks) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate migrating blocks array\n");
		goto free_translation_array;
	}

	ptr->pebs_count = fsi->pebs_per_seg;

	ptr->peb = kcalloc(ptr->pebs_count,
			   sizeof(struct ssdfs_phys_offset_table_array),
			   GFP_KERNEL);
	if (!ptr->peb) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate phys offsets array\n");
		goto free_migrating_blks_array;
	}

	for (i = 0; i < ptr->pebs_count; i++) {
		struct ssdfs_phys_offset_table_array *table = &ptr->peb[i];
		struct ssdfs_sequence_array *seq_ptr = NULL;
		u32 threshold = SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD;

		seq_ptr = ssdfs_create_sequence_array(threshold);
		if (IS_ERR_OR_NULL(seq_ptr)) {
			err = (seq_ptr == NULL ? -ENOMEM : PTR_ERR(seq_ptr));
			SSDFS_ERR("fail to allocate sequence: "
				  "err %d\n", err);
			goto free_phys_offs_array;
		} else
			table->sequence = seq_ptr;

		if (state == SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT) {
			struct ssdfs_phys_offset_table_fragment *fragment;
			u16 start_id = i * fsi->pages_per_peb;
			u32 pages_per_peb = fsi->pages_per_peb;
			int fragment_state = SSDFS_BLK2OFF_FRAG_INITIALIZED;

			atomic_set(&table->fragment_count, 1);

			fragment = ssdfs_blk2off_frag_alloc();
			if (IS_ERR_OR_NULL(fragment)) {
				err = (fragment == NULL ? -ENOMEM :
							PTR_ERR(fragment));
				SSDFS_ERR("fail to allocate fragment: "
					  "err %d\n", err);
				goto free_phys_offs_array;
			}

			err = ssdfs_sequence_array_init_item(table->sequence,
							     0, fragment);
			if (unlikely(err)) {
				ssdfs_blk2off_frag_free(fragment);
				SSDFS_ERR("fail to init fragment: "
					  "err %d\n", err);
				goto free_phys_offs_array;
			}

			err = ssdfs_blk2off_table_init_fragment(fragment, 0,
								start_id,
								pages_per_peb,
								fragment_state,
								NULL);
			if (unlikely(err)) {
				SSDFS_ERR("fail to init fragment: "
					  "fragment_index %d, err %d\n",
					  i, err);
				goto free_phys_offs_array;
			}

			atomic_set(&table->state,
				   SSDFS_BLK2OFF_TABLE_COMPLETE_INIT);
		} else if (state == SSDFS_BLK2OFF_OBJECT_CREATED) {
			atomic_set(&table->fragment_count, 0);
			atomic_set(&table->state,
				   SSDFS_BLK2OFF_TABLE_CREATED);
		} else
			BUG();
	}

	if (state == SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT) {
		bitmap_set(ptr->lbmap[SSDFS_LBMAP_INIT_INDEX],
			   0, items_count);
	}

	init_completion(&ptr->partial_init_end);
	init_completion(&ptr->full_init_end);

	atomic_set(&ptr->state, state);

	return ptr;

free_phys_offs_array:
	for (i = 0; i < ptr->pebs_count; i++) {
		struct ssdfs_sequence_array *sequence;

		sequence = ptr->peb[i].sequence;
		ssdfs_destroy_sequence_array(sequence, ssdfs_blk2off_frag_free);
		ptr->peb[i].sequence = NULL;
	}

	kfree(ptr->peb);

free_migrating_blks_array:
	kfree(ptr->migrating_blks);

free_translation_array:
	kfree(ptr->lblk2off);

free_bmap:
	for (i = 0; i < SSDFS_LBMAP_ARRAY_MAX; i++)
		kfree(ptr->lbmap[i]);

	kfree(ptr);

	return ERR_PTR(err);
}

/*
 * ssdfs_blk2off_table_destroy() - destroy translation table object
 * @table: pointer on translation table object
 */
void ssdfs_blk2off_table_destroy(struct ssdfs_blk2off_table *table)
{
	int state;
	int migrating_blks = -1;
	int i;

	SSDFS_DBG("table %p\n", table);

	if (!table) {
		WARN_ON(!table);
		return;
	}

	if (table->peb) {
		for (i = 0; i < table->pebs_count; i++) {
			struct ssdfs_sequence_array *sequence;

			sequence = table->peb[i].sequence;
			ssdfs_destroy_sequence_array(sequence,
						ssdfs_blk2off_frag_free);
			table->peb[i].sequence = NULL;

			state = atomic_read(&table->peb[i].state);
			WARN_ON(state == SSDFS_BLK2OFF_TABLE_DIRTY);
		}

		kfree(table->peb);
		table->peb = NULL;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (table->last_allocated_blk >= U16_MAX)
		migrating_blks = 0;
	else
		migrating_blks = table->last_allocated_blk + 1;

	for (i = 0; i < migrating_blks; i++) {
		struct ssdfs_migrating_block *blk = &table->migrating_blks[i];

		switch (blk->state) {
		case SSDFS_LBLOCK_UNDER_MIGRATION:
		case SSDFS_LBLOCK_UNDER_COMMIT:
			SSDFS_ERR("logical blk %d is under migration\n", i);
			pagevec_release(&blk->pvec);
			break;
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */

	kfree(table->lblk2off);
	table->lblk2off = NULL;

	kfree(table->migrating_blks);
	table->migrating_blks = NULL;

	for (i = 0; i < SSDFS_LBMAP_ARRAY_MAX; i++) {
		kfree(table->lbmap[i]);
		table->lbmap[i] = NULL;
	}

	kfree(table);
	table = NULL;
}

/*
 * ssdfs_blk2off_table_bmap_set() - set bit for logical block
 * @lbmap: bitmap pointer
 * @logical_blk: logical block number
 */
static inline
void ssdfs_blk2off_table_bmap_set(unsigned long *lbmap, u16 logical_blk)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!lbmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("lbmap %p, logical_blk %u\n",
		  lbmap, logical_blk);

	bitmap_set(lbmap, logical_blk, 1);
}

/*
 * ssdfs_blk2off_table_bmap_clear() - clear bit for logical block
 * @lbmap: bitmap pointer
 * @logical_blk: logical block number
 */
static inline
void ssdfs_blk2off_table_bmap_clear(unsigned long *lbmap, u16 logical_blk)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!lbmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("lbmap %p, logical_blk %u\n",
		  lbmap, logical_blk);

	bitmap_clear(lbmap, logical_blk, 1);
}

/*
 * ssdfs_blk2off_table_bmap_vacant() - check bit for logical block
 * @lbmap: bitmap pointer
 * @lbmap_bits: count of bits in bitmap
 * @logical_blk: logical block number
 */
static inline
bool ssdfs_blk2off_table_bmap_vacant(unsigned long *lbmap,
				     u16 lbmap_bits,
				     u16 logical_blk)
{
	unsigned long found;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!lbmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("lbmap %p, lbmap_bits %u, logical_blk %u\n",
		  lbmap, lbmap_bits, logical_blk);

	found = find_next_zero_bit(lbmap, lbmap_bits, logical_blk);

	return found == logical_blk;
}

/*
 * ssdfs_blk2off_table_extent_vacant() - check extent vacancy
 * @lbmap: bitmap pointer
 * @lbmap_bits: count of bits in bitmap
 * @extent: pointer on extent
 */
static inline
bool ssdfs_blk2off_table_extent_vacant(unsigned long *lbmap,
					u16 lbmap_bits,
					struct ssdfs_blk2off_range *extent)
{
	unsigned long start, end;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!lbmap || !extent);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("lbmap %p, lbmap_bits %u, extent (start %u, len %u)\n",
		  lbmap, lbmap_bits, extent->start_lblk, extent->len);

	if (extent->start_lblk >= lbmap_bits) {
		SSDFS_ERR("invalid extent start %u\n",
			  extent->start_lblk);
		return false;
	}

	if (extent->len == 0 || extent->len >= U16_MAX) {
		SSDFS_ERR("invalid extent length\n");
		return false;
	}

	start = find_next_zero_bit(lbmap, lbmap_bits, extent->start_lblk);

	if (start != extent->start_lblk)
		return false;
	else if (extent->len == 1)
		return true;

	end = find_next_bit(lbmap, lbmap_bits, start);

	if ((end - start) == extent->len)
		return true;

	return false;
}

/*
 * is_ssdfs_table_header_magic_valid() - check segment header's magic
 * @hdr: table header
 */
bool is_ssdfs_table_header_magic_valid(struct ssdfs_blk2off_table_header *hdr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	return le16_to_cpu(hdr->magic.key) == SSDFS_BLK2OFF_TABLE_HDR_MAGIC;
}

/*
 * ssdfs_check_table_header() - check table header
 * @hdr: table header
 * @size: size of header
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO     - header is invalid.
 */
static
int ssdfs_check_table_header(struct ssdfs_blk2off_table_header *hdr,
			     size_t size)
{
	u16 extents_off = offsetof(struct ssdfs_blk2off_table_header,
				   sequence);
	size_t extent_size = sizeof(struct ssdfs_translation_extent);
	size_t extent_area;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("hdr %p, size %zu\n", hdr, size);

	if (!is_ssdfs_magic_valid(&hdr->magic) ||
	    !is_ssdfs_table_header_magic_valid(hdr)) {
		SSDFS_ERR("invalid table magic\n");
		return -EIO;
	}

	if (!is_csum_valid(&hdr->check, hdr, size)) {
		SSDFS_ERR("invalid checksum\n");
		return -EIO;
	}

	if (extents_off != le16_to_cpu(hdr->extents_off)) {
		SSDFS_ERR("invalid extents offset %u\n",
			  le16_to_cpu(hdr->extents_off));
		return -EIO;
	}

	extent_area = extent_size * le16_to_cpu(hdr->extents_count);
	if (le16_to_cpu(hdr->offset_table_off) != (extents_off + extent_area)) {
		SSDFS_ERR("invalid table offset: extents_off %u, "
			  "extents_count %u, offset_table_off %u\n",
			  le16_to_cpu(hdr->extents_off),
			  le16_to_cpu(hdr->extents_count),
			  le16_to_cpu(hdr->offset_table_off));
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_check_fragment() - check table's fragment
 * @table: pointer on table object
 * @peb_index: PEB's index
 * @hdr: fragment's header
 * @fragment_size: size of fragment in bytes
 *
 * Method tries to check fragment validity.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - corrupted fragment.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_check_fragment(struct ssdfs_blk2off_table *table,
			 u16 peb_index,
			 struct ssdfs_phys_offset_table_header *hdr,
			 size_t fragment_size)
{
	u16 start_id, peb_start_id;
	u16 sequence_id;
	u16 id_count;
	u32 byte_size;
	u32 items_size;
	__le32 csum1, csum2;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !hdr);
	BUG_ON(peb_index >= table->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	start_id = le16_to_cpu(hdr->start_id);
	id_count = le16_to_cpu(hdr->id_count);
	byte_size = le32_to_cpu(hdr->byte_size);

	SSDFS_DBG("table %p, peb_index %u, start_id %u, "
		  "id_count %u, byte_size %u, "
		  "fragment_id %u\n",
		  table, peb_index,
		  start_id, id_count, byte_size,
		  hdr->sequence_id);

	if (le32_to_cpu(hdr->magic) != SSDFS_PHYS_OFF_TABLE_MAGIC) {
		SSDFS_ERR("invalid magic %#x\n",
			  le32_to_cpu(hdr->magic));
		return -EIO;
	}

	if (byte_size > fragment_size) {
		SSDFS_ERR("byte_size %u > fragment_size %zu\n",
			  byte_size, fragment_size);
		return -ERANGE;
	}

	csum1 = hdr->checksum;
	hdr->checksum = 0;
	csum2 = ssdfs_crc32_le(hdr, byte_size);
	hdr->checksum = csum1;

	if (csum1 != csum2) {
		SSDFS_ERR("csum1 %#x != csum2 %#x\n",
			  le32_to_cpu(csum1),
			  le32_to_cpu(csum2));
		return -EIO;
	}

	if (le16_to_cpu(hdr->peb_index) != peb_index) {
		SSDFS_ERR("invalid peb_index %u\n",
			  le16_to_cpu(hdr->peb_index));
		return -EIO;
	}

	if (start_id >= table->pages_per_seg)
		start_id %= table->pages_per_seg;

	peb_start_id = peb_index * table->pages_per_peb;

	if (start_id < peb_start_id ||
	    start_id >= (peb_start_id + table->pages_per_peb)) {
		SSDFS_ERR("invalid start_id %u for peb_index %u\n",
			  le16_to_cpu(hdr->start_id),
			  peb_index);
		return -EIO;
	}

	if (id_count == 0 || id_count > table->pages_per_peb) {
		SSDFS_ERR("invalid id_count %u for peb_index %u\n",
			  le16_to_cpu(hdr->id_count),
			  peb_index);
		return -EIO;
	}

	items_size = id_count * sizeof(struct ssdfs_phys_offset_descriptor);

	if (byte_size < items_size) {
		SSDFS_ERR("invalid byte_size %u for peb_index %u\n",
			  le32_to_cpu(hdr->byte_size),
			  peb_index);
		return -EIO;
	}

	sequence_id = le16_to_cpu(hdr->sequence_id);
	if (sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
		SSDFS_ERR("invalid sequence_id %u for peb_index %u\n",
			  sequence_id, peb_index);
		return -EIO;
	}

	if (le16_to_cpu(hdr->type) == SSDFS_UNKNOWN_OFF_TABLE_TYPE ||
	    le16_to_cpu(hdr->type) >= SSDFS_OFF_TABLE_MAX_TYPE) {
		SSDFS_ERR("invalid type %#x for peb_index %u\n",
			  le16_to_cpu(hdr->type), peb_index);
		return -EIO;
	}

	if (le16_to_cpu(hdr->flags) & ~SSDFS_OFF_TABLE_FLAGS_MASK) {
		SSDFS_ERR("invalid flags set %#x for peb_index %u\n",
			  le16_to_cpu(hdr->flags), peb_index);
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_get_checked_table_header() - get and check table header
 * @portion: pointer on portion init environment [out]
 */
static
int ssdfs_get_checked_table_header(struct ssdfs_blk2off_init *portion)
{
	size_t hdr_size = sizeof(struct ssdfs_blk2off_table_header);
	struct page *page;
	void *kaddr;
	int page_index;
	u32 page_off;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || !portion->source);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("source %p, offset %u\n",
		  portion->source, portion->tbl_hdr_off);

	page_index = portion->tbl_hdr_off >> PAGE_SHIFT;
	if (portion->tbl_hdr_off >= PAGE_SIZE)
		page_off = portion->tbl_hdr_off % PAGE_SIZE;
	else
		page_off = portion->tbl_hdr_off;

	if (page_index >= pagevec_count(portion->source)) {
		SSDFS_ERR("invalid page index %d: "
			  "offset %u, pagevec_count %u\n",
			  page_index, portion->tbl_hdr_off,
			  pagevec_count(portion->source));
		return -EINVAL;
	}

	page = portion->source->pages[page_index];

	lock_page(page);
	kaddr = kmap_atomic(page);
	memcpy(&portion->tbl_hdr, (u8 *)kaddr + page_off, hdr_size);
	kunmap_atomic(kaddr);
	unlock_page(page);

	err = ssdfs_check_table_header(&portion->tbl_hdr, hdr_size);
	if (err) {
		SSDFS_ERR("invalid table header\n");
		return err;
	}

	portion->fragments_count =
		le16_to_cpu(portion->tbl_hdr.fragments_count);

	return 0;
}

/*
 * ssdfs_blk2off_prepare_temp_bmap() - prepare temporary bitmap
 * @portion: initialization environment [in | out]
 */
static inline
int ssdfs_blk2off_prepare_temp_bmap(struct ssdfs_blk2off_init *portion)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || portion->bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	portion->bmap_bytes = ssdfs_blk2off_table_bmap_bytes(portion->capacity);
	portion->bmap = kzalloc(portion->bmap_bytes, GFP_KERNEL);
	if (unlikely(!portion->bmap)) {
		SSDFS_ERR("fail to allocate memory\n");
		return -ENOMEM;
	}

	return 0;
}

/*
 * ssdfs_blk2off_prepare_pos_array() - prepare positions array
 * @portion: initialization environment [in | out]
 */
static inline
int ssdfs_blk2off_prepare_pos_array(struct ssdfs_blk2off_init *portion)
{
	size_t pos_size = sizeof(struct ssdfs_offset_position);
	size_t pos_array_bytes;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || portion->pos_array);
#endif /* CONFIG_SSDFS_DEBUG */

	portion->pos_count = portion->capacity;
	pos_array_bytes = portion->capacity * pos_size;
	portion->pos_array = kzalloc(pos_array_bytes, GFP_KERNEL);
	if (unlikely(!portion->pos_array)) {
		SSDFS_ERR("fail to allocate memory\n");
		return -ENOMEM;
	}

	memcpy(portion->pos_array, portion->table->lblk2off,
		pos_array_bytes);

	return 0;
}

/*
 * ssdfs_blk2off_prepare_extent_array() - prepare extents array
 * @portion: initialization environment [in | out]
 */
static
int ssdfs_blk2off_prepare_extent_array(struct ssdfs_blk2off_init *portion)
{
	size_t extent_size = sizeof(struct ssdfs_translation_extent);
	u32 extents_off, table_off;
	size_t ext_array_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || !portion->source || portion->extent_array);
#endif /* CONFIG_SSDFS_DEBUG */

	extents_off = offsetof(struct ssdfs_blk2off_table_header, sequence);
	if (extents_off != le16_to_cpu(portion->tbl_hdr.extents_off)) {
		SSDFS_ERR("invalid extents offset %u\n",
			  le16_to_cpu(portion->tbl_hdr.extents_off));
		return -EIO;
	}

	portion->extents_count = le16_to_cpu(portion->tbl_hdr.extents_count);
	ext_array_size = extent_size * portion->extents_count;
	table_off = le16_to_cpu(portion->tbl_hdr.offset_table_off);

	if (ext_array_size == 0 ||
	    (extents_off + ext_array_size) != table_off) {
		SSDFS_ERR("invalid table header: "
			  "extents_off %u, extents_count %u, "
			  "offset_table_off %u\n",
			  extents_off, portion->extents_count, table_off);
		return -EIO;
	}

	if (ext_array_size > 0) {
		u32 array_size = ext_array_size;
		u32 read_bytes = 0;
		int page_index;
		u32 page_off;

		portion->extent_array = kzalloc(ext_array_size, GFP_KERNEL);
		if (unlikely(!portion->extent_array)) {
			SSDFS_ERR("fail to allocate memory\n");
			return -ENOMEM;
		}

		extents_off = offsetof(struct ssdfs_blk2off_table_header,
					sequence);
		page_index = extents_off >> PAGE_SHIFT;
		page_off = extents_off % PAGE_SIZE;

		while (array_size > 0) {
			u32 size;
			struct page *page;
			void *kaddr;

			size = min_t(u32, PAGE_SIZE - page_off,
					array_size);
			page = portion->source->pages[page_index];

			lock_page(page);
			kaddr = kmap_atomic(page);
			memcpy((u8 *)portion->extent_array + read_bytes,
				(u8 *)kaddr + page_off, size);
			kunmap_atomic(kaddr);
			unlock_page(page);

			read_bytes += size;
			array_size -= size;
			extents_off += size;

			page_index = extents_off >> PAGE_SHIFT;
			page_off = extents_off % PAGE_SIZE;
		};
	}

	return 0;
}

/*
 * ssdfs_get_fragment_header() - get fragment header
 * @portion: initialization environment [in | out]
 */
static
int ssdfs_get_fragment_header(struct ssdfs_blk2off_init *portion)
{
	size_t hdr_size = sizeof(struct ssdfs_phys_offset_table_header);
	struct page *page;
	void *kaddr;
	int page_index;
	u32 page_off;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || !portion->source);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("source %p, offset %u\n",
		  portion->source, portion->pot_hdr_off);

	page_index = portion->pot_hdr_off >> PAGE_SHIFT;
	page_off = portion->pot_hdr_off;
	if (portion->pot_hdr_off >= PAGE_SIZE)
		page_off = portion->pot_hdr_off % PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(page_off > (PAGE_SIZE - hdr_size));
#endif /* CONFIG_SSDFS_DEBUG */

	if (page_index >= pagevec_count(portion->source)) {
		SSDFS_ERR("invalid page index %d: "
			  "offset %u, pagevec_count %u\n",
			  page_index, page_off,
			  pagevec_count(portion->source));
		return -EINVAL;
	}

	page = portion->source->pages[page_index];

	lock_page(page);
	kaddr = kmap_atomic(page);
	memcpy((u8 *)&portion->pot_hdr, (u8 *)kaddr + page_off, hdr_size);
	kunmap_atomic(kaddr);
	unlock_page(page);

	return 0;
}

/*
 * ssdfs_get_checked_fragment() - get checked table's fragment
 * @portion: initialization environment [in | out]
 *
 * This method tries to get and to check fragment validity.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EIO        - corrupted fragment.
 */
static
int ssdfs_get_checked_fragment(struct ssdfs_blk2off_init *portion)
{
	struct ssdfs_phys_offset_table_array *phys_off_table;
	struct ssdfs_phys_offset_table_fragment *fragment;
	struct page *page;
	void *kaddr;
	int page_index;
	u32 page_off;
	size_t fragment_size;
	u16 start_id;
	u16 sequence_id;
	int state;
	u32 read_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || !portion->table || !portion->source);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, peb_index %u, source %p, offset %u\n",
		  portion->table, portion->peb_index,
		  portion->source, portion->pot_hdr_off);

	fragment_size = le32_to_cpu(portion->pot_hdr.byte_size);
	start_id = le16_to_cpu(portion->pot_hdr.start_id);
	sequence_id = le16_to_cpu(portion->pot_hdr.sequence_id);

	SSDFS_DBG("sequence_id %u\n", sequence_id);

	if (fragment_size > PAGE_SIZE) {
		SSDFS_ERR("invalid fragment_size %zu\n",
			  fragment_size);
		return -EIO;
	}

	if (sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
		SSDFS_ERR("invalid sequence_id %u\n",
			  sequence_id);
		return -EIO;
	}

	phys_off_table = &portion->table->peb[portion->peb_index];

	fragment = ssdfs_blk2off_frag_alloc();
	if (IS_ERR_OR_NULL(fragment)) {
		err = (fragment == NULL ? -ENOMEM : PTR_ERR(fragment));
		SSDFS_ERR("fail to allocate fragment: "
			  "err %d\n", err);
		return err;
	}

	err = ssdfs_sequence_array_init_item(phys_off_table->sequence,
					     sequence_id,
					     fragment);
	if (unlikely(err)) {
		ssdfs_blk2off_frag_free(fragment);
		SSDFS_ERR("fail to init fragment: "
			  "err %d\n", err);
		return err;
	}

	state = SSDFS_BLK2OFF_FRAG_CREATED;
	err = ssdfs_blk2off_table_init_fragment(fragment,
						sequence_id,
						start_id,
						portion->table->pages_per_peb,
						state,
						&fragment_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to initialize fragment: err %d\n",
			  err);
		return err;
	}

	page_index = portion->pot_hdr_off >> PAGE_SHIFT;
	if (portion->pot_hdr_off >= PAGE_SIZE)
		page_off = portion->pot_hdr_off % PAGE_SIZE;
	else
		page_off = portion->pot_hdr_off;

	if (page_index >= pagevec_count(portion->source)) {
		SSDFS_ERR("invalid offset %u\n", portion->pot_hdr_off);
		return -EINVAL;
	}

	down_write(&fragment->lock);

	read_bytes = 0;
	while (fragment_size > 0) {
		u32 size;

		size = min_t(u32, PAGE_SIZE - page_off, fragment_size);
		page = portion->source->pages[page_index];

		lock_page(page);
		kaddr = kmap_atomic(page);
		memcpy((u8 *)fragment->buf + read_bytes,
		       (u8 *)kaddr + page_off, size);
		kunmap_atomic(kaddr);
		unlock_page(page);

		read_bytes += size;
		fragment_size -= size;
		portion->pot_hdr_off += size;

		page_index = portion->pot_hdr_off >> PAGE_SHIFT;
		if (portion->pot_hdr_off >= PAGE_SIZE)
			page_off = portion->pot_hdr_off % PAGE_SIZE;
		else
			page_off = portion->pot_hdr_off;
	};

	err = ssdfs_check_fragment(portion->table, portion->peb_index,
				   fragment->hdr,
				   fragment->buf_size);
	if (err)
		goto finish_fragment_read;

	fragment->start_id = start_id;
	atomic_set(&fragment->id_count,
		   le16_to_cpu(fragment->hdr->id_count));
	atomic_set(&fragment->state, SSDFS_BLK2OFF_FRAG_INITIALIZED);

	SSDFS_DBG("FRAGMENT: sequence_id %u, start_id %u, id_count %d\n",
		  sequence_id, start_id, atomic_read(&fragment->id_count));

finish_fragment_read:
	up_write(&fragment->lock);

	if (err) {
		SSDFS_ERR("corrupted fragment: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * is_ssdfs_offset_position_older() - is position checkpoint older?
 * @pos: position offset
 * @cno: checkpoint number for comparison
 */
static inline
bool is_ssdfs_offset_position_older(struct ssdfs_offset_position *pos,
				    u64 cno)
{
	if (pos->cno != SSDFS_INVALID_CNO)
		return pos->cno >= cno;

	return false;
}

/*
 * ssdfs_check_translation_extent() - check translation extent
 * @extent: pointer on translation extent
 * @capacity: logical blocks capacity
 * @sequence_id: extent's sequence id
 *
 * This method tries to check extent's validity.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - corrupted translation extent.
 */
static
int ssdfs_check_translation_extent(struct ssdfs_translation_extent *extent,
				   u16 capacity, u8 sequence_id)
{
	u16 logical_blk;
	u16 offset_id;
	u16 len;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!extent);
#endif /* CONFIG_SSDFS_DEBUG */

	logical_blk = le16_to_cpu(extent->logical_blk);
	offset_id = le16_to_cpu(extent->offset_id);
	len = le16_to_cpu(extent->len);

	SSDFS_DBG("logical_blk %u, offset_id %u, len %u, "
		  "sequence_id %u, state %#x\n",
		  logical_blk, offset_id, len,
		  extent->sequence_id, extent->state);

	if (logical_blk > (U16_MAX - len) ||
	    (logical_blk + len) > capacity) {
		SSDFS_ERR("invalid translation extent: "
			  "logical_blk %u, len %u, capacity %u\n",
			  logical_blk, len, capacity);
		return -EIO;
	}

	if (offset_id > (U16_MAX - len)) {
		SSDFS_ERR("invalid translation extent: "
			  "offset_id %u, len %u\n",
			  offset_id, len);
		return -EIO;
	}

	if (sequence_id != extent->sequence_id) {
		SSDFS_ERR("invalid translation extent: "
			  "sequence_id %u != extent->sequence_id %u\n",
			  sequence_id, extent->sequence_id);
		return -EIO;
	}

	if (extent->state <= SSDFS_LOGICAL_BLK_UNKNOWN_STATE ||
	    extent->state >= SSDFS_LOGICAL_BLK_STATE_MAX) {
		SSDFS_ERR("invalid translation extent: "
			  "unknown state %#x\n",
			  extent->state);
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_process_used_translation_extent() - process used translation extent
 * @portion: pointer on portion init environment [in | out]
 * @extent_index: index of extent
 *
 * This method checks translation extent, to set bitmap for
 * logical blocks in the extent and to fill portion of
 * offset position array by physical offsets id.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EIO        - corrupted translation extent.
 */
static
int ssdfs_process_used_translation_extent(struct ssdfs_blk2off_init *portion,
					  int *extent_index)
{
	struct ssdfs_sequence_array *sequence = NULL;
	struct ssdfs_phys_offset_table_fragment *frag = NULL;
	struct ssdfs_phys_offset_descriptor *phys_off = NULL;
	struct ssdfs_translation_extent *extent = NULL;
	void *ptr;
	u16 peb_index;
	u16 sequence_id;
	u16 pos_array_items;
	u16 start_id;
	u16 id_count;
	u32 logical_blk;
	u16 offset_id;
	u16 len;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || !extent_index);
	BUG_ON(!portion->bmap || !portion->pos_array || !portion->extent_array);
	BUG_ON(portion->cno == SSDFS_INVALID_CNO);
	BUG_ON(*extent_index >= portion->extents_count);
#endif /* CONFIG_SSDFS_DEBUG */

	peb_index = portion->peb_index;
	sequence_id = le16_to_cpu(portion->pot_hdr.sequence_id);

	sequence = portion->table->peb[peb_index].sequence;
	ptr = ssdfs_sequence_array_get_item(sequence, sequence_id);
	if (IS_ERR_OR_NULL(ptr)) {
		err = (ptr == NULL ? -ENOENT : PTR_ERR(ptr));
		SSDFS_ERR("fail to get fragment: "
			  "sequence_id %u, err %d\n",
			  sequence_id, err);
		return err;
	}
	frag = (struct ssdfs_phys_offset_table_fragment *)ptr;

	start_id = le16_to_cpu(portion->pot_hdr.start_id);
	id_count = le16_to_cpu(portion->pot_hdr.id_count);

	extent = &portion->extent_array[*extent_index];
	logical_blk = le16_to_cpu(extent->logical_blk);
	offset_id = le16_to_cpu(extent->offset_id);
	len = le16_to_cpu(extent->len);

	SSDFS_DBG("logical_blk %u, offset_id %u, len %u, "
		  "sequence_id %u, state %#x\n",
		  logical_blk, offset_id, len,
		  extent->sequence_id, extent->state);

	pos_array_items = portion->capacity - logical_blk;

	if (pos_array_items < len) {
		SSDFS_ERR("array_items %u < len %u\n",
			  pos_array_items, len);
		return -EINVAL;
	}

	err = ssdfs_check_translation_extent(extent, portion->capacity,
					     *extent_index);
	if (err) {
		SSDFS_ERR("invalid translation extent: "
			  "sequence_id %u, err %d\n",
			  *extent_index, err);
		return err;
	}

	if (*extent_index == 0 && extent->state != SSDFS_LOGICAL_BLK_USED) {
		SSDFS_ERR("invalid translation extent state %#x\n",
			  extent->state);
		return -EIO;
	}

	if (start_id > offset_id) {
		SSDFS_ERR("start_id %u > offset_id %u\n",
			  start_id, offset_id);
		return -EIO;
	} else if ((offset_id + len) > (start_id + id_count)) {
		SSDFS_ERR("offset_id %u + len %u > "
			  "start_id %u + id_count %u\n",
			  offset_id, len,
			  start_id, id_count);
		return -EIO;
	}

	if (id_count > atomic_read(&frag->id_count)) {
		SSDFS_ERR("id_count %u > frag->id_count %d\n",
			  id_count,
			  atomic_read(&frag->id_count));
		return -EIO;
	}

	bitmap_clear(portion->bmap, 0, portion->capacity);

	down_read(&frag->lock);

	for (i = 0; i < len; i++) {
		struct ssdfs_offset_position *pos;
		u16 id = offset_id + i;
		u16 cur_blk;

		phys_off = &frag->phys_offs[i];

		cur_blk = le16_to_cpu(phys_off->page_desc.logical_blk);

		if (cur_blk >= portion->capacity) {
			err = -EIO;
			SSDFS_ERR("logical_blk %u >= portion->capacity %u\n",
				  cur_blk, portion->capacity);
			goto finish_process_fragment;
		}

		if (cur_blk < logical_blk || cur_blk >= (logical_blk + len)) {
			err = -EIO;
			SSDFS_ERR("cur_blk %u, logical_blk %u, len %u\n",
				  cur_blk, logical_blk, len);
			goto finish_process_fragment;
		}

		pos = &portion->pos_array[cur_blk];

		if (is_ssdfs_offset_position_older(pos, portion->cno)) {
			/* logical block has been initialized already */
			continue;
		}

		peb_index = portion->peb_index;

		bitmap_set(portion->bmap, cur_blk, 1);

		pos->cno = portion->cno;
		pos->id = id;
		pos->peb_index = peb_index;
		pos->sequence_id = sequence_id;
		pos->offset_index = (offset_id - start_id) + i;

		bitmap_set(portion->table->lbmap[SSDFS_LBMAP_INIT_INDEX],
			   cur_blk, 1);
	}

finish_process_fragment:
	up_read(&frag->lock);

	if (unlikely(err))
		return err;

	if (bitmap_intersects(portion->bmap,
			      portion->table->lbmap[SSDFS_LBMAP_STATE_INDEX],
			      portion->capacity)) {
		SSDFS_ERR("invalid translation extent: "
			  "logical_blk %u, offset_id %u, len %u\n",
			  logical_blk, offset_id, len);
		return -EIO;
	}

	bitmap_or(portion->table->lbmap[SSDFS_LBMAP_STATE_INDEX],
		  portion->bmap,
		  portion->table->lbmap[SSDFS_LBMAP_STATE_INDEX],
		  portion->capacity);

	return 0;
}

/*
 * ssdfs_process_free_translation_extent() - process free translation extent
 * @portion: pointer on portion init environment [in | out]
 * @extent_index: index of extent
 *
 * This method checks translation extent, to set bitmap for
 * logical blocks in the extent and to fill portion of
 * offset position array by physical offsets id.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EIO        - corrupted translation extent.
 */
static
int ssdfs_process_free_translation_extent(struct ssdfs_blk2off_init *portion,
					  int *extent_index)
{
	struct ssdfs_sequence_array *sequence = NULL;
	struct ssdfs_phys_offset_table_fragment *frag = NULL;
	struct ssdfs_phys_offset_descriptor *phys_off = NULL;
	struct ssdfs_translation_extent *extent = NULL;
	void *ptr;
	u16 peb_index;
	u16 sequence_id;
	u16 pos_array_items;
	size_t pos_size = sizeof(struct ssdfs_offset_position);
	u32 logical_blk;
	u16 offset_id;
	u16 len;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || !extent_index);
	BUG_ON(!portion->pos_array || !portion->extent_array);
	BUG_ON(portion->cno == SSDFS_INVALID_CNO);
	BUG_ON(*extent_index >= portion->extents_count);
#endif /* CONFIG_SSDFS_DEBUG */

	peb_index = portion->peb_index;
	sequence_id = le16_to_cpu(portion->pot_hdr.sequence_id);

	sequence = portion->table->peb[peb_index].sequence;
	ptr = ssdfs_sequence_array_get_item(sequence, sequence_id);
	if (IS_ERR_OR_NULL(ptr)) {
		err = (ptr == NULL ? -ENOENT : PTR_ERR(ptr));
		SSDFS_ERR("fail to get fragment: "
			  "sequence_id %u, err %d\n",
			  sequence_id, err);
		return err;
	}
	frag = (struct ssdfs_phys_offset_table_fragment *)ptr;

	extent = &portion->extent_array[*extent_index];
	logical_blk = le16_to_cpu(extent->logical_blk);
	offset_id = le16_to_cpu(extent->offset_id);
	len = le16_to_cpu(extent->len);

	SSDFS_DBG("logical_blk %u, offset_id %u, len %u, "
		  "sequence_id %u, state %#x\n",
		  logical_blk, offset_id, len,
		  extent->sequence_id, extent->state);

	pos_array_items = portion->capacity - logical_blk;

	if (pos_array_items < len) {
		SSDFS_ERR("array_items %u < len %u\n",
			  pos_array_items, len);
		return -EINVAL;
	}

	err = ssdfs_check_translation_extent(extent, portion->capacity,
					     *extent_index);
	if (err) {
		SSDFS_ERR("invalid translation extent: "
			  "sequence_id %u, err %d\n",
			  *extent_index, err);
		return err;
	}

	down_read(&frag->lock);

	for (i = 0; i < len; i++) {
		struct ssdfs_offset_position *pos;
		u16 cur_blk;

		phys_off = &frag->phys_offs[i];

		cur_blk = le16_to_cpu(phys_off->page_desc.logical_blk);

		if (cur_blk >= portion->capacity) {
			err = -EIO;
			SSDFS_ERR("logical_blk %u >= portion->capacity %u\n",
				  cur_blk, portion->capacity);
			goto finish_process_fragment;
		}

		if (cur_blk < logical_blk || cur_blk >= (logical_blk + len)) {
			err = -EIO;
			SSDFS_ERR("cur_blk %u, logical_blk %u, len %u\n",
				  cur_blk, logical_blk, len);
			goto finish_process_fragment;
		}

		pos = &portion->pos_array[cur_blk];

		if (is_ssdfs_offset_position_older(pos, portion->cno)) {
			/* logical block has been initialized already */
			continue;
		}

		bitmap_clear(portion->table->lbmap[SSDFS_LBMAP_STATE_INDEX],
			     cur_blk, 1);
		memset(pos, 0xFF, pos_size);

		bitmap_set(portion->table->lbmap[SSDFS_LBMAP_INIT_INDEX],
			   cur_blk, 1);
	}

finish_process_fragment:
	up_read(&frag->lock);

	return err;
}

/*
 * ssdfs_blk2off_fragment_init() - initialize portion's fragment
 * @portion: pointer on portion init environment [in | out]
 * @extent_index: pointer on extent index [in | out]
 */
static
int ssdfs_blk2off_fragment_init(struct ssdfs_blk2off_init *portion,
				int *extent_index)
{
	struct ssdfs_sequence_array *sequence = NULL;
	struct ssdfs_translation_extent *extent = NULL;
	size_t pos_size = sizeof(struct ssdfs_offset_position);
	size_t pos_array_bytes;
	u16 logical_blk;
	u16 offset_id;
	u16 len;
	u16 start_id;
	u16 id_count;
	int state;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion || !portion->table || !portion->source);
	BUG_ON(!portion->bmap || !portion->pos_array || !portion->extent_array);
	BUG_ON(!extent_index);
	BUG_ON(portion->peb_index >= portion->table->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_index %u, extent_index %u\n",
		  portion->peb_index, *extent_index);

	err = ssdfs_get_fragment_header(portion);
	if (err) {
		SSDFS_ERR("fail to get fragment header: err %d\n",
			  err);
		return err;
	}

	err = ssdfs_get_checked_fragment(portion);
	if (err) {
		SSDFS_ERR("fail to get checked fragment: "
			  "peb_index %u, offset %u, err %d\n",
			  portion->peb_index,
			  portion->pot_hdr_off, err);
		return err;
	}

	if (*extent_index >= portion->extents_count) {
		err = -ERANGE;
		SSDFS_ERR("extent_index %u >= extents_count %u\n",
			  *extent_index, portion->extents_count);
		return err;
	}

	start_id = le16_to_cpu(portion->pot_hdr.start_id);
	id_count = le16_to_cpu(portion->pot_hdr.id_count);

	do {
		extent = &portion->extent_array[*extent_index];
		logical_blk = le16_to_cpu(extent->logical_blk);
		offset_id = le16_to_cpu(extent->offset_id);
		len = le16_to_cpu(extent->len);
		state = extent->state;

		if (logical_blk >= portion->capacity) {
			err = -ERANGE;
			SSDFS_ERR("logical_blk %u >= capacity %u\n",
				  logical_blk, portion->capacity);
			return err;
		}

		if (offset_id < start_id) {
			err = -ERANGE;
			SSDFS_ERR("offset_id %u < start_id %u\n",
				  offset_id, start_id);
			return err;
		}

		if (offset_id >= (start_id + id_count))
			break;

		if (state == SSDFS_LOGICAL_BLK_USED) {
			err = ssdfs_process_used_translation_extent(portion,
								extent_index);
			if (unlikely(err)) {
				SSDFS_ERR("invalid translation extent: "
					  "sequence_id %u, err %d\n",
					  *extent_index, err);
				return err;
			}
		} else if (state == SSDFS_LOGICAL_BLK_FREE) {
			err = ssdfs_process_free_translation_extent(portion,
								extent_index);
			if (err) {
				SSDFS_ERR("invalid translation extent: "
					  "sequence_id %u, err %d\n",
					  *extent_index, err);
				return err;
			}
		} else
			BUG();

		++*extent_index;
	} while (*extent_index < portion->extents_count);

	pos_array_bytes = portion->capacity * pos_size;
	memcpy(portion->table->lblk2off, portion->pos_array,
		pos_array_bytes);

	if (portion->table->init_cno == U64_MAX ||
	    portion->cno > portion->table->init_cno) {
		u16 peb_index = portion->peb_index;

		portion->table->init_cno = portion->cno;
		portion->table->used_logical_blks =
			le16_to_cpu(portion->pot_hdr.used_logical_blks);
		portion->table->free_logical_blks =
			le16_to_cpu(portion->pot_hdr.free_logical_blks);
		portion->table->last_allocated_blk =
			le16_to_cpu(portion->pot_hdr.last_allocated_blk);

		sequence = portion->table->peb[peb_index].sequence;
		ssdfs_sequence_array_set_last_id(sequence,
				le16_to_cpu(portion->pot_hdr.sequence_id));
	}

	portion->pot_hdr_off = le16_to_cpu(portion->pot_hdr.next_fragment_off);
	if (portion->pot_hdr_off == U16_MAX && portion->fragments_count > 1) {
		SSDFS_ERR("corrupted table\n");
		return -EIO;
	}

	atomic_inc(&portion->table->peb[portion->peb_index].fragment_count);

	return 0;
}

/*
 * ssdfs_define_peb_table_state() - define PEB's table state
 * @table: pointer on translation table object
 * @peb_index: PEB's index
 */
static inline
int ssdfs_define_peb_table_state(struct ssdfs_blk2off_table *table,
				 u16 peb_index)
{
	int state;
	u16 last_allocated_blk;
	u16 allocated_blks;
	int init_bits;
	int count;
	unsigned long last_id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
	BUG_ON(peb_index >= table->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	count = atomic_read(&table->peb[peb_index].fragment_count);
	last_id = ssdfs_sequence_array_last_id(table->peb[peb_index].sequence);
	last_allocated_blk = table->last_allocated_blk;

	if (last_allocated_blk >= U16_MAX)
		allocated_blks = 0;
	else
		allocated_blks = last_allocated_blk + 1;

	init_bits = bitmap_weight(table->lbmap[SSDFS_LBMAP_INIT_INDEX],
				  allocated_blks);

	SSDFS_DBG("table %p, peb_index %u, count %d, last_id %lu, "
		  "last_allocated_blk %u, init_bits %d\n",
		  table, peb_index, count, last_id,
		  last_allocated_blk, init_bits);

	if (init_bits < 0) {
		SSDFS_ERR("invalid init bmap: weight %d\n",
			  init_bits);
		return -ERANGE;
	}

	if (count == 0) {
		SSDFS_ERR("fragment_count == 0\n");
		return -ERANGE;
	}

	if (count == 1) {
		state = atomic_cmpxchg(&table->peb[peb_index].state,
					SSDFS_BLK2OFF_TABLE_CREATED,
					SSDFS_BLK2OFF_TABLE_PARTIAL_INIT);
		if (state <= SSDFS_BLK2OFF_TABLE_UNDEFINED ||
		    state > SSDFS_BLK2OFF_TABLE_PARTIAL_INIT) {
			SSDFS_WARN("unexpected state %#x\n",
				   state);
			return -ERANGE;
		}
	}

	if (init_bits > 0) {
		if (init_bits >= allocated_blks) {
			state = atomic_cmpxchg(&table->peb[peb_index].state,
					SSDFS_BLK2OFF_TABLE_PARTIAL_INIT,
					SSDFS_BLK2OFF_TABLE_COMPLETE_INIT);
			if (state < SSDFS_BLK2OFF_TABLE_PARTIAL_INIT ||
			    state > SSDFS_BLK2OFF_TABLE_COMPLETE_INIT) {
				SSDFS_WARN("unexpected state %#x\n",
					   state);
				return -ERANGE;
			}
		}
	} else {
		SSDFS_WARN("init_bits == 0\n");
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_define_blk2off_table_object_state() - define table object state
 * @table: pointer on translation table object
 */
static inline
int ssdfs_define_blk2off_table_object_state(struct ssdfs_blk2off_table *table)
{
	int state;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
#endif /* CONFIG_SSDFS_DEBUG */

	state = SSDFS_BLK2OFF_TABLE_STATE_MAX;
	for (i = 0; i < table->pebs_count; i++) {
		int peb_tbl_state = atomic_read(&table->peb[i].state);

		if (peb_tbl_state < state)
			state = peb_tbl_state;
	}

	SSDFS_DBG("table %p, state %#x\n", table, state);

	switch (state) {
	case SSDFS_BLK2OFF_TABLE_CREATED:
		state = atomic_read(&table->state);
		if (state != SSDFS_BLK2OFF_OBJECT_CREATED) {
			SSDFS_WARN("unexpected state %#x\n",
				   state);
			return -ERANGE;
		}
		break;

	case SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT:
		state = atomic_cmpxchg(&table->state,
					SSDFS_BLK2OFF_OBJECT_CREATED,
					SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT);
		complete_all(&table->partial_init_end);

		if (state <= SSDFS_BLK2OFF_OBJECT_UNKNOWN ||
		    state > SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT) {
			SSDFS_WARN("unexpected state %#x\n",
				   state);
			return -ERANGE;
		}
		break;

	case SSDFS_BLK2OFF_TABLE_COMPLETE_INIT:
		state = atomic_cmpxchg(&table->state,
					SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT,
					SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT);
		if (state == SSDFS_BLK2OFF_OBJECT_CREATED) {
			state = atomic_cmpxchg(&table->state,
					SSDFS_BLK2OFF_OBJECT_CREATED,
					SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT);
		}
		complete_all(&table->full_init_end);

		if (state < SSDFS_BLK2OFF_OBJECT_CREATED ||
		    state > SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT) {
			SSDFS_WARN("unexpected state %#x\n",
				   state);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_WARN("unexpected state %#x\n", state);
		return -ERANGE;
	};

	return 0;
}

/*
 * ssdfs_blk2off_table_partial_init() - initialize PEB's table fragment
 * @table: pointer on translation table object
 * @source: pagevec contains fragment
 * @peb_index: PEB's index
 * @cno: fragment's checkpoint (log's checkpoint)
 *
 * This method tries to initialize PEB's table fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EIO        - corrupted translation extent.
 */
int ssdfs_blk2off_table_partial_init(struct ssdfs_blk2off_table *table,
				     struct pagevec *source,
				     u16 peb_index,
				     u64 cno)
{
	struct ssdfs_blk2off_init portion;
	int extent_index = 0;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !source);
	BUG_ON(peb_index >= table->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, peb_index %u\n",
		  table, peb_index);

	memset(&portion, 0, sizeof(struct ssdfs_blk2off_init));

	if (pagevec_count(source) == 0) {
		SSDFS_ERR("fail to init because of empty pagevec\n");
		return -EINVAL;
	}

	if (ssdfs_blk2off_table_initialized(table, peb_index)) {
		SSDFS_DBG("PEB's table has been initialized already: "
			   "peb_index %u\n",
			   peb_index);
		return 0;
	}

	portion.table = table;
	portion.source = source;
	portion.peb_index = peb_index;
	portion.cno = cno;

	portion.tbl_hdr_off = 0;
	err = ssdfs_get_checked_table_header(&portion);
	if (err) {
		SSDFS_ERR("invalid table header\n");
		return err;
	}

	down_write(&table->translation_lock);

	portion.capacity = table->lblk2off_capacity;

	err = ssdfs_blk2off_prepare_temp_bmap(&portion);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate memory\n");
		goto unlock_translation_table;
	}

	err = ssdfs_blk2off_prepare_pos_array(&portion);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate memory\n");
		goto unlock_translation_table;
	}

	err = ssdfs_blk2off_prepare_extent_array(&portion);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate memory\n");
		goto unlock_translation_table;
	}

	if (portion.fragments_count > portion.extents_count) {
		err = -EIO;
		SSDFS_ERR("fragments_count %u > extents_count %u\n",
			  portion.fragments_count,
			  portion.extents_count);
		goto unlock_translation_table;
	}

	portion.pot_hdr_off = portion.tbl_hdr_off +
			le16_to_cpu(portion.tbl_hdr.offset_table_off);

	for (i = 0; i < portion.fragments_count; i++) {
		err = ssdfs_blk2off_fragment_init(&portion,
						  &extent_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to initialize fragment: "
				  "fragment_index %d, extent_index %d, "
				  "err %d\n",
				  i, extent_index, err);
			goto unlock_translation_table;
		}
	}

	err = ssdfs_define_peb_table_state(table, peb_index);
	if (err) {
		SSDFS_ERR("fail to define PEB's table state: "
			  "peb_index %u, err %d\n",
			  peb_index, err);
		goto unlock_translation_table;
	}

	err = ssdfs_define_blk2off_table_object_state(table);
	if (err) {
		SSDFS_ERR("fail to define table object state: "
			  "err %d\n",
			  err);
		goto unlock_translation_table;
	}

unlock_translation_table:
	up_write(&table->translation_lock);

	kfree(portion.bmap);
	kfree(portion.pos_array);
	kfree(portion.extent_array);

	return err;
}

const u16 last_used_blk[U8_MAX + 1] = {
/* 00 - 0x00 */	U16_MAX, 0, 1, 1,
/* 01 - 0x04 */	2, 2, 2, 2,
/* 02 - 0x08 */	3, 3, 3, 3,
/* 03 - 0x0C */	3, 3, 3, 3,
/* 04 - 0x10 */	4, 4, 4, 4,
/* 05 - 0x14 */	4, 4, 4, 4,
/* 06 - 0x18 */	4, 4, 4, 4,
/* 07 - 0x1C */	4, 4, 4, 4,
/* 08 - 0x20 */	5, 5, 5, 5,
/* 09 - 0x24 */	5, 5, 5, 5,
/* 10 - 0x28 */	5, 5, 5, 5,
/* 11 - 0x2C */	5, 5, 5, 5,
/* 12 - 0x30 */	5, 5, 5, 5,
/* 13 - 0x34 */	5, 5, 5, 5,
/* 14 - 0x38 */	5, 5, 5, 5,
/* 15 - 0x3C */	5, 5, 5, 5,
/* 16 - 0x40 */	6, 6, 6, 6,
/* 17 - 0x44 */	6, 6, 6, 6,
/* 18 - 0x48 */	6, 6, 6, 6,
/* 19 - 0x4C */	6, 6, 6, 6,
/* 20 - 0x50 */	6, 6, 6, 6,
/* 21 - 0x54 */	6, 6, 6, 6,
/* 22 - 0x58 */	6, 6, 6, 6,
/* 23 - 0x5C */	6, 6, 6, 6,
/* 24 - 0x60 */	6, 6, 6, 6,
/* 25 - 0x64 */	6, 6, 6, 6,
/* 26 - 0x68 */	6, 6, 6, 6,
/* 27 - 0x6C */	6, 6, 6, 6,
/* 28 - 0x70 */	6, 6, 6, 6,
/* 29 - 0x74 */	6, 6, 6, 6,
/* 30 - 0x78 */	6, 6, 6, 6,
/* 31 - 0x7C */	6, 6, 6, 6,
/* 32 - 0x80 */	7, 7, 7, 7,
/* 33 - 0x84 */	7, 7, 7, 7,
/* 34 - 0x88 */	7, 7, 7, 7,
/* 35 - 0x8C */	7, 7, 7, 7,
/* 36 - 0x90 */	7, 7, 7, 7,
/* 37 - 0x94 */	7, 7, 7, 7,
/* 38 - 0x98 */	7, 7, 7, 7,
/* 39 - 0x9C */	7, 7, 7, 7,
/* 40 - 0xA0 */	7, 7, 7, 7,
/* 41 - 0xA4 */	7, 7, 7, 7,
/* 42 - 0xA8 */	7, 7, 7, 7,
/* 43 - 0xAC */	7, 7, 7, 7,
/* 44 - 0xB0 */	7, 7, 7, 7,
/* 45 - 0xB4 */	7, 7, 7, 7,
/* 46 - 0xB8 */	7, 7, 7, 7,
/* 47 - 0xBC */	7, 7, 7, 7,
/* 48 - 0xC0 */	7, 7, 7, 7,
/* 49 - 0xC4 */	7, 7, 7, 7,
/* 50 - 0xC8 */	7, 7, 7, 7,
/* 51 - 0xCC */	7, 7, 7, 7,
/* 52 - 0xD0 */	7, 7, 7, 7,
/* 53 - 0xD4 */	7, 7, 7, 7,
/* 54 - 0xD8 */	7, 7, 7, 7,
/* 55 - 0xDC */	7, 7, 7, 7,
/* 56 - 0xE0 */	7, 7, 7, 7,
/* 57 - 0xE4 */	7, 7, 7, 7,
/* 58 - 0xE8 */	7, 7, 7, 7,
/* 59 - 0xEC */	7, 7, 7, 7,
/* 60 - 0xF0 */	7, 7, 7, 7,
/* 61 - 0xF4 */	7, 7, 7, 7,
/* 62 - 0xF8 */	7, 7, 7, 7,
/* 63 - 0xFC */	7, 7, 7, 7
};

/*
 * ssdfs_blk2off_table_find_last_valid_block() - find last valid block
 * @table: pointer on translation table object
 *
 * RETURN:
 * [success] - last valid logical block number.
 * [failure] - U16_MAX.
 */
static
u16 ssdfs_blk2off_table_find_last_valid_block(struct ssdfs_blk2off_table *table)
{
	u16 logical_blk;
	unsigned long *lbmap;
	unsigned char *byte;
	int long_count, byte_count;
	int i, j;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
	BUG_ON(!rwsem_is_locked(&table->translation_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	logical_blk = U16_MAX;
	long_count = BITS_TO_LONGS(table->lblk2off_capacity);
	lbmap = table->lbmap[SSDFS_LBMAP_STATE_INDEX];

	for (i = long_count - 1; i >= 0; i--) {
		if (lbmap[i] != 0) {
			byte_count = sizeof(unsigned long);
			for (j = byte_count - 1; j >= 0; j--) {
				byte = (unsigned char *)lbmap[i] + j;
				logical_blk = last_used_blk[*byte];
				if (logical_blk != U16_MAX)
					break;
			}
			goto calculate_logical_blk;
		}
	}

calculate_logical_blk:
	if (logical_blk != U16_MAX)
		logical_blk += i * BITS_PER_LONG;

	SSDFS_DBG("table %p, logical_blk %u\n",
		  table, logical_blk);

	return logical_blk;
}

/*
 * ssdfs_blk2off_table_resize() - resize table
 * @table: pointer on translation table object
 * @new_items_count: new table size
 *
 * This method tries to grow or to shrink table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - unable to shrink table.
 * %-ENOMEM     - unable to realloc table.
 */
int ssdfs_blk2off_table_resize(struct ssdfs_blk2off_table *table,
				u16 new_items_count)
{
	unsigned long *bmap_ptr;
	size_t off_pos_size = sizeof(struct ssdfs_offset_position);
	size_t blk_desc_size = sizeof(struct ssdfs_migrating_block);
	u16 *off_ptr;
	u16 *migrating_ptr;
	u32 new_bytes;
	u16 last_blk;
	int diff;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, lblk2off_capacity %u, new_items_count %u\n",
		  table, table->lblk2off_capacity, new_items_count);

	down_write(&table->translation_lock);

	if (new_items_count == table->lblk2off_capacity) {
		SSDFS_WARN("new_items_count %u == lblk2off_capacity %u\n",
			   new_items_count, table->lblk2off_capacity);
		goto finish_table_resize;
	} else if (new_items_count < table->lblk2off_capacity) {
		last_blk = ssdfs_blk2off_table_find_last_valid_block(table);

		if (last_blk != U16_MAX && last_blk >= new_items_count) {
			err = -ERANGE;
			SSDFS_ERR("unable to shrink bitmap: "
				  "last_blk %u >= new_items_count %u\n",
				  last_blk, new_items_count);
			goto finish_table_resize;
		}
	}

	new_bytes = ssdfs_blk2off_table_bmap_bytes(new_items_count);

	for (i = 0; i < SSDFS_LBMAP_ARRAY_MAX; i++) {
		bmap_ptr = krealloc(table->lbmap[i], new_bytes,
				    GFP_KERNEL | __GFP_ZERO);
		if (!bmap_ptr) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate bitmaps\n");
			goto finish_table_resize;
		} else
			table->lbmap[i] = (unsigned long *)bmap_ptr;
	}

	off_ptr = krealloc(table->lblk2off, off_pos_size * new_items_count,
			   GFP_KERNEL | __GFP_ZERO);
	if (!off_ptr) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate translation array\n");
		goto finish_table_resize;
	} else
		table->lblk2off = (struct ssdfs_offset_position *)off_ptr;

	diff = (int)new_items_count - table->lblk2off_capacity;

	memset((u8 *)table->lblk2off +
		(off_pos_size * table->lblk2off_capacity),
		0xFF, off_pos_size * diff);

	migrating_ptr = krealloc(table->migrating_blks,
				 blk_desc_size * new_items_count,
				 GFP_KERNEL | __GFP_ZERO);
	if (!migrating_ptr) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate migrating blocks array\n");
		goto finish_table_resize;
	} else {
		table->migrating_blks =
			(struct ssdfs_migrating_block *)migrating_ptr;
	}

	memset((u8 *)table->migrating_blks +
		(blk_desc_size * table->lblk2off_capacity),
		0, blk_desc_size * diff);

	table->lblk2off_capacity = new_items_count;
	table->free_logical_blks += diff;

finish_table_resize:
	up_write(&table->translation_lock);

	return err;
}

/*
 * ssdfs_blk2off_table_dirtied() - check that PEB's table is dirty
 * @table: pointer on translation table object
 * @peb_index: PEB's index
 */
bool ssdfs_blk2off_table_dirtied(struct ssdfs_blk2off_table *table,
				 u16 peb_index)
{
	bool is_dirty = false;
	struct ssdfs_phys_offset_table_array *phys_off_table;
	struct ssdfs_sequence_array *sequence;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
	BUG_ON(!table->peb);
	BUG_ON(peb_index >= table->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, peb_index %u\n",
		  table, peb_index);

	phys_off_table = &table->peb[peb_index];
	sequence = phys_off_table->sequence;
	is_dirty = has_ssdfs_sequence_array_state(sequence,
				SSDFS_SEQUENCE_ITEM_DIRTY_TAG);

	switch (atomic_read(&phys_off_table->state)) {
	case SSDFS_BLK2OFF_TABLE_DIRTY:
		if (!is_dirty) {
			/* table is dirty without dirty fragments */
			SSDFS_WARN("table is marked as dirty!\n");
		}
		break;

	default:
		if (is_dirty) {
			/* there dirty fragments but table is clean */
			SSDFS_WARN("table is not dirty\n");
		}
		break;
	}

	return is_dirty;
}

/*
 * ssdfs_blk2off_table_initialized() - check that PEB's table is initialized
 * @table: pointer on translation table object
 * @peb_index: PEB's index
 */
bool ssdfs_blk2off_table_initialized(struct ssdfs_blk2off_table *table,
				     u16 peb_index)
{
	int state;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
	BUG_ON(peb_index >= table->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, peb_index %u\n",
		  table, peb_index);

	BUG_ON(!table->peb);

	state = atomic_read(&table->peb[peb_index].state);

	return state >= SSDFS_BLK2OFF_TABLE_COMPLETE_INIT &&
		state < SSDFS_BLK2OFF_TABLE_STATE_MAX;
}

static
int ssdfs_change_fragment_state(void *item, int old_state, int new_state)
{
	struct ssdfs_phys_offset_table_fragment *fragment =
		(struct ssdfs_phys_offset_table_fragment *)item;
	int state;

	SSDFS_DBG("old_state %#x, new_state %#x\n",
		  old_state, new_state);

	if (!fragment) {
		SSDFS_ERR("pointer is NULL\n");
		return -ERANGE;
	}

	SSDFS_DBG("sequence_id %u, state %#x\n",
		  fragment->sequence_id,
		  atomic_read(&fragment->state));

	state = atomic_cmpxchg(&fragment->state, old_state, new_state);

	switch (new_state) {
	case SSDFS_BLK2OFF_FRAG_DIRTY:
		switch (state) {
		case SSDFS_BLK2OFF_FRAG_CREATED:
		case SSDFS_BLK2OFF_FRAG_INITIALIZED:
		case SSDFS_BLK2OFF_FRAG_DIRTY:
			/* expected old state */
			break;

		default:
			SSDFS_ERR("invalid old_state %#x\n",
				  old_state);
			return -ERANGE;
		}
		break;

	default:
		if (state != old_state) {
			SSDFS_ERR("state %#x != old_state %#x\n",
				  state, old_state);
			return -ERANGE;
		}
		break;
	}

	return 0;
}

static inline
int ssdfs_calculate_start_sequence_id(u16 last_sequence_id,
				      u16 dirty_fragments,
				      u16 *start_sequence_id)
{
	u16 upper_bound;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!start_sequence_id);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("last_sequence_id %u, dirty_fragments %u\n",
		  last_sequence_id, dirty_fragments);

	*start_sequence_id = U16_MAX;

	if (last_sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
		SSDFS_ERR("invalid last_sequence_id %u\n",
			  last_sequence_id);
		return -ERANGE;
	}

	if (dirty_fragments > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
		SSDFS_ERR("invalid dirty_fragments %u\n",
			  dirty_fragments);
		return -ERANGE;
	}

	upper_bound = last_sequence_id + 1;

	if (upper_bound >= dirty_fragments)
		*start_sequence_id = upper_bound - dirty_fragments;
	else {
		*start_sequence_id = SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD -
					(dirty_fragments - upper_bound);
	}

	return 0;
}

/*
 * ssdfs_blk2off_table_snapshot() - get table's snapshot
 * @table: pointer on translation table object
 * @peb_index: PEB's index
 * @snapshot: pointer on table's snapshot object
 *
 * This method tries to get table's snapshot. The @bmap_copy
 * and @tbl_copy fields of snapshot object are allocated during
 * getting snapshot by this method. Freeing of allocated
 * memory SHOULD BE MADE by caller.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENODATA    - PEB hasn't dirty fragments.
 */
int ssdfs_blk2off_table_snapshot(struct ssdfs_blk2off_table *table,
				 u16 peb_index,
				 struct ssdfs_blk2off_table_snapshot *snapshot)
{
	struct ssdfs_sequence_array *sequence;
	size_t off_pos_size = sizeof(struct ssdfs_offset_position);
	u16 capacity;
	size_t bmap_bytes, tbl_bytes;
	u16 last_sequence_id;
	unsigned long dirty_fragments;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !snapshot);
	BUG_ON(peb_index >= table->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, peb_index %u, snapshot %p\n",
		  table, peb_index, snapshot);

	if (!ssdfs_blk2off_table_dirtied(table, peb_index)) {
		SSDFS_DBG("table isn't dirty for peb_index %u\n",
			  peb_index);
		return -ENODATA;
	}

	memset(snapshot, 0, sizeof(struct ssdfs_blk2off_table_snapshot));

	down_read(&table->translation_lock);

	capacity = table->lblk2off_capacity;

	bmap_bytes = ssdfs_blk2off_table_bmap_bytes(capacity);
	snapshot->bmap_copy = kzalloc(bmap_bytes, GFP_KERNEL);
	if (!snapshot->bmap_copy) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocated bytes %zu\n",
			  bmap_bytes);
		goto finish_snapshoting;
	}

	tbl_bytes = capacity * off_pos_size;
	snapshot->tbl_copy = kzalloc(tbl_bytes, GFP_KERNEL);
	if (!snapshot->tbl_copy) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocated bytes %zu\n",
			  tbl_bytes);
		goto finish_snapshoting;
	}

	memcpy(snapshot->bmap_copy,
		table->lbmap[SSDFS_LBMAP_MODIFICATION_INDEX],
		bmap_bytes);
	memcpy(snapshot->tbl_copy, table->lblk2off, tbl_bytes);
	snapshot->capacity = table->lblk2off_capacity;

	snapshot->used_logical_blks = table->used_logical_blks;
	snapshot->free_logical_blks = table->free_logical_blks;
	snapshot->last_allocated_blk = table->last_allocated_blk;

	snapshot->peb_index = peb_index;
	snapshot->start_sequence_id = SSDFS_INVALID_FRAG_ID;

	sequence = table->peb[peb_index].sequence;
	err = ssdfs_sequence_array_change_all_states(sequence,
					SSDFS_SEQUENCE_ITEM_DIRTY_TAG,
					SSDFS_SEQUENCE_ITEM_UNDER_COMMIT_TAG,
					ssdfs_change_fragment_state,
					SSDFS_BLK2OFF_FRAG_DIRTY,
					SSDFS_BLK2OFF_FRAG_UNDER_COMMIT,
					&dirty_fragments);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change from dirty to under_commit: "
			  "err %d\n", err);
		goto finish_snapshoting;
	} else if (dirty_fragments >= U16_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid dirty_fragments %lu\n",
			  dirty_fragments);
		goto finish_snapshoting;
	}

	snapshot->dirty_fragments = (u16)dirty_fragments;

	last_sequence_id =
		ssdfs_sequence_array_last_id(table->peb[peb_index].sequence);
	err = ssdfs_calculate_start_sequence_id(last_sequence_id,
						snapshot->dirty_fragments,
						&snapshot->start_sequence_id);
	if (unlikely(err)) {
		SSDFS_ERR("fail to calculate start sequence ID: "
			  "err %d\n", err);
		goto finish_snapshoting;
	}

	SSDFS_DBG("start_sequence_id %u, dirty_fragments %u\n",
		  snapshot->start_sequence_id,
		  snapshot->dirty_fragments);

	if (snapshot->dirty_fragments == 0) {
		err = -ERANGE;
		SSDFS_ERR("PEB hasn't dirty fragments\n");
		goto finish_snapshoting;
	}

	snapshot->cno = ssdfs_current_cno(table->fsi->sb);

finish_snapshoting:
	up_read(&table->translation_lock);

	if (err) {
		kfree(snapshot->bmap_copy);
		kfree(snapshot->tbl_copy);
	}

	return err;
}

/*
 * ssdfs_blk2off_table_free_snapshot() - free snapshot's resources
 * @sp: pointer on tabls's snapshot
 */
void ssdfs_blk2off_table_free_snapshot(struct ssdfs_blk2off_table_snapshot *sp)
{
	if (!sp)
		return;

	kfree(sp->bmap_copy);
	kfree(sp->tbl_copy);

	memset(sp, 0, sizeof(struct ssdfs_blk2off_table_snapshot));
}

/*
 * ssdfs_find_changed_area() - find changed area
 * @sp: table's snapshot
 * @start: starting bit for search
 * @found: found range of set bits
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 * %-ENODATA    - nothing was found.
 */
static inline
int ssdfs_find_changed_area(struct ssdfs_blk2off_table_snapshot *sp,
			    unsigned long start,
			    struct ssdfs_blk2off_range *found)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sp || !found);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("snapshot %p, peb_index %u, start %lu, found %p\n",
		  sp, sp->peb_index, start, found);

	start = find_next_bit(sp->bmap_copy, sp->capacity, start);
	if (start >= sp->capacity) {
		SSDFS_DBG("nothing found\n");
		return -ENODATA;
	}

	found->start_lblk = (u16)start;

	start = find_next_zero_bit(sp->bmap_copy, sp->capacity, start);
	start = (unsigned long)min_t(u16, (u16)start, sp->capacity);

	found->len = (u16)(start - found->start_lblk);

	if (found->len == 0) {
		SSDFS_ERR("found empty extent\n");
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_translation_extent_init() - init translation extent
 * @found: range of changed logical blocks
 * @id: starting offset ID
 * @sequence_id: sequence ID of extent
 * @state: state of logical blocks in extent (used, free and so on)
 * @extent: pointer on initialized extent [out]
 */
static inline
void ssdfs_translation_extent_init(struct ssdfs_blk2off_range *found,
				   u16 id, u8 sequence_id, u8 state,
				   struct ssdfs_translation_extent *extent)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!found || !extent);
	BUG_ON(id == SSDFS_BLK2OFF_TABLE_INVALID_ID);
	BUG_ON(state <= SSDFS_LOGICAL_BLK_UNKNOWN_STATE ||
		state >= SSDFS_LOGICAL_BLK_STATE_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("start %u, len %u, id %u, sequence_id %u, state %#x\n",
		  found->start_lblk, found->len, id, sequence_id, state);

	extent->logical_blk = cpu_to_le16(found->start_lblk);
	extent->offset_id = cpu_to_le16(id);
	extent->len = cpu_to_le16(found->len);
	extent->sequence_id = sequence_id;
	extent->state = state;
}

/*
 * ssdfs_blk2off_table_extract_extents() - extract changed extents
 * @sp: table's snapshot
 * @array: extents array [in|out]
 * @capacity: capacity of extents array
 * @extent_count: pointer on extents count value [out]
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 */
int ssdfs_blk2off_table_extract_extents(struct ssdfs_blk2off_table_snapshot *sp,
					struct ssdfs_translation_extent *array,
					u16 capacity, u16 *extent_count)
{
	unsigned long start = 0;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sp || !array || !extent_count);
	BUG_ON(capacity == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("snapshot %p, peb_index %u, extents %p, "
		  "capacity %u, extent_count %p\n",
		  sp, sp->peb_index, array,
		  capacity, extent_count);

	*extent_count = 0;

	do {
		struct ssdfs_blk2off_range changed_area = {0};
		struct ssdfs_blk2off_range found = {
			.start_lblk = U16_MAX,
			.len = 0,
		};
		struct ssdfs_offset_position *pos;
		int state = SSDFS_LOGICAL_BLK_UNKNOWN_STATE;
		u16 start_id = SSDFS_BLK2OFF_TABLE_INVALID_ID;

		err = ssdfs_find_changed_area(sp, start, &changed_area);
		if (err == -ENODATA) {
			err = 0;
			SSDFS_DBG("nothing found\n");
			goto finish_extract_extents;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find changed area: err %d\n",
				  err);
			return err;
		}

		SSDFS_DBG("changed area: start %u, len %u\n",
			  changed_area.start_lblk, changed_area.len);

		for (i = 0; i < changed_area.len; i++) {
			u16 blk = changed_area.start_lblk + i;
			bool is_extent_ended = false;

			pos = &sp->tbl_copy[blk];

			if (pos->peb_index == U16_MAX) {
				SSDFS_WARN("invalid peb_index: "
					   "logical_blk %u\n",
					   blk);
				is_extent_ended = true;
			} else if (pos->peb_index != sp->peb_index) {
				/* changes of another PEB */
				is_extent_ended = true;
			} else if (pos->id != SSDFS_BLK2OFF_TABLE_INVALID_ID) {
				if (start_id == SSDFS_BLK2OFF_TABLE_INVALID_ID)
					start_id = pos->id;
				else if (pos->id < start_id)
					start_id = pos->id;
			} else if (pos->id == SSDFS_BLK2OFF_TABLE_INVALID_ID &&
				   state != SSDFS_LOGICAL_BLK_FREE) {
				/* state is changed */
				is_extent_ended = true;
			}

			if (is_extent_ended) {
				struct ssdfs_translation_extent *extent;

				if (found.start_lblk == U16_MAX)
					continue;

				extent = &array[*extent_count];

				BUG_ON(*extent_count >= capacity);
				ssdfs_translation_extent_init(&found, start_id,
							      *extent_count,
							      state,
							      extent);
				(*extent_count)++;

				pos = &sp->tbl_copy[blk];

				if (pos->id == SSDFS_BLK2OFF_TABLE_INVALID_ID)
					state = SSDFS_LOGICAL_BLK_FREE;
				else
					state = SSDFS_LOGICAL_BLK_USED;

				found.start_lblk = blk;
				found.len = 1;
				start_id = pos->id;
			} else {
				if (pos->id == SSDFS_BLK2OFF_TABLE_INVALID_ID)
					state = SSDFS_LOGICAL_BLK_FREE;
				else
					state = SSDFS_LOGICAL_BLK_USED;

				if (found.start_lblk == U16_MAX)
					found.start_lblk = blk;

				found.len++;

				SSDFS_DBG("found (start %u, len %u), "
					  "start_id %u\n",
					  found.start_lblk, found.len,
					  start_id);
			}
		}

		if (found.start_lblk != U16_MAX) {
			struct ssdfs_translation_extent *extent;

			extent = &array[*extent_count];

			BUG_ON(*extent_count >= capacity);
			ssdfs_translation_extent_init(&found, start_id,
						      *extent_count,
						      state,
						      extent);

			found.start_lblk = U16_MAX;
			found.len = 0;
			state = SSDFS_LOGICAL_BLK_UNKNOWN_STATE;
			(*extent_count)++;

			start = found.start_lblk + found.len;
		} else
			start = changed_area.start_lblk + changed_area.len;
	} while (start < sp->capacity);

	SSDFS_DBG("extents_count %u\n", *extent_count);

finish_extract_extents:
	if (*extent_count == 0) {
		err = -ERANGE;
		SSDFS_ERR("invalid state of change bitmap\n");
		return err;
	}

	return 0;
}

/*
 * ssdfs_blk2off_table_prepare_for_commit() - prepare fragment for commit
 * @table: pointer on table object
 * @peb_index: PEB's index
 * @sequence_id: fragment's sequence ID
 * @sp: pointer on snapshot
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 */
int
ssdfs_blk2off_table_prepare_for_commit(struct ssdfs_blk2off_table *table,
				       u16 peb_index, u16 sequence_id,
				       struct ssdfs_blk2off_table_snapshot *sp)
{
	struct ssdfs_phys_offset_table_array *pot_table;
	struct ssdfs_sequence_array *sequence;
	struct ssdfs_phys_offset_table_fragment *fragment;
	void *ptr;
	u16 id_count;
	u32 byte_size;
	u16 flags = 0;
	int last_sequence_id;
	bool has_next_fragment = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !sp);
	BUG_ON(peb_index >= table->pebs_count);
	BUG_ON(peb_index != sp->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, peb_index %u, sequence_id %u, sp %p\n",
		  table, peb_index, sequence_id, sp);

	down_read(&table->translation_lock);

	pot_table = &table->peb[peb_index];

	sequence = pot_table->sequence;
	ptr = ssdfs_sequence_array_get_item(sequence, sequence_id);
	if (IS_ERR_OR_NULL(ptr)) {
		err = (ptr == NULL ? -ENOENT : PTR_ERR(ptr));
		SSDFS_ERR("fail to get fragment: "
			  "sequence_id %u, err %d\n",
			  sequence_id, err);
		goto finish_prepare_for_commit;
	}
	fragment = (struct ssdfs_phys_offset_table_fragment *)ptr;

	if (atomic_read(&fragment->state) != SSDFS_BLK2OFF_FRAG_UNDER_COMMIT) {
		err = -ERANGE;
		SSDFS_ERR("fragment isn't under commit: "
			  "state %#x\n",
			  atomic_read(&fragment->state));
		goto finish_prepare_for_commit;
	}

	down_write(&fragment->lock);

	fragment->hdr->magic = cpu_to_le32(SSDFS_PHYS_OFF_TABLE_MAGIC);
	fragment->hdr->checksum = 0;

	fragment->hdr->start_id = cpu_to_le16(fragment->start_id);
	id_count = (u16)atomic_read(&fragment->id_count);
	fragment->hdr->id_count = cpu_to_le16(id_count);
	byte_size = sizeof(struct ssdfs_phys_offset_table_header);
	byte_size += id_count * sizeof(struct ssdfs_phys_offset_descriptor);
	fragment->hdr->byte_size = cpu_to_le32(byte_size);

	fragment->hdr->peb_index = cpu_to_le16(peb_index);
	fragment->hdr->sequence_id = cpu_to_le16(fragment->sequence_id);
	fragment->hdr->type = cpu_to_le16(table->type);

	SSDFS_DBG("sequence_id %u, start_sequence_id %u, "
		  "dirty_fragments %u, fragment->sequence_id %u\n",
		  sequence_id, sp->start_sequence_id,
		  sp->dirty_fragments,
		  fragment->sequence_id);

	last_sequence_id = ssdfs_sequence_array_last_id(pot_table->sequence);
	has_next_fragment = sequence_id != last_sequence_id;

	flags |= SSDFS_OFF_TABLE_HAS_CSUM;
	if (has_next_fragment)
		flags |= SSDFS_OFF_TABLE_HAS_NEXT_FRAGMENT;
	fragment->hdr->flags = cpu_to_le16(flags);

	fragment->hdr->used_logical_blks = cpu_to_le16(sp->used_logical_blks);
	fragment->hdr->free_logical_blks = cpu_to_le16(sp->free_logical_blks);
	fragment->hdr->last_allocated_blk = cpu_to_le16(sp->last_allocated_blk);

	BUG_ON(byte_size >= U16_MAX);

	if (has_next_fragment)
		fragment->hdr->next_fragment_off = cpu_to_le16((u16)byte_size);
	else
		fragment->hdr->next_fragment_off = cpu_to_le16(U16_MAX);

	fragment->hdr->checksum = ssdfs_crc32_le(fragment->hdr, byte_size);

	up_write(&fragment->lock);

finish_prepare_for_commit:
	up_read(&table->translation_lock);

	return err;
}

/*
 * ssdfs_blk2off_table_forget_snapshot() - undirty PEB's table
 * @table: pointer on table object
 * @sp: pointer on snapshot
 * @array: extents array
 * @extent_count: count of extents in array
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal logic error.
 */
int
ssdfs_blk2off_table_forget_snapshot(struct ssdfs_blk2off_table *table,
				    struct ssdfs_blk2off_table_snapshot *sp,
				    struct ssdfs_translation_extent *array,
				    u16 extent_count)
{
	struct ssdfs_phys_offset_table_array *pot_table;
	struct ssdfs_sequence_array *sequence;
	unsigned long *lbmap;
	u16 last_sequence_id;
	int state;
	unsigned long commited_fragments = 0;
	int i, j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !sp || !array);
	BUG_ON(sp->peb_index >= table->pebs_count);
	BUG_ON(extent_count == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, peb_index %u, sp %p, "
		  "extents %p, extents_count %u\n",
		  table, sp->peb_index, sp,
		  array, extent_count);

	down_write(&table->translation_lock);

	pot_table = &table->peb[sp->peb_index];
	last_sequence_id = ssdfs_sequence_array_last_id(pot_table->sequence);

	if (sp->dirty_fragments == 0) {
		err = -EINVAL;
		SSDFS_ERR("dirty_fragments == 0\n");
		goto finish_forget_snapshot;
	}

	sequence = table->peb[sp->peb_index].sequence;
	err = ssdfs_sequence_array_change_all_states(sequence,
					SSDFS_SEQUENCE_ITEM_UNDER_COMMIT_TAG,
					SSDFS_SEQUENCE_ITEM_COMMITED_TAG,
					ssdfs_change_fragment_state,
					SSDFS_BLK2OFF_FRAG_UNDER_COMMIT,
					SSDFS_BLK2OFF_FRAG_COMMITED,
					&commited_fragments);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set fragments as commited: "
			  "err %d\n", err);
		goto finish_forget_snapshot;
	}

	if (sp->dirty_fragments != commited_fragments) {
		err = -ERANGE;
		SSDFS_ERR("dirty_fragments %u != commited_fragments %lu\n",
			  sp->dirty_fragments, commited_fragments);
		goto finish_forget_snapshot;
	}

	state = atomic_cmpxchg(&pot_table->state,
				SSDFS_BLK2OFF_TABLE_DIRTY,
				SSDFS_BLK2OFF_TABLE_COMPLETE_INIT);
	if (state != SSDFS_BLK2OFF_TABLE_DIRTY) {
		err = -ERANGE;
		SSDFS_ERR("table isn't dirty: "
			  "state %#x\n",
			  state);
		goto finish_forget_snapshot;
	}

	lbmap = table->lbmap[SSDFS_LBMAP_MODIFICATION_INDEX];

	for (i = 0; i < extent_count; i++) {
		u16 start_blk = le16_to_cpu(array[i].logical_blk);
		u16 len = le16_to_cpu(array[i].len);

		for (j = 0; j < len; j++) {
			u16 blk = start_blk + j;
			u64 cno1, cno2;

			cno1 = table->lblk2off[blk].cno;
			cno2 = sp->tbl_copy[blk].cno;
			if (cno1 < cno2) {
				SSDFS_WARN("cno1 %llu < cno2 %llu\n",
					   cno1, cno2);
			} else if (cno1 > cno2)
				continue;

			ssdfs_blk2off_table_bmap_clear(lbmap, blk);
		}
	}

finish_forget_snapshot:
	up_write(&table->translation_lock);

	return err;
}

/*
 * ssdfs_peb_store_offsets_table_header() - store offsets table header
 * @pebi: pointer on PEB object
 * @hdr: table header
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
 *
 * This function tries to store table header into log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to find memory page.
 */
int ssdfs_peb_store_offsets_table_header(struct ssdfs_peb_info *pebi,
					 struct ssdfs_blk2off_table_header *hdr,
					 pgoff_t *cur_page,
					 u32 *write_offset)
{
	size_t hdr_sz = sizeof(struct ssdfs_blk2off_table_header);
	struct page *page;
	void *kaddr;
	u32 page_off, cur_offset;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!hdr || !cur_page || !write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb %llu, current_log.start_page %u, "
		  "hdr %p, cur_page %lu, write_offset %u\n",
		  pebi->peb_id,
		  pebi->current_log.start_page,
		  hdr, *cur_page, *write_offset);

	page_off = *write_offset % PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON((PAGE_SIZE - page_off) < hdr_sz);
#endif /* CONFIG_SSDFS_DEBUG */

	page = ssdfs_page_array_get_page_locked(&pebi->cache, *cur_page);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to get cache page: index %lu\n",
			  *cur_page);
		return -ENOMEM;
	}

	kaddr = kmap_atomic(page);
	memcpy((u8 *)kaddr + page_off, hdr, hdr_sz);
	kunmap_atomic(kaddr);

	SetPagePrivate(page);
	SetPageUptodate(page);

	err = ssdfs_page_array_set_page_dirty(&pebi->cache, *cur_page);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page %lu as dirty: err %d\n",
			  *cur_page, err);
	}

	unlock_page(page);
	put_page(page);

	if (unlikely(err))
		return err;

	*write_offset += hdr_sz;

	cur_offset = (*cur_page << PAGE_SHIFT) + page_off + hdr_sz;
	*cur_page = cur_offset >> PAGE_SHIFT;

	return 0;
}

/*
 * ssdfs_peb_store_offsets_table_extents() - store translation extents
 * @pebi: pointer on PEB object
 * @array: translation extents array
 * @extent_count: count of extents in the array
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
 *
 * This function tries to store translation extents into log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to find memory page.
 */
int
ssdfs_peb_store_offsets_table_extents(struct ssdfs_peb_info *pebi,
				      struct ssdfs_translation_extent *array,
				      u16 extent_count,
				      pgoff_t *cur_page,
				      u32 *write_offset)
{
	struct page *page;
	void *kaddr;
	size_t extent_size = sizeof(struct ssdfs_translation_extent);
	u32 rest_bytes, written_bytes = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!array || !cur_page || !write_offset);
	BUG_ON(extent_count == 0 || extent_count == U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb %llu, current_log.start_page %u, "
		  "array %p, extent_count %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->peb_id,
		  pebi->current_log.start_page,
		  array, extent_count,
		  *cur_page, *write_offset);

	rest_bytes = extent_count * extent_size;

	while (rest_bytes > 0) {
		u32 bytes;
		u32 cur_off = *write_offset % PAGE_SIZE;
		u32 new_off;

		bytes = min_t(u32, rest_bytes, PAGE_SIZE - cur_off);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(bytes < extent_size);
		BUG_ON(written_bytes > (extent_count * extent_size));
#endif /* CONFIG_SSDFS_DEBUG */

		page = ssdfs_page_array_get_page_locked(&pebi->cache,
							*cur_page);
		if (IS_ERR_OR_NULL(page)) {
			SSDFS_ERR("fail to get cache page: index %lu\n",
				  *cur_page);
			return -ENOMEM;
		}

		SSDFS_DBG("cur_off %u, written_bytes %u, bytes %u\n",
			  cur_off, written_bytes, bytes);

		kaddr = kmap_atomic(page);
		memcpy((u8 *)kaddr + cur_off, array + written_bytes, bytes);
		kunmap_atomic(kaddr);

		SetPagePrivate(page);
		SetPageUptodate(page);

		err = ssdfs_page_array_set_page_dirty(&pebi->cache,
						      *cur_page);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu as dirty: err %d\n",
				  *cur_page, err);
		}

		unlock_page(page);
		put_page(page);

		if (unlikely(err))
			return err;

		*write_offset += bytes;

		new_off = (*cur_page << PAGE_SHIFT) + cur_off + bytes;
		*cur_page = new_off >> PAGE_SHIFT;

		rest_bytes -= bytes;
		written_bytes += bytes;
	};

	return 0;
}

/*
 * ssdfs_peb_store_offsets_table_fragment() - store fragment of offsets table
 * @pebi: pointer on PEB object
 * @table: pointer on translation table object
 * @peb_index: PEB's index
 * @sequence_id: sequence ID of fragment
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
 *
 * This function tries to store table's fragment into log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to find memory page.
 */
int ssdfs_peb_store_offsets_table_fragment(struct ssdfs_peb_info *pebi,
					   struct ssdfs_blk2off_table *table,
					   u16 peb_index, u16 sequence_id,
					   pgoff_t *cur_page,
					   u32 *write_offset)
{
	struct ssdfs_phys_offset_table_array *pot_table;
	struct ssdfs_sequence_array *sequence;
	struct ssdfs_phys_offset_table_fragment *fragment;
	struct ssdfs_phys_offset_table_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_phys_offset_table_header);
	struct page *page;
	void *kaddr;
	u32 fragment_size;
	u32 rest_bytes, written_bytes = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!table || !cur_page || !write_offset);
	BUG_ON(peb_index >= table->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb %llu, current_log.start_page %u, "
		  "peb_index %u, sequence_id %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->peb_id,
		  pebi->current_log.start_page,
		  peb_index, sequence_id,
		  *cur_page, *write_offset);

	down_read(&table->translation_lock);

	pot_table = &table->peb[peb_index];

	sequence = pot_table->sequence;
	kaddr = ssdfs_sequence_array_get_item(sequence, sequence_id);
	if (IS_ERR_OR_NULL(kaddr)) {
		err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
		SSDFS_ERR("fail to get fragment: "
			  "sequence_id %u, err %d\n",
			  sequence_id, err);
		goto finish_store_fragment;
	}
	fragment = (struct ssdfs_phys_offset_table_fragment *)kaddr;

	down_write(&fragment->lock);

	if (atomic_read(&fragment->state) != SSDFS_BLK2OFF_FRAG_UNDER_COMMIT) {
		err = -ERANGE;
		SSDFS_ERR("invalid fragment state %#x\n",
			  atomic_read(&fragment->state));
		goto finish_fragment_copy;
	}

	hdr = fragment->hdr;

	if (!hdr) {
		err = -ERANGE;
		SSDFS_ERR("header pointer is NULL\n");
		goto finish_fragment_copy;
	}

	fragment_size = le32_to_cpu(hdr->byte_size);
	rest_bytes = fragment_size;

	if (fragment_size < hdr_size || fragment_size > fragment->buf_size) {
		err = -ERANGE;
		SSDFS_ERR("invalid fragment size %u\n",
			  fragment_size);
		goto finish_fragment_copy;
	}

	while (rest_bytes > 0) {
		u32 bytes;
		u32 cur_off = *write_offset % PAGE_SIZE;
		u32 new_off;

		bytes = min_t(u32, rest_bytes, PAGE_SIZE - cur_off);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(written_bytes > fragment_size);
#endif /* CONFIG_SSDFS_DEBUG */

		page = ssdfs_page_array_get_page_locked(&pebi->cache,
							*cur_page);
		if (IS_ERR_OR_NULL(page)) {
			err = -ENOMEM;
			SSDFS_ERR("fail to get cache page: index %lu\n",
				  *cur_page);
			goto finish_fragment_copy;
		}

		kaddr = kmap_atomic(page);
		memcpy((u8 *)kaddr + cur_off, hdr + written_bytes, bytes);
		kunmap_atomic(kaddr);

		SetPagePrivate(page);
		SetPageUptodate(page);

		err = ssdfs_page_array_set_page_dirty(&pebi->cache,
						      *cur_page);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu as dirty: err %d\n",
				  *cur_page, err);
		}

		unlock_page(page);
		put_page(page);

		if (unlikely(err))
			goto finish_fragment_copy;

		*write_offset += bytes;

		new_off = (*cur_page << PAGE_SHIFT) + cur_off + bytes;
		*cur_page = new_off >> PAGE_SHIFT;

		rest_bytes -= bytes;
		written_bytes += bytes;
	};

finish_fragment_copy:
	up_write(&fragment->lock);

finish_store_fragment:
	up_read(&table->translation_lock);

	return err;
}

static inline
u16 ssdfs_next_sequence_id(u16 sequence_id)
{
	u16 next_sequence_id = U16_MAX;

	SSDFS_DBG("sequence_id %u\n", sequence_id);

	if (sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
		SSDFS_ERR("invalid sequence_id %u\n",
			  sequence_id);
		return U16_MAX;
	} else if (sequence_id < SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
		/* increment value */
		next_sequence_id = sequence_id + 1;
	} else
		next_sequence_id = 0;

	return next_sequence_id;
}

/*
 * ssdfs_peb_store_offsets_table() - store offsets table
 * @pebi: pointer on PEB object
 * @desc: offsets table descriptor [out]
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
 *
 * This function tries to store the offsets table into log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to find memory page.
 */
int ssdfs_peb_store_offsets_table(struct ssdfs_peb_info *pebi,
				  struct ssdfs_metadata_descriptor *desc,
				  pgoff_t *cur_page,
				  u32 *write_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_blk2off_table_snapshot snapshot = {0};
	struct ssdfs_blk2off_table_header hdr;
	struct ssdfs_translation_extent *extents = NULL;
	size_t tbl_hdr_size = sizeof(struct ssdfs_blk2off_table_header);
	u16 extents_off = offsetof(struct ssdfs_blk2off_table_header, sequence);
	u16 extent_count = 0;
	u16 offset_table_off;
	u16 peb_index;
	u32 table_start_offset;
	u16 sequence_id;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!pebi->pebc->parent_si->blk2off_table);
	BUG_ON(!desc || !cur_page || !write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  *cur_page, *write_offset);

	fsi = pebi->pebc->parent_si->fsi;
	peb_index = pebi->peb_index;
	table = pebi->pebc->parent_si->blk2off_table;

	memset(desc, 0, sizeof(struct ssdfs_metadata_descriptor));
	memset(&hdr, 0, tbl_hdr_size);

	if (!ssdfs_blk2off_table_dirtied(table, peb_index)) {
		SSDFS_DBG("table hasn't dirty fragments: peb_index %u\n",
			  peb_index);
		return 0;
	}

	err = ssdfs_blk2off_table_snapshot(table, peb_index, &snapshot);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get snapshot: peb_index %u, err %d\n",
			  peb_index, err);
		return err;
	}

	if (unlikely(peb_index != snapshot.peb_index)) {
		err = -ERANGE;
		SSDFS_ERR("peb_index %u != snapshot.peb_index %u\n",
			  peb_index, snapshot.peb_index);
		goto fail_store_off_table;
	}

	if (unlikely(!snapshot.bmap_copy || !snapshot.tbl_copy)) {
		err = -ERANGE;
		SSDFS_ERR("invalid snapshot: "
			  "peb_index %u, bmap_copy %p, tbl_copy %p\n",
			  peb_index,
			  snapshot.bmap_copy,
			  snapshot.tbl_copy);
		goto fail_store_off_table;
	}

	extents = kcalloc(snapshot.capacity,
			  sizeof(struct ssdfs_translation_extent),
			  GFP_KERNEL);
	if (unlikely(!extents)) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate extent array\n");
		goto fail_store_off_table;
	}

	hdr.magic.common = cpu_to_le32(SSDFS_SUPER_MAGIC);
	hdr.magic.key = cpu_to_le16(SSDFS_BLK2OFF_TABLE_HDR_MAGIC);
	hdr.magic.version.major = SSDFS_MAJOR_REVISION;
	hdr.magic.version.minor = SSDFS_MINOR_REVISION;

	err = ssdfs_blk2off_table_extract_extents(&snapshot, extents,
						  snapshot.capacity,
						  &extent_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract the extent array: "
			  "peb_index %u, err %d\n",
			  peb_index, err);
		goto fail_store_off_table;
	} else if (extent_count == 0) {
		err = -ERANGE;
		SSDFS_ERR("invalid extent count\n");
		goto fail_store_off_table;
	}

	hdr.extents_off = cpu_to_le16(extents_off);
	hdr.extents_count = cpu_to_le16(extent_count);

	sequence_id = snapshot.start_sequence_id;
	for (i = 0; i < snapshot.dirty_fragments; i++) {
		err = ssdfs_blk2off_table_prepare_for_commit(table, peb_index,
							     sequence_id,
							     &snapshot);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare fragment for commit: "
				  "peb_index %u, sequence_id %u, err %d\n",
				  peb_index, sequence_id, err);
			goto fail_store_off_table;
		}

		sequence_id = ssdfs_next_sequence_id(sequence_id);
		if (sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
			err = -ERANGE;
			SSDFS_ERR("invalid next sequence_id %u\n",
				  sequence_id);
			goto fail_store_off_table;
		}
	}

	offset_table_off = tbl_hdr_size +
			   ((extent_count - 1) *
			    sizeof(struct ssdfs_translation_extent));

	hdr.offset_table_off = cpu_to_le16(offset_table_off);
	hdr.fragments_count = cpu_to_le16(snapshot.dirty_fragments);

	memcpy(hdr.sequence, extents, sizeof(struct ssdfs_translation_extent));

	hdr.check.bytes = cpu_to_le16(tbl_hdr_size);
	hdr.check.flags = cpu_to_le16(SSDFS_CRC32);

	err = ssdfs_calculate_csum(&hdr.check, &hdr, tbl_hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("unable to calculate checksum: err %d\n", err);
		goto fail_store_off_table;
	}

	*write_offset = ssdfs_peb_correct_area_write_offset(*write_offset,
							    tbl_hdr_size);
	table_start_offset = *write_offset;

	desc->offset = cpu_to_le32(*write_offset +
				(pebi->current_log.start_page * fsi->pagesize));

	err = ssdfs_peb_store_offsets_table_header(pebi, &hdr,
						   cur_page, write_offset);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store offsets table's header: "
			  "cur_page %lu, write_offset %u, err %d\n",
			  *cur_page, *write_offset, err);
		goto fail_store_off_table;
	}

	if (extent_count > 1) {
		err = ssdfs_peb_store_offsets_table_extents(pebi, &extents[1],
							    extent_count - 1,
							    cur_page,
							    write_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store offsets table's extents: "
				  "cur_page %lu, write_offset %u, err %d\n",
				  *cur_page, *write_offset, err);
			goto fail_store_off_table;
		}
	}

	sequence_id = snapshot.start_sequence_id;
	for (i = 0; i < snapshot.dirty_fragments; i++) {
		err = ssdfs_peb_store_offsets_table_fragment(pebi, table,
							     peb_index,
							     sequence_id,
							     cur_page,
							     write_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store offsets table's fragment: "
				  "sequence_id %u, cur_page %lu, "
				  "write_offset %u, err %d\n",
				  sequence_id, *cur_page,
				  *write_offset, err);
			goto fail_store_off_table;
		}

		sequence_id = ssdfs_next_sequence_id(sequence_id);
		if (sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
			err = -ERANGE;
			SSDFS_ERR("invalid next sequence_id %u\n",
				  sequence_id);
			goto fail_store_off_table;
		}
	}

	err = ssdfs_blk2off_table_forget_snapshot(table, &snapshot,
						  extents, extent_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to forget snapshot state: "
			  "peb_index %u, err %d\n",
			  peb_index, err);
		goto fail_store_off_table;
	}

	BUG_ON(*write_offset <= table_start_offset);
	desc->size = cpu_to_le32(*write_offset - table_start_offset);

	pebi->current_log.seg_flags |= SSDFS_SEG_HDR_HAS_OFFSET_TABLE;

fail_store_off_table:
	ssdfs_blk2off_table_free_snapshot(&snapshot);
	kfree(extents);

	return err;
}

/*
 * ssdfs_blk2off_table_get_used_logical_blks() - get used logical blocks count
 * @tbl: pointer on table object
 * @used_blks: pointer on used logical blocks count [out]
 *
 * This method tries to get used logical blocks count.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EAGAIN     - table doesn't initialized yet.
 */
int ssdfs_blk2off_table_get_used_logical_blks(struct ssdfs_blk2off_table *tbl,
						u16 *used_blks)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl || !used_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, used_blks %p\n",
		  tbl, used_blks);

	*used_blks = U16_MAX;

	if (atomic_read(&tbl->state) < SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT) {
		SSDFS_DBG("table is not initialized yet\n");
		return -EAGAIN;
	}

	down_read(&tbl->translation_lock);
	*used_blks = tbl->used_logical_blks;
	up_read(&tbl->translation_lock);

	return 0;
}

/*
 * ssdfs_blk2off_table_get_checked_position() - get checked offset's position
 * @table: pointer on table object
 * @logical_blk: logical block number
 * @pos: pointer of offset's position [out]
 *
 * This method tries to get and to check offset's position for
 * requested logical block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 * %-ENODATA    - table doesn't contain logical block or corresponding ID.
 * %-ENOENT     - table's fragment for requested logical block not initialized
 */
static
int ssdfs_blk2off_table_get_checked_position(struct ssdfs_blk2off_table *table,
					     u16 logical_blk,
					     struct ssdfs_offset_position *pos)
{
	struct ssdfs_phys_offset_table_array *phys_off_table;
	struct ssdfs_sequence_array *sequence;
	struct ssdfs_phys_offset_table_fragment *fragment;
	unsigned long *lbmap = NULL;
	void *ptr;
	size_t off_pos_size = sizeof(struct ssdfs_offset_position);
	int state;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !pos);
	BUG_ON(!rwsem_is_locked(&table->translation_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, logical_blk %u, pos %p\n",
		  table, logical_blk, pos);

	ssdfs_debug_blk2off_table_object(table);

	if (logical_blk >= table->lblk2off_capacity) {
		SSDFS_ERR("logical_blk %u >= lblk2off_capacity %u\n",
			  logical_blk, table->lblk2off_capacity);
		return -ERANGE;
	}

	lbmap = table->lbmap[SSDFS_LBMAP_STATE_INDEX];
	if (ssdfs_blk2off_table_bmap_vacant(lbmap, table->lblk2off_capacity,
					    logical_blk)) {
		SSDFS_ERR("requested block %u hasn't been allocated\n",
			  logical_blk);
		return -ENODATA;
	}

	memcpy(pos, &table->lblk2off[logical_blk], off_pos_size);

	if (pos->id == U16_MAX) {
		SSDFS_ERR("logical block %u hasn't ID yet\n",
			  logical_blk);
		return -ENODATA;
	}

	if (pos->peb_index >= table->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  pos->peb_index, table->pebs_count);
		return -ERANGE;
	}

	if (pos->sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
		SSDFS_ERR("sequence_id %u is out of order\n",
			  pos->sequence_id);
		return -ERANGE;
	}

	phys_off_table = &table->peb[pos->peb_index];

	sequence = phys_off_table->sequence;
	ptr = ssdfs_sequence_array_get_item(sequence, pos->sequence_id);
	if (IS_ERR_OR_NULL(ptr)) {
		err = (ptr == NULL ? -ENOENT : PTR_ERR(ptr));
		SSDFS_ERR("fail to get fragment: "
			  "sequence_id %u, err %d\n",
			  pos->sequence_id, err);
		return err;
	}
	fragment = (struct ssdfs_phys_offset_table_fragment *)ptr;

	state = atomic_read(&fragment->state);
	if (state < SSDFS_BLK2OFF_FRAG_INITIALIZED) {
		SSDFS_DBG("fragment %u is not initialized yet\n",
			  pos->sequence_id);
		return -ENOENT;
	} else if (state >= SSDFS_BLK2OFF_FRAG_STATE_MAX) {
		SSDFS_ERR("unknown fragment's state\n");
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_blk2off_table_check_fragment_desc() - check fragment's description
 * @table: pointer on table object
 * @frag: pointer on fragment
 * @pos: pointer of offset's position
 *
 * This method tries to check fragment's description.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 */
static
int ssdfs_blk2off_table_check_fragment_desc(struct ssdfs_blk2off_table *table,
				struct ssdfs_phys_offset_table_fragment *frag,
				struct ssdfs_offset_position *pos)
{
	u16 start_id;
	int id_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !frag || !pos);
	BUG_ON(!rwsem_is_locked(&table->translation_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, id %u, peb_index %u, "
		  "sequence_id %u, offset_index %u\n",
		  table, pos->id, pos->peb_index,
		  pos->sequence_id, pos->offset_index);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rwsem_is_locked(&frag->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	start_id = frag->start_id;
	id_count = atomic_read(&frag->id_count);

	if (pos->id < start_id || pos->id >= (start_id + id_count)) {
		SSDFS_ERR("id %u out of range (start %u, len %u)\n",
			  pos->id, start_id, id_count);
		return -ERANGE;
	}

	if (pos->offset_index >= id_count) {
		SSDFS_ERR("offset_index %u >= id_count %u\n",
			  pos->offset_index, id_count);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (!frag->phys_offs) {
		SSDFS_ERR("offsets table pointer is NULL\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_blk2off_table_convert() - convert logical block into offset
 * @table: pointer on table object
 * @logical_blk: logical block number
 * @peb_index: pointer on PEB index value [out]
 * @is_migrating: is block under migration? [out]
 *
 * This method tries to convert logical block number into offset.
 *
 * RETURN:
 * [success] - pointer on found offset.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - table doesn't prepared for conversion yet.
 * %-ENODATA    - table doesn't contain logical block.
 * %-ENOENT     - table's fragment for requested logical block not initialized
 */
struct ssdfs_phys_offset_descriptor *
ssdfs_blk2off_table_convert(struct ssdfs_blk2off_table *table,
			    u16 logical_blk,
			    u16 *peb_index,
			    bool *is_migrating)
{
	struct ssdfs_phys_offset_table_array *phys_off_table;
	struct ssdfs_sequence_array *sequence;
	struct ssdfs_phys_offset_table_fragment *fragment;
	struct ssdfs_phys_offset_descriptor *ptr = NULL;
	struct ssdfs_offset_position pos = {0};
	struct ssdfs_migrating_block *blk = NULL;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, logical_blk %u\n",
		  table, logical_blk);

	*peb_index = U16_MAX;

	down_read(&table->translation_lock);

	if (logical_blk >= table->lblk2off_capacity) {
		err = -EINVAL;
		SSDFS_ERR("fail to convert logical block: "
			  "block %u >= capacity %u\n",
			  logical_blk,
			  table->lblk2off_capacity);
		goto finish_translation;
	}

	if (atomic_read(&table->state) <= SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT) {
		unsigned long *bmap = table->lbmap[SSDFS_LBMAP_INIT_INDEX];
		u16 capacity = table->lblk2off_capacity;

		if (ssdfs_blk2off_table_bmap_vacant(bmap, capacity,
						    logical_blk)) {
			err = -EAGAIN;
			SSDFS_DBG("table is not initialized yet: "
				  "logical_blk %u\n",
				  logical_blk);
			goto finish_translation;
		}
	}

	if (is_migrating) {
		blk = &table->migrating_blks[logical_blk];

		switch (blk->state) {
		case SSDFS_LBLOCK_UNDER_MIGRATION:
		case SSDFS_LBLOCK_UNDER_COMMIT:
			*is_migrating = true;
			break;

		default:
			*is_migrating = false;
			break;
		}
	}

	err = ssdfs_blk2off_table_get_checked_position(table, logical_blk,
							&pos);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get checked offset's position: "
			  "logical_block %u, err %d\n",
			  logical_blk, err);
		goto finish_translation;
	}

	*peb_index = pos.peb_index;
	phys_off_table = &table->peb[pos.peb_index];

	sequence = phys_off_table->sequence;
	kaddr = ssdfs_sequence_array_get_item(sequence, pos.sequence_id);
	if (IS_ERR_OR_NULL(kaddr)) {
		err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
		SSDFS_ERR("fail to get fragment: "
			  "sequence_id %u, err %d\n",
			  pos.sequence_id, err);
		goto finish_translation;
	}
	fragment = (struct ssdfs_phys_offset_table_fragment *)kaddr;

	down_read(&fragment->lock);

	err = ssdfs_blk2off_table_check_fragment_desc(table, fragment, &pos);
	if (unlikely(err)) {
		SSDFS_ERR("invalid fragment description: err %d\n", err);
		goto finish_fragment_lookup;
	}

	ptr = &fragment->phys_offs[pos.offset_index];

finish_fragment_lookup:
	up_read(&fragment->lock);

finish_translation:
	up_read(&table->translation_lock);

	if (err)
		return ERR_PTR(err);

	SSDFS_DBG("logical_blk %u, "
		  "logical_offset %u, peb_index %u, peb_page %u, "
		  "log_start_page %u, log_area %u, "
		  "peb_migration_id %u, byte_offset %u\n",
		  logical_blk,
		  le32_to_cpu(ptr->page_desc.logical_offset),
		  pos.peb_index,
		  le16_to_cpu(ptr->page_desc.peb_page),
		  le16_to_cpu(ptr->blk_state.log_start_page),
		  ptr->blk_state.log_area,
		  ptr->blk_state.peb_migration_id,
		  le32_to_cpu(ptr->blk_state.byte_offset));

	return ptr;
}

/*
 * ssdfs_blk2off_table_get_offset_position() - get offset position
 * @table: pointer on table object
 * @logical_blk: logical block number
 * @pos: offset position
 *
 * This method tries to get offset position.
 *
 * RETURN:
 * [success] - pointer on found offset.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - table doesn't prepared for conversion yet.
 * %-ENODATA    - table doesn't contain logical block.
 */
int ssdfs_blk2off_table_get_offset_position(struct ssdfs_blk2off_table *table,
					    u16 logical_blk,
					    struct ssdfs_offset_position *pos)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !pos);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, logical_blk %u\n",
		  table, logical_blk);

	down_read(&table->translation_lock);

	if (logical_blk >= table->lblk2off_capacity) {
		err = -EINVAL;
		SSDFS_ERR("fail to convert logical block: "
			  "block %u >= capacity %u\n",
			  logical_blk,
			  table->lblk2off_capacity);
		goto finish_extract_position;
	}

	if (atomic_read(&table->state) <= SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT) {
		unsigned long *bmap = table->lbmap[SSDFS_LBMAP_INIT_INDEX];
		u16 capacity = table->lblk2off_capacity;

		if (ssdfs_blk2off_table_bmap_vacant(bmap, capacity,
						    logical_blk)) {
			err = -EAGAIN;
			SSDFS_DBG("table is not initialized yet: "
				  "logical_blk %u\n",
				  logical_blk);
			goto finish_extract_position;
		}
	}

	err = ssdfs_blk2off_table_get_checked_position(table, logical_blk,
							pos);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get checked offset's position: "
			  "logical_block %u, err %d\n",
			  logical_blk, err);
		goto finish_extract_position;
	}

finish_extract_position:
	up_read(&table->translation_lock);

	if (err)
		return err;

	SSDFS_DBG("logical_blk %u, "
		  "pos->cno %llu, pos->id %u, pos->peb_index %u, "
		  "pos->sequence_id %u, pos->offset_index %u\n",
		  logical_blk, pos->cno, pos->id,
		  pos->peb_index, pos->sequence_id,
		  pos->offset_index);

	return 0;
}

/*
 * calculate_rest_range_id_count() - get rest range's IDs
 * @ptr: pointer on fragment object
 *
 * This method calculates the rest count of IDs.
 */
static inline
int calculate_rest_range_id_count(struct ssdfs_phys_offset_table_fragment *ptr)
{
	int id_count = atomic_read(&ptr->id_count);
	size_t blk2off_tbl_hdr_size = sizeof(struct ssdfs_blk2off_table_header);
	size_t hdr_size = sizeof(struct ssdfs_phys_offset_table_header);
	size_t off_size = sizeof(struct ssdfs_phys_offset_descriptor);
	size_t metadata_size = blk2off_tbl_hdr_size + hdr_size;
	int id_capacity;
	int start_id = ptr->start_id;
	int rest_range_ids;

	if ((start_id + 1) >= U16_MAX) {
		SSDFS_DBG("start_id %d\n", start_id);
		return 0;
	}

	id_capacity = (ptr->buf_size - metadata_size) / off_size;

	if (id_count >= id_capacity) {
		SSDFS_DBG("id_count %d, id_capacity %d\n",
			  id_count, id_capacity);
		return 0;
	}

	rest_range_ids = id_capacity - id_count;

	SSDFS_DBG("id_count %d, id_capacity %d, rest_range_ids %d\n",
		  id_count, id_capacity, rest_range_ids);

	return rest_range_ids;
}

/*
 * is_id_valid_for_assignment() - check ID validity
 * @table: pointer on table object
 * @ptr: pointer on fragment object
 * @id: ID value
 */
static
bool is_id_valid_for_assignment(struct ssdfs_blk2off_table *table,
				struct ssdfs_phys_offset_table_fragment *ptr,
				int id)
{
	int id_count = atomic_read(&ptr->id_count);
	int rest_range_ids;

	if (id < ptr->start_id) {
		SSDFS_WARN("id %d < start_id %u\n",
			   id, ptr->start_id);
		return false;
	}

	if (id > (ptr->start_id + id_count)) {
		SSDFS_WARN("id %d > (ptr->start_id %u + id_count %d)",
			   id, ptr->start_id, id_count);
		return false;
	}

	rest_range_ids = calculate_rest_range_id_count(ptr);

	SSDFS_DBG("id %d, rest_range_ids %d\n",
		  id, rest_range_ids);

	return rest_range_ids > 0;
}

/*
 * ssdfs_blk2off_table_assign_id() - assign ID for logical block
 * @table: pointer on table object
 * @logical_blk: logical block number
 * @peb_index: PEB's index
 * @last_sequence_id: pointer on last fragment index [out]
 *
 * This method tries to define physical offset's ID value for
 * requested logical block number in last actual PEB's fragment.
 * If the last actual fragment hasn't vacant ID then the method
 * returns error and found last fragment index in
 * @last_sequence_id.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - internal logic error.
 * %-ENOENT     - table's fragment for requested logical block not initialized
 * %-ENOSPC     - fragment hasn't vacant IDs and it needs to initialize next one
 */
static
int ssdfs_blk2off_table_assign_id(struct ssdfs_blk2off_table *table,
				  u16 logical_blk, u16 peb_index,
				  u16 *last_sequence_id)
{
	struct ssdfs_phys_offset_table_array *phys_off_table;
	struct ssdfs_sequence_array *sequence;
	struct ssdfs_phys_offset_table_fragment *fragment;
	struct ssdfs_offset_position *pos;
	int state;
	int id = -1;
	u16 offset_index = U16_MAX;
	unsigned long *bmap;
	u16 capacity;
	void *kaddr;
	unsigned long last_id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !last_sequence_id);
	BUG_ON(!rwsem_is_locked(&table->translation_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, logical_blk %u, peb_index %u\n",
		  table, logical_blk, peb_index);

	if (peb_index >= table->pebs_count) {
		SSDFS_ERR("fail to change offset value: "
			  "peb_index %u >= pebs_count %u\n",
			  peb_index, table->pebs_count);
		return -EINVAL;
	}

	capacity = table->lblk2off_capacity;
	phys_off_table = &table->peb[peb_index];

	state = atomic_read(&phys_off_table->state);
	if (state < SSDFS_BLK2OFF_TABLE_PARTIAL_INIT) {
		SSDFS_DBG("table doesn't initialized for peb %u\n",
			  peb_index);
		return -ENOENT;
	} else if (state >= SSDFS_BLK2OFF_TABLE_STATE_MAX) {
		SSDFS_DBG("unknown table state %#x\n",
			  state);
		return -ERANGE;
	}

	sequence = phys_off_table->sequence;

	if (is_ssdfs_sequence_array_last_id_invalid(sequence)) {
		/* first creation */
		return -ENOSPC;
	}

	last_id = ssdfs_sequence_array_last_id(sequence);
	if (last_id >= U16_MAX) {
		SSDFS_ERR("invalid last_id %lu\n", last_id);
		return -ERANGE;
	} else
		*last_sequence_id = (u16)last_id;

	if (*last_sequence_id > SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD) {
		SSDFS_ERR("invalid last_sequence_id %d\n",
			  *last_sequence_id);
		return -ERANGE;
	}

	kaddr = ssdfs_sequence_array_get_item(sequence, *last_sequence_id);
	if (IS_ERR_OR_NULL(kaddr)) {
		err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
		SSDFS_ERR("fail to get fragment: "
			  "sequence_id %u, err %d\n",
			  *last_sequence_id, err);
		return err;
	}
	fragment = (struct ssdfs_phys_offset_table_fragment *)kaddr;

	state = atomic_read(&fragment->state);
	if (state < SSDFS_BLK2OFF_FRAG_CREATED) {
		SSDFS_DBG("fragment %u isn't created\n",
			  *last_sequence_id);
		return -ENOENT;
	} else if (state == SSDFS_BLK2OFF_FRAG_UNDER_COMMIT ||
		   state == SSDFS_BLK2OFF_FRAG_COMMITED) {
		SSDFS_DBG("fragment %d is under commit\n",
			  *last_sequence_id);
		return -ENOSPC;
	} else if (state >= SSDFS_BLK2OFF_FRAG_STATE_MAX) {
		SSDFS_DBG("unknown fragment state %#x\n",
			  state);
		return -ERANGE;
	}

	bmap = table->lbmap[SSDFS_LBMAP_MODIFICATION_INDEX];
	pos = &table->lblk2off[logical_blk];

	if (!ssdfs_blk2off_table_bmap_vacant(bmap, capacity,
					     logical_blk)) {
		if (pos->sequence_id != *last_sequence_id) {
			SSDFS_WARN("sequence_id %u != last_sequence_id %d\n",
				  pos->sequence_id,
				  *last_sequence_id);
		}

		pos->cno = ssdfs_current_cno(table->fsi->sb);
		pos->peb_index = peb_index;
		id = pos->id;
		offset_index = pos->offset_index;
	} else {
		offset_index = atomic_inc_return(&fragment->id_count) - 1;
		id = fragment->start_id + offset_index;

		if (!is_id_valid_for_assignment(table, fragment, id)) {
			SSDFS_DBG("id %d cannot be assign for fragment %d\n",
				  id, *last_sequence_id);
			atomic_dec(&fragment->id_count);
			return -ENOSPC;
		}

		pos->cno = ssdfs_current_cno(table->fsi->sb);
		pos->id = (u16)id;
		pos->peb_index = peb_index;
		pos->sequence_id = *last_sequence_id;
		pos->offset_index = offset_index;
	}

	SSDFS_DBG("DONE: logical_blk %u, id %d, "
		  "peb_index %u, sequence_id %u, offset_index %u\n",
		  logical_blk, id, peb_index,
		  *last_sequence_id, offset_index);

	return 0;
}

/*
 * ssdfs_blk2off_table_add_fragment() - add fragment into PEB's table
 * @table: pointer on table object
 * @peb_index: PEB's index
 * @old_sequence_id: old last sequence id
 *
 * This method tries to initialize additional fragment into
 * PEB's table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - PEB's fragment count isn't equal to @old_fragment_count
 * %-ENOSPC     - table hasn't space for new fragments
 */
static
int ssdfs_blk2off_table_add_fragment(struct ssdfs_blk2off_table *table,
					u16 peb_index,
					u16 old_sequence_id)
{
	struct ssdfs_phys_offset_table_array *phys_off_table;
	struct ssdfs_sequence_array *sequence;
	struct ssdfs_phys_offset_table_fragment *fragment, *prev_fragment;
	unsigned long last_sequence_id = ULONG_MAX;
	u16 start_id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
	BUG_ON(!rwsem_is_locked(&table->translation_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p,  peb_index %u, old_sequence_id %d\n",
		  table, peb_index, old_sequence_id);

	if (peb_index >= table->pebs_count) {
		SSDFS_ERR("fail to change offset value: "
			  "peb_index %u >= pebs_count %u\n",
			  peb_index, table->pebs_count);
		return -EINVAL;
	}

	phys_off_table = &table->peb[peb_index];
	sequence = phys_off_table->sequence;

	if (is_ssdfs_sequence_array_last_id_invalid(sequence)) {
		/*
		 * first creation
		 */
	} else {
		last_sequence_id = ssdfs_sequence_array_last_id(sequence);
		if (last_sequence_id != old_sequence_id) {
			SSDFS_DBG("last_id %lu != old_id %u\n",
				  last_sequence_id, old_sequence_id);
			return -EAGAIN;
		}
	}

	fragment = ssdfs_blk2off_frag_alloc();
	if (IS_ERR_OR_NULL(fragment)) {
		err = (fragment == NULL ? -ENOMEM : PTR_ERR(fragment));
		SSDFS_ERR("fail to allocate fragment: "
			  "err %d\n", err);
		return err;
	}

	err = ssdfs_sequence_array_add_item(sequence, fragment,
					    &last_sequence_id);
	if (unlikely(err)) {
		ssdfs_blk2off_frag_free(fragment);
		SSDFS_ERR("fail to add fragment: "
			  "err %d\n", err);
		return err;
	}

	if (last_sequence_id == 0) {
		start_id = 0;
	} else {
		int prev_id_count;
		void *kaddr;

		kaddr = ssdfs_sequence_array_get_item(sequence,
						      last_sequence_id - 1);
		if (IS_ERR_OR_NULL(kaddr)) {
			err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
			SSDFS_ERR("fail to get fragment: "
				  "sequence_id %lu, err %d\n",
				  last_sequence_id - 1, err);
			return err;
		}
		prev_fragment =
			(struct ssdfs_phys_offset_table_fragment *)kaddr;

		start_id = prev_fragment->start_id;
		prev_id_count = atomic_read(&prev_fragment->id_count);

		if ((start_id + prev_id_count + 1) >= U16_MAX)
			start_id = 0;
		else
			start_id += prev_id_count;
	}

	err = ssdfs_blk2off_table_init_fragment(fragment, last_sequence_id,
						start_id, table->pages_per_peb,
						SSDFS_BLK2OFF_FRAG_INITIALIZED,
						NULL);
	if (err) {
		SSDFS_ERR("fail to init fragment %lu: err %d\n",
			  last_sequence_id, err);
		return err;
	}

	atomic_inc(&phys_off_table->fragment_count);

	return 0;
}

/*
 * ssdfs_table_fragment_set_dirty() - set fragment dirty
 * @table: pointer on table object
 * @peb_index: PEB's index value
 * @sequence_id: fragment's sequence_id
 */
static inline
int ssdfs_table_fragment_set_dirty(struct ssdfs_blk2off_table *table,
				    u16 peb_index, u16 sequence_id)
{
	struct ssdfs_phys_offset_table_array *phys_off_table;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
	BUG_ON(!rwsem_is_locked(&table->translation_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p,  peb_index %u, sequence_id %u\n",
		  table, peb_index, sequence_id);

	phys_off_table = &table->peb[peb_index];

	err = ssdfs_sequence_array_change_state(phys_off_table->sequence,
						sequence_id,
						SSDFS_SEQUENCE_ITEM_NO_TAG,
						SSDFS_SEQUENCE_ITEM_DIRTY_TAG,
						ssdfs_change_fragment_state,
						SSDFS_BLK2OFF_FRAG_INITIALIZED,
						SSDFS_BLK2OFF_FRAG_DIRTY);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set fragment dirty: "
			  "sequence_id %u, err %d\n",
			  sequence_id, err);
		return err;
	}

	atomic_cmpxchg(&phys_off_table->state,
			SSDFS_BLK2OFF_TABLE_COMPLETE_INIT,
			SSDFS_BLK2OFF_TABLE_DIRTY);

	return 0;
}

/*
 * ssdfs_blk2off_table_change_offset() - update logical block's offset
 * @table: pointer on table object
 * @logical_blk: logical block number
 * @peb_index: PEB's index value
 * @off: new value of offset [in]
 *
 * This method tries to update offset value for logical block.
 * Firstly, logical blocks' state bitmap is set when allocation
 * takes place. But table->lblk2off array contains U16_MAX for
 * this logical block number. It means that logical block was
 * allocated but it doesn't correspond to any physical offset
 * ID. Secondly, it needs to provide every call of
 * ssdfs_blk2off_table_change_offset() with peb_index value.
 * In such situation the method sets correspondence between
 * logical block and physical offset ID.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - table doesn't prepared for this change yet.
 * %-ENODATA    - table doesn't contain logical block.
 * %-ENOENT     - table's fragment for requested logical block not initialized
 */
int ssdfs_blk2off_table_change_offset(struct ssdfs_blk2off_table *table,
				      u16 logical_blk,
				      u16 peb_index,
				      struct ssdfs_phys_offset_descriptor *off)
{
	struct ssdfs_phys_offset_table_array *phys_off_table;
	struct ssdfs_sequence_array *sequence;
	struct ssdfs_phys_offset_table_fragment *fragment;
	unsigned long *lbmap = NULL;
	struct ssdfs_offset_position pos = {0};
	u16 last_sequence_id = SSDFS_INVALID_FRAG_ID;
	unsigned long *bmap;
	void *kaddr;
	u16 capacity;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !off);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, logical_blk %u, peb_index %u, "
		  "off->page_desc.logical_offset %u, "
		  "off->page_desc.logical_blk %u, "
		  "off->page_desc.peb_page %u, "
		  "off->blk_state.log_start_page %u, "
		  "off->blk_state.log_area %u, "
		  "off->blk_state.peb_migration_id %u, "
		  "off->blk_state.byte_offset %u\n",
		  table, logical_blk, peb_index,
		  le32_to_cpu(off->page_desc.logical_offset),
		  le16_to_cpu(off->page_desc.logical_blk),
		  le16_to_cpu(off->page_desc.peb_page),
		  le16_to_cpu(off->blk_state.log_start_page),
		  off->blk_state.log_area,
		  off->blk_state.peb_migration_id,
		  le32_to_cpu(off->blk_state.byte_offset));

	if (peb_index >= table->pebs_count) {
		SSDFS_ERR("fail to change offset value: "
			  "peb_index %u >= pebs_count %u\n",
			  peb_index, table->pebs_count);
		return -EINVAL;
	}

	down_write(&table->translation_lock);

	if (logical_blk >= table->lblk2off_capacity) {
		err = -EINVAL;
		SSDFS_ERR("fail to convert logical block: "
			  "block %u >= capacity %u\n",
			  logical_blk,
			  table->lblk2off_capacity);
		goto finish_table_modification;
	}

	capacity = table->lblk2off_capacity;

	if (atomic_read(&table->state) <= SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT) {
		bmap = table->lbmap[SSDFS_LBMAP_INIT_INDEX];

		if (ssdfs_blk2off_table_bmap_vacant(bmap, capacity,
						    logical_blk)) {
			SSDFS_DBG("table is not initialized yet: "
				  "logical_blk %u\n",
				  logical_blk);
			return -EAGAIN;
		}
	}

	bmap = table->lbmap[SSDFS_LBMAP_STATE_INDEX];

	if (ssdfs_blk2off_table_bmap_vacant(bmap, capacity,
					    logical_blk)) {
		SSDFS_ERR("logical block is not allocated yet: "
			  "logical_blk %u\n",
			  logical_blk);
		return -ENODATA;
	}

	err = ssdfs_blk2off_table_assign_id(table, logical_blk, peb_index,
					    &last_sequence_id);
	if (err == -ENOSPC) {
		err = ssdfs_blk2off_table_add_fragment(table, peb_index,
							last_sequence_id);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add fragment: "
				  "peb_index %u, err %d\n",
				  peb_index, err);
			goto finish_table_modification;
		}

		err = ssdfs_blk2off_table_assign_id(table, logical_blk,
						    peb_index,
						    &last_sequence_id);
		if (unlikely(err)) {
			SSDFS_ERR("fail to assign id: "
				  "peb_index %u, logical_blk %u, err %d\n",
				  peb_index, logical_blk, err);
			goto finish_table_modification;
		}
	} else if (err == -ENOENT) {
		SSDFS_DBG("meet unintialized fragment: "
			  "peb_index %u, logical_blk %u\n",
			  peb_index, logical_blk);
		goto finish_table_modification;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to assign id: "
			  "peb_index %u, logical_blk %u, err %d\n",
			  peb_index, logical_blk, err);
		goto finish_table_modification;
	}

	err = ssdfs_blk2off_table_get_checked_position(table, logical_blk,
							&pos);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get checked offset's position: "
			  "logical_block %u, err %d\n",
			  logical_blk, err);
		goto finish_table_modification;
	}

	phys_off_table = &table->peb[peb_index];

	sequence = phys_off_table->sequence;
	kaddr = ssdfs_sequence_array_get_item(sequence, pos.sequence_id);
	if (IS_ERR_OR_NULL(kaddr)) {
		err = (kaddr == NULL ? -ENOENT : PTR_ERR(kaddr));
		SSDFS_ERR("fail to get fragment: "
			  "sequence_id %u, err %d\n",
			  pos.sequence_id, err);
		goto finish_table_modification;
	}
	fragment = (struct ssdfs_phys_offset_table_fragment *)kaddr;

	down_write(&fragment->lock);

	err = ssdfs_blk2off_table_check_fragment_desc(table, fragment, &pos);
	if (unlikely(err)) {
		SSDFS_ERR("invalid fragment description: err %d\n", err);
		goto finish_fragment_modification;
	}

	lbmap = table->lbmap[SSDFS_LBMAP_MODIFICATION_INDEX];

	ssdfs_blk2off_table_bmap_set(lbmap, logical_blk);

	downgrade_write(&table->translation_lock);

	memcpy(&fragment->phys_offs[pos.offset_index], off,
		sizeof(struct ssdfs_phys_offset_descriptor));

	ssdfs_table_fragment_set_dirty(table, peb_index, pos.sequence_id);

	up_write(&fragment->lock);
	up_read(&table->translation_lock);

	return 0;

finish_fragment_modification:
	up_write(&fragment->lock);

finish_table_modification:
	up_write(&table->translation_lock);

	return err;
}

/*
 * ssdfs_blk2off_table_bmap_allocate() - find vacant and set logical block
 * @lbmap: bitmap pointer
 * @start_blk: start block for search
 * @len: requested length
 * @max_blks: upper bound for search
 * @extent: pointer on found extent of logical blocks [out]
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EAGAIN     - allocated extent hasn't requested length.
 * %-ENODATA    - unable to allocate.
 */
static inline
int ssdfs_blk2off_table_bmap_allocate(unsigned long *lbmap,
					u16 start_blk, u16 len,
					u16 max_blks,
					struct ssdfs_blk2off_range *extent)
{
	unsigned long found, end;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!lbmap || !extent);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("lbmap %p, start_blk %u, len %u, "
		  "max_blks %u, extent %p\n",
		  lbmap, start_blk, len, max_blks, extent);

	len = min_t(u16, len, max_blks);

	found = find_next_zero_bit(lbmap, max_blks, start_blk);
	if (found >= max_blks) {
		SSDFS_ERR("unable to allocate\n");
		return -ENODATA;
	}
	BUG_ON(found >= U16_MAX);

	end = min_t(unsigned long, found + len, (unsigned long)max_blks);
	end = find_next_bit(lbmap, end, found);

	extent->start_lblk = (u16)found;
	extent->len = (u16)(end - found);

	bitmap_set(lbmap, extent->start_lblk, extent->len);

	SSDFS_DBG("found extent (start %u, len %u)\n",
		  extent->start_lblk, extent->len);

	if (extent->len < len)
		return -EAGAIN;

	return 0;
}

/*
 * ssdfs_blk2off_table_allocate_extent() - allocate vacant extent
 * @table: pointer on table object
 * @len: requested length
 * @extent: pointer on found extent [out]
 *
 * This method tries to allocate vacant extent.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - table doesn't prepared for this change yet.
 * %-ENODATA    - bitmap hasn't vacant logical blocks.
 */
int ssdfs_blk2off_table_allocate_extent(struct ssdfs_blk2off_table *table,
					u16 len,
					struct ssdfs_blk2off_range *extent)
{
	unsigned long *lbmap = NULL;
	size_t off_pos_size = sizeof(struct ssdfs_offset_position);
	u16 start_blk = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !extent);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, len %u, extent %p, "
		  "used_logical_blks %u, free_logical_blks %u, "
		  "last_allocated_blk %u\n",
		  table, len, extent,
		  table->used_logical_blks,
		  table->free_logical_blks,
		  table->last_allocated_blk);

	if (atomic_read(&table->state) <= SSDFS_BLK2OFF_OBJECT_CREATED) {
		SSDFS_DBG("unable to allocate before initialization\n");
		return -EAGAIN;
	}

	down_write(&table->translation_lock);

	if (table->free_logical_blks == 0) {
		if (table->used_logical_blks != table->lblk2off_capacity) {
			err = -ERANGE;
			SSDFS_ERR("used_logical_blks %u != capacity %u\n",
				  table->used_logical_blks,
				  table->lblk2off_capacity);
		} else {
			err = -ENODATA;
			SSDFS_DBG("bitmap hasn't vacant logical blocks\n");
		}
		goto finish_allocation;
	}

	lbmap = table->lbmap[SSDFS_LBMAP_INIT_INDEX];

	if (atomic_read(&table->state) == SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT) {
		u16 capacity = table->lblk2off_capacity;
		bool is_vacant;

		start_blk = table->last_allocated_blk;
		is_vacant = ssdfs_blk2off_table_bmap_vacant(lbmap, capacity,
							    start_blk);

		if (is_vacant) {
			start_blk = table->used_logical_blks;
			if (start_blk > 0)
				start_blk--;

			is_vacant = ssdfs_blk2off_table_bmap_vacant(lbmap,
								    capacity,
								    start_blk);
		}

		if (is_vacant) {
			err = -EAGAIN;
			SSDFS_DBG("table is not initialized yet\n");
			goto finish_allocation;
		}
	}

	lbmap = table->lbmap[SSDFS_LBMAP_STATE_INDEX];

	err = ssdfs_blk2off_table_bmap_allocate(lbmap, start_blk, len,
						table->lblk2off_capacity,
						extent);
	if (err == -EAGAIN) {
		err = 0;
		SSDFS_DBG("requested extent doesn't allocated fully\n");
		goto finish_allocation;
	} else if (err == -ENODATA)
		goto try_next_range;
	else if (unlikely(err)) {
		SSDFS_ERR("fail to find vacant extent: err %d\n",
			  err);
		goto finish_allocation;
	} else
		goto save_found_extent;

try_next_range:
	if (atomic_read(&table->state) < SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT) {
		err = -EAGAIN;
		SSDFS_DBG("table is not initialized yet\n");
		goto finish_allocation;
	}

	err = ssdfs_blk2off_table_bmap_allocate(lbmap, 0, len, start_blk,
						extent);
	if (err == -EAGAIN) {
		err = 0;
		SSDFS_DBG("requested extent doesn't allocated fully\n");
		goto finish_allocation;
	} else if (err == -ENODATA) {
		SSDFS_DBG("bitmap hasn't vacant logical blocks\n");
		goto finish_allocation;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find vacant extent: err %d\n",
			  err);
		goto finish_allocation;
	}

save_found_extent:
	memset(&table->lblk2off[extent->start_lblk], 0xFF,
		extent->len * off_pos_size);

	BUG_ON(table->used_logical_blks > (U16_MAX - extent->len));
	BUG_ON((table->used_logical_blks + extent->len) >
		table->lblk2off_capacity);
	table->used_logical_blks += extent->len;

	BUG_ON(extent->len > table->free_logical_blks);
	table->free_logical_blks -= extent->len;

	BUG_ON(extent->len == 0);
	table->last_allocated_blk = extent->start_lblk + extent->len - 1;

finish_allocation:
	up_write(&table->translation_lock);

	if (!err) {
		SSDFS_DBG("extent (start %u, len %u) has been allocated\n",
			  extent->start_lblk, extent->len);
	}

	ssdfs_debug_blk2off_table_object(table);

	return err;
}

/*
 * ssdfs_blk2off_table_allocate_block() - allocate vacant logical block
 * @table: pointer on table object
 * @logical_blk: pointer on found logical block value [out]
 *
 * This method tries to allocate vacant logical block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - table doesn't prepared for this change yet.
 * %-ENODATA    - bitmap hasn't vacant logical blocks.
 */
int ssdfs_blk2off_table_allocate_block(struct ssdfs_blk2off_table *table,
					u16 *logical_blk)
{
	struct ssdfs_blk2off_range extent = {0};
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !logical_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, logical_blk %p, "
		  "used_logical_blks %u, free_logical_blks %u, "
		  "last_allocated_blk %u\n",
		  table, logical_blk,
		  table->used_logical_blks,
		  table->free_logical_blks,
		  table->last_allocated_blk);

	err = ssdfs_blk2off_table_allocate_extent(table, 1, &extent);
	if (err) {
		SSDFS_ERR("fail to allocate logical block: err %d\n",
			  err);
		return err;
	} else if (extent.start_lblk >= table->lblk2off_capacity ||
		   extent.len != 1) {
		SSDFS_ERR("invalid extent (start %u, len %u)\n",
			  extent.start_lblk, extent.len);
		return -ERANGE;
	}

	*logical_blk = extent.start_lblk;

	SSDFS_DBG("logical block %u has been allocated\n",
		  *logical_blk);

	return err;
}

/*
 * ssdfs_blk2off_table_free_extent() - free extent
 * @table: pointer on table object
 * @extent: pointer on extent
 *
 * This method tries to free extent of logical blocks.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - table doesn't prepared for this change yet.
 * %-ENOENT     - logical block isn't allocated yet.
 */
int ssdfs_blk2off_table_free_extent(struct ssdfs_blk2off_table *table,
				    struct ssdfs_blk2off_range *extent)
{
	unsigned long *lbmap1 = NULL;
	unsigned long *lbmap2 = NULL;
	struct ssdfs_offset_position pos = {0};
	bool is_vacant;
	u16 end_lblk;
	int state;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !extent);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, extent (start %u, len %u)\n",
		  table, extent->start_lblk, extent->len);

	if (atomic_read(&table->state) <= SSDFS_BLK2OFF_OBJECT_CREATED) {
		SSDFS_DBG("unable to free before initialization: "
			  "extent (start %u, len %u)\n",
			  extent->start_lblk, extent->len);
		return -EAGAIN;
	}

	down_write(&table->translation_lock);

	BUG_ON(table->lblk2off_capacity > (U16_MAX - extent->len));
	BUG_ON((table->used_logical_blks + extent->len) >
		table->lblk2off_capacity);

	if ((extent->start_lblk + extent->len) > table->lblk2off_capacity) {
		err = -EINVAL;
		SSDFS_ERR("fail to free extent (start %u, len %u)\n",
			  extent->start_lblk, extent->len);
		goto finish_freeing;
	}

	lbmap1 = table->lbmap[SSDFS_LBMAP_INIT_INDEX];

	state = atomic_read(&table->state);
	if (state == SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT) {
		is_vacant = ssdfs_blk2off_table_extent_vacant(lbmap1,
						      table->lblk2off_capacity,
						      extent);

		if (is_vacant) {
			err = -EAGAIN;
			SSDFS_DBG("unable to free before initialization: "
				  "extent (start %u, len %u)\n",
				  extent->start_lblk, extent->len);
			goto finish_freeing;
		}
	}

	lbmap1 = table->lbmap[SSDFS_LBMAP_STATE_INDEX];

	is_vacant = ssdfs_blk2off_table_extent_vacant(lbmap1,
						      table->lblk2off_capacity,
						      extent);
	if (is_vacant) {
		err = -ENOENT;
		SSDFS_WARN("extent (start %u, len %u) "
			   "doesn't allocated yet\n",
			   extent->start_lblk, extent->len);
		goto finish_freeing;
	}

	lbmap2 = table->lbmap[SSDFS_LBMAP_MODIFICATION_INDEX];

	end_lblk = extent->start_lblk + extent->len;
	for (i = extent->start_lblk; i < end_lblk; i++) {
		if (table->lblk2off[i].id == U16_MAX) {
			SSDFS_WARN("logical block %d hasn't associated ID\n",
				   i);
		}

		err = ssdfs_blk2off_table_get_checked_position(table, (u16)i,
								&pos);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get checked offset's position: "
				  "logical_block %d, err %d\n",
				  i, err);
			goto finish_freeing;
		}

		ssdfs_blk2off_table_bmap_clear(lbmap1, (u16)i);
		ssdfs_blk2off_table_bmap_set(lbmap2, (u16)i);

		ssdfs_table_fragment_set_dirty(table, pos.peb_index,
						pos.sequence_id);

		pos.cno = ssdfs_current_cno(table->fsi->sb);
		pos.id = SSDFS_BLK2OFF_TABLE_INVALID_ID;
		pos.sequence_id = SSDFS_INVALID_FRAG_ID;
		pos.offset_index = U16_MAX;

		BUG_ON(table->used_logical_blks == 0);
		table->used_logical_blks--;
		BUG_ON(table->free_logical_blks == U16_MAX);
		table->free_logical_blks++;
	}

finish_freeing:
	up_write(&table->translation_lock);

	if (!err) {
		SSDFS_DBG("extent (start %u, len %u) has been freed\n",
			  extent->start_lblk, extent->len);
	}

	return err;
}

/*
 * ssdfs_blk2off_table_free_block() - free logical block
 * @table: pointer on table object
 * @logical_blk: logical block number
 *
 * This method tries to free logical block number.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - table doesn't prepared for this change yet.
 * %-ENOENT     - logical block isn't allocated yet.
 */
int ssdfs_blk2off_table_free_block(struct ssdfs_blk2off_table *table,
				   u16 logical_blk)
{
	struct ssdfs_blk2off_range extent = {
		.start_lblk = logical_blk,
		.len = 1,
	};
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, logical_blk %u\n",
		  table, logical_blk);

	err = ssdfs_blk2off_table_free_extent(table, &extent);
	if (err) {
		SSDFS_ERR("fail to free logical block %u: err %d\n",
			  logical_blk, err);
		return err;
	}

	SSDFS_DBG("logical block %u has been freed\n",
		  logical_blk);

	return 0;
}

/*
 * ssdfs_blk2off_table_set_block_migration() - set block migration
 * @table: pointer on table object
 * @logical_blk: logical block number
 * @peb_index: PEB index in the segment
 * @blk_state: pagevec with block's content
 *
 * This method tries to set migration state for logical block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - table doesn't prepared for this change yet.
 */
int ssdfs_blk2off_table_set_block_migration(struct ssdfs_blk2off_table *table,
					    u16 logical_blk,
					    u16 peb_index,
					    struct pagevec *blk_state)
{
	struct ssdfs_migrating_block *blk = NULL;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !blk_state);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, logical_blk %u, peb_index %u, blk_state %p\n",
		  table, logical_blk, peb_index, blk_state);

	if (peb_index >= table->pebs_count) {
		SSDFS_ERR("fail to set block migration: "
			  "peb_index %u >= pebs_count %u\n",
			  peb_index, table->pebs_count);
		return -EINVAL;
	}

	down_write(&table->translation_lock);

	if (logical_blk > table->last_allocated_blk) {
		err = -EINVAL;
		SSDFS_ERR("fail to set block migrating: "
			  "block %u > last_allocated_block %u\n",
			  logical_blk,
			  table->last_allocated_blk);
		goto finish_set_block_migration;
	}

	if (atomic_read(&table->state) <= SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT) {
		unsigned long *bmap = table->lbmap[SSDFS_LBMAP_INIT_INDEX];
		u16 capacity = table->lblk2off_capacity;

		if (ssdfs_blk2off_table_bmap_vacant(bmap, capacity,
						    logical_blk)) {
			err = -EAGAIN;
			SSDFS_DBG("table is not initialized yet: "
				  "logical_blk %u\n",
				  logical_blk);
			goto finish_set_block_migration;
		}
	}

	blk = &table->migrating_blks[logical_blk];

	switch (blk->state) {
	case SSDFS_LBLOCK_UNKNOWN_STATE:
		/* expected state */
		break;

	case SSDFS_LBLOCK_UNDER_MIGRATION:
	case SSDFS_LBLOCK_UNDER_COMMIT:
		err = -ERANGE;
		SSDFS_ERR("logical_blk %u is under migration already\n",
			  logical_blk);
		goto finish_set_block_migration;

	default:
		err = -ERANGE;
		SSDFS_ERR("unexpected state %#x\n",
			  blk->state);
		goto finish_set_block_migration;
	}

	pagevec_init(&blk->pvec);
	for (i = 0; i < pagevec_count(blk_state); i++) {
		struct page *page;
		void *kaddr1, *kaddr2;

		page = alloc_page(GFP_KERNEL);
		if (unlikely(!page)) {
			SSDFS_ERR("unable to allocate #%d memory page\n", i);
			err = -ENOMEM;
			pagevec_release(&blk->pvec);
			goto finish_set_block_migration;
		}

		get_page(page);

		kaddr1 = kmap_atomic(blk_state->pages[i]);
		kaddr2 = kmap_atomic(page);
		memcpy(kaddr2, kaddr1, PAGE_SIZE);
		kunmap_atomic(kaddr2);
		kunmap_atomic(kaddr1);

		pagevec_add(&blk->pvec, page);
	}

	blk->state = SSDFS_LBLOCK_UNDER_MIGRATION;
	blk->peb_index = peb_index;

finish_set_block_migration:
	up_write(&table->translation_lock);

	if (!err) {
		SSDFS_DBG("logical_blk %u (peb_index %u) is under migration\n",
			  logical_blk, peb_index);
	}

	return err;
}

/*
 * ssdfs_blk2off_table_get_block_state() - get state migrating block
 * @table: pointer on table object
 * @req: segment request [in|out]
 *
 * This method tries to get the state of logical block under migration.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal logic error.
 * %-EAGAIN     - logical block is not migrating.
 * %-ENOMEM     - fail to allocate memory.
 */
int ssdfs_blk2off_table_get_block_state(struct ssdfs_blk2off_table *table,
					struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	u16 logical_blk;
	struct ssdfs_migrating_block *blk = NULL;
	u32 read_bytes;
	int start_page;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, req %p\n",
		  table, req);

	fsi = table->fsi;
	read_bytes = req->result.processed_blks * fsi->pagesize;
	start_page = (int)(read_bytes >> PAGE_SHIFT);
	BUG_ON(start_page >= U16_MAX);

	if (pagevec_count(&req->result.pvec) <= start_page) {
		SSDFS_ERR("page_index %d >= pagevec_count %u\n",
			  start_page,
			  pagevec_count(&req->result.pvec));
		return -ERANGE;
	}

	logical_blk = req->place.start.blk_index + req->result.processed_blks;

	down_read(&table->translation_lock);

	if (logical_blk > table->last_allocated_blk) {
		err = -EINVAL;
		SSDFS_ERR("fail to set block migrating: "
			  "block %u > last_allocated_block %u\n",
			  logical_blk,
			  table->last_allocated_blk);
		goto finish_get_block_state;
	}

	blk = &table->migrating_blks[logical_blk];

	switch (blk->state) {
	case SSDFS_LBLOCK_UNDER_MIGRATION:
	case SSDFS_LBLOCK_UNDER_COMMIT:
		/* expected state */
		break;

	case SSDFS_LBLOCK_UNKNOWN_STATE:
		err = -EAGAIN;
		goto finish_get_block_state;

	default:
		err = -ERANGE;
		SSDFS_ERR("unexpected state %#x\n",
			  blk->state);
		goto finish_get_block_state;
	}

	for (i = 0; i < pagevec_count(&blk->pvec); i++) {
		int page_index = start_page + i;
		struct page *page;
		void *kaddr1, *kaddr2;

		if (page_index >= pagevec_count(&req->result.pvec)) {
			err = -ERANGE;
			SSDFS_ERR("index %d > count %d\n",
				  page_index,
				  pagevec_count(&req->result.pvec));
			goto finish_get_block_state;
		}

		page = req->result.pvec.pages[page_index];

		lock_page(page);

		kaddr1 = kmap_atomic(blk->pvec.pages[i]);
		kaddr2 = kmap_atomic(page);
		memcpy(kaddr2, kaddr1, PAGE_SIZE);
		kunmap_atomic(kaddr2);
		kunmap_atomic(kaddr1);

		SetPageUptodate(page);
		unlock_page(page);
	}

finish_get_block_state:
	up_read(&table->translation_lock);

	return err;
}

/*
 * ssdfs_blk2off_table_set_block_commit() - set block commit
 * @table: pointer on table object
 * @logical_blk: logical block number
 * @peb_index: PEB index in the segment
 *
 * This method tries to set commit state for logical block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input
 * %-ERANGE     - internal logic error
 */
int ssdfs_blk2off_table_set_block_commit(struct ssdfs_blk2off_table *table,
					 u16 logical_blk,
					 u16 peb_index)
{
	struct ssdfs_migrating_block *blk = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!table);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, logical_blk %u, peb_index %u\n",
		  table, logical_blk, peb_index);

	if (peb_index >= table->pebs_count) {
		SSDFS_ERR("fail to set block commit: "
			  "peb_index %u >= pebs_count %u\n",
			  peb_index, table->pebs_count);
		return -EINVAL;
	}

	down_write(&table->translation_lock);

	if (logical_blk > table->last_allocated_blk) {
		err = -EINVAL;
		SSDFS_ERR("fail to set block commit: "
			  "block %u > last_allocated_block %u\n",
			  logical_blk,
			  table->last_allocated_blk);
		goto finish_set_block_commit;
	}

	blk = &table->migrating_blks[logical_blk];

	switch (blk->state) {
	case SSDFS_LBLOCK_UNDER_MIGRATION:
		/* expected state */
		break;

	case SSDFS_LBLOCK_UNDER_COMMIT:
		err = -ERANGE;
		SSDFS_ERR("logical_blk %u is under commit already\n",
			  logical_blk);
		goto finish_set_block_commit;

	default:
		err = -ERANGE;
		SSDFS_ERR("unexpected state %#x\n",
			  blk->state);
		goto finish_set_block_commit;
	}

	if (blk->peb_index != peb_index) {
		err = -ERANGE;
		SSDFS_ERR("blk->peb_index %u != peb_index %u\n",
			  blk->peb_index, peb_index);
		goto finish_set_block_commit;
	}

	blk->state = SSDFS_LBLOCK_UNDER_COMMIT;

finish_set_block_commit:
	up_write(&table->translation_lock);

	if (!err) {
		SSDFS_DBG("logical_blk %u (peb_index %u) is under commit\n",
			  logical_blk, peb_index);
	}

	return err;
}

/*
 * ssdfs_blk2off_table_revert_migration_state() - revert migration state
 * @table: pointer on table object
 * @peb_index: PEB index in the segment
 *
 * This method tries to revert migration state for logical block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input
 */
int ssdfs_blk2off_table_revert_migration_state(struct ssdfs_blk2off_table *tbl,
						u16 peb_index)
{
	struct ssdfs_migrating_block *blk = NULL;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tbl);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("table %p, peb_index %u\n",
		  tbl, peb_index);

	if (peb_index >= tbl->pebs_count) {
		SSDFS_ERR("fail to revert migration state: "
			  "peb_index %u >= pebs_count %u\n",
			  peb_index, tbl->pebs_count);
		return -EINVAL;
	}

	down_write(&tbl->translation_lock);

	for (i = 0; i <= tbl->last_allocated_blk; i++) {
		blk = &tbl->migrating_blks[i];

		if (blk->peb_index != peb_index)
			continue;

		if (blk->state == SSDFS_LBLOCK_UNDER_COMMIT) {
			blk->state = SSDFS_LBLOCK_UNKNOWN_STATE;
			pagevec_release(&blk->pvec);
		}
	}

	up_write(&tbl->translation_lock);

	SSDFS_DBG("migration state was reverted for peb_index %u\n",
		  peb_index);

	return 0;
}
