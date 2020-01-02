//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/offset_translation_table.h - offset table declarations.
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

#ifndef _SSDFS_OFFSET_TRANSLATION_TABLE_H
#define _SSDFS_OFFSET_TRANSLATION_TABLE_H

#include <linux/pagevec.h>

#include "request_queue.h"
#include "sequence_array.h"

/*
 * struct ssdfs_phys_offset_table_fragment - fragment of phys offsets table
 * @lock: table fragment lock
 * @start_id: starting physical offset id number in fragment
 * @sequence_id: fragment's sequence_id in PEB
 * @id_count: count of id numbers in sequence
 * @state: fragment state
 * @hdr: pointer on fragment's header
 * @phys_offs: array of physical offsets in fragment
 * @buf: buffer of fragment
 * @buf_size: size of buffer in bytes
 *
 * One fragment can be used for one PEB's log. But one log can contain
 * several fragments too. In memory exists the same count of fragments
 * as on volume.
 */
struct ssdfs_phys_offset_table_fragment {
	struct rw_semaphore lock;
	u16 start_id;
	u16 sequence_id;
	atomic_t id_count;
	atomic_t state;

	struct ssdfs_phys_offset_table_header *hdr;
	struct ssdfs_phys_offset_descriptor *phys_offs;
	unsigned char *buf;
	size_t buf_size;
};

enum {
	SSDFS_BLK2OFF_FRAG_UNDEFINED,
	SSDFS_BLK2OFF_FRAG_CREATED,
	SSDFS_BLK2OFF_FRAG_INITIALIZED,
	SSDFS_BLK2OFF_FRAG_DIRTY,
	SSDFS_BLK2OFF_FRAG_UNDER_COMMIT,
	SSDFS_BLK2OFF_FRAG_COMMITED,
	SSDFS_BLK2OFF_FRAG_STATE_MAX,
};

#define SSDFS_INVALID_FRAG_ID			U16_MAX
#define SSDFS_BLK2OFF_TBL_REVERT_THRESHOLD	(U16_MAX - 1)

/*
 * struct ssdfs_phys_offset_table_array - array of log's fragments in PEB
 * @state: PEB's translation table state
 * @fragment_count: fragments count
 * @array: array of fragments
 */
struct ssdfs_phys_offset_table_array {
	atomic_t state;
	atomic_t fragment_count;
	struct ssdfs_sequence_array *sequence;
};

enum {
	SSDFS_BLK2OFF_TABLE_UNDEFINED,
	SSDFS_BLK2OFF_TABLE_CREATED,
	SSDFS_BLK2OFF_TABLE_PARTIAL_INIT,
	SSDFS_BLK2OFF_TABLE_COMPLETE_INIT,
	SSDFS_BLK2OFF_TABLE_DIRTY,
	SSDFS_BLK2OFF_TABLE_STATE_MAX,
};

#define SSDFS_BLK2OFF_TABLE_INVALID_ID		U16_MAX

/*
 * struct ssdfs_offset_position - defines offset id and position
 * @cno: checkpoint of change
 * @id: physical offset ID
 * @peb_index: PEB's index
 * @sequence_id: sequence ID of physical offset table's fragment
 * @offset_index: offset index inside of fragment
 */
struct ssdfs_offset_position {
	u64 cno;
	u16 id;
	u16 peb_index;
	u16 sequence_id;
	u16 offset_index;
};

/*
 * struct ssdfs_migrating_block - migrating block state
 * @state: logical block's state
 * @peb_index: PEB's index
 * @pvec: copy of logical block's content (under migration only)
 */
struct ssdfs_migrating_block {
	int state;
	u16 peb_index;
	struct pagevec pvec;
};

/*
 * Migrating block's states
 */
enum {
	SSDFS_LBLOCK_UNKNOWN_STATE,
	SSDFS_LBLOCK_UNDER_MIGRATION,
	SSDFS_LBLOCK_UNDER_COMMIT,
	SSDFS_LBLOCK_STATE_MAX
};

enum {
	SSDFS_LBMAP_INIT_INDEX,
	SSDFS_LBMAP_STATE_INDEX,
	SSDFS_LBMAP_MODIFICATION_INDEX,
	SSDFS_LBMAP_ARRAY_MAX,
};

/*
 * struct ssdfs_blk2off_table - in-core translation table
 * @flags: flags of translation table
 * @state: translation table object state
 * @pages_per_peb: pages per physical erase block
 * @pages_per_seg: pages per segment
 * @type: translation table type
 * @translation_lock: lock of translation operation
 * @init_cno: last actual checkpoint
 * @used_logical_blks: count of used logical blocks
 * @free_logical_blks: count of free logical blocks
 * @last_allocated_blk: last allocated block (hint for allocation)
 * @lbmap: array of block bitmaps
 * @lblk2off: array of correspondence between logical numbers and phys off ids
 * @migrating_blks: array of migrating blocks
 * @lblk2off_capacity: capacity of correspondence array
 * @peb: sequence of physical offset arrays
 * @pebs_count: count of PEBs in segment
 * @partial_init_end: wait of partial init ending
 * @full_init_end: wait of full init ending
 * @fsi: pointer on shared file system object
 */
struct ssdfs_blk2off_table {
	atomic_t flags;
	atomic_t state;

	u32 pages_per_peb;
	u32 pages_per_seg;
	u8 type;

	struct rw_semaphore translation_lock;
	u64 init_cno;
	u16 used_logical_blks;
	u16 free_logical_blks;
	u16 last_allocated_blk;
	unsigned long *lbmap[SSDFS_LBMAP_ARRAY_MAX];
	struct ssdfs_offset_position *lblk2off;
	struct ssdfs_migrating_block *migrating_blks;
	u16 lblk2off_capacity;

	struct ssdfs_phys_offset_table_array *peb;
	u16 pebs_count;

	struct completion partial_init_end;
	struct completion full_init_end;

	struct ssdfs_fs_info *fsi;
};

enum {
	SSDFS_BLK2OFF_OBJECT_UNKNOWN,
	SSDFS_BLK2OFF_OBJECT_CREATED,
	SSDFS_BLK2OFF_OBJECT_PARTIAL_INIT,
	SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT,
	SSDFS_BLK2OFF_OBJECT_STATE_MAX,
};

/*
 * struct ssdfs_blk2off_table_snapshot - table state snapshot
 * @cno: checkpoint of snapshot
 * @bmap_copy: copy of modification bitmap
 * @tbl_copy: copy of translation table
 * @capacity: capacity of table
 * @used_logical_blks: count of used logical blocks
 * @free_logical_blks: count of free logical blocks
 * @last_allocated_blk: last allocated block (hint for allocation)
 * @peb_index: PEB index
 * @start_sequence_id: sequence ID of the first dirty fragment
 * @dirty_fragments: count of dirty fragments
 *
 * The @bmap_copy and @tbl_copy are allocated during getting
 * snapshot inside of called function. Freeing of allocated
 * memory SHOULD BE MADE by caller.
 */
struct ssdfs_blk2off_table_snapshot {
	u64 cno;

	unsigned long *bmap_copy;
	struct ssdfs_offset_position *tbl_copy;
	u16 capacity;

	u16 used_logical_blks;
	u16 free_logical_blks;
	u16 last_allocated_blk;

	u16 peb_index;
	u16 start_sequence_id;
	u16 dirty_fragments;
};

/*
 * struct ssdfs_blk2off_range - extent of logical blocks
 * @start_lblk: start logical block number
 * @len: count of logical blocks in extent
 */
struct ssdfs_blk2off_range {
	u16 start_lblk;
	u16 len;
};

/*
 * Inline functions
 */

/*
 * ssdfs_blk2off_table_bmap_bytes() - calculate bmap bytes count
 * @items_count: bits count in bitmap
 */
static inline
size_t ssdfs_blk2off_table_bmap_bytes(size_t items_count)
{
	size_t bytes;

	bytes = (items_count + BITS_PER_LONG - 1) / BITS_PER_BYTE;

	SSDFS_DBG("items_count %zu, bmap_bytes %zu\n",
		  items_count, bytes);

	return bytes;
}

static inline
int ssdfs_show_fragment_details(void *ptr)
{
	struct ssdfs_phys_offset_table_fragment *fragment;

	fragment = (struct ssdfs_phys_offset_table_fragment *)ptr;
	if (!fragment) {
		SSDFS_ERR("empty pointer on fragment\n");
		return -ERANGE;
	}

	SSDFS_DBG("fragment: "
		  "start_id %u, sequence_id %u, "
		  "id_count %d, state %#x, "
		  "hdr %p, phys_offs %p, "
		  "buf_size %zu\n",
		  fragment->start_id,
		  fragment->sequence_id,
		  atomic_read(&fragment->id_count),
		  atomic_read(&fragment->state),
		  fragment->hdr,
		  fragment->phys_offs,
		  fragment->buf_size);

	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				fragment->buf,
				fragment->buf_size);

	return 0;
}

static inline
void ssdfs_debug_blk2off_table_object(struct ssdfs_blk2off_table *tbl)
{
#ifdef CONFIG_SSDFS_DEBUG
	size_t bytes;
	int i;

	BUG_ON(!tbl);

	SSDFS_DBG("flags %#x, state %#x, pages_per_peb %u, "
		  "pages_per_seg %u, type %#x\n",
		  atomic_read(&tbl->flags),
		  atomic_read(&tbl->state),
		  tbl->pages_per_peb,
		  tbl->pages_per_seg,
		  tbl->type);

	SSDFS_DBG("init_cno %llu, used_logical_blks %u, "
		  "free_logical_blks %u, last_allocated_blk %u\n",
		  tbl->init_cno, tbl->used_logical_blks,
		  tbl->free_logical_blks, tbl->last_allocated_blk);

	bytes = ssdfs_blk2off_table_bmap_bytes(tbl->lblk2off_capacity);
	for (i = 0; i < SSDFS_LBMAP_ARRAY_MAX; i++) {
		unsigned long *bmap = tbl->lbmap[i];

		SSDFS_DBG("lbmap: index %d, bmap %p\n", i, bmap);
		if (bmap) {
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
						bmap, bytes);
		}
	}

	SSDFS_DBG("lblk2off_capacity %u\n", tbl->lblk2off_capacity);

	for (i = 0; i < tbl->lblk2off_capacity; i++) {
		SSDFS_DBG("lbk2off: index %d, "
			  "cno %llu, id %u, peb_index %u, "
			  "sequence_id %u, offset_index %u\n",
			  i, tbl->lblk2off[i].cno,
			  tbl->lblk2off[i].id,
			  tbl->lblk2off[i].peb_index,
			  tbl->lblk2off[i].sequence_id,
			  tbl->lblk2off[i].offset_index);
	}

	SSDFS_DBG("pebs_count %u\n", tbl->pebs_count);

	for (i = 0; i < tbl->pebs_count; i++) {
		struct ssdfs_phys_offset_table_array *peb = &tbl->peb[i];
		int fragments_count = atomic_read(&peb->fragment_count);

		SSDFS_DBG("peb: index %d, state %#x, "
			  "fragment_count %d, last_sequence_id %lu\n",
			  i, atomic_read(&peb->state),
			  fragments_count,
			  ssdfs_sequence_array_last_id(peb->sequence));

		ssdfs_sequence_array_apply_for_all(peb->sequence,
						ssdfs_show_fragment_details);
	}
#endif /* CONFIG_SSDFS_DEBUG */
}

/* Function prototypes */
struct ssdfs_blk2off_table *
ssdfs_blk2off_table_create(struct ssdfs_fs_info *fsi,
			   u16 items_count, u8 type,
			   int state);
void ssdfs_blk2off_table_destroy(struct ssdfs_blk2off_table *table);
int ssdfs_blk2off_table_partial_init(struct ssdfs_blk2off_table *table,
				     struct pagevec *source,
				     u16 peb_index,
				     u64 cno);
int ssdfs_blk2off_table_resize(struct ssdfs_blk2off_table *table,
				u16 new_items_count);
int ssdfs_blk2off_table_snapshot(struct ssdfs_blk2off_table *table,
				 u16 peb_index,
				 struct ssdfs_blk2off_table_snapshot *snapshot);
void ssdfs_blk2off_table_free_snapshot(struct ssdfs_blk2off_table_snapshot *sp);
int ssdfs_blk2off_table_extract_extents(struct ssdfs_blk2off_table_snapshot *sp,
					struct ssdfs_translation_extent *array,
					u16 capacity,
					u16 *extent_count);
int
ssdfs_blk2off_table_prepare_for_commit(struct ssdfs_blk2off_table *table,
				       u16 peb_index, u16 sequence_id,
				       struct ssdfs_blk2off_table_snapshot *sp);
int ssdfs_peb_store_offsets_table_header(struct ssdfs_peb_info *pebi,
					 struct ssdfs_blk2off_table_header *hdr,
					 pgoff_t *cur_page,
					 u32 *write_offset);
int
ssdfs_peb_store_offsets_table_extents(struct ssdfs_peb_info *pebi,
				      struct ssdfs_translation_extent *array,
				      u16 extent_count,
				      pgoff_t *cur_page,
				      u32 *write_offset);
int ssdfs_peb_store_offsets_table_fragment(struct ssdfs_peb_info *pebi,
					   struct ssdfs_blk2off_table *table,
					   u16 peb_index, u16 sequence_id,
					   pgoff_t *cur_page,
					   u32 *write_offset);
int ssdfs_peb_store_offsets_table(struct ssdfs_peb_info *pebi,
				  struct ssdfs_metadata_descriptor *desc,
				  pgoff_t *cur_page,
				  u32 *write_offset);
int
ssdfs_blk2off_table_forget_snapshot(struct ssdfs_blk2off_table *table,
				    struct ssdfs_blk2off_table_snapshot *sp,
				    struct ssdfs_translation_extent *array,
				    u16 extent_count);

bool ssdfs_blk2off_table_dirtied(struct ssdfs_blk2off_table *table,
				 u16 peb_index);
bool ssdfs_blk2off_table_initialized(struct ssdfs_blk2off_table *table,
				     u16 peb_index);

int ssdfs_blk2off_table_get_used_logical_blks(struct ssdfs_blk2off_table *tbl,
						u16 *used_blks);
int ssdfs_blk2off_table_get_offset_position(struct ssdfs_blk2off_table *table,
					    u16 logical_blk,
					    struct ssdfs_offset_position *pos);
struct ssdfs_phys_offset_descriptor *
ssdfs_blk2off_table_convert(struct ssdfs_blk2off_table *table,
			    u16 logical_blk, u16 *peb_index,
			    bool *is_migrating);
int ssdfs_blk2off_table_allocate_block(struct ssdfs_blk2off_table *table,
					u16 *logical_blk);
int ssdfs_blk2off_table_allocate_extent(struct ssdfs_blk2off_table *table,
					u16 len,
					struct ssdfs_blk2off_range *extent);
int ssdfs_blk2off_table_change_offset(struct ssdfs_blk2off_table *table,
				      u16 logical_blk,
				      u16 peb_index,
				      struct ssdfs_phys_offset_descriptor *off);
int ssdfs_blk2off_table_free_block(struct ssdfs_blk2off_table *table,
				   u16 logical_blk);
int ssdfs_blk2off_table_free_extent(struct ssdfs_blk2off_table *table,
				    struct ssdfs_blk2off_range *extent);

int ssdfs_blk2off_table_set_block_migration(struct ssdfs_blk2off_table *table,
					    u16 logical_blk,
					    u16 peb_index,
					    struct pagevec *blk_state);
int ssdfs_blk2off_table_get_block_state(struct ssdfs_blk2off_table *table,
					struct ssdfs_segment_request *req);
int ssdfs_blk2off_table_set_block_commit(struct ssdfs_blk2off_table *table,
					 u16 logical_blk,
					 u16 peb_index);
int ssdfs_blk2off_table_revert_migration_state(struct ssdfs_blk2off_table *tbl,
						u16 peb_index);

#endif /* _SSDFS_OFFSET_TRANSLATION_TABLE_H */
