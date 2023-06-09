// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/offset_translation_table.h - offset table declarations.
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

#ifndef _SSDFS_OFFSET_TRANSLATION_TABLE_H
#define _SSDFS_OFFSET_TRANSLATION_TABLE_H

#include <linux/pagevec.h>

#include "request_queue.h"
#include "sequence_array.h"
#include "dynamic_array.h"

/*
 * struct ssdfs_phys_offset_table_fragment - fragment of phys offsets table
 * @lock: table fragment lock
 * @start_id: starting physical offset id number in fragment
 * @sequence_id: fragment's sequence_id in PEB
 * @id_count: count of id numbers in sequence
 * @state: fragment state
 * @peb_id: PEB ID containing the fragment
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
	u64 peb_id;

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
	SSDFS_BLK2OFF_TABLE_DIRTY_PARTIAL_INIT,
	SSDFS_BLK2OFF_TABLE_COMPLETE_INIT,
	SSDFS_BLK2OFF_TABLE_DIRTY,
	SSDFS_BLK2OFF_TABLE_STATE_MAX,
};

#define SSDFS_BLK2OFF_TABLE_INVALID_ID		U16_MAX

/*
 * struct ssdfs_block_descriptor_state - block descriptor state
 * @status: state of block descriptor buffer
 * @buf: block descriptor buffer
 */
struct ssdfs_block_descriptor_state {
	u32 status;
	struct ssdfs_block_descriptor buf;
};

/*
 * Block descriptor buffer state
 */
enum {
	SSDFS_BLK_DESC_BUF_UNKNOWN_STATE,
	SSDFS_BLK_DESC_BUF_INITIALIZED,
	SSDFS_BLK_DESC_BUF_STATE_MAX,
	SSDFS_BLK_DESC_BUF_ALLOCATED = U32_MAX,
};

/*
 * struct ssdfs_offset_position - defines offset id and position
 * @cno: checkpoint of change
 * @id: physical offset ID
 * @peb_index: PEB's index
 * @sequence_id: sequence ID of physical offset table's fragment
 * @offset_index: offset index inside of fragment
 * @blk_desc: logical block descriptor
 */
struct ssdfs_offset_position {
	u64 cno;
	u16 id;
	u16 peb_index;
	u16 sequence_id;
	u16 offset_index;

	struct ssdfs_block_descriptor_state blk_desc;
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
 * struct ssdfs_bitmap_array - bitmap array
 * @bits_count: number of available bits in every bitmap
 * @bytes_count: number of allocated bytes in every bitmap
 * @array: array of bitmaps
 */
struct ssdfs_bitmap_array {
	u32 bits_count;
	u32 bytes_count;
	unsigned long *array[SSDFS_LBMAP_ARRAY_MAX];
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
 * @wait_queue: wait queue of blk2off table
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
	struct ssdfs_bitmap_array lbmap;
	struct ssdfs_dynamic_array lblk2off;
	struct ssdfs_dynamic_array migrating_blks;
	u16 lblk2off_capacity;

	struct ssdfs_phys_offset_table_array *peb;
	u16 pebs_count;

	struct completion partial_init_end;
	struct completion full_init_end;
	wait_queue_head_t wait_queue;

	struct ssdfs_fs_info *fsi;
};

#define SSDFS_OFF_POS(ptr) \
	((struct ssdfs_offset_position *)(ptr))
#define SSDFS_MIGRATING_BLK(ptr) \
	((struct ssdfs_migrating_block *)(ptr))
#define SSDFS_TRANS_EXT(ptr) \
	((struct ssdfs_translation_extent *)(ptr))

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
 * @new_sequence_id: sequence ID of the first newly added fragment
 * @start_offset_id: starting offset ID
 * @end_offset_id: ending offset ID
 * @dirty_fragments: count of dirty fragments
 * @fragments_count: total count of fragments
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
	u16 new_sequence_id;
	u16 start_offset_id;
	u16 end_offset_id;
	u16 dirty_fragments;
	u32 fragments_count;
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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_count %zu, bmap_bytes %zu\n",
		  items_count, bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	return bytes;
}

static inline
bool is_ssdfs_logical_block_migrating(int blk_state)
{
	bool is_migrating = false;

	switch (blk_state) {
	case SSDFS_LBLOCK_UNDER_MIGRATION:
	case SSDFS_LBLOCK_UNDER_COMMIT:
		is_migrating = true;
		break;

	default:
		/* do nothing */
		break;
	}

	return is_migrating;
}

/* Function prototypes */
struct ssdfs_blk2off_table *
ssdfs_blk2off_table_create(struct ssdfs_fs_info *fsi,
			   u16 items_count, u8 type,
			   int state);
void ssdfs_blk2off_table_destroy(struct ssdfs_blk2off_table *table);
int ssdfs_blk2off_table_partial_clean_init(struct ssdfs_blk2off_table *table,
					   u16 peb_index);
int ssdfs_blk2off_table_partial_init(struct ssdfs_blk2off_table *table,
				     struct ssdfs_read_init_env *env,
				     u16 peb_index, u64 peb_id, u64 cno);
int ssdfs_blk2off_table_blk_desc_init(struct ssdfs_blk2off_table *table,
					u16 logical_blk,
					struct ssdfs_offset_position *pos);
int ssdfs_blk2off_table_resize(struct ssdfs_blk2off_table *table,
				u16 new_items_count);
int ssdfs_blk2off_table_snapshot(struct ssdfs_blk2off_table *table,
				 u16 peb_index, u64 peb_id,
				 struct ssdfs_blk2off_table_snapshot *snapshot);
void ssdfs_blk2off_table_free_snapshot(struct ssdfs_blk2off_table_snapshot *sp);
int ssdfs_blk2off_table_extract_extents(struct ssdfs_blk2off_table_snapshot *sp,
					struct ssdfs_dynamic_array *array,
					u16 capacity, u16 *extent_count);

int
ssdfs_blk2off_table_prepare_for_commit(struct ssdfs_blk2off_table *table,
				       u16 peb_index, u16 sequence_id,
				       struct ssdfs_blk2off_table_snapshot *sp);
int ssdfs_peb_store_offsets_table_header(struct ssdfs_peb_info *pebi,
					struct ssdfs_blk2off_table_header *hdr,
					struct ssdfs_peb_log_offset *log_offset);
int
ssdfs_peb_store_offsets_table_extents(struct ssdfs_peb_info *pebi,
				      struct ssdfs_dynamic_array *array,
				      u16 extent_count,
				      struct ssdfs_peb_log_offset *log_offset);
int ssdfs_peb_store_offsets_table_fragment(struct ssdfs_peb_info *pebi,
					struct ssdfs_blk2off_table *table,
					u16 peb_index, u16 sequence_id,
					struct ssdfs_peb_log_offset *log_offset);
int ssdfs_peb_store_offsets_table(struct ssdfs_peb_info *pebi,
				  struct ssdfs_metadata_descriptor *desc,
				  struct ssdfs_peb_log_offset *log_offset);
int
ssdfs_blk2off_table_forget_snapshot(struct ssdfs_blk2off_table *table,
				    struct ssdfs_blk2off_table_snapshot *sp,
				    struct ssdfs_dynamic_array *array,
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
			    int *migration_state,
			    struct ssdfs_offset_position *pos);
int ssdfs_blk2off_table_allocate_block(struct ssdfs_blk2off_table *table,
					u16 *logical_blk);
int ssdfs_blk2off_table_allocate_extent(struct ssdfs_blk2off_table *table,
					u16 len,
					struct ssdfs_blk2off_range *extent);
int ssdfs_blk2off_table_change_offset(struct ssdfs_blk2off_table *table,
				      u16 logical_blk,
				      u16 peb_index,
				      struct ssdfs_block_descriptor *blk_desc,
				      struct ssdfs_phys_offset_descriptor *off);
int ssdfs_blk2off_table_free_block(struct ssdfs_blk2off_table *table,
				   u16 peb_index, u16 logical_blk);
int ssdfs_blk2off_table_free_extent(struct ssdfs_blk2off_table *table,
				    u16 peb_index,
				    struct ssdfs_blk2off_range *extent);

int ssdfs_blk2off_table_get_block_migration(struct ssdfs_blk2off_table *table,
					    u16 logical_blk,
					    u16 peb_index);
int ssdfs_blk2off_table_set_block_migration(struct ssdfs_blk2off_table *table,
					    u16 logical_blk,
					    u16 peb_index,
					    struct ssdfs_segment_request *req);
int ssdfs_blk2off_table_get_block_state(struct ssdfs_blk2off_table *table,
					struct ssdfs_segment_request *req);
int ssdfs_blk2off_table_update_block_state(struct ssdfs_blk2off_table *table,
					   struct ssdfs_segment_request *req);
int ssdfs_blk2off_table_set_block_commit(struct ssdfs_blk2off_table *table,
					 u16 logical_blk,
					 u16 peb_index);
int ssdfs_blk2off_table_revert_migration_state(struct ssdfs_blk2off_table *tbl,
						u16 peb_index);

#ifdef CONFIG_SSDFS_TESTING
int ssdfs_blk2off_table_fragment_set_clean(struct ssdfs_blk2off_table *table,
					   u16 peb_index, u16 sequence_id);
#else
static inline
int ssdfs_blk2off_table_fragment_set_clean(struct ssdfs_blk2off_table *table,
					   u16 peb_index, u16 sequence_id)
{
	SSDFS_ERR("set fragment clean is not supported\n");
	return -EOPNOTSUPP;
}
#endif /* CONFIG_SSDFS_TESTING */

#endif /* _SSDFS_OFFSET_TRANSLATION_TABLE_H */
