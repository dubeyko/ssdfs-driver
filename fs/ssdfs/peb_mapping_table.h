/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_mapping_table.h - PEB mapping table declarations.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2024 Viacheslav Dubeyko <slava@dubeyko.com>
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

#ifndef _SSDFS_PEB_MAPPING_TABLE_H
#define _SSDFS_PEB_MAPPING_TABLE_H

#define SSDFS_MAPTBL_FIRST_PROTECTED_INDEX	0
#define SSDFS_MAPTBL_PROTECTION_STEP		50
#define SSDFS_MAPTBL_PROTECTION_RANGE		3

#define SSDFS_PRE_ERASE_PEB_THRESHOLD_PCT	(3)
#define SSDFS_UNUSED_LEB_THRESHOLD_PCT		(1)

/*
 * struct ssdfs_maptbl_fragment_desc - fragment descriptor
 * @lock: fragment lock
 * @state: fragment state
 * @fragment_id: fragment's ID in the whole sequence
 * @fragment_folios: count of memory folios in fragment
 * @start_leb: start LEB of fragment
 * @lebs_count: count of LEB descriptors in the whole fragment
 * @lebs_per_page: count of LEB descriptors in memory folio
 * @lebtbl_pages: count of memory folios are used for LEBs description
 * @pebs_per_page: count of PEB descriptors in memory folio
 * @stripe_pages: count of memory folios in one stripe
 * @mapped_lebs: mapped LEBs count in the fragment
 * @migrating_lebs: migrating LEBs count in the fragment
 * @reserved_pebs: count of reserved PEBs in fragment
 * @pre_erase_pebs: count of PEBs in pre-erase state per fragment
 * @recovering_pebs: count of recovering PEBs per fragment
 * @array: fragment's memory folios
 * @init_end: wait of init ending
 * @flush_req1: main flush requests array
 * @flush_req2: backup flush requests array
 * @flush_req_count: number of flush requests in the array
 * @flush_seq_size: flush requests' array capacity
 */
struct ssdfs_maptbl_fragment_desc {
	struct rw_semaphore lock;
	atomic_t state;

	u32 fragment_id;
	u32 fragment_folios;

	u64 start_leb;
	u32 lebs_count;

	u16 lebs_per_page;
	u16 lebtbl_pages;

	u16 pebs_per_page;
	u16 stripe_pages;

	u32 mapped_lebs;
	u32 migrating_lebs;
	u32 reserved_pebs;
	u32 pre_erase_pebs;
	u32 recovering_pebs;

	struct ssdfs_folio_array array;
	struct completion init_end;

	struct ssdfs_segment_request *flush_req1;
	struct ssdfs_segment_request *flush_req2;
	u32 flush_req_count;
	u32 flush_seq_size;
};

/* Fragment's state */
enum {
	SSDFS_MAPTBL_FRAG_CREATED	= 0,
	SSDFS_MAPTBL_FRAG_INIT_FAILED	= 1,
	SSDFS_MAPTBL_FRAG_INITIALIZED	= 2,
	SSDFS_MAPTBL_FRAG_DIRTY		= 3,
	SSDFS_MAPTBL_FRAG_TOWRITE	= 4,
	SSDFS_MAPTBL_FRAG_STATE_MAX	= 5,
};

/*
 * struct ssdfs_maptbl_area - mapping table area
 * @portion_id: sequential ID of mapping table fragment
 * @folios: array of memory folio pointers
 * @folios_capacity: capacity of array
 * @folios_count: count of folios in array
 */
struct ssdfs_maptbl_area {
	u16 portion_id;
	struct folio **folios;
	size_t folios_capacity;
	size_t folios_count;
};

/*
 * struct ssdfs_peb_mapping_table - mapping table object
 * @tbl_lock: mapping table lock
 * @fragments_count: count of fragments
 * @fragments_per_seg: count of fragments in segment
 * @fragments_per_peb: count of fragments in PEB
 * @fragment_bytes: count of bytes in one fragment
 * @fragment_folios: count of memory folios in one fragment
 * @flags: mapping table flags
 * @lebs_count: count of LEBs are described by mapping table
 * @pebs_count: count of PEBs are described by mapping table
 * @lebs_per_fragment: count of LEB descriptors in fragment
 * @pebs_per_fragment: count of PEB descriptors in fragment
 * @pebs_per_stripe: count of PEB descriptors in stripe
 * @stripes_per_fragment: count of stripes in fragment
 * @extents: metadata extents that describe mapping table location
 * @segs: array of pointers on segment objects
 * @segs_count: count of segment objects are used for mapping table
 * @state: mapping table's state
 * @erase_op_state: state of erase operation
 * @pre_erase_pebs: count of PEBs in pre-erase state
 * @max_erase_ops: upper bound of erase operations for one iteration
 * @erase_ops_end_wq: wait queue of threads are waiting end of erase operation
 * @bmap_lock: dirty bitmap's lock
 * @dirty_bmap: bitmap of dirty fragments
 * @desc_array: array of fragment descriptors
 * @wait_queue: wait queue of mapping table's thread
 * @thread: descriptor of mapping table's thread
 * @fsi: pointer on shared file system object
 */
struct ssdfs_peb_mapping_table {
	struct rw_semaphore tbl_lock;
	u32 fragments_count;
	u16 fragments_per_seg;
	u16 fragments_per_peb;
	u32 fragment_bytes;
	u32 fragment_folios;
	atomic_t flags;
	u64 lebs_count;
	u64 pebs_count;
	u16 lebs_per_fragment;
	u16 pebs_per_fragment;
	u16 pebs_per_stripe;
	u16 stripes_per_fragment;
	struct ssdfs_meta_area_extent extents[MAPTBL_LIMIT1][MAPTBL_LIMIT2];
	struct ssdfs_segment_info **segs[SSDFS_MAPTBL_SEG_COPY_MAX];
	u16 segs_count;

	atomic_t state;

	atomic_t erase_op_state;
	atomic_t pre_erase_pebs;
	atomic_t max_erase_ops;
	wait_queue_head_t erase_ops_end_wq;

	atomic64_t last_peb_recover_cno;

	struct mutex bmap_lock;
	unsigned long *dirty_bmap;
	struct ssdfs_maptbl_fragment_desc *desc_array;

	wait_queue_head_t wait_queue;
	struct ssdfs_thread_info thread;
	struct ssdfs_fs_info *fsi;
};

/* PEB mapping table's state */
enum {
	SSDFS_MAPTBL_CREATED			= 0,
	SSDFS_MAPTBL_GOING_TO_BE_DESTROY	= 1,
	SSDFS_MAPTBL_STATE_MAX			= 2,
};

/*
 * struct ssdfs_maptbl_peb_descriptor - PEB descriptor
 * @peb_id: PEB identification number
 * @shared_peb_index: index of external shared destination PEB
 * @erase_cycles: P/E cycles
 * @type: PEB type
 * @state: PEB state
 * @flags: PEB flags
 * @consistency: PEB state consistency type
 */
struct ssdfs_maptbl_peb_descriptor {
	u64 peb_id;
	u8 shared_peb_index;
	u32 erase_cycles;
	u8 type;
	u8 state;
	u8 flags;
	u8 consistency;
};

/*
 * struct ssdfs_maptbl_peb_relation - PEBs association
 * @pebs: array of PEB descriptors
 */
struct ssdfs_maptbl_peb_relation {
	struct ssdfs_maptbl_peb_descriptor pebs[SSDFS_MAPTBL_RELATION_MAX];
};

/*
 * Erase operation state
 */
enum {
	SSDFS_MAPTBL_NO_ERASE,
	SSDFS_MAPTBL_ERASE_IN_PROGRESS
};

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
	SSDFS_ERASE_SB_PEB_DONE,
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

#define SSDFS_ERASE_RESULTS_PER_FRAGMENT	(10)

/*
 * Inline functions
 */

/*
 * SSDFS_ERASE_RESULT_INIT() - init erase result
 * @fragment_index: index of mapping table's fragment
 * @peb_index: PEB's index in fragment
 * @peb_id: PEB ID number
 * @state: state of erase operation
 * @result: erase operation result [out]
 *
 * This method initializes the erase operation result.
 */
static inline
void SSDFS_ERASE_RESULT_INIT(u32 fragment_index, u16 peb_index,
			     u64 peb_id, int state,
			     struct ssdfs_erase_result *result)
{
	result->fragment_index = fragment_index;
	result->peb_index = peb_index;
	result->peb_id = peb_id;
	result->state = state;
}

/*
 * DEFINE_PEB_INDEX_IN_FRAGMENT() - define PEB index in the whole fragment
 * @fdesc: fragment descriptor
 * @folio_index: folio index in the fragment
 * @item_index: item index in the memory folio
 */
static inline
u16 DEFINE_PEB_INDEX_IN_FRAGMENT(struct ssdfs_maptbl_fragment_desc *fdesc,
				 pgoff_t folio_index,
				 u16 item_index)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);
	BUG_ON(folio_index < fdesc->lebtbl_pages);

	SSDFS_DBG("fdesc %p, folio_index %lu, item_index %u\n",
		  fdesc, folio_index, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	folio_index -= fdesc->lebtbl_pages;
	folio_index *= fdesc->pebs_per_page;
	folio_index += item_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(folio_index >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u16)folio_index;
}

/*
 * GET_PEB_ID() - define PEB ID for the index
 * @kaddr: pointer on memory folio's content
 * @item_index: item index inside of the folio
 *
 * This method tries to convert @item_index into
 * PEB ID value.
 *
 * RETURN:
 * [success] - PEB ID
 * [failure] - U64_MAX
 */
static inline
u64 GET_PEB_ID(void *kaddr, u16 item_index)
{
	struct ssdfs_peb_table_fragment_header *hdr;
	u64 start_peb;
	u16 pebs_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);

	SSDFS_DBG("kaddr %p, item_index %u\n",
		  kaddr, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;

	if (le16_to_cpu(hdr->magic) != SSDFS_PEB_TABLE_MAGIC) {
		SSDFS_ERR("corrupted folio\n");
		return U64_MAX;
	}

	start_peb = le64_to_cpu(hdr->start_peb);
	pebs_count = le16_to_cpu(hdr->pebs_count);

	if (item_index >= pebs_count) {
		SSDFS_ERR("item_index %u >= pebs_count %u\n",
			  item_index, pebs_count);
		return U64_MAX;
	}

	return start_peb + item_index;
}

/*
 * PEBTBL_FOLIO_INDEX() - define PEB table folio index
 * @fdesc: fragment descriptor
 * @peb_index: index of PEB in the fragment
 */
static inline
pgoff_t PEBTBL_FOLIO_INDEX(struct ssdfs_maptbl_fragment_desc *fdesc,
			   u16 peb_index)
{
	pgoff_t folio_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);

	SSDFS_DBG("fdesc %p, peb_index %u\n",
		  fdesc, peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	folio_index = fdesc->lebtbl_pages;
	folio_index += peb_index / fdesc->pebs_per_page;
	return folio_index;
}

/*
 * GET_PEB_DESCRIPTOR() - retrieve PEB descriptor
 * @kaddr: pointer on memory folio's content
 * @item_index: item index inside of the folio
 *
 * This method tries to return the pointer on
 * PEB descriptor for @item_index.
 *
 * RETURN:
 * [success] - pointer on PEB descriptor
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static inline
struct ssdfs_peb_descriptor *GET_PEB_DESCRIPTOR(void *kaddr, u16 item_index)
{
	struct ssdfs_peb_table_fragment_header *hdr;
	u16 pebs_count;
	u32 peb_desc_off;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr);

	SSDFS_DBG("kaddr %p, item_index %u\n",
		  kaddr, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;

	if (le16_to_cpu(hdr->magic) != SSDFS_PEB_TABLE_MAGIC) {
		SSDFS_ERR("corrupted folio\n");
		return ERR_PTR(-ERANGE);
	}

	pebs_count = le16_to_cpu(hdr->pebs_count);

	if (item_index >= pebs_count) {
		SSDFS_ERR("item_index %u >= pebs_count %u\n",
			  item_index, pebs_count);
		return ERR_PTR(-ERANGE);
	}

	peb_desc_off = SSDFS_PEBTBL_FRAGMENT_HDR_SIZE;
	peb_desc_off += item_index * sizeof(struct ssdfs_peb_descriptor);

	if (peb_desc_off >= PAGE_SIZE) {
		SSDFS_ERR("invalid offset %u\n", peb_desc_off);
		return ERR_PTR(-ERANGE);
	}

	return (struct ssdfs_peb_descriptor *)((u8 *)kaddr + peb_desc_off);
}

/*
 * SEG2PEB_TYPE() - convert segment into PEB type
 */
static inline
int SEG2PEB_TYPE(int seg_type)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_type %d\n", seg_type);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (seg_type) {
	case SSDFS_USER_DATA_SEG_TYPE:
		return SSDFS_MAPTBL_DATA_PEB_TYPE;

	case SSDFS_LEAF_NODE_SEG_TYPE:
		return SSDFS_MAPTBL_LNODE_PEB_TYPE;

	case SSDFS_HYBRID_NODE_SEG_TYPE:
		return SSDFS_MAPTBL_HNODE_PEB_TYPE;

	case SSDFS_INDEX_NODE_SEG_TYPE:
		return SSDFS_MAPTBL_IDXNODE_PEB_TYPE;

	case SSDFS_INITIAL_SNAPSHOT_SEG_TYPE:
		return SSDFS_MAPTBL_INIT_SNAP_PEB_TYPE;

	case SSDFS_SB_SEG_TYPE:
		return SSDFS_MAPTBL_SBSEG_PEB_TYPE;

	case SSDFS_SEGBMAP_SEG_TYPE:
		return SSDFS_MAPTBL_SEGBMAP_PEB_TYPE;

	case SSDFS_MAPTBL_SEG_TYPE:
		return SSDFS_MAPTBL_MAPTBL_PEB_TYPE;
	}

	return SSDFS_MAPTBL_PEB_TYPE_MAX;
}

/*
 * PEB2SEG_TYPE() - convert PEB into segment type
 */
static inline
int PEB2SEG_TYPE(int peb_type)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_type %d\n", peb_type);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (peb_type) {
	case SSDFS_MAPTBL_DATA_PEB_TYPE:
		return SSDFS_USER_DATA_SEG_TYPE;

	case SSDFS_MAPTBL_LNODE_PEB_TYPE:
		return SSDFS_LEAF_NODE_SEG_TYPE;

	case SSDFS_MAPTBL_HNODE_PEB_TYPE:
		return SSDFS_HYBRID_NODE_SEG_TYPE;

	case SSDFS_MAPTBL_IDXNODE_PEB_TYPE:
		return SSDFS_INDEX_NODE_SEG_TYPE;

	case SSDFS_MAPTBL_INIT_SNAP_PEB_TYPE:
		return SSDFS_INITIAL_SNAPSHOT_SEG_TYPE;

	case SSDFS_MAPTBL_SBSEG_PEB_TYPE:
		return SSDFS_SB_SEG_TYPE;

	case SSDFS_MAPTBL_SEGBMAP_PEB_TYPE:
		return SSDFS_SEGBMAP_SEG_TYPE;

	case SSDFS_MAPTBL_MAPTBL_PEB_TYPE:
		return SSDFS_MAPTBL_SEG_TYPE;
	}

	return SSDFS_UNKNOWN_SEG_TYPE;
}

static inline
bool is_ssdfs_maptbl_under_flush(struct ssdfs_fs_info *fsi)
{
	return atomic_read(&fsi->maptbl->flags) & SSDFS_MAPTBL_UNDER_FLUSH;
}

/*
 * is_peb_protected() - check that PEB is protected
 * @found_item: PEB index in the fragment
 */
static inline
bool is_peb_protected(unsigned long found_item)
{
	unsigned long remainder;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("found_item %lu\n", found_item);
#endif /* CONFIG_SSDFS_DEBUG */

	remainder = found_item % SSDFS_MAPTBL_PROTECTION_STEP;
	return remainder == 0;
}

static inline
bool is_ssdfs_maptbl_going_to_be_destroyed(struct ssdfs_peb_mapping_table *tbl)
{
	return atomic_read(&tbl->state) == SSDFS_MAPTBL_GOING_TO_BE_DESTROY;
}

static inline
void set_maptbl_going_to_be_destroyed(struct ssdfs_fs_info *fsi)
{
	atomic_set(&fsi->maptbl->state, SSDFS_MAPTBL_GOING_TO_BE_DESTROY);
}

static inline
void ssdfs_account_updated_user_data_pages(struct ssdfs_fs_info *fsi,
					   u32 count)
{
#ifdef CONFIG_SSDFS_DEBUG
	u64 updated = 0;

	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p, count %u\n",
		  fsi, count);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&fsi->volume_state_lock);
	fsi->updated_user_data_pages += count;
#ifdef CONFIG_SSDFS_DEBUG
	updated = fsi->updated_user_data_pages;
#endif /* CONFIG_SSDFS_DEBUG */
	spin_unlock(&fsi->volume_state_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("updated %llu\n", updated);
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * PEB mapping table's API
 */
int ssdfs_maptbl_create(struct ssdfs_fs_info *fsi);
void ssdfs_maptbl_destroy(struct ssdfs_fs_info *fsi);
int ssdfs_maptbl_fragment_init(struct ssdfs_peb_container *pebc,
				struct ssdfs_maptbl_area *area);
int ssdfs_maptbl_flush(struct ssdfs_peb_mapping_table *tbl);
int ssdfs_maptbl_resize(struct ssdfs_peb_mapping_table *tbl,
			u64 new_pebs_count);

int ssdfs_maptbl_convert_leb2peb(struct ssdfs_fs_info *fsi,
				 u64 leb_id, u8 peb_type,
				 struct ssdfs_maptbl_peb_relation *pebr,
				 struct completion **end);
int ssdfs_maptbl_map_leb2peb(struct ssdfs_fs_info *fsi,
			     u64 leb_id, u8 peb_type,
			     struct ssdfs_maptbl_peb_relation *pebr,
			     struct completion **end);
int ssdfs_maptbl_recommend_search_range(struct ssdfs_fs_info *fsi,
					u64 *start_leb,
					u64 *end_leb,
					struct completion **end);
int ssdfs_maptbl_change_peb_state(struct ssdfs_fs_info *fsi,
				  u64 leb_id, u8 peb_type,
				  int peb_state,
				  struct completion **end);
int ssdfs_maptbl_prepare_pre_erase_state(struct ssdfs_fs_info *fsi,
					 u64 leb_id, u8 peb_type,
					 struct completion **end);
int ssdfs_maptbl_set_pre_erased_snapshot_peb(struct ssdfs_fs_info *fsi,
					     u64 peb_id,
					     struct completion **end);
int ssdfs_maptbl_add_migration_peb(struct ssdfs_fs_info *fsi,
				   u64 leb_id, u8 peb_type,
				   struct ssdfs_maptbl_peb_relation *pebr,
				   struct completion **end);
int ssdfs_maptbl_exclude_migration_peb(struct ssdfs_fs_info *fsi,
					u64 leb_id, u8 peb_type,
					u64 peb_create_time,
					u64 last_log_time,
					struct completion **end);
int ssdfs_maptbl_set_indirect_relation(struct ssdfs_peb_mapping_table *tbl,
					u64 leb_id, u8 peb_type,
					u64 dst_leb_id, u16 dst_peb_index,
					struct completion **end);
int ssdfs_maptbl_break_indirect_relation(struct ssdfs_peb_mapping_table *tbl,
					 u64 leb_id, u8 peb_type,
					 u64 dst_leb_id, int dst_peb_refs,
					 struct completion **end);
int ssdfs_maptbl_set_zns_indirect_relation(struct ssdfs_peb_mapping_table *tbl,
					   u64 leb_id, u8 peb_type,
					   struct completion **end);
int ssdfs_maptbl_break_zns_indirect_relation(struct ssdfs_peb_mapping_table *tbl,
					     u64 leb_id, u8 peb_type,
					     struct completion **end);

int ssdfs_reserve_free_pages(struct ssdfs_fs_info *fsi,
			     u32 count, int type);

/*
 * It makes sense to have special thread for the whole mapping table.
 * The goal of the thread will be clearing of dirty PEBs,
 * tracking P/E cycles, excluding bad PEBs and recovering PEBs
 * in the background. Knowledge about PEBs will be hidden by
 * mapping table. All other subsystems will operate by LEBs.
 */

/*
 * PEB mapping table's internal API
 */
int ssdfs_maptbl_start_thread(struct ssdfs_peb_mapping_table *tbl);
int ssdfs_maptbl_stop_thread(struct ssdfs_peb_mapping_table *tbl);

int ssdfs_maptbl_define_fragment_info(struct ssdfs_fs_info *fsi,
				      u64 leb_id,
				      u16 *pebs_per_fragment,
				      u16 *pebs_per_stripe,
				      u16 *stripes_per_fragment);
struct ssdfs_maptbl_fragment_desc *
ssdfs_maptbl_get_fragment_descriptor(struct ssdfs_peb_mapping_table *tbl,
				     u64 leb_id);
void ssdfs_maptbl_set_fragment_dirty(struct ssdfs_peb_mapping_table *tbl,
				     struct ssdfs_maptbl_fragment_desc *fdesc,
				     u64 leb_id);
int ssdfs_maptbl_solve_inconsistency(struct ssdfs_peb_mapping_table *tbl,
				     struct ssdfs_maptbl_fragment_desc *fdesc,
				     u64 leb_id,
				     struct ssdfs_maptbl_peb_relation *pebr);
int ssdfs_maptbl_solve_pre_deleted_state(struct ssdfs_peb_mapping_table *tbl,
				     struct ssdfs_maptbl_fragment_desc *fdesc,
				     u64 leb_id,
				     struct ssdfs_maptbl_peb_relation *pebr);
void ssdfs_maptbl_move_fragment_folios(struct ssdfs_segment_request *req,
					struct ssdfs_maptbl_area *area,
					u16 folios_count);
int ssdfs_maptbl_erase_peb(struct ssdfs_fs_info *fsi,
			   struct ssdfs_erase_result *result);
int ssdfs_maptbl_correct_dirty_peb(struct ssdfs_peb_mapping_table *tbl,
				   struct ssdfs_maptbl_fragment_desc *fdesc,
				   struct ssdfs_erase_result *result);
int ssdfs_maptbl_erase_reserved_peb_now(struct ssdfs_fs_info *fsi,
					u64 leb_id, u8 peb_type,
					struct completion **end);

#ifdef CONFIG_SSDFS_TESTING
int ssdfs_maptbl_erase_dirty_pebs_now(struct ssdfs_peb_mapping_table *tbl);
#else
static inline
int ssdfs_maptbl_erase_dirty_pebs_now(struct ssdfs_peb_mapping_table *tbl)
{
	SSDFS_ERR("function is not supported\n");
	return -EOPNOTSUPP;
}
#endif /* CONFIG_SSDFS_TESTING */

void ssdfs_debug_maptbl_object(struct ssdfs_peb_mapping_table *tbl);

#endif /* _SSDFS_PEB_MAPPING_TABLE_H */
