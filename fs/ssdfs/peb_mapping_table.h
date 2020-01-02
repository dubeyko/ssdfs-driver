//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_mapping_table.h - PEB mapping table declarations.
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

#ifndef _SSDFS_PEB_MAPPING_TABLE_H
#define _SSDFS_PEB_MAPPING_TABLE_H

/*
 * struct ssdfs_maptbl_fragment_desc - fragment descriptor
 * @lock: fragment lock
 * @state: fragment state
 * @fragment_id: fragment's ID in the whole sequence
 * @fragment_pages: count of memory pages in fragment
 * @start_leb: start LEB of fragment
 * @lebs_count: count of LEB descriptors in the whole fragment
 * @lebs_per_page: count of LEB descriptors in memory page
 * @lebtbl_pages: count of memory pages are used for LEBs description
 * @pebs_per_page: count of PEB descriptors in memory page
 * @stripe_pages: count of memory pages in one stripe
 * @mapped_lebs: mapped LEBs count in the fragment
 * @migrating_lebs: migrating LEBs count in the fragment
 * @pre_erase_pebs: count of PEBs in pre-erase state per fragment
 * @recovering_pebs: count of recovering PEBs per fragment
 * @array: fragment's memory pages
 * @init_end: wait of init ending
 * @flush_req1: main flush requests array
 * @flush_req2: backup flush requests array
 * @flush_seq_size: flush requests' array size
 */
struct ssdfs_maptbl_fragment_desc {
	struct rw_semaphore lock;
	atomic_t state;

	u32 fragment_id;
	u32 fragment_pages;

	u64 start_leb;
	u32 lebs_count;

	u16 lebs_per_page;
	u16 lebtbl_pages;

	u16 pebs_per_page;
	u16 stripe_pages;

	u32 mapped_lebs;
	u32 migrating_lebs;
	u32 pre_erase_pebs;
	u32 recovering_pebs;

	struct ssdfs_page_array array;
	struct completion init_end;

	struct ssdfs_segment_request *flush_req1;
	struct ssdfs_segment_request *flush_req2;
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
 * @pages: array of memory page pointers
 * @pages_capacity: capacity of array
 * @pages_count: count of pages in array
 */
struct ssdfs_maptbl_area {
	u16 portion_id;
	struct page **pages;
	size_t pages_capacity;
	size_t pages_count;
};

/*
 * struct ssdfs_peb_mapping_table - mapping table object
 * @tbl_lock: mapping table lock
 * @fragments_count: count of fragments
 * @fragments_per_seg: count of fragments in segment
 * @fragments_per_peb: count of fragments in PEB
 * @fragment_bytes: count of bytes in one fragment
 * @fragment_pages: count of memory pages in one fragment
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
 * @pre_erase_pebs: count of PEBs in pre-erase state
 * @max_erase_ops: upper bound of erase operations for one iteration
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
	u32 fragment_pages;
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

	atomic_t pre_erase_pebs;
	atomic_t max_erase_ops;
	atomic64_t last_peb_recover_cno;

	struct mutex bmap_lock;
	unsigned long *dirty_bmap;
	struct ssdfs_maptbl_fragment_desc *desc_array;

	wait_queue_head_t wait_queue;
	struct ssdfs_thread_info thread;
	struct ssdfs_fs_info *fsi;
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
 * Inline functions
 */

/*
 * DEFINE_PEB_INDEX_IN_FRAGMENT() - define PEB index in the whole fragment
 * @fdesc: fragment descriptor
 * @page_index: page index in the fragment
 * @item_index: item index in the memory page
 */
static inline
u16 DEFINE_PEB_INDEX_IN_FRAGMENT(struct ssdfs_maptbl_fragment_desc *fdesc,
				 pgoff_t page_index,
				 u16 item_index)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);
	BUG_ON(page_index < fdesc->lebtbl_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fdesc %p, page_index %lu, item_index %u\n",
		  fdesc, page_index, item_index);

	page_index -= fdesc->lebtbl_pages;
	page_index *= fdesc->pebs_per_page;
	page_index += item_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(page_index >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u16)page_index;
}

/*
 * GET_PEB_ID() - define PEB ID for the index
 * @kaddr: pointer on memory page's content
 * @item_index: item index inside of the page
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, item_index %u\n",
		  kaddr, item_index);

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;

	if (le16_to_cpu(hdr->magic) != SSDFS_PEB_TABLE_MAGIC) {
		SSDFS_ERR("corrupted page\n");
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
 * PEBTBL_PAGE_INDEX() - define PEB table page index
 * @fdesc: fragment descriptor
 * @peb_index: index of PEB in the fragment
 */
static inline
pgoff_t PEBTBL_PAGE_INDEX(struct ssdfs_maptbl_fragment_desc *fdesc,
			  u16 peb_index)
{
	pgoff_t page_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fdesc);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fdesc %p, peb_index %u\n",
		  fdesc, peb_index);

	page_index = fdesc->lebtbl_pages;
	page_index += peb_index / fdesc->pebs_per_page;
	return page_index;
}

/*
 * GET_PEB_DESCRIPTOR() - retrieve PEB descriptor
 * @kaddr: pointer on memory page's content
 * @item_index: item index inside of the page
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p, item_index %u\n",
		  kaddr, item_index);

	hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;

	if (le16_to_cpu(hdr->magic) != SSDFS_PEB_TABLE_MAGIC) {
		SSDFS_ERR("corrupted page\n");
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
	SSDFS_DBG("seg_type %d\n", seg_type);

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

static inline
bool is_ssdfs_maptbl_under_flush(struct ssdfs_fs_info *fsi)
{
	return atomic_read(&fsi->maptbl->flags) & SSDFS_MAPTBL_UNDER_FLUSH;
}

static inline
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

			kaddr = kmap_atomic(page);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
						kaddr, PAGE_SIZE);
			kunmap_atomic(kaddr);

			unlock_page(page);
			put_page(page);
		}
	}
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
int ssdfs_maptbl_change_peb_state(struct ssdfs_fs_info *fsi,
				  u64 leb_id, u8 peb_type,
				  int peb_state,
				  struct completion **end);
int ssdfs_maptbl_add_migration_peb(struct ssdfs_fs_info *fsi,
				   u64 leb_id, u8 peb_type,
				   struct ssdfs_maptbl_peb_relation *pebr,
				   struct completion **end);
int ssdfs_maptbl_exclude_migration_peb(struct ssdfs_fs_info *fsi,
					u64 leb_id, u8 peb_type,
					struct completion **end);
int ssdfs_maptbl_set_indirect_relation(struct ssdfs_peb_mapping_table *tbl,
					u64 leb_id, u8 peb_type,
					u64 dst_leb_id, u16 dst_peb_index,
					struct completion **end);
int ssdfs_maptbl_break_indirect_relation(struct ssdfs_peb_mapping_table *tbl,
					 u64 leb_id, u8 peb_type,
					 u64 dst_leb_id, int dst_peb_refs,
					 struct completion **end);

/*
 * TODO: It makes sense to have special thread for the whole mapping table.
 *       The goal of the thread will be clearing of dirty PEBs,
 *       tracking P/E cycles, excluding bad PEBs and recovering PEBs
 *       in the background. Knowledge about PEBs will be hidden by
 *       mapping table. All other subsystems will operate by LEBs.
 */

/*
 * PEB mapping table's internal API
 */
int ssdfs_maptbl_start_thread(struct ssdfs_peb_mapping_table *tbl);
int ssdfs_maptbl_stop_thread(struct ssdfs_peb_mapping_table *tbl);

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
				     u64 leb_id);

#endif /* _SSDFS_PEB_MAPPING_TABLE_H */
