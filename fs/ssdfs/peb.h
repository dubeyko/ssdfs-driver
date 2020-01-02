//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb.h - Physical Erase Block (PEB) object declarations.
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

#ifndef _SSDFS_PEB_H
#define _SSDFS_PEB_H

#include "request_queue.h"

/*
 * struct ssdfs_peb_diffs_area_metadata - diffs area's metadata
 * @hdr: diffs area's table header
 */
struct ssdfs_peb_diffs_area_metadata {
	struct ssdfs_block_state_descriptor hdr;
};

/*
 * struct ssdfs_peb_journal_area_metadata - journal area's metadata
 * @hdr: journal area's table header
 */
struct ssdfs_peb_journal_area_metadata {
	struct ssdfs_block_state_descriptor hdr;
};

/*
 * struct ssdfs_peb_area_metadata - descriptor of area's items chain
 * @area.blk_desc.table: block descriptors area table
 * @area.blk_desc.capacity: max number of block descriptors in reserved space
 * @area.blk_desc.items_count: number of items in the whole table
 * @area.diffs.table: diffs area's table
 * @area.journal.table: journal area's table
 * @area.main.desc: main area's descriptor
 * @reserved_offset: reserved write offset of table
 * @sequence_id: fragment's sequence number
 */
struct ssdfs_peb_area_metadata {
	union {
		struct {
			struct ssdfs_area_block_table table;
			int capacity;
			int items_count;
		} blk_desc;

		struct {
			struct ssdfs_peb_diffs_area_metadata table;
		} diffs;

		struct {
			struct ssdfs_peb_journal_area_metadata table;
		} journal;

		struct {
			struct ssdfs_block_state_descriptor desc;
		} main;
	} area;

	u32 reserved_offset;
	u8 sequence_id;
};

/*
 * struct ssdfs_peb_area - log's area descriptor
 * @has_metadata: does area contain metadata?
 * @metadata: descriptor of area's items chain
 * @write_offset: current write offset
 * @array: area's memory pages
 */
struct ssdfs_peb_area {
	bool has_metadata;
	struct ssdfs_peb_area_metadata metadata;

	u32 write_offset;
	struct ssdfs_page_array array;
};

/* Log possible states */
enum {
	SSDFS_LOG_UNKNOWN,
	SSDFS_LOG_PREPARED,
	SSDFS_LOG_INITIALIZED,
	SSDFS_LOG_CREATED,
	SSDFS_LOG_COMMITTED,
	SSDFS_LOG_STATE_MAX,
};

/*
 * struct ssdfs_peb_log - current log
 * @lock: exclusive lock of current log
 * @state: current log's state
 * @sequence_id: index of partial log in the sequence
 * @start_page: current log's start page index
 * @pages_capacity: rest free pages in log
 * @write_offset: current offset in bytes for adding data in log
 * @seg_flags: segment header's flags for the log
 * @area: log's areas (main, diff updates, journal)
 */
struct ssdfs_peb_log {
	struct mutex lock;
	atomic_t state;
	atomic_t sequence_id;
	u16 start_page;
	u16 reserved_pages; /* metadata pages in the log */
	u16 free_data_pages; /* free data pages capacity */
	u32 seg_flags;
	struct ssdfs_peb_area area[SSDFS_LOG_AREA_MAX];
};

/*
 * struct ssdfs_peb_info - Physical Erase Block (PEB) description
 * @peb_id: PEB number
 * @peb_index: PEB index
 * @log_pages: count of pages in full partial log
 * @peb_migration_id: identification number of PEB in migration sequence
 * @state: PEB object state
 * @init_end: wait of full init ending
 * @reserved_bytes.blk_bmap: reserved bytes for block bitmap
 * @reserved_bytes.blk2off_tbl: reserved bytes for blk2off table
 * @reserved_bytes.blk_desc_tbl: reserved bytes for block descriptor table
 * @current_log: PEB's current log
 * @cache: PEB's memory pages
 * @pebc: pointer on parent container
 */
struct ssdfs_peb_info {
	/* Static data */
	u64 peb_id;
	u16 peb_index;
	u16 log_pages;

	/*
	 * The peb_migration_id is stored in two places:
	 * (1) struct ssdfs_segment_header;
	 * (2) struct ssdfs_blk_state_offset.
	 *
	 * The goal of peb_migration_id is to distinguish PEB
	 * objects during PEB object's migration. Every
	 * destination PEB is received the migration_id that
	 * is incremented migration_id value of source PEB
	 * object. If peb_migration_id is achieved value of
	 * SSDFS_PEB_MIGRATION_ID_MAX then peb_migration_id
	 * is started from SSDFS_PEB_MIGRATION_ID_START again.
	 *
	 * A PEB object is received the peb_migration_id value
	 * during the PEB object creation operation. The "clean"
	 * PEB object receives SSDFS_PEB_MIGRATION_ID_START
	 * value. The destinaton PEB object receives incremented
	 * peb_migration_id value of source PEB object during
	 * creation operation. Otherwise, the real peb_migration_id
	 * value is set during PEB's initialization
	 * by means of extracting the actual value from segment
	 * header.
	 */
	atomic_t peb_migration_id;

	atomic_t state;
	struct completion init_end;

	/* Reserved bytes */
	struct {
		atomic_t blk_bmap;
		atomic_t blk2off_tbl;
		atomic_t blk_desc_tbl;
	} reserved_bytes;

	/* Current log */
	struct ssdfs_peb_log current_log;

	/* PEB's memory pages */
	struct ssdfs_page_array cache;

	/* Parent container */
	struct ssdfs_peb_container *pebc;
};

/* PEB object states */
enum {
	SSDFS_PEB_OBJECT_UNKNOWN_STATE,
	SSDFS_PEB_OBJECT_CREATED,
	SSDFS_PEB_OBJECT_INITIALIZED,
	SSDFS_PEB_OBJECT_STATE_MAX
};

#define SSDFS_AREA_TYPE2INDEX(type)({ \
	int index; \
	switch (type) { \
	case SSDFS_LOG_BLK_DESC_AREA: \
		index = SSDFS_BLK_DESC_AREA_INDEX; \
		break; \
	case SSDFS_LOG_MAIN_AREA: \
		index = SSDFS_COLD_PAYLOAD_AREA_INDEX; \
		break; \
	case SSDFS_LOG_DIFFS_AREA: \
		index = SSDFS_WARM_PAYLOAD_AREA_INDEX; \
		break; \
	case SSDFS_LOG_JOURNAL_AREA: \
		index = SSDFS_HOT_PAYLOAD_AREA_INDEX; \
		break; \
	default: \
		BUG(); \
	}; \
	index; \
})

#define SSDFS_AREA_TYPE2FLAG(type)({ \
	int flag; \
	switch (type) { \
	case SSDFS_LOG_BLK_DESC_AREA: \
		flag = SSDFS_LOG_HAS_BLK_DESC_CHAIN; \
		break; \
	case SSDFS_LOG_MAIN_AREA: \
		flag = SSDFS_LOG_HAS_COLD_PAYLOAD; \
		break; \
	case SSDFS_LOG_DIFFS_AREA: \
		flag = SSDFS_LOG_HAS_WARM_PAYLOAD; \
		break; \
	case SSDFS_LOG_JOURNAL_AREA: \
		flag = SSDFS_LOG_HAS_HOT_PAYLOAD; \
		break; \
	default: \
		BUG(); \
	}; \
	flag; \
})

/*
 * Inline functions
 */

/*
 * ssdfs_peb_correct_area_write_offset() - correct write offset
 * @write_offset: current write offset
 * @data_size: requested size of data
 *
 * This function checks that we can place whole data into current
 * memory page.
 *
 * RETURN: corrected value of write offset.
 */
static inline
u32 ssdfs_peb_correct_area_write_offset(u32 write_offset, u32 data_size)
{
	u32 page_index1, page_index2;

	page_index1 = write_offset / PAGE_SIZE;
	page_index2 = (write_offset + data_size) / PAGE_SIZE;

	if (page_index1 != page_index2)
		return page_index2 * PAGE_SIZE;

	return write_offset;
}

/*
 * ssdfs_peb_current_log_lock() - lock current log object
 * @pebi: pointer on PEB object
 */
static inline
void ssdfs_peb_current_log_lock(struct ssdfs_peb_info *pebi)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
#endif /* CONFIG_SSDFS_DEBUG */

	err = mutex_lock_killable(&pebi->current_log.lock);
	WARN_ON(err);
}

/*
 * ssdfs_peb_current_log_unlock() - unlock current log object
 * @pebi: pointer on PEB object
 */
static inline
void ssdfs_peb_current_log_unlock(struct ssdfs_peb_info *pebi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	WARN_ON(!mutex_is_locked(&pebi->current_log.lock));
#endif /* CONFIG_SSDFS_DEBUG */

	mutex_unlock(&pebi->current_log.lock);
}

static inline
bool is_ssdfs_peb_current_log_locked(struct ssdfs_peb_info *pebi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
#endif /* CONFIG_SSDFS_DEBUG */

	return mutex_is_locked(&pebi->current_log.lock);
}

/*
 * ssdfs_peb_current_log_state() - check current log's state
 * @pebi: pointer on PEB object
 * @state: checked state
 */
static inline
bool ssdfs_peb_current_log_state(struct ssdfs_peb_info *pebi,
				 int state)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(state < SSDFS_LOG_UNKNOWN || state >= SSDFS_LOG_STATE_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	return atomic_read(&pebi->current_log.state) >= state;
}

/*
 * ssdfs_peb_set_current_log_state() - set current log's state
 * @pebi: pointer on PEB object
 * @state: new log's state
 */
static inline
void ssdfs_peb_set_current_log_state(struct ssdfs_peb_info *pebi,
				     int state)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(state < SSDFS_LOG_UNKNOWN || state >= SSDFS_LOG_STATE_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	return atomic_set(&pebi->current_log.state, state);
}

/*
 * ssdfs_peb_current_log_init() - initialize current log object
 * @pebi: pointer on PEB object
 * @free_pages: free pages in the current log
 * @start_page: start page of the current log
 * @sequence_id: index of partial log in the sequence
 */
static inline
void ssdfs_peb_current_log_init(struct ssdfs_peb_info *pebi,
				u16 free_pages,
				u16 start_page,
				u8 sequence_id)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_peb_current_log_lock(pebi);
	pebi->current_log.start_page = start_page;
	pebi->current_log.free_data_pages = free_pages;
	atomic_set(&pebi->current_log.sequence_id, sequence_id);
	atomic_set(&pebi->current_log.state, SSDFS_LOG_INITIALIZED);
	ssdfs_peb_current_log_unlock(pebi);
}

/*
 * ssdfs_get_leb_id_for_peb_index() - convert PEB's index into LEB's ID
 * @fsi: pointer on shared file system object
 * @seg: segment number
 * @peb_index: index of PEB object in array
 *
 * This function converts PEB's index into LEB's identification
 * number.
 *
 * RETURN:
 * [success] - LEB's identification number.
 * [failure] - U64_MAX.
 */
static inline
u64 ssdfs_get_leb_id_for_peb_index(struct ssdfs_fs_info *fsi,
				   u64 seg, u32 peb_index)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	if (peb_index >= fsi->pebs_per_seg) {
		SSDFS_ERR("requested peb_index %u >= pebs_per_seg %u\n",
			  peb_index, fsi->pebs_per_seg);
		return U64_MAX;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, seg %llu, peb_index %u\n",
		  fsi, seg, peb_index);

	return (seg * fsi->pebs_per_seg) + peb_index;
}

/*
 * ssdfs_get_peb_migration_id() - get PEB's migration ID
 * @pebi: pointer on PEB object
 */
static inline
int ssdfs_get_peb_migration_id(struct ssdfs_peb_info *pebi)
{
	int id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
#endif /* CONFIG_SSDFS_DEBUG */

	id = atomic_read(&pebi->peb_migration_id);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(id >= U8_MAX);
	BUG_ON(id < 0);
#endif /* CONFIG_SSDFS_DEBUG */

	return id;
}

/*
 * is_peb_migration_id_valid() - check PEB's migration_id
 * @peb_migration_id: PEB's migration ID value
 */
static inline
bool is_peb_migration_id_valid(int peb_migration_id)
{
	if (peb_migration_id < 0 ||
	    peb_migration_id > SSDFS_PEB_MIGRATION_ID_MAX) {
		/* preliminary check */
		return false;
	}

	switch (peb_migration_id) {
	case SSDFS_PEB_MIGRATION_ID_MAX:
	case SSDFS_PEB_UNKNOWN_MIGRATION_ID:
		return false;
	}

	return true;
}

/*
 * ssdfs_get_peb_migration_id_checked() - get checked PEB's migration ID
 * @pebi: pointer on PEB object
 */
static inline
int ssdfs_get_peb_migration_id_checked(struct ssdfs_peb_info *pebi)
{
	int res, err;

	switch (atomic_read(&pebi->state)) {
	case SSDFS_PEB_OBJECT_CREATED:
		res = wait_for_completion_timeout(&pebi->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("PEB init failed: "
				  "err %d\n", err);
			return err;
		}

		if (atomic_read(&pebi->state) != SSDFS_PEB_OBJECT_INITIALIZED) {
			SSDFS_ERR("PEB %llu is not initialized\n",
				  pebi->peb_id);
			return -ERANGE;
		}
		break;

	case SSDFS_PEB_OBJECT_INITIALIZED:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid PEB state %#x\n",
			  atomic_read(&pebi->state));
		return -ERANGE;
	}

	res = ssdfs_get_peb_migration_id(pebi);

	if (!is_peb_migration_id_valid(res)) {
		res = -ERANGE;
		SSDFS_WARN("invalid peb_migration_id: "
			   "peb %llu, peb_index %u, id %d\n",
			   pebi->peb_id, pebi->peb_index, res);
	}

	return res;
}

/*
 * ssdfs_set_peb_migration_id() - set PEB's migration ID
 * @pebi: pointer on PEB object
 * @id: new PEB's migration_id
 */
static inline
void ssdfs_set_peb_migration_id(struct ssdfs_peb_info *pebi,
				int id)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_id %llu, peb_migration_id %d\n",
		  pebi->peb_id, id);

	atomic_set(&pebi->peb_migration_id, id);
}

static inline
int __ssdfs_define_next_peb_migration_id(int prev_id)
{
	int id = prev_id;

	if (id < 0)
		return SSDFS_PEB_MIGRATION_ID_START;

	id += 1;

	if (id >= SSDFS_PEB_MIGRATION_ID_MAX)
		id = SSDFS_PEB_MIGRATION_ID_START;

	return id;
}

/*
 * ssdfs_define_next_peb_migration_id() - define next PEB's migration_id
 * @pebi: pointer on source PEB object
 */
static inline
int ssdfs_define_next_peb_migration_id(struct ssdfs_peb_info *src_peb)
{
	int id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!src_peb);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb %llu, peb_index %u\n",
		  src_peb->peb_id, src_peb->peb_index);

	id = ssdfs_get_peb_migration_id_checked(src_peb);
	if (id < 0) {
		SSDFS_ERR("fail to get peb_migration_id: "
			  "peb %llu, peb_index %u, err %d\n",
			  src_peb->peb_id, src_peb->peb_index,
			  id);
		return SSDFS_PEB_MIGRATION_ID_MAX;
	}

	return __ssdfs_define_next_peb_migration_id(id);
}

/*
 * ssdfs_define_prev_peb_migration_id() - define prev PEB's migration_id
 * @pebi: pointer on source PEB object
 */
static inline
int ssdfs_define_prev_peb_migration_id(struct ssdfs_peb_info *pebi)
{
	int id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb %llu, peb_index %u\n",
		  pebi->peb_id, pebi->peb_index);

	id = ssdfs_get_peb_migration_id_checked(pebi);
	if (id < 0) {
		SSDFS_ERR("fail to get peb_migration_id: "
			  "peb %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index,
			  id);
		return SSDFS_PEB_MIGRATION_ID_MAX;
	}

	id--;

	if (id == SSDFS_PEB_UNKNOWN_MIGRATION_ID)
		id = SSDFS_PEB_MIGRATION_ID_MAX - 1;

	return id;
}

/*
 * PEB object's API
 */
int ssdfs_peb_object_create(struct ssdfs_peb_info *pebi,
			    struct ssdfs_peb_container *pebc,
			    u64 peb_id, int peb_state,
			    u8 peb_migration_id);
int ssdfs_peb_object_destroy(struct ssdfs_peb_info *pebi);

/*
 * PEB internal functions declaration
 */
int ssdfs_unaligned_read_cache(struct ssdfs_peb_info *pebi,
				u32 area_offset, u32 area_size,
				void *buf);
int ssdfs_peb_read_log_hdr_desc_array(struct ssdfs_peb_info *pebi,
				      u16 log_index,
				      struct ssdfs_metadata_descriptor *array,
				      size_t array_size);
u16 ssdfs_peb_estimate_min_partial_log_pages(struct ssdfs_peb_info *pebi);
bool is_ssdfs_peb_exhausted(struct ssdfs_fs_info *fsi,
			    struct ssdfs_peb_info *pebi);

#endif /* _SSDFS_PEB_H */
