/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb.h - Physical Erase Block (PEB) object declarations.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2026 Viacheslav Dubeyko <slava@dubeyko.com>
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

#ifndef _SSDFS_PEB_H
#define _SSDFS_PEB_H

#include "request_queue.h"
#include "fingerprint_array.h"
#include "peb_init.h"

/*
 * struct ssdfs_protection_window - protection window length
 * @cno_lock: lock of checkpoints set
 * @create_cno: creation checkpoint
 * @last_request_cno: last request checkpoint
 * @reqs_count: current number of active requests
 * @protected_range: last measured protected range length
 * @future_request_cno: expectation to receive a next request in the future
 */
struct ssdfs_protection_window {
	spinlock_t cno_lock;
	u64 create_cno;
	u64 last_request_cno;
	u32 reqs_count;
	u64 protected_range;
	u64 future_request_cno;
};

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
 * @area.blk_desc.flush_buf: write block descriptors buffer (compression case)
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
			struct ssdfs_peb_temp_buffer flush_buf;
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
 * @compressed_offset: current write offset for compressed data
 * @frag_offset: offset of current fragment
 * @array: area's memory folios
 */
struct ssdfs_peb_area {
	bool has_metadata;
	struct ssdfs_peb_area_metadata metadata;

	u32 write_offset;
	u32 compressed_offset;
	u32 frag_offset;
	struct ssdfs_folio_array array;
};

/*
 * struct ssdfs_blk2off_table_area - blk2off table descriptor
 * @hdr: offset descriptors area table's header
 * @reserved_offset: reserved header offset
 * @compressed_offset: current write offset for compressed data
 * @sequence_id: fragment's sequence number
 */
struct ssdfs_blk2off_table_area {
	struct ssdfs_blk2off_table_header hdr;

	u32 reserved_offset;
	u32 compressed_offset;
	u8 sequence_id;
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
 * struct ssdfs_peb_prev_log - previous log's details
 * @bmap_bytes: bytes count in block bitmap of previous log
 * @blk2off_bytes: bytes count in blk2off table of previous log
 * @blk_desc_bytes: bytes count in blk desc table of previous log
 */
struct ssdfs_peb_prev_log {
	u32 bmap_bytes;
	u32 blk2off_bytes;
	u32 blk_desc_bytes;
};

/*
 * struct ssdfs_peb_log - current log
 * @lock: exclusive lock of current log
 * @state: current log's state
 * @sequence_id: index of partial log in the sequence
 * @start_block: current log's start block index
 * @reserved_blocks: metadata blocks in the log
 * @free_data_blocks: free data blocks capacity
 * @seg_flags: segment header's flags for the log
 * @prev_log: previous log's details
 * @last_log_time: creation timestamp of last log
 * @last_log_cno: last log checkpoint
 * @bmap_snapshot: snapshot of block bitmap
 * @blk2off_tbl: blk2off table descriptor
 * @area: log's areas (main, diff updates, journal)
 */
struct ssdfs_peb_log {
	struct mutex lock;
	atomic_t state;
	atomic_t sequence_id;
	u32 start_block;
	u32 reserved_blocks; /* metadata blocks in the log */
	u32 free_data_blocks; /* free data blocks capacity */
	u32 seg_flags;
	struct ssdfs_peb_prev_log prev_log;
	u64 last_log_time;
	u64 last_log_cno;
	struct ssdfs_folio_vector bmap_snapshot;
	struct ssdfs_blk2off_table_area blk2off_tbl;
	struct ssdfs_peb_area area[SSDFS_LOG_AREA_MAX];
};

/*
 * struct ssdfs_peb_log_offset - current log offset
 * @blocksize_shift: log2(block size)
 * @log_blocks: count of blocks in full partial log
 * @start_block: current log's start block index
 * @cur_block: current block in the log
 * @offset_into_block: current offset into block
 */
struct ssdfs_peb_log_offset {
	u32 blocksize_shift;
	u32 log_blocks;
	pgoff_t start_block;
	pgoff_t cur_block;
	u32 offset_into_block;
};

/*
 * struct ssdfs_peb_deduplication - PEB deduplication environment
 * @shash_tfm: message digest handle
 * @fingerprints: fingeprints array
 */
struct ssdfs_peb_deduplication {
	struct crypto_shash *shash_tfm;
	struct ssdfs_fingerprint_array fingerprints;
};

/*
 * struct ssdfs_peb_info - Physical Erase Block (PEB) description
 * @peb_id: PEB number
 * @peb_index: PEB index
 * @log_blocks: count of blocks in full partial log
 * @peb_create_time: PEB creation timestamp
 * @peb_migration_id: identification number of PEB in migration sequence
 * @state: PEB object state
 * @init_end: wait of full init ending
 * @peb_state: current PEB state
 * @reserved_bytes.blk_bmap: reserved bytes for block bitmap
 * @reserved_bytes.blk2off_tbl: reserved bytes for blk2off table
 * @reserved_bytes.blk_desc_tbl: reserved bytes for block descriptor table
 * @current_log: PEB's current log
 * @dedup: PEB's deduplication environment
 * @read_buffer: temporary read buffers (compression case)
 * @env: init environment
 * @cache: PEB's memory folios
 * @pebc: pointer on parent container
 */
struct ssdfs_peb_info {
	/* Static data */
	u64 peb_id;
	u16 peb_index;
	u32 log_blocks;

	u64 peb_create_time;

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

	atomic_t peb_state;

	/* Reserved bytes */
	struct {
		atomic_t blk_bmap;
		atomic_t blk2off_tbl;
		atomic_t blk_desc_tbl;
	} reserved_bytes;

	/* Current log */
	struct ssdfs_peb_log current_log;

	/* Fingerprints array */
#ifdef CONFIG_SSDFS_PEB_DEDUPLICATION
	struct ssdfs_peb_deduplication dedup;
#endif /* CONFIG_SSDFS_PEB_DEDUPLICATION */

	/* Read buffer */
	struct ssdfs_peb_temp_read_buffers read_buffer;

	/* Init environment */
	struct ssdfs_read_init_env env;

	/* PEB's memory folios */
	struct ssdfs_folio_array cache;

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
 * IS_SSDFS_BLK_STATE_OFFSET_INVALID() - check that block state offset invalid
 * @desc: block state offset
 */
static inline
bool IS_SSDFS_BLK_STATE_OFFSET_INVALID(struct ssdfs_blk_state_offset *desc)
{
	if (!desc)
		return true;

	if (le16_to_cpu(desc->log_start_page) == U16_MAX &&
	    desc->log_area == U8_MAX &&
	    desc->peb_migration_id == U8_MAX &&
	    le32_to_cpu(desc->byte_offset) == U32_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("log_start_block %u, log_area %u, "
			  "peb_migration_id %u, byte_offset %u\n",
			  le16_to_cpu(desc->log_start_page),
			  desc->log_area,
			  desc->peb_migration_id,
			  le32_to_cpu(desc->byte_offset));
#endif /* CONFIG_SSDFS_DEBUG */
		return true;
	}

	if (desc->peb_migration_id == SSDFS_PEB_UNKNOWN_MIGRATION_ID) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("log_start_block %u, log_area %u, "
			  "peb_migration_id %u, byte_offset %u\n",
			  le16_to_cpu(desc->log_start_page),
			  desc->log_area,
			  desc->peb_migration_id,
			  le32_to_cpu(desc->byte_offset));
#endif /* CONFIG_SSDFS_DEBUG */
		return true;
	}

	return false;
}

/*
 * SSDFS_BLK_DESC_INIT() - init block descriptor
 * @blk_desc: block descriptor
 */
static inline
void SSDFS_BLK_DESC_INIT(struct ssdfs_block_descriptor *blk_desc)
{
	if (!blk_desc) {
		SSDFS_WARN("block descriptor pointer is NULL\n");
		return;
	}

	memset(blk_desc, 0xFF, sizeof(struct ssdfs_block_descriptor));
}

/*
 * IS_SSDFS_BLK_DESC_EXHAUSTED() - check that block descriptor is exhausted
 * @blk_desc: block descriptor
 */
static inline
bool IS_SSDFS_BLK_DESC_EXHAUSTED(struct ssdfs_block_descriptor *blk_desc)
{
	struct ssdfs_blk_state_offset *offset = NULL;

	if (!blk_desc)
		return true;

	offset = &blk_desc->state[SSDFS_BLK_STATE_OFF_MAX - 1];

	if (!IS_SSDFS_BLK_STATE_OFFSET_INVALID(offset))
		return true;

	return false;
}

static inline
bool IS_SSDFS_BLK_DESC_READY_FOR_DIFF(struct ssdfs_block_descriptor *blk_desc)
{
	return !IS_SSDFS_BLK_STATE_OFFSET_INVALID(&blk_desc->state[0]);
}

static inline
u8 SSDFS_GET_BLK_DESC_MIGRATION_ID(struct ssdfs_block_descriptor *blk_desc)
{
	if (IS_SSDFS_BLK_STATE_OFFSET_INVALID(&blk_desc->state[0]))
		return U8_MAX;

	return blk_desc->state[0].peb_migration_id;
}

static inline
void DEBUG_BLOCK_DESCRIPTOR(u64 seg_id, u64 peb_id,
			    struct ssdfs_block_descriptor *blk_desc)
{
#ifdef CONFIG_SSDFS_DEBUG
	int i;

	SSDFS_DBG("seg_id %llu, peb_id %llu, ino %llu, "
		  "logical_offset %u, peb_index %u, peb_page %u\n",
		  seg_id, peb_id,
		  le64_to_cpu(blk_desc->ino),
		  le32_to_cpu(blk_desc->logical_offset),
		  le16_to_cpu(blk_desc->peb_index),
		  le16_to_cpu(blk_desc->peb_page));

	for (i = 0; i < SSDFS_BLK_STATE_OFF_MAX; i++) {
		SSDFS_DBG("BLK STATE OFFSET %d: "
			  "log_start_page %u, log_area %#x, "
			  "byte_offset %u, peb_migration_id %u\n",
			  i,
			  le16_to_cpu(blk_desc->state[i].log_start_page),
			  blk_desc->state[i].log_area,
			  le32_to_cpu(blk_desc->state[i].byte_offset),
			  blk_desc->state[i].peb_migration_id);
	}
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * PEB object's API
 */
int ssdfs_peb_object_create(struct ssdfs_peb_info *pebi,
			    struct ssdfs_peb_container *pebc,
			    u64 peb_id, int peb_state,
			    u8 peb_migration_id);
int ssdfs_peb_object_destroy(struct ssdfs_peb_info *pebi);
void ssdfs_peb_current_log_init(struct ssdfs_peb_info *pebi,
				u32 free_blocks,
				u32 start_block,
				int sequence_id,
				struct ssdfs_peb_prev_log *prev_log);
u64 ssdfs_get_leb_id_for_peb_index(struct ssdfs_fs_info *fsi,
				   u64 seg, u32 peb_index);
u64 ssdfs_get_seg_id_for_leb_id(struct ssdfs_fs_info *fsi,
				u64 leb_id);
int ssdfs_get_peb_migration_id(struct ssdfs_peb_info *pebi);
bool is_peb_migration_id_valid(int peb_migration_id);
int ssdfs_get_peb_migration_id_checked(struct ssdfs_peb_info *pebi);
void ssdfs_set_peb_migration_id(struct ssdfs_peb_info *pebi,
				int id);
int __ssdfs_define_next_peb_migration_id(int prev_id);
int ssdfs_define_next_peb_migration_id(struct ssdfs_peb_info *src_peb);
int ssdfs_define_prev_peb_migration_id(struct ssdfs_peb_info *pebi);

#ifdef CONFIG_SSDFS_PEB_DEDUPLICATION
bool is_ssdfs_block_duplicated(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				struct ssdfs_fingerprint_pair *pair);
int ssdfs_peb_deduplicate_logical_block(struct ssdfs_peb_info *pebi,
					struct ssdfs_segment_request *req,
					struct ssdfs_fingerprint_pair *pair,
					struct ssdfs_block_descriptor *blk_desc);
bool should_ssdfs_save_fingerprint(struct ssdfs_peb_info *pebi,
				   struct ssdfs_segment_request *req);
int ssdfs_peb_save_fingerprint(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				struct ssdfs_block_descriptor *blk_desc,
				struct ssdfs_fingerprint_pair *pair);
#else
static inline
bool is_ssdfs_block_duplicated(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				struct ssdfs_fingerprint_pair *pair)
{
	return false;
}
static inline
int ssdfs_peb_deduplicate_logical_block(struct ssdfs_peb_info *pebi,
					struct ssdfs_segment_request *req,
					struct ssdfs_fingerprint_pair *pair,
					struct ssdfs_block_descriptor *blk_desc)
{
	return -EOPNOTSUPP;
}
static inline
bool should_ssdfs_save_fingerprint(struct ssdfs_peb_info *pebi,
				   struct ssdfs_segment_request *req)
{
	return false;
}
static inline
int ssdfs_peb_save_fingerprint(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				struct ssdfs_block_descriptor *blk_desc,
				struct ssdfs_fingerprint_pair *pair)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_SSDFS_PEB_DEDUPLICATION */

/*
 * PEB internal functions declaration
 */
int ssdfs_unaligned_read_cache(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				u32 area_offset, u32 area_size,
				void *buf);
int ssdfs_peb_read_log_hdr_desc_array(struct ssdfs_peb_info *pebi,
				      struct ssdfs_segment_request *req,
				      u16 log_start_block,
				      struct ssdfs_metadata_descriptor *array,
				      size_t array_size);
u16 ssdfs_peb_estimate_min_partial_log_pages(struct ssdfs_peb_info *pebi);
u32 ssdfs_request_rest_bytes(struct ssdfs_peb_info *pebi,
			     struct ssdfs_segment_request *req);
bool is_ssdfs_peb_exhausted(struct ssdfs_fs_info *fsi,
			    struct ssdfs_peb_info *pebi);
bool is_ssdfs_peb_ready_to_exhaust(struct ssdfs_fs_info *fsi,
				   struct ssdfs_peb_info *pebi);

#endif /* _SSDFS_PEB_H */
