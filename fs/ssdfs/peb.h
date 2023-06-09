// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb.h - Physical Erase Block (PEB) object declarations.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2023 Viacheslav Dubeyko <slava@dubeyko.com>
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

#define SSDFS_BLKBMAP_FRAG_HDR_CAPACITY \
	(sizeof(struct ssdfs_block_bitmap_fragment) + \
	 (sizeof(struct ssdfs_fragment_desc) * \
	  SSDFS_BLK_BMAP_FRAGMENTS_CHAIN_MAX))

#define SSDFS_BLKBMAP_HDR_CAPACITY \
	(sizeof(struct ssdfs_block_bitmap_header) + \
	 SSDFS_BLKBMAP_FRAG_HDR_CAPACITY)

/*
 * struct ssdfs_blk_bmap_init_env - block bitmap init environment
 * @bmap_hdr: pointer on block bitmap header
 * @bmap_hdr_buf: block bitmap header buffer
 * @frag_hdr: block bitmap fragment header
 * @frag_hdr_buf: block bitmap fragment header buffer
 * @fragment_index: index of bmap fragment
 * @array: page vector that stores block bitmap content
 * @read_bytes: counter of all read bytes
 */
struct ssdfs_blk_bmap_init_env {
	struct ssdfs_block_bitmap_header *bmap_hdr;
	struct ssdfs_block_bitmap_fragment *frag_hdr;
	u8 bmap_hdr_buf[SSDFS_BLKBMAP_HDR_CAPACITY];
	int fragment_index;
	struct ssdfs_page_vector array;
	u32 read_bytes;
};


/*
 * struct ssdfs_content_stream - content stream
 * @pvec: page vector
 * @write_off: current write offset
 * @bytes_count: total size of content in bytes
 */
struct ssdfs_content_stream {
	struct ssdfs_page_vector pvec;
	u32 write_off;
	u32 bytes_count;
};

/*
 * struct ssdfs_blk2off_table_init_env - blk2off table init environment
 * @hdr: blk2off table header
 * @extents: translation extents sequence
 * @extents_count: count of extents in sequence
 * @descriptors: phys offset descriptors sequence
 * @area_offset: offset to the blk2off area
 * @read_off: current read offset
 */
struct ssdfs_blk2off_table_init_env {
	struct ssdfs_blk2off_table_header hdr;
	struct ssdfs_content_stream extents;
	u32 extents_count;
	struct ssdfs_content_stream descriptors;
	u32 area_offset;
	u32 read_off;
};

/*
 * struct ssdfs_blk_desc_table_init_env - blk desc table init environment
 * @hdr: blk desc table header
 * @array pagevec with blk desc table fragment
 * @area_offset: offset to the blk2off area
 * @read_off: current read offset
 * @write_off: current write offset
 */
struct ssdfs_blk_desc_table_init_env {
	struct ssdfs_area_block_table hdr;
	struct ssdfs_page_vector array;
	u32 area_offset;
	u32 read_off;
	u32 write_off;
};

/*
 * struct ssdfs_read_init_env - read operation init environment
 * @log_hdr: log header
 * @has_seg_hdr: does log have segment header?
 * @footer: log footer
 * @has_footer: does log have footer?
 * @cur_migration_id: current PEB's migration ID
 * @prev_migration_id: previous PEB's migration ID
 * @log_offset: offset in pages of the requested log
 * @log_pages: pages count in every log of segment
 * @log_bytes: number of bytes in the requested log
 * @b_init: block bitmap init environment
 * @t_init: blk2off table init environment
 * @bdt_init: blk desc table init environment
 */
struct ssdfs_read_init_env {
	void *log_hdr;
	bool has_seg_hdr;
	struct ssdfs_log_footer *footer;
	bool has_footer;
	int cur_migration_id;
	int prev_migration_id;
	u32 log_offset;
	u32 log_pages;
	u32 log_bytes;

	struct ssdfs_blk_bmap_init_env b_init;
	struct ssdfs_blk2off_table_init_env t_init;
	struct ssdfs_blk_desc_table_init_env bdt_init;
};

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
 * struct ssdfs_peb_read_buffer - read buffer
 * @ptr: pointer on buffer
 * @offset: logical offset in metadata structure
 * @fragment_size: size of fragment in bytes
 * @buf_size: buffer size in bytes
 */
struct ssdfs_peb_read_buffer {
	void *ptr;
	u32 offset;
	size_t fragment_size;
	size_t buf_size;
};

/*
 * struct ssdfs_peb_temp_read_buffers - read temporary buffers
 * @lock: temporary buffers lock
 * @blk_desc: block descriptor table's temp read buffer
 */
struct ssdfs_peb_temp_read_buffers {
	struct rw_semaphore lock;
	struct ssdfs_peb_read_buffer blk_desc;
};

/*
 * struct ssdfs_peb_temp_buffer - temporary (write) buffer
 * @ptr: pointer on buffer
 * @write_offset: current write offset into buffer
 * @granularity: size of one item in bytes
 * @size: buffer size in bytes
 */
struct ssdfs_peb_temp_buffer {
	void *ptr;
	u32 write_offset;
	size_t granularity;
	size_t size;
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
 * @array: area's memory pages
 */
struct ssdfs_peb_area {
	bool has_metadata;
	struct ssdfs_peb_area_metadata metadata;

	u32 write_offset;
	u32 compressed_offset;
	struct ssdfs_page_array array;
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
 * struct ssdfs_peb_log - current log
 * @lock: exclusive lock of current log
 * @state: current log's state
 * @sequence_id: index of partial log in the sequence
 * @start_page: current log's start page index
 * @pages_capacity: rest free pages in log
 * @write_offset: current offset in bytes for adding data in log
 * @seg_flags: segment header's flags for the log
 * @prev_log_bmap_bytes: bytes count in block bitmap of previous log
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
	u32 start_page;
	u32 reserved_pages; /* metadata pages in the log */
	u32 free_data_pages; /* free data pages capacity */
	u32 seg_flags;
	u32 prev_log_bmap_bytes;
	u64 last_log_time;
	u64 last_log_cno;
	struct ssdfs_page_vector bmap_snapshot;
	struct ssdfs_blk2off_table_area blk2off_tbl;
	struct ssdfs_peb_area area[SSDFS_LOG_AREA_MAX];
};

/*
 * struct ssdfs_peb_log_offset - current log offset
 * @log_pages: count of pages in full partial log
 * @start_page: current log's start page index
 * @cur_page: current page in the log
 * @offset_into_page: current offset into page
 */
struct ssdfs_peb_log_offset {
	u32 log_pages;
	pgoff_t start_page;
	pgoff_t cur_page;
	u32 offset_into_page;
};

/*
 * struct ssdfs_peb_info - Physical Erase Block (PEB) description
 * @peb_id: PEB number
 * @peb_index: PEB index
 * @log_pages: count of pages in full partial log
 * @peb_create_time: PEB creation timestamp
 * @peb_migration_id: identification number of PEB in migration sequence
 * @state: PEB object state
 * @init_end: wait of full init ending
 * @reserved_bytes.blk_bmap: reserved bytes for block bitmap
 * @reserved_bytes.blk2off_tbl: reserved bytes for blk2off table
 * @reserved_bytes.blk_desc_tbl: reserved bytes for block descriptor table
 * @current_log: PEB's current log
 * @read_buffer: temporary read buffers (compression case)
 * @env: init environment
 * @cache: PEB's memory pages
 * @pebc: pointer on parent container
 */
struct ssdfs_peb_info {
	/* Static data */
	u64 peb_id;
	u16 peb_index;
	u32 log_pages;

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

	/* Reserved bytes */
	struct {
		atomic_t blk_bmap;
		atomic_t blk2off_tbl;
		atomic_t blk_desc_tbl;
	} reserved_bytes;

	/* Current log */
	struct ssdfs_peb_log current_log;

	/* Read buffer */
	struct ssdfs_peb_temp_read_buffers read_buffer;

	/* Init environment */
	struct ssdfs_read_init_env env;

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
 * SSDFS_LOG_OFFSET_INIT() - init log offset
 */
static inline
void SSDFS_LOG_OFFSET_INIT(struct ssdfs_peb_log_offset *log,
			   u32 log_pages,
			   pgoff_t start_page)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!log);

	SSDFS_DBG("log_pages %u, start_page %lu\n",
		  log_pages, start_page);
#endif /* CONFIG_SSDFS_DEBUG */

	log->log_pages = log_pages;
	log->start_page = start_page;
	log->cur_page = start_page;
	log->offset_into_page = 0;
}

/*
 * IS_SSDFS_LOG_OFFSET_VALID() - check log offset validity
 */
static inline
bool IS_SSDFS_LOG_OFFSET_VALID(struct ssdfs_peb_log_offset *log)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!log);
#endif /* CONFIG_SSDFS_DEBUG */

	if (log->start_page > log->cur_page) {
		SSDFS_ERR("inconsistent log offset: "
			  "start_page %lu > cur_page %lu\n",
			  log->start_page, log->cur_page);
		return false;
	}

	if ((log->cur_page - log->start_page) >= log->log_pages) {
		SSDFS_ERR("inconsistent log offset: "
			  "start_page %lu, cur_page %lu, "
			  "log_pages %u\n",
			  log->start_page, log->cur_page,
			  log->log_pages);
		return false;
	}

	if (log->offset_into_page >= PAGE_SIZE) {
		SSDFS_ERR("inconsistent log offset: "
			  "offset_into_page %u\n",
			  log->offset_into_page);
		return false;
	}

	return true;
}

/*
 * SSDFS_ABSOLUTE_LOG_OFFSET() - get offset in bytes from PEB's beginning
 */
static inline
u64 SSDFS_ABSOLUTE_LOG_OFFSET(struct ssdfs_peb_log_offset *log)
{
	u64 offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!log);
	BUG_ON(!IS_SSDFS_LOG_OFFSET_VALID(log));
#endif /* CONFIG_SSDFS_DEBUG */

	offset = (u64)log->cur_page << PAGE_SHIFT;
	offset += log->offset_into_page;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(offset >= U64_MAX);

	SSDFS_DBG("cur_page %lu, offset_into_page %u, "
		  "offset %llu\n",
		  log->cur_page, log->offset_into_page,
		  offset);
#endif /* CONFIG_SSDFS_DEBUG */

	return offset;
}

/*
 * SSDFS_LOCAL_LOG_OFFSET() - get offset in bytes from log's beginning
 */
static inline
u32 SSDFS_LOCAL_LOG_OFFSET(struct ssdfs_peb_log_offset *log)
{
	u32 offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!log);
	BUG_ON(!IS_SSDFS_LOG_OFFSET_VALID(log));
#endif /* CONFIG_SSDFS_DEBUG */

	offset = (log->cur_page - log->start_page) << PAGE_SHIFT;
	offset += log->offset_into_page;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(offset >= U32_MAX);

	SSDFS_DBG("start_page %lu, cur_page %lu, "
		  "offset_into_page %u, offset %u\n",
		  log->start_page, log->cur_page,
		  log->offset_into_page, offset);
#endif /* CONFIG_SSDFS_DEBUG */

	return offset;
}

/*
 * SSDFS_SHIFT_LOG_OFFSET() - move log offset
 */
static inline
int SSDFS_SHIFT_LOG_OFFSET(struct ssdfs_peb_log_offset *log,
			   u32 shift)
{
	u32 offset_into_page;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!log);
	BUG_ON(!IS_SSDFS_LOG_OFFSET_VALID(log));

	if (!IS_SSDFS_LOG_OFFSET_VALID(log)) {
		SSDFS_ERR("inconsistent log offset: "
			  "start_page %lu, cur_page %lu, "
			  "offset_into_page %u\n",
			  log->start_page, log->cur_page,
			  log->offset_into_page);
		return -ERANGE;
	}

	SSDFS_DBG("shift %u\n", shift);
#endif /* CONFIG_SSDFS_DEBUG */

	offset_into_page = log->offset_into_page;
	offset_into_page += shift;

	if (offset_into_page < PAGE_SIZE) {
		log->offset_into_page = offset_into_page;
	} else if (offset_into_page == PAGE_SIZE) {
		log->cur_page++;
		log->offset_into_page = 0;
	} else {
		log->cur_page += offset_into_page >> PAGE_SHIFT;
		log->offset_into_page = offset_into_page % PAGE_SIZE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_page %lu, cur_page %lu, "
		  "offset_into_page %u\n",
		  log->start_page, log->cur_page,
		  log->offset_into_page);

	if (!IS_SSDFS_LOG_OFFSET_VALID(log)) {
		SSDFS_ERR("inconsistent log offset: "
			  "start_page %lu, cur_page %lu, "
			  "offset_into_page %u\n",
			  log->start_page, log->cur_page,
			  log->offset_into_page);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * IS_SSDFS_LOG_OFFSET_UNALIGNED() - check that log offset is aligned
 */
static inline
bool IS_SSDFS_LOG_OFFSET_UNALIGNED(struct ssdfs_peb_log_offset *log)
{
	return SSDFS_LOCAL_LOG_OFFSET(log) % PAGE_SIZE;
}

/*
 * SSDFS_ALIGN_LOG_OFFSET() - align log offset on page size
 */
static inline
void SSDFS_ALIGN_LOG_OFFSET(struct ssdfs_peb_log_offset *log)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!log);
#endif /* CONFIG_SSDFS_DEBUG */

	if (IS_SSDFS_LOG_OFFSET_UNALIGNED(log)) {
		log->cur_page++;
		log->offset_into_page = 0;
	}
}

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
	u32 new_write_offset = write_offset + data_size;

	page_index1 = write_offset / PAGE_SIZE;
	page_index2 = new_write_offset / PAGE_SIZE;

	if (page_index1 != page_index2) {
		u32 calculated_write_offset = page_index2 * PAGE_SIZE;

		if (new_write_offset == calculated_write_offset)
			return write_offset;
		else
			return calculated_write_offset;
	}

	return write_offset;
}

/*
 * SSDFS_CORRECT_LOG_OFFSET() - correct log offset
 */
static inline
int SSDFS_CORRECT_LOG_OFFSET(struct ssdfs_peb_log_offset *log,
			     u32 data_size)
{
	u32 old_offset;
	u32 new_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!log);
#endif /* CONFIG_SSDFS_DEBUG */

	old_offset = SSDFS_LOCAL_LOG_OFFSET(log);
	new_offset = ssdfs_peb_correct_area_write_offset(old_offset, data_size);

	if (old_offset != new_offset) {
		u32 diff;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(old_offset > new_offset);
#endif /* CONFIG_SSDFS_DEBUG */

		diff = new_offset - old_offset;
		err = SSDFS_SHIFT_LOG_OFFSET(log, diff);
		if (unlikely(err)) {
			SSDFS_ERR("fail to shift log offset: "
				  "shift %u, err %d\n",
				  diff, err);
			return err;
		}
	}

	return 0;
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
 * @prev_log_bmap_bytes: bytes count in block bitmap of previous log
 */
static inline
void ssdfs_peb_current_log_init(struct ssdfs_peb_info *pebi,
				u32 free_pages,
				u32 start_page,
				int sequence_id,
				u32 prev_log_bmap_bytes)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);

	SSDFS_DBG("peb_id %llu, "
		  "pebi->current_log.start_page %u, "
		  "free_pages %u, sequence_id %d, "
		  "prev_log_bmap_bytes %u\n",
		  pebi->peb_id, start_page, free_pages,
		  sequence_id, prev_log_bmap_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_peb_current_log_lock(pebi);
	pebi->current_log.start_page = start_page;
	pebi->current_log.free_data_pages = free_pages;
	pebi->current_log.prev_log_bmap_bytes = prev_log_bmap_bytes;
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
	u64 leb_id = U64_MAX;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	if (peb_index >= fsi->pebs_per_seg) {
		SSDFS_ERR("requested peb_index %u >= pebs_per_seg %u\n",
			  peb_index, fsi->pebs_per_seg);
		return U64_MAX;
	}

	SSDFS_DBG("fsi %p, seg %llu, peb_index %u\n",
		  fsi, seg, peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (fsi->lebs_per_peb_index == SSDFS_LEBS_PER_PEB_INDEX_DEFAULT)
		leb_id = (seg * fsi->pebs_per_seg) + peb_index;
	else
		leb_id = seg + (peb_index * fsi->lebs_per_peb_index);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb_index %u, leb_id %llu\n",
		  seg, peb_index, leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	return leb_id;
}

/*
 * ssdfs_get_seg_id_for_leb_id() - convert LEB's into segment's ID
 * @fsi: pointer on shared file system object
 * @leb_id: LEB ID
 *
 * This function converts LEB's ID into segment's identification
 * number.
 *
 * RETURN:
 * [success] - LEB's identification number.
 * [failure] - U64_MAX.
 */
static inline
u64 ssdfs_get_seg_id_for_leb_id(struct ssdfs_fs_info *fsi,
				u64 leb_id)
{
	u64 seg_id = U64_MAX;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p, leb_id %llu\n",
		  fsi, leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (fsi->lebs_per_peb_index == SSDFS_LEBS_PER_PEB_INDEX_DEFAULT)
		seg_id = div_u64(leb_id, fsi->pebs_per_seg);
	else
		seg_id = div_u64(leb_id, fsi->lebs_per_peb_index);

	return seg_id;
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
		err = SSDFS_WAIT_COMPLETION(&pebi->init_end);
		if (unlikely(err)) {
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

	SSDFS_DBG("peb_id %llu, peb_migration_id %d\n",
		  pebi->peb_id, id);
#endif /* CONFIG_SSDFS_DEBUG */

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

	SSDFS_DBG("peb %llu, peb_index %u\n",
		  src_peb->peb_id, src_peb->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

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

	SSDFS_DBG("peb %llu, peb_index %u\n",
		  pebi->peb_id, pebi->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

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
		SSDFS_DBG("log_start_page %u, log_area %u, "
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
		SSDFS_DBG("log_start_page %u, log_area %u, "
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

/*
 * PEB internal functions declaration
 */
int ssdfs_unaligned_read_cache(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				u32 area_offset, u32 area_size,
				void *buf);
int ssdfs_peb_read_log_hdr_desc_array(struct ssdfs_peb_info *pebi,
				      struct ssdfs_segment_request *req,
				      u16 log_start_page,
				      struct ssdfs_metadata_descriptor *array,
				      size_t array_size);
u16 ssdfs_peb_estimate_min_partial_log_pages(struct ssdfs_peb_info *pebi);
bool is_ssdfs_peb_exhausted(struct ssdfs_fs_info *fsi,
			    struct ssdfs_peb_info *pebi);
bool is_ssdfs_peb_ready_to_exhaust(struct ssdfs_fs_info *fsi,
				   struct ssdfs_peb_info *pebi);
int ssdfs_peb_realloc_read_buffer(struct ssdfs_peb_read_buffer *buf,
				  size_t new_size);
int ssdfs_peb_realloc_write_buffer(struct ssdfs_peb_temp_buffer *buf);

#endif /* _SSDFS_PEB_H */
