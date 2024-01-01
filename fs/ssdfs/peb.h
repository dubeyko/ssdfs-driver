/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb.h - Physical Erase Block (PEB) object declarations.
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

#ifndef _SSDFS_PEB_H
#define _SSDFS_PEB_H

#include "request_queue.h"
#include "fingerprint_array.h"

/*
 * struct ssdfs_contigous_bytes - contigous sequence of bytes
 * @offset: offset of sequence in bytes
 * @size: length of sequence in bytes
 */
struct ssdfs_contigous_bytes {
	u32 offset;
	u32 size;
};

/*
 * struct ssdfs_compressed_area - compressed area descriptor
 * @compressed: descriptor of compressed byte stream
 * @meta_desc: copy of metadata area's descriptor
 */
struct ssdfs_compressed_area {
	struct ssdfs_contigous_bytes compressed;
	struct ssdfs_metadata_descriptor meta_desc;

};

/*
 * struct ssdfs_compressed_portion - compressed portion descriptor
 * @area: descriptor of area that contains portion
 * @header_size: size of th eportion header
 * @compressed: descriptor of compressed state of portion
 * @uncompressed: descriptor of decompressed state of portion
 */
struct ssdfs_compressed_portion {
	struct ssdfs_compressed_area area;

	size_t header_size;

	struct ssdfs_contigous_bytes compressed;
	struct ssdfs_contigous_bytes uncompressed;
};

/*
 * struct ssdfs_compressed_fragment - compressed fragment descriptor
 * @portion: portion descriptor that contains fragment
 * @compressed: descriptor of compressed state of fragment
 * @uncompressed: descriptor of decompressed state of fragment
 * @frag_desc: fragment descriptor
 */
struct ssdfs_compressed_fragment {
	struct ssdfs_compressed_portion portion;

	struct ssdfs_contigous_bytes compressed;
	struct ssdfs_contigous_bytes uncompressed;

	struct ssdfs_fragment_desc frag_desc;
};

/*
 * struct ssdfs_fragment_raw_iterator - raw fragment iterator
 * @frag_desc: fragment descriptor
 * @offset: current offset
 * @bytes_count: total number of bytes
 * @processed_bytes: number of processed bytes
 * @fragments_count: total number of fragments
 * @processed_fragments: number of preocessed fragments
 */
struct ssdfs_fragment_raw_iterator {
	struct ssdfs_compressed_fragment fragment_desc;

	u32 offset;
	u32 bytes_count;
	u32 processed_bytes;

	u32 fragments_count;
	u32 processed_fragments;
};

/*
 * struct ssdfs_raw_iterator - raw stream iterator
 * @start_offset: start offset in stream
 * @current_offset: current offset in stream
 * @bytes_count: total size of content in bytes
 */
struct ssdfs_raw_iterator {
	u32 start_offset;
	u32 current_offset;
	u32 bytes_count;
};

/*
 * struct ssdfs_content_stream - content stream
 * @batch: folio vector with content's byte stream
 * @write_iter: write iterator
 */
struct ssdfs_content_stream {
	struct ssdfs_folio_vector batch;
//	struct ssdfs_raw_iterator write_iter;

	u32 write_off;
	u32 bytes_count;
};

#define SSDFS_BLKBMAP_FRAG_HDR_CAPACITY \
	(sizeof(struct ssdfs_block_bitmap_fragment) + \
	 (sizeof(struct ssdfs_fragment_desc) * \
	  SSDFS_BLK_BMAP_FRAGMENTS_CHAIN_MAX))

#define SSDFS_BLKBMAP_HDR_CAPACITY \
	(sizeof(struct ssdfs_block_bitmap_header) + \
	 SSDFS_BLKBMAP_FRAG_HDR_CAPACITY)

/*
 * struct ssdfs_blk_bmap_init_env - block bitmap init environment
 * @raw.content: folio vector that stores block bitmap content
 * @raw.metadata: block bitmap fragment's metadata buffer
 * @header.ptr: pointer on block bitmap header
 * @fragment.index: index of block bitmap's fragment
 * @fragment.header: block bitmap fragment's header
 * @read_bytes: counter of all read bytes
 */
struct ssdfs_blk_bmap_init_env {
	struct {
		struct ssdfs_folio_vector content;
		u8 metadata[SSDFS_BLKBMAP_HDR_CAPACITY];
	} raw;

	struct {
		struct ssdfs_block_bitmap_header *ptr;
	} header;

	struct {
		int index;
		struct ssdfs_block_bitmap_fragment *header;
	} fragment;

	u32 read_bytes;
};

/*
 * struct ssdfs_blk2off_table_init_env - blk2off table init environment
 * @extents.stream: translation extents sequence
 * @extents.count: count of extents in sequence
 * @portion.header: blk2off table header
 * @portion.fragments.stream: phys offset descriptors sequence
 * @portion.read_iter: read iterator in portion
 * @portion.area_offset: offset to the blk2off area
 * @portion.read_off: current read offset
 */
struct ssdfs_blk2off_table_init_env {
	struct {
		struct ssdfs_content_stream stream;
		u32 count;
	} extents;

	struct {
		struct ssdfs_blk2off_table_header header;

		struct {
			struct ssdfs_content_stream stream;
		} fragments;

//		struct ssdfs_fragment_raw_iterator read_iter;
		u32 area_offset;
		u32 read_off;
	} portion;
};

/*
 * struct ssdfs_blk_desc_table_init_env - blk desc table init environment
 * @portion.header: blk desc table header
 * @portion.raw.content: pagevec with blk desc table fragment
 * @portion.read_iter: read iterator in portion
 * @portion.area_offset: offset to the blk2off area
 * @portion.read_off: current read offset
 * @portion.write_off: current write offset
 */
struct ssdfs_blk_desc_table_init_env {
	struct {
		struct ssdfs_area_block_table header;

		struct {
			struct ssdfs_folio_vector content;
		} raw;

//		struct ssdfs_fragment_raw_iterator read_iter;
		u32 area_offset;
		u32 read_off;
		u32 write_off;
	} portion;
};

/*
 * struct ssdfs_read_init_env - read operation init environment
 * @peb.cur_migration_id: current PEB's migration ID
 * @peb.prev_migration_id: previous PEB's migration ID
 * @log.offset: offset in pages of the requested log
 * @log.blocks: blocks count in every log of segment
 * @log.bytes: number of bytes in the requested log
 * @log.header.ptr: log header
 * @log.header.of_full_log: is it full log header (segment header)?
 * @log.footer.ptr: log footer
 * @log.footer.is_present: does log have footer?
 * @log.bmap: block bitmap init environment
 * @log.off_tbl: blk2off table init environment
 * @log.desc_tbl: blk desc table init environment
 */
struct ssdfs_read_init_env {
	struct {
		int cur_migration_id;
		int prev_migration_id;
	} peb;

	struct {
		u32 offset;
		u32 blocks;
		u32 bytes;

		struct {
			void *ptr;
			bool of_full_log;
		} header;

		struct {
			struct ssdfs_log_footer *ptr;
			bool is_present;
		} footer;

		struct ssdfs_blk_bmap_init_env blk_bmap;
		struct ssdfs_blk2off_table_init_env blk2off_tbl;
		struct ssdfs_blk_desc_table_init_env blk_desc_tbl;
	} log;
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
 * @buf_size: buffer size in bytes
 * @frag_desc: fragment descriptor
 */
struct ssdfs_peb_read_buffer {
	void *ptr;
	size_t buf_size;

	struct ssdfs_compressed_fragment frag_desc;
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
 * struct ssdfs_peb_log - current log
 * @lock: exclusive lock of current log
 * @state: current log's state
 * @sequence_id: index of partial log in the sequence
 * @start_block: current log's start block index
 * @reserved_blocks: metadata blocks in the log
 * @free_data_blocks: free data blocks capacity
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
	u32 start_block;
	u32 reserved_blocks; /* metadata blocks in the log */
	u32 free_data_blocks; /* free data blocks capacity */
	u32 seg_flags;
	u32 prev_log_bmap_bytes;
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
 * ssdfs_create_content_stream() - create content stream
 */
static inline
void ssdfs_create_content_stream(struct ssdfs_content_stream *stream,
				 u32 capacity)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!stream);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_folio_vector_create(&stream->batch,
				  get_order(PAGE_SIZE), capacity);

	stream->write_off = 0;
	stream->bytes_count = 0;
}

/*
 * ssdfs_reinit_content_stream() - reinit content stream
 */
static inline
void ssdfs_reinit_content_stream(struct ssdfs_content_stream *stream)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!stream);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_folio_vector_release(&stream->batch);
	ssdfs_folio_vector_reinit(&stream->batch);

	stream->write_off = 0;
	stream->bytes_count = 0;
}

/*
 * ssdfs_destroy_content_stream() - destroy content stream
 */
static inline
void ssdfs_destroy_content_stream(struct ssdfs_content_stream *stream)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!stream);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_folio_vector_release(&stream->batch);
	ssdfs_folio_vector_destroy(&stream->batch);

	stream->write_off = 0;
	stream->bytes_count = 0;
}

/*
 * IS_SSDFS_CONTIGOUS_BYTES_DESC_INVALID() - check validity of descriptor
 */
static inline
bool IS_SSDFS_CONTIGOUS_BYTES_DESC_INVALID(struct ssdfs_contigous_bytes *desc)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
#endif /* CONFIG_SSDFS_DEBUG */

	if (desc->offset >= U32_MAX)
		return true;
	else if (desc->size == 0 || desc->size >= U32_MAX)
		return true;
	else
		return false;
}

/*
 * SSDFS_INIT_CONTIGOUS_BYTES_DESC() - init descriptor
 */
static inline
void SSDFS_INIT_CONTIGOUS_BYTES_DESC(struct ssdfs_contigous_bytes *desc,
				     u32 offset, u32 size)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
#endif /* CONFIG_SSDFS_DEBUG */

	desc->offset = offset;
	desc->size = size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("offset %u, size %u\n",
		  desc->offset, desc->size);

	BUG_ON(IS_SSDFS_CONTIGOUS_BYTES_DESC_INVALID(desc));
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * SSDFS_AREA_COMPRESSED_OFFSET() - get area compressed offset
 */
static inline
u32 SSDFS_AREA_COMPRESSED_OFFSET(struct ssdfs_compressed_area *area)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!area);

	SSDFS_DBG("AREA: compressed (offset %u, size %u)\n",
		  area->compressed.offset,
		  area->compressed.size);
#endif /* CONFIG_SSDFS_DEBUG */

	return area->compressed.offset;
}

/*
 * SSDFS_AREA_COMPRESSED_SIZE() - get area compressed size
 */
static inline
u32 SSDFS_AREA_COMPRESSED_SIZE(struct ssdfs_compressed_area *area)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!area);

	SSDFS_DBG("AREA: compressed (offset %u, size %u)\n",
		  area->compressed.offset,
		  area->compressed.size);
#endif /* CONFIG_SSDFS_DEBUG */

	return area->compressed.size;
}

/*
 * IS_SSDFS_COMPRESSED_AREA_DESC_INVALID() - check validity of descriptor
 */
static inline
bool IS_SSDFS_COMPRESSED_AREA_DESC_INVALID(struct ssdfs_compressed_area *desc)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
#endif /* CONFIG_SSDFS_DEBUG */

	return IS_SSDFS_CONTIGOUS_BYTES_DESC_INVALID(&desc->compressed);
}

/*
 * SSDFS_INIT_COMPRESSED_AREA_DESC() - init compressed area descriptor
 */
static inline
void SSDFS_INIT_COMPRESSED_AREA_DESC(struct ssdfs_compressed_area *desc,
				     struct ssdfs_metadata_descriptor *meta_desc)
{
	size_t meta_desc_size = sizeof(struct ssdfs_metadata_descriptor);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !meta_desc);

	SSDFS_DBG("offset %u, size %u\n",
		  le32_to_cpu(meta_desc->offset),
		  le32_to_cpu(meta_desc->size));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_INIT_CONTIGOUS_BYTES_DESC(&desc->compressed,
					le32_to_cpu(meta_desc->offset),
					le32_to_cpu(meta_desc->size));

	ssdfs_memcpy(&desc->meta_desc, 0, meta_desc_size,
		     meta_desc, 0, meta_desc_size,
		     meta_desc_size);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(IS_SSDFS_COMPRESSED_AREA_DESC_INVALID(desc));
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * SSDFS_COMPRESSED_AREA_UPPER_BOUND() - get compressed area's upper bound
 */
static inline
u64 SSDFS_COMPRESSED_AREA_UPPER_BOUND(struct ssdfs_compressed_area *desc)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);

	SSDFS_DBG("offset %u, size %u\n",
		  desc->compressed.offset,
		  desc->compressed.size);

	BUG_ON(IS_SSDFS_COMPRESSED_AREA_DESC_INVALID(desc));
#endif /* CONFIG_SSDFS_DEBUG */

	return (u64)desc->compressed.offset + desc->compressed.size;
}

/*
 * IS_SSDFS_COMPRESSED_PORTION_INVALID() - check validity of descriptor
 */
static inline
bool IS_SSDFS_COMPRESSED_PORTION_INVALID(struct ssdfs_compressed_portion *desc)
{
	bool is_invalid;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
#endif /* CONFIG_SSDFS_DEBUG */

	is_invalid = IS_SSDFS_COMPRESSED_AREA_DESC_INVALID(&desc->area) ||
		     IS_SSDFS_CONTIGOUS_BYTES_DESC_INVALID(&desc->compressed) ||
		     IS_SSDFS_CONTIGOUS_BYTES_DESC_INVALID(&desc->uncompressed);

	return is_invalid;
}

/*
 * SSDFS_PORTION_COMPRESSED_OFFSET() - get portion's compressed offset
 */
static inline
u32 SSDFS_PORTION_COMPRESSED_OFFSET(struct ssdfs_compressed_portion *portion)
{
	u64 offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion);

	SSDFS_DBG("PORTION: compressed (offset %u, size %u), "
		  "uncompressed (offset %u, size %u)\n",
		  portion->compressed.offset,
		  portion->compressed.size,
		  portion->uncompressed.offset,
		  portion->uncompressed.size);

	BUG_ON(IS_SSDFS_COMPRESSED_PORTION_INVALID(portion));
#endif /* CONFIG_SSDFS_DEBUG */

	offset = SSDFS_AREA_COMPRESSED_OFFSET(&portion->area);
	offset += portion->compressed.offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(offset >= U32_MAX);

	SSDFS_DBG("compressed offset %llu\n", offset);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u32)offset;
}

/*
 * SSDFS_PORTION_UNCOMPRESSED_OFFSET() - get portion's uncompressed offset
 */
static inline
u32 SSDFS_PORTION_UNCOMPRESSED_OFFSET(struct ssdfs_compressed_portion *portion)
{
	u64 offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!portion);

	SSDFS_DBG("PORTION: compressed (offset %u, size %u), "
		  "uncompressed (offset %u, size %u)\n",
		  portion->compressed.offset,
		  portion->compressed.size,
		  portion->uncompressed.offset,
		  portion->uncompressed.size);

	BUG_ON(IS_SSDFS_COMPRESSED_PORTION_INVALID(portion));
#endif /* CONFIG_SSDFS_DEBUG */

	offset = SSDFS_AREA_COMPRESSED_OFFSET(&portion->area);
	offset += portion->uncompressed.offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(offset >= U32_MAX);

	SSDFS_DBG("uncompressed offset %llu\n", offset);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u32)offset;
}

/*
 * IS_SSDFS_COMPRESSED_PORTION_IN_AREA() - check that portion insdie of area
 */
static inline
bool IS_SSDFS_COMPRESSED_PORTION_IN_AREA(struct ssdfs_compressed_portion *desc)
{
	u64 offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
	BUG_ON(IS_SSDFS_COMPRESSED_PORTION_INVALID(desc));
#endif /* CONFIG_SSDFS_DEBUG */

	offset = desc->compressed.offset + desc->compressed.size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(offset >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	if (offset > SSDFS_AREA_COMPRESSED_SIZE(&desc->area))
		return false;
	else
		return true;
}

/*
 * SSDFS_INIT_COMPRESSED_PORTION_DESC() - init portion's descriptor
 */
static inline
void SSDFS_INIT_COMPRESSED_PORTION_DESC(struct ssdfs_compressed_portion *desc,
					struct ssdfs_metadata_descriptor *meta,
					struct ssdfs_fragments_chain_header *hdr,
					size_t header_size)
{
	size_t compr_size;
	size_t uncompr_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !meta || !hdr);

	SSDFS_DBG("AREA: offset %u, size %u, "
		  "PORTION: compr_bytes %u, uncompr_bytes %u\n",
		  le32_to_cpu(meta->offset),
		  le32_to_cpu(meta->size),
		  le32_to_cpu(hdr->compr_bytes),
		  le32_to_cpu(hdr->uncompr_bytes));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_INIT_COMPRESSED_AREA_DESC(&desc->area, meta);

	desc->header_size = header_size;

	compr_size = header_size + le32_to_cpu(hdr->compr_bytes);
	SSDFS_INIT_CONTIGOUS_BYTES_DESC(&desc->compressed,
					0, compr_size);

	uncompr_size = header_size + le32_to_cpu(hdr->uncompr_bytes);
	SSDFS_INIT_CONTIGOUS_BYTES_DESC(&desc->uncompressed,
					0, uncompr_size);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(IS_SSDFS_COMPRESSED_PORTION_INVALID(desc));
	BUG_ON(!IS_SSDFS_COMPRESSED_PORTION_IN_AREA(desc));
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * SSDFS_ADD_COMPRESSED_PORTION() - calculate portion's position in stream
 */
static inline
int SSDFS_ADD_COMPRESSED_PORTION(struct ssdfs_compressed_portion *desc,
				 struct ssdfs_fragments_chain_header *hdr)
{
	size_t compr_size;
	size_t uncompr_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !hdr);

	SSDFS_DBG("AREA: offset %u, size %u, "
		  "OLD PORTION: compressed (offset %u, size %u), "
		  "uncompressed (offset %u, size %u), "
		  "NEW PORTION: compr_bytes %u, uncompr_bytes %u\n",
		  desc->area.compressed.offset,
		  desc->area.compressed.size,
		  desc->compressed.offset,
		  desc->compressed.size,
		  desc->uncompressed.offset,
		  desc->uncompressed.size,
		  le32_to_cpu(hdr->compr_bytes),
		  le32_to_cpu(hdr->uncompr_bytes));

	BUG_ON(IS_SSDFS_COMPRESSED_PORTION_INVALID(desc));
#endif /* CONFIG_SSDFS_DEBUG */

	desc->compressed.offset += desc->compressed.size;
	compr_size = desc->header_size + le32_to_cpu(hdr->compr_bytes);
	desc->compressed.size = compr_size;

	desc->uncompressed.offset += desc->uncompressed.size;
	uncompr_size = desc->header_size + le32_to_cpu(hdr->uncompr_bytes);
	desc->uncompressed.size = uncompr_size;

	if (IS_SSDFS_COMPRESSED_PORTION_INVALID(desc)) {
		SSDFS_ERR("invalid portion descriptor\n");
		return -ERANGE;
	}

	if (!IS_SSDFS_COMPRESSED_PORTION_IN_AREA(desc)) {
		SSDFS_ERR("invalid portion descriptor\n");
		return -ERANGE;
	}

	return 0;
}

/*
 * IS_OFFSET_INSIDE_UNCOMPRESSED_PORTION() - check that offset inside of portion
 */
static inline
bool IS_OFFSET_INSIDE_UNCOMPRESSED_PORTION(struct ssdfs_compressed_portion *desc,
					   u32 offset)
{
	u64 lower_bound;
	u64 upper_bound;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);

	SSDFS_DBG("AREA: offset %u, size %u, "
		  "PORTION: compressed (offset %u, size %u), "
		  "uncompressed (offset %u, size %u), "
		  "OFFSET: offset %u\n",
		  desc->area.compressed.offset,
		  desc->area.compressed.size,
		  desc->compressed.offset,
		  desc->compressed.size,
		  desc->uncompressed.offset,
		  desc->uncompressed.size,
		  offset);

	BUG_ON(IS_SSDFS_COMPRESSED_PORTION_INVALID(desc));
#endif /* CONFIG_SSDFS_DEBUG */

	lower_bound = SSDFS_PORTION_UNCOMPRESSED_OFFSET(desc);
	upper_bound = lower_bound + desc->uncompressed.size;

	return lower_bound <= offset && offset < upper_bound;
}

/*
 * SSDFS_COMPRESSED_PORTION_UPPER_BOUND() -  calculate portion's upper bound
 */
static inline
u64 SSDFS_COMPRESSED_PORTION_UPPER_BOUND(struct ssdfs_compressed_portion *desc)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);

	SSDFS_DBG("AREA: offset %u, size %u, "
		  "PORTION: compressed (offset %u, size %u), "
		  "uncompressed (offset %u, size %u)\n",
		  desc->area.compressed.offset,
		  desc->area.compressed.size,
		  desc->compressed.offset,
		  desc->compressed.size,
		  desc->uncompressed.offset,
		  desc->uncompressed.size);

	BUG_ON(IS_SSDFS_COMPRESSED_PORTION_INVALID(desc));
#endif /* CONFIG_SSDFS_DEBUG */

	return (u64)SSDFS_PORTION_COMPRESSED_OFFSET(desc) +
						desc->compressed.size;
}

/*
 * SSDFS_UNCOMPRESSED_PORTION_UPPER_BOUND() -  calculate portion's upper bound
 */
static inline
u64 SSDFS_UNCOMPRESSED_PORTION_UPPER_BOUND(struct ssdfs_compressed_portion *desc)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);

	SSDFS_DBG("AREA: offset %u, size %u, "
		  "PORTION: compressed (offset %u, size %u), "
		  "uncompressed (offset %u, size %u)\n",
		  desc->area.compressed.offset,
		  desc->area.compressed.size,
		  desc->compressed.offset,
		  desc->compressed.size,
		  desc->uncompressed.offset,
		  desc->uncompressed.size);

	BUG_ON(IS_SSDFS_COMPRESSED_PORTION_INVALID(desc));
#endif /* CONFIG_SSDFS_DEBUG */

	return (u64)SSDFS_PORTION_UNCOMPRESSED_OFFSET(desc) +
						desc->compressed.size;
}

/*
 * IS_SSDFS_COMPRESSED_FRAGMENT_INVALID() - check validity of descriptor
 */
static inline
bool IS_SSDFS_COMPRESSED_FRAGMENT_INVALID(struct ssdfs_compressed_fragment *desc)
{
	bool is_invalid;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
#endif /* CONFIG_SSDFS_DEBUG */

	is_invalid = IS_SSDFS_COMPRESSED_PORTION_INVALID(&desc->portion) ||
		     IS_SSDFS_CONTIGOUS_BYTES_DESC_INVALID(&desc->compressed) ||
		     IS_SSDFS_CONTIGOUS_BYTES_DESC_INVALID(&desc->uncompressed);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("AREA: offset %u, size %u, "
		  "PORTION: compressed (offset %u, size %u), "
		  "uncompressed (offset %u, size %u), "
		  "FRAGMENT: compressed (offset %u, size %u), "
		  "uncompressed (offset %u, size %u), "
		  "is_invalid %#x\n",
		  desc->portion.area.compressed.offset,
		  desc->portion.area.compressed.size,
		  desc->portion.compressed.offset,
		  desc->portion.compressed.size,
		  desc->portion.uncompressed.offset,
		  desc->portion.uncompressed.size,
		  desc->compressed.offset,
		  desc->compressed.size,
		  desc->uncompressed.offset,
		  desc->uncompressed.size,
		  is_invalid);
#endif /* CONFIG_SSDFS_DEBUG */

	return is_invalid;
}

/*
 * IS_SSDFS_COMPRESSED_FRAGMENT_IN_PORTION() - check that fragment in portion
 */
static inline
bool
IS_SSDFS_COMPRESSED_FRAGMENT_IN_PORTION(struct ssdfs_compressed_fragment *desc)
{
	u64 offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
#endif /* CONFIG_SSDFS_DEBUG */

	offset = desc->compressed.offset + desc->compressed.size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(offset >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	if (offset > SSDFS_COMPRESSED_PORTION_UPPER_BOUND(&desc->portion))
		return false;
	else
		return true;

	offset = desc->uncompressed.offset + desc->uncompressed.size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(offset >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	if (offset > SSDFS_UNCOMPRESSED_PORTION_UPPER_BOUND(&desc->portion))
		return false;
	else
		return true;
}

/*
 * SSDFS_INIT_COMPRESSED_FRAGMENT_DESC() - init fragment descriptor
 */
static inline
int SSDFS_INIT_COMPRESSED_FRAGMENT_DESC(struct ssdfs_compressed_fragment *desc,
					 struct ssdfs_fragment_desc *frag)
{
	size_t frag_desc_size = sizeof(struct ssdfs_fragment_desc);
	u32 frag_offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !frag);

	SSDFS_DBG("AREA: offset %u, size %u, "
		  "PORTION: compressed (offset %u, size %u), "
		  "uncompressed (offset %u, size %u), "
		  "FRAGMENT: offset %u, compr_size %u, uncompr_size %u\n",
		  desc->portion.area.compressed.offset,
		  desc->portion.area.compressed.size,
		  desc->portion.compressed.offset,
		  desc->portion.compressed.size,
		  desc->portion.uncompressed.offset,
		  desc->portion.uncompressed.size,
		  le32_to_cpu(frag->offset),
		  le16_to_cpu(frag->compr_size),
		  le16_to_cpu(frag->uncompr_size));

	BUG_ON(IS_SSDFS_COMPRESSED_PORTION_INVALID(&desc->portion));
	BUG_ON(!IS_SSDFS_COMPRESSED_PORTION_IN_AREA(&desc->portion));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_memcpy(&desc->frag_desc, 0, frag_desc_size,
		     frag, 0, frag_desc_size,
		     frag_desc_size);

	SSDFS_INIT_CONTIGOUS_BYTES_DESC(&desc->compressed,
					le32_to_cpu(frag->offset),
					le16_to_cpu(frag->compr_size));

	frag_offset = desc->portion.uncompressed.offset;
	frag_offset += desc->portion.header_size;

	SSDFS_INIT_CONTIGOUS_BYTES_DESC(&desc->uncompressed,
					frag_offset,
					le16_to_cpu(frag->uncompr_size));

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(IS_SSDFS_COMPRESSED_FRAGMENT_INVALID(desc));
	BUG_ON(!IS_SSDFS_COMPRESSED_FRAGMENT_IN_PORTION(desc));
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * SSDFS_ADD_COMPRESSED_FRAGMENT() - calculate fragment's position in stream
 */
static inline
int SSDFS_ADD_COMPRESSED_FRAGMENT(struct ssdfs_compressed_fragment *desc,
				  struct ssdfs_fragment_desc *frag)
{
	size_t frag_desc_size = sizeof(struct ssdfs_fragment_desc);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !frag);

	SSDFS_DBG("AREA: offset %u, size %u, "
		  "PORTION: compressed (offset %u, size %u), "
		  "uncompressed (offset %u, size %u), "
		  "FRAGMENT: offset %u, compr_size %u, uncompr_size %u\n",
		  desc->portion.area.compressed.offset,
		  desc->portion.area.compressed.size,
		  desc->portion.compressed.offset,
		  desc->portion.compressed.size,
		  desc->portion.uncompressed.offset,
		  desc->portion.uncompressed.size,
		  le32_to_cpu(frag->offset),
		  le16_to_cpu(frag->compr_size),
		  le16_to_cpu(frag->uncompr_size));

	BUG_ON(IS_SSDFS_COMPRESSED_PORTION_INVALID(&desc->portion));
	BUG_ON(!IS_SSDFS_COMPRESSED_PORTION_IN_AREA(&desc->portion));
	BUG_ON(IS_SSDFS_COMPRESSED_FRAGMENT_INVALID(desc));
	BUG_ON(!IS_SSDFS_COMPRESSED_FRAGMENT_IN_PORTION(desc));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_memcpy(&desc->frag_desc, 0, frag_desc_size,
		     frag, 0, frag_desc_size,
		     frag_desc_size);

	SSDFS_INIT_CONTIGOUS_BYTES_DESC(&desc->compressed,
					le32_to_cpu(frag->offset),
					le16_to_cpu(frag->compr_size));

	desc->uncompressed.offset += desc->uncompressed.size;
	desc->uncompressed.size = le16_to_cpu(frag->uncompr_size);

	if (IS_SSDFS_COMPRESSED_FRAGMENT_INVALID(desc)) {
		SSDFS_ERR("invalid fragment descriptor\n");
		return -ERANGE;
	}

	if (!IS_SSDFS_COMPRESSED_FRAGMENT_IN_PORTION(desc)) {
		SSDFS_ERR("invalid fragment descriptor\n");
		return -ERANGE;
	}

	return 0;
}

/*
 * SSDFS_FRAGMENT_COMPRESSED_OFFSET() - get fragment's compressed offset
 */
static inline
u32 SSDFS_FRAGMENT_COMPRESSED_OFFSET(struct ssdfs_compressed_fragment *desc)
{
	u64 offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);

	SSDFS_DBG("AREA: offset %u, size %u, "
		  "PORTION: compressed (offset %u, size %u), "
		  "uncompressed (offset %u, size %u), "
		  "FRAGMENT: compressed (offset %u, size %u), "
		  "uncompressed (offset %u, size %u)\n",
		  desc->portion.area.compressed.offset,
		  desc->portion.area.compressed.size,
		  desc->portion.compressed.offset,
		  desc->portion.compressed.size,
		  desc->portion.uncompressed.offset,
		  desc->portion.uncompressed.size,
		  desc->compressed.offset,
		  desc->compressed.size,
		  desc->uncompressed.offset,
		  desc->uncompressed.size);
#endif /* CONFIG_SSDFS_DEBUG */

	offset = SSDFS_AREA_COMPRESSED_OFFSET(&desc->portion.area);
	offset += desc->compressed.offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(offset >= U32_MAX);

	SSDFS_DBG("compressed offset %llu\n", offset);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u32)offset;
}

/*
 * SSDFS_FRAGMENT_UNCOMPRESSED_OFFSET() - get fragment's uncompressed offset
 */
static inline
u32 SSDFS_FRAGMENT_UNCOMPRESSED_OFFSET(struct ssdfs_compressed_fragment *desc)
{
	u64 offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);

	SSDFS_DBG("AREA: offset %u, size %u, "
		  "PORTION: compressed (offset %u, size %u), "
		  "uncompressed (offset %u, size %u), "
		  "FRAGMENT: compressed (offset %u, size %u), "
		  "uncompressed (offset %u, size %u)\n",
		  desc->portion.area.compressed.offset,
		  desc->portion.area.compressed.size,
		  desc->portion.compressed.offset,
		  desc->portion.compressed.size,
		  desc->portion.uncompressed.offset,
		  desc->portion.uncompressed.size,
		  desc->compressed.offset,
		  desc->compressed.size,
		  desc->uncompressed.offset,
		  desc->uncompressed.size);
#endif /* CONFIG_SSDFS_DEBUG */

	offset = SSDFS_AREA_COMPRESSED_OFFSET(&desc->portion.area);
	offset += desc->uncompressed.offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(offset >= U32_MAX);

	SSDFS_DBG("uncompressed offset %llu\n", offset);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u32)offset;
}

/*
 * IS_OFFSET_INSIDE_UNCOMPRESSED_FRAGMENT() - check that offset inside fragment
 */
static inline
bool
IS_OFFSET_INSIDE_UNCOMPRESSED_FRAGMENT(struct ssdfs_compressed_fragment *desc,
					u32 offset)
{
	u64 lower_bound;
	u64 upper_bound;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);

	SSDFS_DBG("REQUESTED: offset %u, "
		  "AREA: offset %u, size %u, "
		  "PORTION: compressed (offset %u, size %u), "
		  "uncompressed (offset %u, size %u), "
		  "FRAGMENT: compressed (offset %u, size %u), "
		  "uncompressed (offset %u, size %u)\n",
		  offset,
		  desc->portion.area.compressed.offset,
		  desc->portion.area.compressed.size,
		  desc->portion.compressed.offset,
		  desc->portion.compressed.size,
		  desc->portion.uncompressed.offset,
		  desc->portion.uncompressed.size,
		  desc->compressed.offset,
		  desc->compressed.size,
		  desc->uncompressed.offset,
		  desc->uncompressed.size);

	BUG_ON(IS_SSDFS_COMPRESSED_FRAGMENT_INVALID(desc));
#endif /* CONFIG_SSDFS_DEBUG */

	lower_bound = SSDFS_FRAGMENT_UNCOMPRESSED_OFFSET(desc);
	upper_bound = lower_bound + desc->uncompressed.size;

	return lower_bound <= offset && offset < upper_bound;
}

/*
 * IS_SSDFS_FRAG_RAW_ITER_INVALID() - check that raw iterator is invalid
 */
static inline
bool IS_SSDFS_FRAG_RAW_ITER_INVALID(struct ssdfs_fragment_raw_iterator *iter)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!iter);
#endif /* CONFIG_SSDFS_DEBUG */

	return IS_SSDFS_COMPRESSED_FRAGMENT_INVALID(&iter->fragment_desc) ||
		iter->offset >= U32_MAX || iter->bytes_count >= U32_MAX ||
		iter->processed_bytes >= U32_MAX ||
		iter->fragments_count >= U32_MAX ||
		iter->processed_fragments >= U32_MAX;
}

/*
 * SSDFS_FRAG_RAW_ITER_CREATE() - create raw iterator
 */
static inline
void SSDFS_FRAG_RAW_ITER_CREATE(struct ssdfs_fragment_raw_iterator *iter)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!iter);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(iter, 0xFF, sizeof(struct ssdfs_fragment_raw_iterator));
}

/*
 * SSDFS_FRAG_RAW_ITER_INIT() - init raw iterator
 */
static inline
void SSDFS_FRAG_RAW_ITER_INIT(struct ssdfs_fragment_raw_iterator *iter,
			      u32 offset, u32 bytes_count, u32 fragments_count)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!iter);
#endif /* CONFIG_SSDFS_DEBUG */

	iter->offset = offset;
	iter->bytes_count = bytes_count;
	iter->processed_bytes = 0;
	iter->fragments_count = fragments_count;
	iter->processed_fragments = 0;
}

/*
 * SSDFS_FRAG_RAW_ITER_ADD_FRAGMENT() - add fragment
 */
static inline
int SSDFS_FRAG_RAW_ITER_ADD_FRAGMENT(struct ssdfs_fragment_raw_iterator *iter,
				     struct ssdfs_fragment_desc *frag)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!iter);
	BUG_ON(IS_SSDFS_FRAG_RAW_ITER_INVALID(iter));
#endif /* CONFIG_SSDFS_DEBUG */

	if (IS_SSDFS_COMPRESSED_FRAGMENT_INVALID(&iter->fragment_desc)) {
		err = SSDFS_INIT_COMPRESSED_FRAGMENT_DESC(&iter->fragment_desc,
							  frag);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init fragment: "
				  "processed_bytes %u, bytes_count %u, "
				  "processed_fragments %u, "
				  "fragments_count %u, err %d\n",
				  iter->processed_bytes,
				  iter->bytes_count,
				  iter->processed_fragments,
				  iter->fragments_count,
				  err);
			return err;
		}
	} else {
		err = SSDFS_ADD_COMPRESSED_FRAGMENT(&iter->fragment_desc,
						    frag);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add fragment: "
				  "processed_bytes %u, bytes_count %u, "
				  "processed_fragments %u, "
				  "fragments_count %u, err %d\n",
				  iter->processed_bytes,
				  iter->bytes_count,
				  iter->processed_fragments,
				  iter->fragments_count,
				  err);
			return err;
		}
	}

	iter->processed_bytes += le16_to_cpu(frag->compr_size);

	if (iter->processed_bytes > iter->bytes_count) {
		SSDFS_ERR("invalid state: "
			  "processed_bytes %u > bytes_count %u\n",
			  iter->processed_bytes, iter->bytes_count);
		return -ERANGE;
	}

	iter->processed_fragments++;

	if (iter->processed_fragments > iter->fragments_count) {
		SSDFS_ERR("invalid state: "
			  "processed_fragments %u > fragments_count %u\n",
			  iter->processed_fragments,
			  iter->fragments_count);
		return -ERANGE;
	}

	return 0;
}

/*
 * SSDFS_FRAG_RAW_ITER_SHIFT_OFFSET() - shift raw iterator's offset
 */
static inline
int SSDFS_FRAG_RAW_ITER_SHIFT_OFFSET(struct ssdfs_fragment_raw_iterator *iter,
				     u32 shift)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!iter);
	BUG_ON(IS_SSDFS_FRAG_RAW_ITER_INVALID(iter));
#endif /* CONFIG_SSDFS_DEBUG */

	iter->offset += shift;
	iter->processed_bytes += shift;

	if (iter->processed_bytes > iter->bytes_count) {
		SSDFS_ERR("invalid state: "
			  "processed_bytes %u > bytes_count %u\n",
			  iter->processed_bytes, iter->bytes_count);
		return -ERANGE;
	}

	return 0;
}

/*
 * IS_SSDFS_FRAG_RAW_ITER_ENDED() - check that raw iterator is ended
 */
static inline
bool IS_SSDFS_FRAG_RAW_ITER_ENDED(struct ssdfs_fragment_raw_iterator *iter)
{
	bool is_ended;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!iter);
	BUG_ON(IS_SSDFS_FRAG_RAW_ITER_INVALID(iter));
#endif /* CONFIG_SSDFS_DEBUG */

	is_ended = iter->processed_bytes >= iter->bytes_count &&
			iter->processed_fragments >= iter->fragments_count;

	if (!is_ended) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("iterator is not ended: "
			  "processed_bytes %u, bytes_count %u, "
			  "processed_fragments %u, "
			  "fragments_count %u\n",
			  iter->processed_bytes,
			  iter->bytes_count,
			  iter->processed_fragments,
			  iter->fragments_count);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return is_ended;
}

/*
 * SSDFS_LOG_OFFSET_INIT() - init log offset
 */
static inline
void SSDFS_LOG_OFFSET_INIT(struct ssdfs_peb_log_offset *log,
			   u32 block_size,
			   u32 log_blocks,
			   pgoff_t start_block)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!log);

	SSDFS_DBG("block_size %u, log_blocks %u, start_block %lu\n",
		  block_size, log_blocks, start_block);
#endif /* CONFIG_SSDFS_DEBUG */

	log->blocksize_shift = ilog2(block_size);
	log->log_blocks = log_blocks;
	log->start_block = start_block;
	log->cur_block = start_block;
	log->offset_into_block = 0;
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

	switch (1 << log->blocksize_shift) {
	case SSDFS_4KB:
	case SSDFS_8KB:
	case SSDFS_16KB:
	case SSDFS_32KB:
	case SSDFS_64KB:
	case SSDFS_128KB:
		/* expected block size */
		break;

	default:
		SSDFS_ERR("unexpected logical block size %u\n",
			  1 << log->blocksize_shift);
		return false;
	}

	if (log->start_block > log->cur_block) {
		SSDFS_ERR("inconsistent log offset: "
			  "start_block %lu > cur_block %lu\n",
			  log->start_block, log->cur_block);
		return false;
	}

	if ((log->cur_block - log->start_block) >= log->log_blocks) {
		SSDFS_ERR("inconsistent log offset: "
			  "start_block %lu, cur_block %lu, "
			  "log_pages %u\n",
			  log->start_block, log->cur_block,
			  log->log_blocks);
		return false;
	}

	if (log->offset_into_block >= (1 << log->blocksize_shift)) {
		SSDFS_ERR("inconsistent log offset: "
			  "offset_into_block %u\n",
			  log->offset_into_block);
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

	offset = (u64)log->cur_block << log->blocksize_shift;
	offset += log->offset_into_block;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(offset >= U64_MAX);

	SSDFS_DBG("cur_block %lu, offset_into_block %u, "
		  "offset %llu\n",
		  log->cur_block, log->offset_into_block,
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

	offset = (log->cur_block - log->start_block) << log->blocksize_shift;
	offset += log->offset_into_block;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(offset >= U32_MAX);

	SSDFS_DBG("start_block %lu, cur_block %lu, "
		  "offset_into_block %u, offset %u\n",
		  log->start_block, log->cur_block,
		  log->offset_into_block, offset);
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
	u32 offset_into_block;
	u32 block_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!log);
	BUG_ON(!IS_SSDFS_LOG_OFFSET_VALID(log));

	if (!IS_SSDFS_LOG_OFFSET_VALID(log)) {
		SSDFS_ERR("inconsistent log offset: "
			  "start_block %lu, cur_block %lu, "
			  "offset_into_block %u\n",
			  log->start_block, log->cur_block,
			  log->offset_into_block);
		return -ERANGE;
	}

	SSDFS_DBG("shift %u\n", shift);
#endif /* CONFIG_SSDFS_DEBUG */

	block_size = 1 << log->blocksize_shift;

	offset_into_block = log->offset_into_block;
	offset_into_block += shift;

	if (offset_into_block < block_size) {
		log->offset_into_block = offset_into_block;
	} else if (offset_into_block == block_size) {
		log->cur_block++;
		log->offset_into_block = 0;
	} else {
		log->cur_block += offset_into_block >> log->blocksize_shift;
		log->offset_into_block = offset_into_block % block_size;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_block %lu, cur_block %lu, "
		  "offset_into_block %u\n",
		  log->start_block, log->cur_block,
		  log->offset_into_block);

	if (!IS_SSDFS_LOG_OFFSET_VALID(log)) {
		SSDFS_ERR("inconsistent log offset: "
			  "start_block %lu, cur_block %lu, "
			  "offset_into_block %u\n",
			  log->start_block, log->cur_block,
			  log->offset_into_block);
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
	return SSDFS_LOCAL_LOG_OFFSET(log) % (1 << log->blocksize_shift);
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
		log->cur_block++;
		log->offset_into_block = 0;
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
 * @free_blocks: free blocks in the current log
 * @start_block: start block of the current log
 * @sequence_id: index of partial log in the sequence
 * @prev_log_bmap_bytes: bytes count in block bitmap of previous log
 */
static inline
void ssdfs_peb_current_log_init(struct ssdfs_peb_info *pebi,
				u32 free_blocks,
				u32 start_block,
				int sequence_id,
				u32 prev_log_bmap_bytes)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);

	SSDFS_DBG("peb_id %llu, "
		  "pebi->current_log.start_block %u, "
		  "free_blocks %u, sequence_id %d, "
		  "prev_log_bmap_bytes %u\n",
		  pebi->peb_id, start_block, free_blocks,
		  sequence_id, prev_log_bmap_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_peb_current_log_lock(pebi);
	pebi->current_log.start_block = start_block;
	pebi->current_log.free_data_blocks = free_blocks;
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
int ssdfs_peb_realloc_read_buffer(struct ssdfs_peb_read_buffer *buf,
				  size_t new_size);
int ssdfs_peb_realloc_write_buffer(struct ssdfs_peb_temp_buffer *buf);

#endif /* _SSDFS_PEB_H */
