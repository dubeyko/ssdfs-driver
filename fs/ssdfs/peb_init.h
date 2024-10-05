/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_init.h - PEB init structures' declarations.
 *
 * Copyright (c) 2024 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_PEB_INIT_H
#define _SSDFS_PEB_INIT_H

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

struct ssdfs_peb_log_offset;

/*
 * PEB object init API
 */
void ssdfs_create_content_stream(struct ssdfs_content_stream *stream,
				 u32 capacity);
void ssdfs_reinit_content_stream(struct ssdfs_content_stream *stream);
void ssdfs_destroy_content_stream(struct ssdfs_content_stream *stream);

bool IS_SSDFS_CONTIGOUS_BYTES_DESC_INVALID(struct ssdfs_contigous_bytes *desc);
void SSDFS_INIT_CONTIGOUS_BYTES_DESC(struct ssdfs_contigous_bytes *desc,
				     u32 offset, u32 size);
u32 SSDFS_AREA_COMPRESSED_OFFSET(struct ssdfs_compressed_area *area);
u32 SSDFS_AREA_COMPRESSED_SIZE(struct ssdfs_compressed_area *area);
bool IS_SSDFS_COMPRESSED_AREA_DESC_INVALID(struct ssdfs_compressed_area *desc);
void SSDFS_INIT_COMPRESSED_AREA_DESC(struct ssdfs_compressed_area *desc,
				     struct ssdfs_metadata_descriptor *meta_desc);
u64 SSDFS_COMPRESSED_AREA_UPPER_BOUND(struct ssdfs_compressed_area *desc);

bool IS_SSDFS_COMPRESSED_PORTION_INVALID(struct ssdfs_compressed_portion *desc);
u32 SSDFS_PORTION_COMPRESSED_OFFSET(struct ssdfs_compressed_portion *portion);
u32 SSDFS_PORTION_UNCOMPRESSED_OFFSET(struct ssdfs_compressed_portion *portion);
bool IS_SSDFS_COMPRESSED_PORTION_IN_AREA(struct ssdfs_compressed_portion *desc);
void SSDFS_INIT_COMPRESSED_PORTION_DESC(struct ssdfs_compressed_portion *desc,
					struct ssdfs_metadata_descriptor *meta,
					struct ssdfs_fragments_chain_header *hdr,
					size_t header_size);
int SSDFS_ADD_COMPRESSED_PORTION(struct ssdfs_compressed_portion *desc,
				 struct ssdfs_fragments_chain_header *hdr);
bool IS_OFFSET_INSIDE_UNCOMPRESSED_PORTION(struct ssdfs_compressed_portion *desc,
					   u32 offset);
u64 SSDFS_COMPRESSED_PORTION_UPPER_BOUND(struct ssdfs_compressed_portion *desc);
u64 SSDFS_UNCOMPRESSED_PORTION_UPPER_BOUND(struct ssdfs_compressed_portion *desc);

bool IS_SSDFS_COMPRESSED_FRAGMENT_INVALID(struct ssdfs_compressed_fragment *desc);
bool
IS_SSDFS_COMPRESSED_FRAGMENT_IN_PORTION(struct ssdfs_compressed_fragment *desc);
int SSDFS_INIT_COMPRESSED_FRAGMENT_DESC(struct ssdfs_compressed_fragment *desc,
					 struct ssdfs_fragment_desc *frag);
int SSDFS_ADD_COMPRESSED_FRAGMENT(struct ssdfs_compressed_fragment *desc,
				  struct ssdfs_fragment_desc *frag);
u32 SSDFS_FRAGMENT_COMPRESSED_OFFSET(struct ssdfs_compressed_fragment *desc);
u32 SSDFS_FRAGMENT_UNCOMPRESSED_OFFSET(struct ssdfs_compressed_fragment *desc);
bool
IS_OFFSET_INSIDE_UNCOMPRESSED_FRAGMENT(struct ssdfs_compressed_fragment *desc,
					u32 offset);

bool IS_SSDFS_FRAG_RAW_ITER_INVALID(struct ssdfs_fragment_raw_iterator *iter);
void SSDFS_FRAG_RAW_ITER_CREATE(struct ssdfs_fragment_raw_iterator *iter);
void SSDFS_FRAG_RAW_ITER_INIT(struct ssdfs_fragment_raw_iterator *iter,
			      u32 offset, u32 bytes_count, u32 fragments_count);
int SSDFS_FRAG_RAW_ITER_ADD_FRAGMENT(struct ssdfs_fragment_raw_iterator *iter,
				     struct ssdfs_fragment_desc *frag);
int SSDFS_FRAG_RAW_ITER_SHIFT_OFFSET(struct ssdfs_fragment_raw_iterator *iter,
				     u32 shift);
bool IS_SSDFS_FRAG_RAW_ITER_ENDED(struct ssdfs_fragment_raw_iterator *iter);

void SSDFS_LOG_OFFSET_INIT(struct ssdfs_peb_log_offset *log,
			   u32 block_size,
			   u32 log_blocks,
			   pgoff_t start_block);
bool IS_SSDFS_LOG_OFFSET_VALID(struct ssdfs_peb_log_offset *log);
u64 SSDFS_ABSOLUTE_LOG_OFFSET(struct ssdfs_peb_log_offset *log);
u32 SSDFS_LOCAL_LOG_OFFSET(struct ssdfs_peb_log_offset *log);
int SSDFS_SHIFT_LOG_OFFSET(struct ssdfs_peb_log_offset *log,
			   u32 shift);
bool IS_SSDFS_LOG_OFFSET_UNALIGNED(struct ssdfs_peb_log_offset *log);
void SSDFS_ALIGN_LOG_OFFSET(struct ssdfs_peb_log_offset *log);
u32 ssdfs_peb_correct_area_write_offset(u32 write_offset, u32 data_size);
int SSDFS_CORRECT_LOG_OFFSET(struct ssdfs_peb_log_offset *log,
			     u32 data_size);

size_t ssdfs_peb_temp_buffer_default_size(u32 pagesize);
int ssdfs_peb_realloc_read_buffer(struct ssdfs_peb_read_buffer *buf,
				  size_t new_size);
int ssdfs_peb_realloc_write_buffer(struct ssdfs_peb_temp_buffer *buf);

#endif /* _SSDFS_PEB_INIT_H */
