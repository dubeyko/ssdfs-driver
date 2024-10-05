/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_init.c - PEB init primitives implementation.
 *
 * Copyright (c) 2024 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 *
 */

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "compression.h"
#include "block_bitmap.h"
#include "segment_bitmap.h"
#include "folio_array.h"
#include "peb_init.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment.h"
#include "peb_mapping_table.h"

/*
 * ssdfs_create_content_stream() - create content stream
 */
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

	if ((log->cur_block - log->start_block) > log->log_blocks) {
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
bool IS_SSDFS_LOG_OFFSET_UNALIGNED(struct ssdfs_peb_log_offset *log)
{
	return SSDFS_LOCAL_LOG_OFFSET(log) % (1 << log->blocksize_shift);
}

/*
 * SSDFS_ALIGN_LOG_OFFSET() - align log offset on page size
 */
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

size_t ssdfs_peb_temp_buffer_default_size(u32 pagesize)
{
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	size_t size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(pagesize > SSDFS_128KB);
#endif /* CONFIG_SSDFS_DEBUG */

	size = (SSDFS_128KB / pagesize) * blk_desc_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page_size %u, default_size %zu\n",
		  pagesize, size);
#endif /* CONFIG_SSDFS_DEBUG */

	return size;
}

/*
 * ssdfs_peb_realloc_read_buffer() - realloc temporary read buffer
 * @buf: pointer on read buffer
 */
int ssdfs_peb_realloc_read_buffer(struct ssdfs_peb_read_buffer *buf,
				  size_t new_size)
{
	unsigned int nofs_flags;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!buf);
#endif /* CONFIG_SSDFS_DEBUG */

	if (buf->buf_size >= PAGE_SIZE) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to realloc buffer: "
			  "old_size %zu\n",
			  buf->buf_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return -E2BIG;
	}

	if (buf->buf_size == new_size) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("do nothing: old_size %zu, new_size %zu\n",
			  buf->buf_size, new_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	if (buf->buf_size > new_size) {
		SSDFS_ERR("shrink not supported\n");
		return -EOPNOTSUPP;
	}

	nofs_flags = memalloc_nofs_save();
	buf->ptr = krealloc(buf->ptr, new_size, GFP_KERNEL);
	memalloc_nofs_restore(nofs_flags);

	if (!buf->ptr) {
		SSDFS_ERR("fail to allocate buffer\n");
		return -ENOMEM;
	}

	buf->buf_size = new_size;

	return 0;
}

/*
 * ssdfs_peb_realloc_write_buffer() - realloc temporary write buffer
 * @buf: pointer on write buffer
 */
int ssdfs_peb_realloc_write_buffer(struct ssdfs_peb_temp_buffer *buf)
{
	size_t new_size;
	unsigned int nofs_flags;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!buf);
#endif /* CONFIG_SSDFS_DEBUG */

	if (buf->size >= PAGE_SIZE) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to realloc buffer: "
			  "old_size %zu\n",
			  buf->size);
#endif /* CONFIG_SSDFS_DEBUG */
		return -E2BIG;
	}

	new_size = min_t(size_t, buf->size * 2, (size_t)PAGE_SIZE);

	nofs_flags = memalloc_nofs_save();
	buf->ptr = krealloc(buf->ptr, new_size, GFP_KERNEL);
	memalloc_nofs_restore(nofs_flags);

	if (!buf->ptr) {
		SSDFS_ERR("fail to allocate buffer\n");
		return -ENOMEM;
	}

	buf->size = new_size;

	return 0;
}
