//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/block_bitmap.c - PEB's block bitmap implementation.
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

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "block_bitmap.h"

extern const bool detect_free_blk[U8_MAX + 1];
extern const bool detect_pre_allocated_blk[U8_MAX + 1];
extern const bool detect_valid_blk[U8_MAX + 1];
extern const bool detect_invalid_blk[U8_MAX + 1];

#define ALIGNED_START_BLK(blk) ({ \
	u32 aligned_blk; \
	aligned_blk = (blk >> SSDFS_BLK_STATE_BITS) << SSDFS_BLK_STATE_BITS; \
	aligned_blk; \
})

#define ALIGNED_END_BLK(blk) ({ \
	u32 aligned_blk; \
	aligned_blk = blk + SSDFS_ITEMS_PER_BYTE(SSDFS_BLK_STATE_BITS) - 1; \
	aligned_blk >>= SSDFS_BLK_STATE_BITS; \
	aligned_blk <<= SSDFS_BLK_STATE_BITS; \
	aligned_blk; \
})

#define SSDFS_BLK_BMAP_STATE_FLAGS_FNS(state, name)			\
static inline								\
bool is_block_bmap_##name(struct ssdfs_block_bmap *blk_bmap)		\
{									\
	return atomic_read(&blk_bmap->flags) & SSDFS_BLK_BMAP_##state;	\
}									\
static inline								\
void set_block_bmap_##name(struct ssdfs_block_bmap *blk_bmap)		\
{									\
	atomic_or(SSDFS_BLK_BMAP_##state, &blk_bmap->flags);		\
}									\
static inline								\
void clear_block_bmap_##name(struct ssdfs_block_bmap *blk_bmap)		\
{									\
	atomic_and(~SSDFS_BLK_BMAP_##state, &blk_bmap->flags);		\
}									\

/*
 * is_block_bmap_initialized()
 * set_block_bmap_initialized()
 * clear_block_bmap_initialized()
 */
SSDFS_BLK_BMAP_STATE_FLAGS_FNS(INITIALIZED, initialized)

/*
 * is_block_bmap_dirty()
 * set_block_bmap_dirty()
 * clear_block_bmap_dirty()
 */
SSDFS_BLK_BMAP_STATE_FLAGS_FNS(DIRTY, dirty)

static
int ssdfs_cache_block_state(struct ssdfs_block_bmap *blk_bmap,
			    u32 blk, int blk_state);

bool ssdfs_block_bmap_dirtied(struct ssdfs_block_bmap *blk_bmap)
{
	return is_block_bmap_dirty(blk_bmap);
}

bool ssdfs_block_bmap_initialized(struct ssdfs_block_bmap *blk_bmap)
{
	return is_block_bmap_initialized(blk_bmap);
}

static
int ssdfs_set_range_in_storage(struct ssdfs_block_bmap *blk_bmap,
				struct ssdfs_block_bmap_range *range,
				int blk_state);
static
int ssdfs_block_bmap_find_block_in_cache(struct ssdfs_block_bmap *blk_bmap,
					 u32 start, u32 max_blk,
					 int blk_state, u32 *found_blk);

/*
 * ssdfs_block_bmap_storage_destroy() - destroy block bitmap's storage
 * @storage: pointer on block bitmap's storage
 */
static
void ssdfs_block_bmap_storage_destroy(struct ssdfs_block_bmap_storage *storage)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!storage);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (storage->state) {
	case SSDFS_BLOCK_BMAP_STORAGE_PAGE_VEC:
		pagevec_release(&storage->pvec);
		break;

	case SSDFS_BLOCK_BMAP_STORAGE_BUFFER:
		if (storage->buf)
			kfree(storage->buf);
		break;

	default:
		SSDFS_WARN("unexpected state %#x\n", storage->state);
		break;
	}

	storage->state = SSDFS_BLOCK_BMAP_STORAGE_ABSENT;
}

/*
 * ssdfs_block_bmap_destroy() - destroy PEB's block bitmap
 * @blk_bmap: pointer on block bitmap
 *
 * This function releases memory pages of pagevec and
 * to free memory of ssdfs_block_bmap structure.
 */
void ssdfs_block_bmap_destroy(struct ssdfs_block_bmap *blk_bmap)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, items count %zu, "
		  "bmap bytes %zu\n",
		  blk_bmap, blk_bmap->items_count,
		  blk_bmap->bytes_count);

#ifdef CONFIG_SSDFS_DEBUG
	if (mutex_is_locked(&blk_bmap->lock))
		SSDFS_WARN("block bitmap's mutex is locked\n");
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_block_bmap_initialized(blk_bmap))
		SSDFS_WARN("block bitmap hasn't been initialized\n");

	if (is_block_bmap_dirty(blk_bmap))
		SSDFS_WARN("block bitmap is dirty\n");

	ssdfs_block_bmap_storage_destroy(&blk_bmap->storage);
}

/*
 * ssdfs_block_bmap_create_empty_storage() - create block bitmap's storage
 * @storage: pointer on block bitmap's storage
 * @bmap_bytes: number of bytes in block bitmap
 */
static
int ssdfs_block_bmap_create_empty_storage(struct ssdfs_block_bmap_storage *ptr,
					  size_t bmap_bytes)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("storage %p, bmap_bytes %zu\n",
		  ptr, bmap_bytes);

	ptr->state = SSDFS_BLOCK_BMAP_STORAGE_ABSENT;

	if (bmap_bytes > (PAGE_SIZE / 2)) {
		pagevec_init(&ptr->pvec);
		ptr->state = SSDFS_BLOCK_BMAP_STORAGE_PAGE_VEC;
	} else {
		ptr->buf = kmalloc(bmap_bytes, GFP_KERNEL);
		if (!ptr->buf) {
			SSDFS_ERR("fail to allocate memory: "
				  "bmap_bytes %zu\n",
				  bmap_bytes);
			return -ENOMEM;
		}

		ptr->state = SSDFS_BLOCK_BMAP_STORAGE_BUFFER;
	}

	return 0;
}

/*
 * ssdfs_block_bmap_init_clean_storage() - init clean block bitmap
 * @ptr: pointer on block bitmap object
 * @bmap_pages: memory pages count in block bitmap
 *
 * This function initializes storage space of the clean
 * block bitmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_block_bmap_init_clean_storage(struct ssdfs_block_bmap *ptr,
					size_t bmap_pages)
{
	struct page *page;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("bmap %p, storage_state %#x, "
		  "bmap_bytes %zu, bmap_pages %zu\n",
		  ptr, ptr->storage.state,
		  ptr->bytes_count, bmap_pages);

	switch (ptr->storage.state) {
	case SSDFS_BLOCK_BMAP_STORAGE_PAGE_VEC:
		for (i = 0; i < bmap_pages; i++) {
			if (pagevec_space(&ptr->storage.pvec) == 0) {
				SSDFS_ERR("unable to add page: i %d\n", i);
				return -ENOMEM;
			}

			page = alloc_page(GFP_KERNEL | __GFP_ZERO);
			if (unlikely(!page)) {
				SSDFS_ERR("unable to allocate #%d page\n", i);
				return -ENOMEM;
			}

			get_page(page);

			pagevec_add(&ptr->storage.pvec, page);
		}
		break;

	case SSDFS_BLOCK_BMAP_STORAGE_BUFFER:
		memset(ptr->storage.buf, 0, ptr->bytes_count);
		break;

	default:
		SSDFS_ERR("unexpected state %#x\n", ptr->storage.state);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_block_bmap_create() - construct PEB's block bitmap
 * @fsi: file system info object
 * @ptr: pointer on block bitmap object
 * @items_count: count of described items
 * @flag: define necessity to allocate memory
 * @init_state: block state is used during initialization
 *
 * This function prepares page vector and
 * makes initialization of ssdfs_block_bmap structure.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EOPNOTSUPP - pagevec is too small for block bitmap
 *                representation.
 * %-ENOMEM     - unable to allocate memory.
 */
int ssdfs_block_bmap_create(struct ssdfs_fs_info *fsi,
			    struct ssdfs_block_bmap *ptr,
			    u32 items_count,
			    int flag, int init_state)
{
	size_t bmap_bytes = 0;
	size_t bmap_pages = 0;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !ptr);

	if (init_state > SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", init_state);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, pagesize %u, segsize %u, pages_per_seg %u, "
		  "items_count %u, flag %#x, init_state %#x\n",
		  fsi, fsi->pagesize, fsi->segsize, fsi->pages_per_seg,
		  items_count, flag, init_state);

	bmap_bytes = BLK_BMAP_BYTES(items_count);
	bmap_pages = (bmap_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

	if (bmap_pages > PAGEVEC_SIZE) {
		SSDFS_WARN("unable to allocate bmap with %zu pages\n",
			    bmap_pages);
		return -EOPNOTSUPP;
	}

	mutex_init(&ptr->lock);
	atomic_set(&ptr->flags, 0);
	ptr->bytes_count = bmap_bytes;
	ptr->items_count = items_count;
	ptr->metadata_items = 0;
	ptr->invalid_blks = 0;

	err = ssdfs_block_bmap_create_empty_storage(&ptr->storage, bmap_bytes);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create empty bmap's storage: "
			  "bmap_bytes %zu, err %d\n",
			  bmap_bytes, err);
		return err;
	}

	for (i = 0; i < SSDFS_SEARCH_TYPE_MAX; i++) {
		ptr->last_search[i].page_index = PAGEVEC_SIZE;
		ptr->last_search[i].offset = U16_MAX;
	}

	if (flag == SSDFS_BLK_BMAP_INIT)
		goto alloc_end;

	err = ssdfs_block_bmap_init_clean_storage(ptr, bmap_pages);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init clean bmap's storage: "
			  "bmap_bytes %zu, bmap_pages %zu, err %d\n",
			  bmap_bytes, bmap_pages, err);
		goto destroy_pagevec;
	}

	if (init_state != SSDFS_BLK_FREE) {
		struct ssdfs_block_bmap_range range = {0, ptr->items_count};

		err = ssdfs_set_range_in_storage(ptr, &range, init_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to initialize block bmap: "
				  "range (start %u, len %u), "
				  "init_state %#x, err %d\n",
				  range.start, range.len, init_state, err);
			goto destroy_pagevec;
		}
	}

	err = ssdfs_cache_block_state(ptr, 0, SSDFS_BLK_FREE);
	if (unlikely(err)) {
		SSDFS_ERR("fail to cache last free page: err %d\n",
			  err);
		goto destroy_pagevec;
	}

	set_block_bmap_initialized(ptr);

alloc_end:
	return 0;

destroy_pagevec:
	ssdfs_block_bmap_destroy(ptr);
	return err;
}

/*
 * ssdfs_block_bmap_init_storage() - initialize block bitmap storage
 * @blk_bmap: pointer on block bitmap
 * @source: prepared pagevec after reading from volume
 *
 * This function initializes block bitmap's storage on
 * the basis of pages @source are read from volume.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_block_bmap_init_storage(struct ssdfs_block_bmap *blk_bmap,
				  struct pagevec *source)
{
	struct page *page;
	void *kaddr;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !source);

	if (!mutex_is_locked(&blk_bmap->lock)) {
		SSDFS_WARN("block bitmap mutex should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("bmap %p, bmap_bytes %zu\n",
		  blk_bmap, blk_bmap->bytes_count);

	if (blk_bmap->storage.state != SSDFS_BLOCK_BMAP_STORAGE_ABSENT) {
		switch (blk_bmap->storage.state) {
		case SSDFS_BLOCK_BMAP_STORAGE_PAGE_VEC:
			pagevec_release(&blk_bmap->storage.pvec);
			pagevec_reinit(&blk_bmap->storage.pvec);
			break;

		case SSDFS_BLOCK_BMAP_STORAGE_BUFFER:
			/* Do nothing. We have buffer already */
			break;

		default:
			BUG();
		}
	} else {
		err = ssdfs_block_bmap_create_empty_storage(&blk_bmap->storage,
							blk_bmap->bytes_count);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create empty bmap's storage: "
				  "err %d\n", err);
			return err;
		}
	}

	switch (blk_bmap->storage.state) {
	case SSDFS_BLOCK_BMAP_STORAGE_PAGE_VEC:
		for (i = 0; i < pagevec_count(source); i++) {
			if (!source->pages[i]) {
				SSDFS_WARN("page %d is NULL\n", i);
				return -ERANGE;
			}

			get_page(source->pages[i]);

#ifdef CONFIG_SSDFS_DEBUG
			kaddr = kmap(source->pages[i]);
			SSDFS_DBG("BMAP INIT\n");
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr, 32);
			kunmap(source->pages[i]);
#endif /* CONFIG_SSDFS_DEBUG */

			pagevec_add(&blk_bmap->storage.pvec, source->pages[i]);
			unlock_page(source->pages[i]);
			source->pages[i] = NULL;
		}
		break;

	case SSDFS_BLOCK_BMAP_STORAGE_BUFFER:
		if (pagevec_count(source) > 1) {
			SSDFS_ERR("invalid source pvec size %u\n",
				  pagevec_count(source));
			return -ERANGE;
		}

		page = source->pages[0];

		if (!page) {
			SSDFS_WARN("page %d is NULL\n", 0);
			return -ERANGE;
		}

		get_page(page);

		kaddr = kmap_atomic(page);
		memcpy(blk_bmap->storage.buf, kaddr, blk_bmap->bytes_count);
		kunmap_atomic(kaddr);

#ifdef CONFIG_SSDFS_DEBUG
		kaddr = kmap(page);
		SSDFS_DBG("BMAP INIT\n");
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr, 32);
		kunmap(page);
#endif /* CONFIG_SSDFS_DEBUG */

		unlock_page(page);
		put_page(page);
		break;

	default:
		SSDFS_ERR("unexpected state %#x\n",
			  blk_bmap->storage.state);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_block_bmap_init() - initialize block bitmap pagevec
 * @blk_bmap: pointer on block bitmap
 * @source: prepared pagevec after reading from volume
 * @last_free_blk: saved on volume last free page
 * @metadata_blks: saved on volume reserved metadata blocks count
 * @invalid_blks: saved on volume count of invalid blocks
 *
 * This function initializes block bitmap's pagevec on
 * the basis of pages @source are read from volume.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
int ssdfs_block_bmap_init(struct ssdfs_block_bmap *blk_bmap,
			  struct pagevec *source,
			  u16 last_free_blk,
			  u16 metadata_blks,
			  u16 invalid_blks)
{
	int free_pages;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !source);

	if (!mutex_is_locked(&blk_bmap->lock)) {
		SSDFS_WARN("block bitmap mutex should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, source %p, "
		  "last_free_blk %u, metadata_blks %u, invalid_blks %u\n",
		  blk_bmap, source,
		  last_free_blk, metadata_blks, invalid_blks);

	if (is_block_bmap_initialized(blk_bmap)) {
		if (is_block_bmap_dirty(blk_bmap)) {
			SSDFS_WARN("block bitmap has been initialized\n");
			return -ERANGE;
		}

		free_pages = ssdfs_block_bmap_get_free_pages(blk_bmap);
		if (unlikely(free_pages < 0)) {
			err = free_pages;
			SSDFS_ERR("fail to define free pages: err %d\n",
				  err);
			return err;
		}

		if (free_pages != blk_bmap->items_count) {
			SSDFS_WARN("block bitmap has been initialized\n");
			return -ERANGE;
		}

		for (i = 0; i < SSDFS_SEARCH_TYPE_MAX; i++) {
			blk_bmap->last_search[i].page_index = PAGEVEC_SIZE;
			blk_bmap->last_search[i].offset = U16_MAX;
		}

		ssdfs_block_bmap_storage_destroy(&blk_bmap->storage);
		clear_block_bmap_initialized(blk_bmap);
	}

	if (pagevec_count(source) == 0) {
		SSDFS_ERR("fail to init because of empty pagevec\n");
		return -EINVAL;
	}

	if (last_free_blk > blk_bmap->items_count) {
		SSDFS_ERR("invalid values: "
			  "last_free_blk %u, items_count %zu\n",
			  last_free_blk, blk_bmap->items_count);
		return -EINVAL;
	}

	if (metadata_blks > blk_bmap->items_count) {
		SSDFS_ERR("invalid values: "
			  "metadata_blks %u, items_count %zu\n",
			  metadata_blks, blk_bmap->items_count);
		return -EINVAL;
	}

	blk_bmap->metadata_items = metadata_blks;

	if (invalid_blks > blk_bmap->items_count ||
	    invalid_blks > last_free_blk) {
		SSDFS_ERR("invalid values: "
			  "invalid_blks %u, last_free_blk %u, "
			  "items_count %zu\n",
			  invalid_blks, last_free_blk,
			  blk_bmap->items_count);
		return -EINVAL;
	}

	blk_bmap->invalid_blks = invalid_blks;

	err = ssdfs_block_bmap_init_storage(blk_bmap, source);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init bmap's storage: err %d\n",
			  err);
		return err;
	}

	pagevec_reinit(source);

	err = ssdfs_cache_block_state(blk_bmap, last_free_blk, SSDFS_BLK_FREE);
	if (unlikely(err)) {
		SSDFS_ERR("fail to cache last free page %u, err %d\n",
			  last_free_blk, err);
		return err;
	}

	set_block_bmap_initialized(blk_bmap);

	return 0;
}

/*
 * ssdfs_define_last_free_page() - define last free page
 * @blk_bmap: pointer on block bitmap
 * @found_blk: found last free page [out]
 */
static
int ssdfs_define_last_free_page(struct ssdfs_block_bmap *blk_bmap,
				u32 *found_blk)
{
	int cache_type;
	struct ssdfs_last_bmap_search *last_search;
	u32 first_cached_blk;
	u32 max_blk;
	int err;

	SSDFS_DBG("blk_bmap %p, found_blk %p\n",
		  blk_bmap, found_blk);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !found_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	cache_type = SSDFS_GET_CACHE_TYPE(SSDFS_BLK_FREE);
	max_blk = blk_bmap->items_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(cache_type >= SSDFS_SEARCH_TYPE_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	last_search = &blk_bmap->last_search[cache_type];

	SSDFS_DBG("last_search.cache %lx\n", last_search->cache);

	first_cached_blk = SSDFS_FIRST_CACHED_BLOCK(last_search);

	err = ssdfs_block_bmap_find_block_in_cache(blk_bmap, first_cached_blk,
						   max_blk, SSDFS_BLK_FREE,
						   found_blk);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find last free block: err %d\n",
			  err);
		return err;
	}

	SSDFS_DBG("last free block: %u\n", *found_blk);

	return 0;
}

/*
 * ssdfs_block_bmap_snapshot_storage() - make snapshot of bmap's storage
 * @blk_bmap: pointer on block bitmap
 * @snapshot: pagevec with snapshot of block bitmap state [out]
 *
 * This function copies pages of block bitmap's styorage into
 * @snapshot pagevec.
 *
 * RETURN:
 * [success] - @snapshot contains copy of block bitmap's state
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 */
static
int ssdfs_block_bmap_snapshot_storage(struct ssdfs_block_bmap *blk_bmap,
					struct pagevec *snapshot)
{
	struct page *page;
	void *kaddr1, *kaddr2;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !snapshot);
	BUG_ON(pagevec_count(snapshot) != 0);

	if (!mutex_is_locked(&blk_bmap->lock)) {
		SSDFS_WARN("block bitmap's mutex should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, snapshot %p\n",
		  blk_bmap, snapshot);

	switch (blk_bmap->storage.state) {
	case SSDFS_BLOCK_BMAP_STORAGE_PAGE_VEC:
		for (i = 0; i < pagevec_count(&blk_bmap->storage.pvec); i++) {
			page = alloc_page(GFP_KERNEL);
			if (unlikely(!page)) {
				SSDFS_ERR("unable to allocate #%d page\n", i);
				return -ENOMEM;
			}

			get_page(page);

			kaddr1 = kmap_atomic(blk_bmap->storage.pvec.pages[i]);
			kaddr2 = kmap_atomic(page);
			memcpy(kaddr2, kaddr1, PAGE_SIZE);
			kunmap_atomic(kaddr2);
			kunmap_atomic(kaddr1);

#ifdef CONFIG_SSDFS_DEBUG
			kaddr1 = kmap(page);
			SSDFS_DBG("BMAP SNAPSHOT\n");
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr1, 32);
			kunmap(page);
#endif /* CONFIG_SSDFS_DEBUG */

			pagevec_add(snapshot, page);
		}
		break;

	case SSDFS_BLOCK_BMAP_STORAGE_BUFFER:
		page = alloc_page(GFP_KERNEL);
		if (unlikely(!page)) {
			SSDFS_ERR("unable to allocate page\n");
			return -ENOMEM;
		}

		get_page(page);

		kaddr1 = blk_bmap->storage.buf;
		kaddr2 = kmap_atomic(page);
		memcpy(kaddr2, kaddr1, PAGE_SIZE);
		kunmap_atomic(kaddr2);

#ifdef CONFIG_SSDFS_DEBUG
		kaddr1 = kmap(page);
		SSDFS_DBG("BMAP SNAPSHOT\n");
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr1, 32);
		kunmap(page);
#endif /* CONFIG_SSDFS_DEBUG */

		pagevec_add(snapshot, page);
		break;

	default:
		SSDFS_ERR("unexpected state %#x\n",
			  blk_bmap->storage.state);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_block_bmap_snapshot() - make snapshot of block bitmap's pagevec
 * @blk_bmap: pointer on block bitmap
 * @snapshot: pagevec with snapshot of block bitmap state [out]
 * @last_free_blk: pointer on last free page value [out]
 * @metadata_blks: pointer on reserved metadata pages count [out]
 * @invalid_blks: pointer on invalid blocks count [out]
 * @bytes_count: size of block bitmap in bytes [out]
 *
 * This function copy pages of block bitmap's pagevec into
 * @snapshot pagevec.
 *
 * RETURN:
 * [success] - @snapshot contains copy of block bitmap's state
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 */
int ssdfs_block_bmap_snapshot(struct ssdfs_block_bmap *blk_bmap,
				struct pagevec *snapshot,
				u32 *last_free_page,
				u32 *metadata_blks,
				u32 *invalid_blks,
				size_t *bytes_count)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !snapshot);
	BUG_ON(!last_free_page || !metadata_blks || !bytes_count);
	BUG_ON(pagevec_count(snapshot) != 0);

	if (!mutex_is_locked(&blk_bmap->lock)) {
		SSDFS_WARN("block bitmap's mutex should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, snapshot %p, last_free_page %p, "
		  "metadata_blks %p, bytes_count %p\n",
		  blk_bmap, snapshot, last_free_page,
		  metadata_blks, bytes_count);

	if (!is_block_bmap_initialized(blk_bmap)) {
		SSDFS_WARN("block bitmap hasn't been initialized\n");
		return -EINVAL;
	}

	err = ssdfs_block_bmap_snapshot_storage(blk_bmap, snapshot);
	if (unlikely(err)) {
		SSDFS_ERR("fail to snapshot bmap's storage: err %d\n", err);
		goto cleanup_snapshot_pagevec;
	}

	err = ssdfs_define_last_free_page(blk_bmap, last_free_page);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define last free page: err %d\n", err);
		goto cleanup_snapshot_pagevec;
	}

	*metadata_blks = blk_bmap->metadata_items;

	if ((*metadata_blks + *last_free_page) > blk_bmap->items_count) {
		err = -ERANGE;
		SSDFS_ERR("invalid values: "
			  "metadata_blks %u, last_free_blk %u, "
			  "items_count %zu\n",
			  *metadata_blks, *last_free_page,
			  blk_bmap->items_count);
		goto cleanup_snapshot_pagevec;
	}

	*invalid_blks = blk_bmap->invalid_blks;

	if ((*invalid_blks + *last_free_page) > blk_bmap->items_count) {
		err = -ERANGE;
		SSDFS_ERR("invalid values: "
			  "invalid_blks %u, last_free_blk %u, "
			  "items_count %zu\n",
			  *invalid_blks, *last_free_page,
			  blk_bmap->items_count);
		goto cleanup_snapshot_pagevec;
	}

	*bytes_count = blk_bmap->bytes_count;

	clear_block_bmap_dirty(blk_bmap);

	SSDFS_DBG("last_free_page %u, metadata_blks %u, "
		  "bytes_count %zu\n",
		  *last_free_page, *metadata_blks, *bytes_count);

	return 0;

cleanup_snapshot_pagevec:
	pagevec_release(snapshot);
	return err;
}

/*
 * ssdfs_block_bmap_lock() - lock segment's block bitmap
 * @blk_bmap: pointer on block bitmap
 */
int ssdfs_block_bmap_lock(struct ssdfs_block_bmap *blk_bmap)
{
	int err;

	SSDFS_DBG("blk_bmap %p\n", blk_bmap);

	err = mutex_lock_killable(&blk_bmap->lock);
	if (err) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_block_bmap_is_locked() - check that block bitmap is locked
 * @blk_bmap: pointer on block bitmap
 */
bool ssdfs_block_bmap_is_locked(struct ssdfs_block_bmap *blk_bmap)
{
	return mutex_is_locked(&blk_bmap->lock);
}

/*
 * ssdfs_block_bmap_unlock() - unlock segment's block bitmap
 * @blk_bmap: pointer on block bitmap
 */
void ssdfs_block_bmap_unlock(struct ssdfs_block_bmap *blk_bmap)
{
	SSDFS_DBG("blk_bmap %p\n", blk_bmap);
	mutex_unlock(&blk_bmap->lock);
}

/*
 * ssdfs_get_cache_type() - define cache type for block
 * @blk_bmap: pointer on block bitmap
 * @blk: block number
 *
 * RETURN:
 * [success] - cache type
 * [failure] - SSDFS_SEARCH_TYPE_MAX
 */
static
int ssdfs_get_cache_type(struct ssdfs_block_bmap *blk_bmap,
			 u32 blk)
{
	int page_index;
	u16 offset;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, block %u\n", blk_bmap, blk);

	page_index = SSDFS_BLK2PAGE(blk, SSDFS_BLK_STATE_BITS, &offset);

	for (i = 0; i < SSDFS_SEARCH_TYPE_MAX; i++) {
		struct ssdfs_last_bmap_search *last;

		last = &blk_bmap->last_search[i];
		if (last->page_index == page_index &&
		    last->offset == offset)
			return i;
	}

	return SSDFS_SEARCH_TYPE_MAX;
}

/*
 * is_block_state_cached() - check that block state is in cache
 * @blk_bmap: pointer on block bitmap
 * @blk: block number
 *
 * RETURN:
 * [true]  - block state is in cache
 * [false] - cache doesn't contain block state
 */
static
bool is_block_state_cached(struct ssdfs_block_bmap *blk_bmap,
			   u32 blk)
{
	int cache_type;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, block %u\n", blk_bmap, blk);

	cache_type = ssdfs_get_cache_type(blk_bmap, blk);

	if (cache_type < 0) {
		SSDFS_ERR("invalid cache type %d\n", cache_type);
		return false;
	}

	if (cache_type >= SSDFS_SEARCH_TYPE_MAX)
		return false;

	return true;
}

/*
 * ssdfs_determine_cache_type() - detect type of cache for value
 * @cache: value for caching
 *
 * RETURN: suggested type of cache
 */
static
int ssdfs_determine_cache_type(unsigned long cache)
{
	size_t bytes_per_long = sizeof(cache);
	size_t criterion = bytes_per_long / 2;
	u8 bytes[SSDFS_BLK_STATE_MAX] = {0};
	int i;

	for (i = 0; i < bytes_per_long; i++) {
		int cur_state = (int)((cache >> (i * BITS_PER_BYTE)) & 0xFF);

		switch (cur_state) {
		case SSDFS_FREE_STATES_BYTE:
			bytes[SSDFS_BLK_FREE]++;
			break;

		case SSDFS_PRE_ALLOC_STATES_BYTE:
			bytes[SSDFS_BLK_PRE_ALLOCATED]++;
			break;

		case SSDFS_VALID_STATES_BYTE:
			bytes[SSDFS_BLK_VALID]++;
			break;

		case SSDFS_INVALID_STATES_BYTE:
			bytes[SSDFS_BLK_INVALID]++;
			break;

		default:
			/* mix of block states */
			break;
		};
	}

	if (bytes[SSDFS_BLK_FREE] > criterion)
		return SSDFS_FREE_BLK_SEARCH;
	else if (bytes[SSDFS_BLK_VALID] > criterion)
		return SSDFS_VALID_BLK_SEARCH;

	return SSDFS_OTHER_BLK_SEARCH;
}

/*
 * ssdfs_cache_block_state() - cache block state from pagevec
 * @blk_bmap: pointer on block bitmap
 * @blk: segment's block
 * @blk_state: state as hint for cache type determination
 *
 * This function retrieves state of @blk from pagevec
 * and  save retrieved value for requested type of cache.
 * If @blk_state has SSDFS_BLK_STATE_MAX value then function
 * defines block state and to cache value in proper place.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-EOPNOTSUPP - invalid page index.
 */
static
int ssdfs_cache_block_state(struct ssdfs_block_bmap *blk_bmap,
			    u32 blk, int blk_state)
{
	int page_index;
	u16 offset;
	void *kaddr;
	unsigned long cache;
	int cache_type;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, block %u, state %#x\n",
		  blk_bmap, blk, blk_state);

	if (blk_state > SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return -EINVAL;
	}

	if (is_block_state_cached(blk_bmap, blk)) {
		SSDFS_DBG("block %u has been cached already\n", blk);
		return 0;
	}

	page_index = SSDFS_BLK2PAGE(blk, SSDFS_BLK_STATE_BITS, &offset);

	if (page_index >= PAGEVEC_SIZE) {
		SSDFS_ERR("invalid page index %d\n", page_index);
		return -EOPNOTSUPP;
	}

	if (offset >= PAGE_SIZE) {
		SSDFS_ERR("invalid offset inside page %u\n", (u32)offset);
		return -EINVAL;
	}

	switch (blk_bmap->storage.state) {
	case SSDFS_BLOCK_BMAP_STORAGE_PAGE_VEC:
		kaddr = kmap_atomic(blk_bmap->storage.pvec.pages[page_index]);
		memcpy(&cache, (u8 *)kaddr + offset, sizeof(unsigned long));
		kunmap_atomic(kaddr);
		break;

	case SSDFS_BLOCK_BMAP_STORAGE_BUFFER:
		if (page_index > 0) {
			SSDFS_ERR("invalid page_index %d\n", page_index);
			return -ERANGE;
		}

		kaddr = blk_bmap->storage.buf;
		memcpy(&cache, (u8 *)kaddr + offset, sizeof(unsigned long));
		break;

	default:
		SSDFS_ERR("unexpected state %#x\n", blk_bmap->storage.state);
		return -ERANGE;
	}

	cache_type = ssdfs_determine_cache_type(cache);
	BUG_ON(cache_type >= SSDFS_SEARCH_TYPE_MAX);

	if (blk_state < SSDFS_BLK_STATE_MAX)
		cache_type = blk_state;

	blk_bmap->last_search[cache_type].page_index = page_index;
	blk_bmap->last_search[cache_type].offset = offset;
	blk_bmap->last_search[cache_type].cache = cache;

	SSDFS_DBG("last_search.cache %lx\n", cache);

	return 0;
}

/*
 * ssdfs_define_bits_shift_in_cache() - calculate bit shift of block in cache
 * @blk_bmap: pointer on block bitmap
 * @cache_type: type of cache
 * @blk: segment's block
 *
 * This function calculates bit shift of @blk in cache of
 * @cache_type.
 *
 * RETURN:
 * [success] - bit shift
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 */
static
int ssdfs_define_bits_shift_in_cache(struct ssdfs_block_bmap *blk_bmap,
				     int cache_type, u32 blk)
{
	struct ssdfs_last_bmap_search *last_search;
	u32 first_cached_block, diff;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);

	if (blk >= blk_bmap->items_count) {
		SSDFS_ERR("invalid block %u\n", blk);
		return -EINVAL;
	}

	if (cache_type < 0) {
		SSDFS_ERR("invalid cache type %d\n", cache_type);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, cache_type %#x, blk %u\n",
		  blk_bmap, cache_type, blk);

	if (cache_type >= SSDFS_SEARCH_TYPE_MAX) {
		SSDFS_ERR("cache doesn't contain block %u\n", blk);
		return -EINVAL;
	}

	last_search = &blk_bmap->last_search[cache_type];

	SSDFS_DBG("last_search.cache %lx\n", last_search->cache);

	first_cached_block = SSDFS_FIRST_CACHED_BLOCK(last_search);

	if (first_cached_block > blk) {
		SSDFS_ERR("first_cached_block %u > blk %u\n",
			  first_cached_block, blk);
		return -EINVAL;
	}

	diff = blk - first_cached_block;

#ifdef CONFIG_SSDFS_DEBUG
	if (diff >= (U32_MAX / SSDFS_BLK_STATE_BITS)) {
		SSDFS_ERR("invalid diff %u; blk %u, first_cached_block %u\n",
			  diff, blk, first_cached_block);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	diff *= SSDFS_BLK_STATE_BITS;

#ifdef CONFIG_SSDFS_DEBUG
	if (diff > (BITS_PER_LONG - SSDFS_BLK_STATE_BITS)) {
		SSDFS_ERR("invalid diff %u; bits_per_long %u, "
			  "bits_per_state %u\n",
			  diff, BITS_PER_LONG, SSDFS_BLK_STATE_BITS);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("diff %u\n", diff);

	return (int)diff;
}

/*
 * ssdfs_get_block_state_from_cache() - retrieve block state from cache
 * @blk_bmap: pointer on block bitmap
 * @blk: segment's block
 *
 * This function retrieve state of @blk from cache.
 *
 * RETURN:
 * [success] - state of block
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 */
static
int ssdfs_get_block_state_from_cache(struct ssdfs_block_bmap *blk_bmap,
				     u32 blk)
{
	int cache_type;
	struct ssdfs_last_bmap_search *last_search;
	int shift;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);

	if (blk >= blk_bmap->items_count) {
		SSDFS_ERR("invalid block %u\n", blk);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, block %u\n", blk_bmap, blk);

	cache_type = ssdfs_get_cache_type(blk_bmap, blk);
	shift = ssdfs_define_bits_shift_in_cache(blk_bmap, cache_type, blk);
	if (unlikely(shift < 0)) {
		SSDFS_ERR("fail to define bits shift: "
			  "cache_type %d, blk %u, err %d\n",
			  cache_type, blk, shift);
		return shift;
	}

	last_search = &blk_bmap->last_search[cache_type];

	SSDFS_DBG("last_search.cache %lx\n", last_search->cache);

	return (int)((last_search->cache >> shift) & SSDFS_BLK_STATE_MASK);
}

/*
 * ssdfs_set_block_state_in_cache() - set block state in cache
 * @blk_bmap: pointer on block bitmap
 * @blk: segment's block
 * @blk_state: new state of @blk
 *
 * This function sets state @blk_state of @blk in cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 */
static
int ssdfs_set_block_state_in_cache(struct ssdfs_block_bmap *blk_bmap,
				   u32 blk, int blk_state)
{
	int cache_type;
	int shift;
	unsigned long value, *cached_value;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);

	if (blk >= blk_bmap->items_count) {
		SSDFS_ERR("invalid block %u\n", blk);
		return -EINVAL;
	}

	if (blk_state > SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, block %u, blk_state %#x\n",
		  blk_bmap, blk, blk_state);

	cache_type = ssdfs_get_cache_type(blk_bmap, blk);
	shift = ssdfs_define_bits_shift_in_cache(blk_bmap, cache_type, blk);
	if (unlikely(shift < 0)) {
		SSDFS_ERR("fail to define bits shift: "
			  "cache_type %d, blk %u, err %d\n",
			  cache_type, blk, shift);
		return shift;
	}

	value = blk_state & SSDFS_BLK_STATE_MASK;
	value <<= shift;

	SSDFS_DBG("value %lx, cache %lx\n",
		  value,
		  blk_bmap->last_search[cache_type].cache);

	cached_value = &blk_bmap->last_search[cache_type].cache;
	*cached_value &= ~((unsigned long)SSDFS_BLK_STATE_MASK << shift);
	*cached_value |= value;

	return 0;
}

/*
 * ssdfs_save_cache_in_storage() - save cached values in storage
 * @blk_bmap: pointer on block bitmap
 *
 * This function saves cached values in storage.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 */
static
int ssdfs_save_cache_in_storage(struct ssdfs_block_bmap *blk_bmap)
{
	struct pagevec *pvec;
	void *kaddr;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p\n", blk_bmap);

	for (i = 0; i < SSDFS_SEARCH_TYPE_MAX; i++) {
		int page_index = blk_bmap->last_search[i].page_index;
		u16 offset = blk_bmap->last_search[i].offset;
		unsigned long cache = blk_bmap->last_search[i].cache;

		SSDFS_DBG("search_type %d, page_index %d, offset %u\n",
			  i, page_index, offset);
		SSDFS_DBG("last_search.cache %lx\n", cache);

		if (page_index == PAGEVEC_SIZE || offset == U16_MAX)
			continue;

		if (page_index > PAGEVEC_SIZE || offset >= PAGE_SIZE) {
			SSDFS_ERR("block bmap's cache is corrupted: "
				  "page_index %d, offset %u\n",
				  page_index, (u32)offset);
			return -EINVAL;
		}

		switch (blk_bmap->storage.state) {
		case SSDFS_BLOCK_BMAP_STORAGE_PAGE_VEC:
			pvec = &blk_bmap->storage.pvec;
			kaddr = kmap_atomic(pvec->pages[page_index]);
			memcpy((u8 *)kaddr + offset, &cache,
				sizeof(unsigned long));
			kunmap_atomic(kaddr);
			break;

		case SSDFS_BLOCK_BMAP_STORAGE_BUFFER:
			if (page_index > 0) {
				SSDFS_ERR("invalid page_index %d\n", page_index);
				return -ERANGE;
			}

			kaddr = blk_bmap->storage.buf;
			memcpy((u8 *)kaddr + offset, &cache,
				sizeof(unsigned long));
			break;

		default:
			SSDFS_ERR("unexpected state %#x\n",
					blk_bmap->storage.state);
			return -ERANGE;
		}
	}

	return 0;
}

/*
 * is_cache_invalid() - check that cache is invalid for requested state
 * @blk_bmap: pointer on block bitmap
 * @blk_state: requested block's state
 *
 * RETURN:
 * [true]  - cache doesn't been initialized yet.
 * [false] - cache is valid.
 */
static inline
bool is_cache_invalid(struct ssdfs_block_bmap *blk_bmap, int blk_state)
{
	struct ssdfs_last_bmap_search *last_search;
	int cache_type = SSDFS_GET_CACHE_TYPE(blk_state);

	if (cache_type >= SSDFS_SEARCH_TYPE_MAX) {
		SSDFS_ERR("invalid cache type %#x, blk_state %#x\n",
			  cache_type, blk_state);
		return true;
	}

	last_search = &blk_bmap->last_search[cache_type];

	SSDFS_DBG("last_search.cache %lx\n", last_search->cache);

	if (last_search->page_index >= PAGEVEC_SIZE ||
	    last_search->offset == U16_MAX)
		return true;

	return false;
}

/*
 * ssdfs_block_bmap_correct_max_blk() - correct requested maximum block number
 * @blk_bmap: pointer on block bitmap
 * @max_blk: requested maximum block number
 * @blk_state: requested block's state
 *
 * This function corrects @max_blk value with taking into account
 * requested @blk_state. Namely, items count in block bitmap is
 * upper bound for search of free block. Otherwise, for pre-allocated,
 * valid and invalid states first free block can be the upper
 * bound during search.
 *
 * RETURN:
 * [success] - corrected value of upper bound for search.
 */
static inline
u32 ssdfs_block_bmap_correct_max_blk(struct ssdfs_block_bmap *blk_bmap,
				     u32 max_blk, int blk_state)
{
	struct ssdfs_last_bmap_search *search;
	u32 cached_max;

	if (blk_state == SSDFS_BLK_FREE)
		return min_t(u32, max_blk, blk_bmap->items_count);

	if (!is_cache_invalid(blk_bmap, SSDFS_BLK_FREE)) {
		search = &blk_bmap->last_search[SSDFS_FREE_BLK_SEARCH];

		SSDFS_DBG("last_search.cache %lx\n", search->cache);

		cached_max = SSDFS_FIRST_CACHED_BLOCK(search);
		cached_max += SSDFS_ITEMS_PER_LONG(SSDFS_BLK_STATE_BITS);
		return min_t(u32, max_blk, cached_max);
	}

	return min_t(u32, max_blk, blk_bmap->items_count);
}

/*
 * BYTE_CONTAINS_STATE() - check that provided byte contains state
 * @value: pointer on analysed byte
 * @blk_state: requested block's state
 *
 * RETURN:
 * [true]  - @value contains @blk_state.
 * [false] - @value hasn't @blk_state.
 */
static inline
bool BYTE_CONTAINS_STATE(u8 *value, int blk_state)
{
	switch (blk_state) {
	case SSDFS_BLK_FREE:
		return detect_free_blk[*value];

	case SSDFS_BLK_PRE_ALLOCATED:
		return detect_pre_allocated_blk[*value];

	case SSDFS_BLK_VALID:
		return detect_valid_blk[*value];

	case SSDFS_BLK_INVALID:
		return detect_invalid_blk[*value];
	};

	return false;
}

/*
 * ssdfs_block_bmap_find_block_in_cache() - find block for state in cache
 * @blk_bmap: pointer on block bitmap
 * @start: starting block for search
 * @max_blk: upper bound for search
 * @blk_state: requested block's state
 * @found_blk: pointer on found block for requested state [out]
 *
 * This function tries to find in block block bitmap with @blk_state
 * in range [@start, @max_blk).
 *
 * RETURN:
 * [success] - @found_blk contains found block number for @blk_state.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENODATA    - requested range [@start, @max_blk) doesn't contain
 *                any block with @blk_state.
 */
static
int ssdfs_block_bmap_find_block_in_cache(struct ssdfs_block_bmap *blk_bmap,
					 u32 start, u32 max_blk,
					 int blk_state, u32 *found_blk)
{
	int cache_type = SSDFS_GET_CACHE_TYPE(blk_state);
	u32 items_per_byte = SSDFS_ITEMS_PER_BYTE(SSDFS_BLK_STATE_BITS);
	struct ssdfs_last_bmap_search *last_search;
	u32 first_cached_blk;
	u32 byte_index;
	u8 blks_diff;
	size_t bytes_per_long = sizeof(unsigned long);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !found_blk);

	if (blk_state > SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return -EINVAL;
	}

	if (start >= blk_bmap->items_count) {
		SSDFS_ERR("invalid start block %u\n", start);
		return -EINVAL;
	}

	if (start > max_blk) {
		SSDFS_ERR("start %u > max_blk %u\n", start, max_blk);
		return -EINVAL;
	}

	if (!is_block_state_cached(blk_bmap, start)) {
		SSDFS_ERR("cache doesn't contain start %u\n", start);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, start %u, max_blk %u, "
		  "state %#x, found_blk %p\n",
		  blk_bmap, start, max_blk, blk_state, found_blk);

	if (cache_type >= SSDFS_SEARCH_TYPE_MAX) {
		SSDFS_ERR("invalid cache type %#x, blk_state %#x\n",
			  cache_type, blk_state);
		return -EINVAL;
	}

	*found_blk = U32_MAX;
	max_blk = ssdfs_block_bmap_correct_max_blk(blk_bmap, max_blk,
						   blk_state);

	last_search = &blk_bmap->last_search[cache_type];

	SSDFS_DBG("last_search.cache %lx\n", last_search->cache);

	first_cached_blk = SSDFS_FIRST_CACHED_BLOCK(last_search);
	blks_diff = start - first_cached_blk;
	byte_index = blks_diff / items_per_byte;
	blks_diff = blks_diff % items_per_byte;

	SSDFS_DBG("first_cached_blk %u, start %u, "
		  "byte_index %u, bytes_per_long %zu\n",
		  first_cached_blk, start,
		  byte_index, bytes_per_long);

	for (; byte_index < bytes_per_long; byte_index++) {
		u8 *value = (u8 *)&last_search->cache + byte_index;
		u8 found_off;

		err = FIND_FIRST_ITEM_IN_BYTE(value, blk_state,
					      SSDFS_BLK_STATE_BITS,
					      SSDFS_BLK_STATE_MASK,
					      blks_diff,
					      BYTE_CONTAINS_STATE,
					      FIRST_STATE_IN_BYTE,
					      &found_off);
		if (err == -ENODATA) {
			blks_diff = 0;
			continue;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find block in byte: "
				  "start_off %u, blk_state %#x, err %d\n",
				  blks_diff, blk_state, err);
			return err;
		}

		*found_blk = first_cached_blk;
		*found_blk += byte_index * items_per_byte;
		*found_blk += found_off;

		SSDFS_DBG("block %u has been found for state %#x\n",
			  *found_blk, blk_state);

		return 0;
	}

	return -ENODATA;
}

static inline
void ssdfs_block_bmap_define_start_item(int page_index,
					u32 start,
					u32 aligned_start,
					u32 aligned_end,
					u32 *start_byte,
					u32 *rest_bytes,
					u8 *item_offset)
{
	u32 items_per_byte = SSDFS_ITEMS_PER_BYTE(SSDFS_BLK_STATE_BITS);
	u32 items_per_page = PAGE_SIZE * items_per_byte;
	u32 items;
	u32 offset;

	if ((page_index * items_per_page) <= aligned_start)
		offset = aligned_start % items_per_page;
	else
		offset = aligned_start;

	*start_byte = offset / items_per_byte;

	items = items_per_page - offset;

	if (aligned_end <= start) {
		SSDFS_WARN("aligned_end %u <= start %u\n",
			   aligned_end, start);
	} else
		items = min_t(u32, items, aligned_end);

	*rest_bytes = items + items_per_byte - 1;
	*rest_bytes /= items_per_byte;

	*item_offset = (u8)(start - aligned_start);

	SSDFS_DBG("page_index %d, start %u, aligned_start %u, "
		  "start_byte %u, rest_bytes %u, item_offset %u\n",
		  page_index, start, aligned_start,
		  *start_byte, *rest_bytes, *item_offset);
}

/*
 * ssdfs_block_bmap_find_block_in_memory_range() - find block in memory range
 * @kaddr: pointer on memory range
 * @blk_state: requested state of searching block
 * @byte_index: index of byte in memory range [in|out]
 * @search_bytes: upper bound for search
 * @start_off: starting bit offset in byte
 * @found_off: pointer on found byte's offset [out]
 *
 * This function searches a block with requested @blk_state
 * into memory range.
 *
 * RETURN:
 * [success] - found byte's offset in @found_off.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENODATA    - block with requested state is not found.
 */
static
int ssdfs_block_bmap_find_block_in_memory_range(void *kaddr,
						int blk_state,
						u32 *byte_index,
						u32 search_bytes,
						u8 start_off,
						u8 *found_off)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !byte_index || !found_off);

	if (blk_state > SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	for (; *byte_index < search_bytes; ++(*byte_index)) {
		u8 *value = (u8 *)kaddr + *byte_index;

		err = FIND_FIRST_ITEM_IN_BYTE(value, blk_state,
					      SSDFS_BLK_STATE_BITS,
					      SSDFS_BLK_STATE_MASK,
					      start_off,
					      BYTE_CONTAINS_STATE,
					      FIRST_STATE_IN_BYTE,
					      found_off);
		if (err == -ENODATA) {
			start_off = 0;
			continue;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find block in byte: "
				  "start_off %u, blk_state %#x, "
				  "err %d\n",
				  start_off, blk_state, err);
			return err;
		}

		SSDFS_DBG("offset %u has been found for state %#x, "
			  "err %d\n",
			  *found_off, blk_state, err);

		return 0;
	}

	return -ENODATA;
}

/*
 * ssdfs_block_bmap_find_block_in_buffer() - find block in buffer with state
 * @blk_bmap: pointer on block bitmap
 * @start: start position for search
 * @max_blk: upper bound for search
 * @blk_state: requested state of searching block
 * @found_blk: pointer on found block number [out]
 *
 * This function searches a block with requested @blk_state
 * from @start till @max_blk (not inclusive) into buffer.
 * The found block's number is returned via @found_blk.
 *
 * RETURN:
 * [success] - found block number in @found_blk.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENODATA    - block with requested state is not found.
 */
static
int ssdfs_block_bmap_find_block_in_buffer(struct ssdfs_block_bmap *blk_bmap,
					  u32 start, u32 max_blk,
					  int blk_state, u32 *found_blk)
{
	u32 items_per_byte = SSDFS_ITEMS_PER_BYTE(SSDFS_BLK_STATE_BITS);
	u32 aligned_start, aligned_end;
	u32 byte_index, search_bytes;
	u8 start_off;
	void *kaddr;
	u8 found_off = U8_MAX;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !found_blk);

	if (blk_state > SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return -EINVAL;
	}

	if (start >= blk_bmap->items_count) {
		SSDFS_ERR("invalid start block %u\n", start);
		return -EINVAL;
	}

	if (start > max_blk) {
		SSDFS_ERR("start %u > max_blk %u\n", start, max_blk);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, start %u, max_blk %u, "
		  "state %#x, found_blk %p\n",
		  blk_bmap, start, max_blk, blk_state, found_blk);

	*found_blk = U32_MAX;
	max_blk = ssdfs_block_bmap_correct_max_blk(blk_bmap, max_blk,
						   blk_state);

	aligned_start = ALIGNED_START_BLK(start);
	aligned_end = ALIGNED_END_BLK(max_blk);

	ssdfs_block_bmap_define_start_item(0,
					   start,
					   aligned_start,
					   aligned_end,
					   &byte_index,
					   &search_bytes,
					   &start_off);

	kaddr = blk_bmap->storage.buf;

	err = ssdfs_block_bmap_find_block_in_memory_range(kaddr, blk_state,
							  &byte_index,
							  search_bytes,
							  start_off,
							  &found_off);
	if (err == -ENODATA) {
		/* no item has been found */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find block: "
			  "start_off %u, blk_state %#x, "
			  "err %d\n",
			  start_off, blk_state, err);
		return err;
	}

	*found_blk = byte_index * items_per_byte;
	*found_blk += found_off;

	if (*found_blk >= max_blk)
		err = -ENODATA;

	SSDFS_DBG("block %u has been found for state %#x, "
		  "err %d\n",
		  *found_blk, blk_state, err);

	return err;
}

/*
 * ssdfs_block_bmap_find_block_in_pagevec() - find block in pagevec with state
 * @blk_bmap: pointer on block bitmap
 * @start: start position for search
 * @max_blk: upper bound for search
 * @blk_state: requested state of searching block
 * @found_blk: pointer on found block number [out]
 *
 * This function searches a block with requested @blk_state
 * from @start till @max_blk (not inclusive) into pagevec.
 * The found block's number is returned via @found_blk.
 *
 * RETURN:
 * [success] - found block number in @found_blk.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENODATA    - block with requested state is not found.
 */
static
int ssdfs_block_bmap_find_block_in_pagevec(struct ssdfs_block_bmap *blk_bmap,
					   u32 start, u32 max_blk,
					   int blk_state, u32 *found_blk)
{
	u32 items_per_byte = SSDFS_ITEMS_PER_BYTE(SSDFS_BLK_STATE_BITS);
	size_t items_per_page = PAGE_SIZE * items_per_byte;
	u32 aligned_start, aligned_end;
	void *kaddr;
	int page_index;
	u8 found_off = U8_MAX;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !found_blk);

	if (blk_state > SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return -EINVAL;
	}

	if (start >= blk_bmap->items_count) {
		SSDFS_ERR("invalid start block %u\n", start);
		return -EINVAL;
	}

	if (start > max_blk) {
		SSDFS_ERR("start %u > max_blk %u\n", start, max_blk);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, start %u, max_blk %u, "
		  "state %#x, found_blk %p\n",
		  blk_bmap, start, max_blk, blk_state, found_blk);

	*found_blk = U32_MAX;
	max_blk = ssdfs_block_bmap_correct_max_blk(blk_bmap, max_blk,
						   blk_state);

	aligned_start = ALIGNED_START_BLK(start);
	aligned_end = ALIGNED_END_BLK(max_blk);

	for (page_index = aligned_start / items_per_page;
	     page_index < pagevec_count(&blk_bmap->storage.pvec);
	     page_index++) {
		u32 byte_index, search_bytes;
		u8 start_off;

		ssdfs_block_bmap_define_start_item(page_index, start,
						    aligned_start,
						    aligned_end,
						    &byte_index,
						    &search_bytes,
						    &start_off);

		kaddr = kmap(blk_bmap->storage.pvec.pages[page_index]);
		err = ssdfs_block_bmap_find_block_in_memory_range(kaddr,
								  blk_state,
								  &byte_index,
								  search_bytes,
								  start_off,
								  &found_off);
		kunmap(blk_bmap->storage.pvec.pages[page_index]);

		if (err == -ENODATA) {
			/* no item has been found */
			continue;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find block: "
				  "start_off %u, blk_state %#x, "
				  "err %d\n",
				  start_off, blk_state, err);
			return err;
		}

		*found_blk = page_index * items_per_page;
		*found_blk += byte_index * items_per_byte;
		*found_blk += found_off;

		if (*found_blk >= max_blk)
			err = -ENODATA;

		SSDFS_DBG("block %u has been found for state %#x, "
			  "err %d\n",
			  *found_blk, blk_state, err);
		return err;
	}

	return -ENODATA;
}

/*
 * ssdfs_block_bmap_find_block_in_storage() - find block in storage with state
 * @blk_bmap: pointer on block bitmap
 * @start: start position for search
 * @max_blk: upper bound for search
 * @blk_state: requested state of searching block
 * @found_blk: pointer on found block number [out]
 *
 * This function searches a block with requested @blk_state
 * from @start till @max_blk (not inclusive) into storage.
 * The found block's number is returned via @found_blk.
 *
 * RETURN:
 * [success] - found block number in @found_blk.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENODATA    - block with requested state is not found.
 */
static
int ssdfs_block_bmap_find_block_in_storage(struct ssdfs_block_bmap *blk_bmap,
					   u32 start, u32 max_blk,
					   int blk_state, u32 *found_blk)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !found_blk);

	if (blk_state > SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return -EINVAL;
	}

	if (start >= blk_bmap->items_count) {
		SSDFS_ERR("invalid start block %u\n", start);
		return -EINVAL;
	}

	if (start > max_blk) {
		SSDFS_ERR("start %u > max_blk %u\n", start, max_blk);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, start %u, max_blk %u, "
		  "state %#x, found_blk %p\n",
		  blk_bmap, start, max_blk, blk_state, found_blk);

	switch (blk_bmap->storage.state) {
	case SSDFS_BLOCK_BMAP_STORAGE_PAGE_VEC:
		err = ssdfs_block_bmap_find_block_in_pagevec(blk_bmap,
							     start,
							     max_blk,
							     blk_state,
							     found_blk);
		break;

	case SSDFS_BLOCK_BMAP_STORAGE_BUFFER:
		err = ssdfs_block_bmap_find_block_in_buffer(blk_bmap,
							    start,
							    max_blk,
							    blk_state,
							    found_blk);
		break;

	default:
		SSDFS_ERR("unexpected state %#x\n",
				blk_bmap->storage.state);
		return -ERANGE;
	}

	return err;
}

/*
 * ssdfs_block_bmap_find_block() - find block with requested state
 * @blk_bmap: pointer on block bitmap
 * @start: start position for search
 * @max_blk: upper bound for search
 * @blk_state: requested state of searching block
 * @found_blk: pointer on found block number [out]
 *
 * This function searches a block with requested @blk_state
 * from @start till @max_blk (not inclusive). The found block's
 * number is returned via @found_blk. If @blk_state has
 * SSDFS_BLK_STATE_MAX then it needs to get block state
 * for @start block number, simply.
 *
 * RETURN:
 * [success] - found block number in @found_blk.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENODATA    - block with requested state is not found.
 */
static
int ssdfs_block_bmap_find_block(struct ssdfs_block_bmap *blk_bmap,
				u32 start, u32 max_blk, int blk_state,
				u32 *found_blk)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !found_blk);

	if (blk_state > SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return -EINVAL;
	}

	if (start >= blk_bmap->items_count) {
		SSDFS_ERR("invalid start block %u\n", start);
		return -EINVAL;
	}

	if (start > max_blk) {
		SSDFS_ERR("start %u > max_blk %u\n", start, max_blk);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, start %u, max_blk %u, "
		  "state %#x, found_blk %p\n",
		  blk_bmap, start, max_blk, blk_state, found_blk);

	if (blk_state == SSDFS_BLK_STATE_MAX) {
		err = ssdfs_cache_block_state(blk_bmap, start, blk_state);
		if (unlikely(err)) {
			SSDFS_ERR("unable to cache block %u state: err %d\n",
				  start, err);
			return err;
		}

		*found_blk = start;
		return 0;
	}

	*found_blk = U32_MAX;
	max_blk = min_t(u32, max_blk, blk_bmap->items_count);

	if (is_cache_invalid(blk_bmap, blk_state)) {
		err = ssdfs_block_bmap_find_block_in_storage(blk_bmap,
							     0, max_blk,
							     blk_state,
							     found_blk);
		if (err == -ENODATA) {
			SSDFS_DBG("unable to find block in pagevec: "
				  "start %u, max_blk %u, state %#x\n",
				  0, max_blk, blk_state);
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find block in pagevec: "
				  "start %u, max_blk %u, state %#x, err %d\n",
				  0, max_blk, blk_state, err);
			goto fail_find;
		}

		err = ssdfs_cache_block_state(blk_bmap, *found_blk, blk_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to cache block: "
				  "found_blk %u, state %#x, err %d\n",
				  *found_blk, blk_state, err);
			goto fail_find;
		}
	}

	if (*found_blk >= start && *found_blk < max_blk)
		goto end_search;

	if (is_block_state_cached(blk_bmap, start)) {
		err = ssdfs_block_bmap_find_block_in_cache(blk_bmap,
							   start, max_blk,
							   blk_state,
							   found_blk);
		if (err == -ENODATA) {
			SSDFS_DBG("unable to find block in cache: "
				  "start %u, max_blk %u, state %#x\n",
				  start, max_blk, blk_state);
			/*
			 * Continue to search in pagevec
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find block in cache: "
				  "start %u, max_blk %u, state %#x, err %d\n",
				  start, max_blk, blk_state, err);
			goto fail_find;
		} else if (*found_blk >= start && *found_blk < max_blk)
			goto end_search;
	}

	err = ssdfs_block_bmap_find_block_in_storage(blk_bmap, start, max_blk,
						     blk_state, found_blk);
	if (err == -ENODATA) {
		SSDFS_DBG("unable to find block in pagevec: "
			  "start %u, max_blk %u, state %#x\n",
			  start, max_blk, blk_state);
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find block in pagevec: "
			  "start %u, max_blk %u, state %#x, err %d\n",
			  start, max_blk, blk_state, err);
		goto fail_find;
	}

	if (SSDFS_GET_CACHE_TYPE(blk_state) == SSDFS_OTHER_BLK_SEARCH) {
		err = ssdfs_cache_block_state(blk_bmap, *found_blk, blk_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to cache block: "
				  "found_blk %u, state %#x, err %d\n",
				  *found_blk, blk_state, err);
			goto fail_find;
		}
	}

end_search:
	SSDFS_DBG("block %u has been found for state %#x\n",
		  *found_blk, blk_state);
	return 0;

fail_find:
	return err;
}

/*
 * BYTE_CONTAIN_DIVERSE_STATES() - check that byte contains diverse state
 * @value: pointer on analysed byte
 * @blk_state: requested block's state
 *
 * RETURN:
 * [true]  - @value contains diverse states.
 * [false] - @value contains @blk_state only.
 */
static inline
bool BYTE_CONTAIN_DIVERSE_STATES(u8 *value, int blk_state)
{
	switch (blk_state) {
	case SSDFS_BLK_FREE:
		return *value != SSDFS_FREE_STATES_BYTE;

	case SSDFS_BLK_PRE_ALLOCATED:
		return *value != SSDFS_PRE_ALLOC_STATES_BYTE;

	case SSDFS_BLK_VALID:
		return *value != SSDFS_VALID_STATES_BYTE;

	case SSDFS_BLK_INVALID:
		return *value != SSDFS_INVALID_STATES_BYTE;
	};

	return false;
}

/*
 * GET_FIRST_DIFF_STATE() - determine first block offset for different state
 * @value: pointer on analysed byte
 * @blk_state: requested block's state
 * @start_off: starting block offset for analysis beginning
 *
 * This function tries to determine an item with different that @blk_state in
 * @value starting from @start_off.
 *
 * RETURN:
 * [success] - found block offset.
 * [failure] - BITS_PER_BYTE.
 */
static inline
u8 GET_FIRST_DIFF_STATE(u8 *value, int blk_state, u8 start_off)
{
	u8 i;
	u8 bits_off;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!value);
	BUG_ON(start_off >= (BITS_PER_BYTE / SSDFS_BLK_STATE_BITS));
#endif /* CONFIG_SSDFS_DEBUG */

	bits_off = start_off * SSDFS_BLK_STATE_BITS;

	for (i = bits_off; i < BITS_PER_BYTE; i += SSDFS_BLK_STATE_BITS) {
		if (((*value >> i) & SSDFS_BLK_STATE_MASK) != blk_state) {
			SSDFS_DBG("blk_state %#x, start_off %u, blk_off %u\n",
				  blk_state, start_off, i);
			return i / SSDFS_BLK_STATE_BITS;
		}
	}

	return BITS_PER_BYTE;
}

/*
 * ssdfs_find_state_area_end_in_byte() - find end block for state area in byte
 * @value: pointer on analysed byte
 * @blk_state: requested block's state
 * @start_off: starting block offset for search
 * @found_off: pointer on found end block [out]
 *
 * RETURN:
 * [success] - @found_off contains found end offset.
 * [failure] - error code:
 *
 * %-ENODATA    - analyzed @value contains @blk_state only.
 */
static inline
int ssdfs_find_state_area_end_in_byte(u8 *value, int blk_state,
					u8 start_off, u8 *found_off)
{
	SSDFS_DBG("value %p, blk_state %#x, "
		  "start_off %u, found_off %p\n",
		  value, blk_state, start_off, found_off);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!value || !found_off);
	BUG_ON(start_off >= (BITS_PER_BYTE / SSDFS_BLK_STATE_BITS));
#endif /* CONFIG_SSDFS_DEBUG */

	*found_off = BITS_PER_BYTE;

	if (BYTE_CONTAIN_DIVERSE_STATES(value, blk_state)) {
		u8 blk_offset = GET_FIRST_DIFF_STATE(value, blk_state,
							start_off);

		if (blk_offset < BITS_PER_BYTE) {
			*found_off = blk_offset;

			SSDFS_DBG("block offset %u for *NOT* state %#x\n",
				  *found_off, blk_state);

			return 0;
		}
	}

	return -ENODATA;
}

/*
 * ssdfs_block_bmap_find_state_area_end_in_memory() - find state area end
 * @kaddr: pointer on memory range
 * @blk_state: requested state of searching block
 * @byte_index: index of byte in memory range [in|out]
 * @search_bytes: upper bound for search
 * @start_off: starting bit offset in byte
 * @found_off: pointer on found end block [out]
 *
 * This function tries to find @blk_state area end
 * in range [@start, @max_blk).
 *
 * RETURN:
 * [success] - found byte's offset in @found_off.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENODATA    - nothing has been found.
 */
static
int ssdfs_block_bmap_find_state_area_end_in_memory(void *kaddr,
						   int blk_state,
						   u32 *byte_index,
						   u32 search_bytes,
						   u8 start_off,
						   u8 *found_off)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !byte_index || !found_off);

	if (blk_state > SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	for (; *byte_index < search_bytes; ++(*byte_index)) {
		u8 *value = (u8 *)kaddr + *byte_index;

		err = ssdfs_find_state_area_end_in_byte(value,
							blk_state,
							start_off,
							found_off);
		if (err == -ENODATA) {
			start_off = 0;
			continue;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find state area's end: "
				  "start_off %u, blk_state %#x, "
				  "err %d\n",
				  start_off, blk_state, err);
			return err;
		}

		SSDFS_DBG("offset %u has been found for state %#x, "
			  "err %d\n",
			  *found_off, blk_state, err);

		return 0;
	}

	return -ENODATA;
}

/*
 * ssdfs_block_bmap_find_state_area_end_in_buffer() - find state area end
 * @bmap: pointer on block bitmap
 * @start: start position for search
 * @max_blk: upper bound for search
 * @blk_state: area state
 * @found_end: pointer on found end block [out]
 *
 * This function tries to find @blk_state area end
 * in range [@start, @max_blk).
 *
 * RETURN:
 * [success] - @found_end contains found end block.
 * [failure] - items count in block bitmap or error:
 *
 * %-EINVAL     - invalid input value.
 */
static int
ssdfs_block_bmap_find_state_area_end_in_buffer(struct ssdfs_block_bmap *bmap,
						u32 start, u32 max_blk,
						int blk_state, u32 *found_end)
{
	u32 aligned_start, aligned_end;
	u32 items_per_byte = SSDFS_ITEMS_PER_BYTE(SSDFS_BLK_STATE_BITS);
	u32 byte_index, search_bytes;
	u8 start_off;
	void *kaddr;
	u8 found_off = U8_MAX;
	int err = 0;

	SSDFS_DBG("start %u, max_blk %u, blk_state %#x\n",
		  start, max_blk, blk_state);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !found_end);

	if (start >= bmap->items_count) {
		SSDFS_ERR("invalid start block %u\n", start);
		return -EINVAL;
	}

	if (start > max_blk) {
		SSDFS_ERR("start %u > max_blk %u\n", start, max_blk);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	*found_end = U32_MAX;
	max_blk = ssdfs_block_bmap_correct_max_blk(bmap, max_blk,
						   blk_state);

	aligned_start = ALIGNED_START_BLK(start);
	aligned_end = ALIGNED_END_BLK(max_blk);

	ssdfs_block_bmap_define_start_item(0,
					   start,
					   aligned_start,
					   aligned_end,
					   &byte_index,
					   &search_bytes,
					   &start_off);

	kaddr = bmap->storage.buf;

	err = ssdfs_block_bmap_find_state_area_end_in_memory(kaddr, blk_state,
							     &byte_index,
							     search_bytes,
							     start_off,
							     &found_off);
	if (err == -ENODATA) {
		*found_end = max_blk;
		SSDFS_DBG("area end %u has been found for state %#x\n",
			  *found_end, blk_state);
		return 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find state area's end: "
			  "start_off %u, blk_state %#x, "
			  "err %d\n",
			  start_off, blk_state, err);
		return err;
	}

	*found_end = byte_index * items_per_byte;
	*found_end += found_off;

	SSDFS_DBG("start %u, aligned_start %u, "
		  "aligned_end %u, byte_index %u, "
		  "items_per_byte %u, start_off %u, "
		  "found_off %u\n",
		  start, aligned_start, aligned_end, byte_index,
		  items_per_byte, start_off, found_off);

	if (*found_end > max_blk)
		*found_end = max_blk;

	SSDFS_DBG("area end %u has been found for state %#x\n",
		  *found_end, blk_state);

	return 0;
}

/*
 * ssdfs_block_bmap_find_state_area_end_in_pagevec() - find state area end
 * @bmap: pointer on block bitmap
 * @start: start position for search
 * @max_blk: upper bound for search
 * @blk_state: area state
 * @found_end: pointer on found end block [out]
 *
 * This function tries to find @blk_state area end
 * in range [@start, @max_blk).
 *
 * RETURN:
 * [success] - @found_end contains found end block.
 * [failure] - items count in block bitmap or error:
 *
 * %-EINVAL     - invalid input value.
 */
static int
ssdfs_block_bmap_find_state_area_end_in_pagevec(struct ssdfs_block_bmap *bmap,
						u32 start, u32 max_blk,
						int blk_state, u32 *found_end)
{
	u32 aligned_start, aligned_end;
	u32 items_per_byte = SSDFS_ITEMS_PER_BYTE(SSDFS_BLK_STATE_BITS);
	size_t items_per_page = PAGE_SIZE * items_per_byte;
	void *kaddr;
	int page_index;
	u8 found_off = U8_MAX;
	int err = 0;

	SSDFS_DBG("start %u, max_blk %u, blk_state %#x\n",
		  start, max_blk, blk_state);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !found_end);

	if (start >= bmap->items_count) {
		SSDFS_ERR("invalid start block %u\n", start);
		return -EINVAL;
	}

	if (start > max_blk) {
		SSDFS_ERR("start %u > max_blk %u\n", start, max_blk);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	*found_end = U32_MAX;
	max_blk = ssdfs_block_bmap_correct_max_blk(bmap, max_blk,
						   blk_state);

	aligned_start = ALIGNED_START_BLK(start);
	aligned_end = ALIGNED_END_BLK(max_blk);

	for (page_index = aligned_start / items_per_page;
	     page_index < pagevec_count(&bmap->storage.pvec);
	     page_index++) {
		u32 byte_index, search_bytes;
		u8 start_off;

		ssdfs_block_bmap_define_start_item(page_index, start,
						    aligned_start,
						    aligned_end,
						    &byte_index,
						    &search_bytes,
						    &start_off);

		kaddr = kmap(bmap->storage.pvec.pages[page_index]);
		err = ssdfs_block_bmap_find_state_area_end_in_memory(kaddr,
								blk_state,
								&byte_index,
								search_bytes,
								start_off,
								&found_off);
		kunmap(bmap->storage.pvec.pages[page_index]);

		if (err == -ENODATA) {
			/* nothing has been found */
			continue;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find state area's end: "
				  "start_off %u, blk_state %#x, "
				  "err %d\n",
				  start_off, blk_state, err);
			return err;
		}

		*found_end = page_index * items_per_page;
		*found_end += byte_index * items_per_byte;
		*found_end += found_off;

		SSDFS_DBG("start %u, aligned_start %u, "
			  "aligned_end %u, "
			  "page_index %d, items_per_page %zu, "
			  "byte_index %u, "
			  "items_per_byte %u, start_off %u, "
			  "found_off %u\n",
			  start, aligned_start, aligned_end,
			  page_index, items_per_page, byte_index,
			  items_per_byte, start_off, found_off);

		if (*found_end > max_blk)
			*found_end = max_blk;

		SSDFS_DBG("area end %u has been found for state %#x\n",
			  *found_end, blk_state);
		return 0;
	}

	*found_end = max_blk;
	SSDFS_DBG("area end %u has been found for state %#x\n",
		  *found_end, blk_state);
	return 0;
}

/*
 * ssdfs_block_bmap_find_state_area_end() - find state area end
 * @blk_bmap: pointer on block bitmap
 * @start: start position for search
 * @max_blk: upper bound for search
 * @blk_state: area state
 * @found_end: pointer on found end block [out]
 *
 * This function tries to find @blk_state area end
 * in range [@start, @max_blk).
 *
 * RETURN:
 * [success] - @found_end contains found end block.
 * [failure] - items count in block bitmap or error:
 *
 * %-EINVAL     - invalid input value.
 */
static
int ssdfs_block_bmap_find_state_area_end(struct ssdfs_block_bmap *blk_bmap,
					 u32 start, u32 max_blk, int blk_state,
					 u32 *found_end)
{
	int err = 0;

	SSDFS_DBG("start %u, max_blk %u, blk_state %#x\n",
		  start, max_blk, blk_state);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !found_end);

	if (start >= blk_bmap->items_count) {
		SSDFS_ERR("invalid start block %u\n", start);
		return -EINVAL;
	}

	if (start > max_blk) {
		SSDFS_ERR("start %u > max_blk %u\n", start, max_blk);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (blk_state == SSDFS_BLK_FREE) {
		*found_end = blk_bmap->items_count;
		return 0;
	}

	switch (blk_bmap->storage.state) {
	case SSDFS_BLOCK_BMAP_STORAGE_PAGE_VEC:
		err = ssdfs_block_bmap_find_state_area_end_in_pagevec(blk_bmap,
								     start,
								     max_blk,
								     blk_state,
								     found_end);
		break;

	case SSDFS_BLOCK_BMAP_STORAGE_BUFFER:
		err = ssdfs_block_bmap_find_state_area_end_in_buffer(blk_bmap,
								     start,
								     max_blk,
								     blk_state,
								     found_end);
		break;

	default:
		SSDFS_ERR("unexpected state %#x\n",
				blk_bmap->storage.state);
		return -ERANGE;
	}

	return err;
}

/*
 * range_corrupted() - check that range is corrupted
 * @blk_bmap: pointer on block bitmap
 * @range: range for check
 *
 * RETURN:
 * [true]  - range is invalid
 * [false] - range is valid
 */
static inline
bool range_corrupted(struct ssdfs_block_bmap *blk_bmap,
		     struct ssdfs_block_bmap_range *range)
{
	if (range->len > blk_bmap->items_count)
		return true;
	if (range->start > (blk_bmap->items_count - range->len))
		return true;
	return false;
}

/*
 * is_whole_range_cached() - check that cache contains requested range
 * @blk_bmap: pointer on block bitmap
 * @range: range for check
 *
 * RETURN:
 * [true]  - cache contains the whole range
 * [false] - cache doesn't include the whole range
 */
static
bool is_whole_range_cached(struct ssdfs_block_bmap *blk_bmap,
			   struct ssdfs_block_bmap_range *range)
{
	struct ssdfs_block_bmap_range cached_range;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !range);

	if (range_corrupted(blk_bmap, range)) {
		SSDFS_ERR("invalid range (start %u, len %u); items count %zu\n",
			  range->start, range->len,
			  blk_bmap->items_count);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, range (start %u, len %u)\n",
		  blk_bmap, range->start, range->len);

	for (i = 0; i < SSDFS_SEARCH_TYPE_MAX; i++) {
		struct ssdfs_last_bmap_search *last_search;
		int cmp;

		last_search = &blk_bmap->last_search[i];

		SSDFS_DBG("last_search.cache %lx\n", last_search->cache);

		cached_range.start = SSDFS_FIRST_CACHED_BLOCK(last_search);
		cached_range.len = SSDFS_ITEMS_PER_LONG(SSDFS_BLK_STATE_BITS);

		cmp = compare_block_bmap_ranges(&cached_range, range);

		if (cmp >= 0)
			return true;
		else if (ranges_have_intersection(&cached_range, range))
			return false;
	}

	return false;
}

/*
 * ssdfs_set_range_in_cache() - set small range in cache
 * @blk_bmap: pointer on block bitmap
 * @range: requested range
 * @blk_state: state for set
 *
 * This function sets small range in cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 */
static
int ssdfs_set_range_in_cache(struct ssdfs_block_bmap *blk_bmap,
				struct ssdfs_block_bmap_range *range,
				int blk_state)
{
	u32 blk, index;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);

	if (blk_state >= SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return -EINVAL;
	}

	if (range_corrupted(blk_bmap, range)) {
		SSDFS_ERR("invalid range (start %u, len %u); items count %zu\n",
			  range->start, range->len,
			  blk_bmap->items_count);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, range (start %u, len %u), state %#x\n",
		  blk_bmap, range->start, range->len, blk_state);

	for (index = 0; index < range->len; index++) {
		blk = range->start + index;
		err = ssdfs_set_block_state_in_cache(blk_bmap, blk, blk_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set block %u in cache: err %d\n",
				  blk, err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_set_uncached_tiny_range() - set tiny uncached range by state
 * @blk_bmap: pointer on block bitmap
 * @range: range for set
 * @blk_state: state for set
 *
 * This function caches @range, to set @range in cache by @blk_state
 * and to save the cache in pagevec.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 */
static
int ssdfs_set_uncached_tiny_range(struct ssdfs_block_bmap *blk_bmap,
				  struct ssdfs_block_bmap_range *range,
				  int blk_state)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !range);

	if (blk_state >= SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return -EINVAL;
	}

	if (range_corrupted(blk_bmap, range)) {
		SSDFS_ERR("invalid range (start %u, len %u); items count %zu\n",
			  range->start, range->len,
			  blk_bmap->items_count);
		return -EINVAL;
	}

	if (range->len > SSDFS_ITEMS_PER_BYTE(SSDFS_BLK_STATE_BITS)) {
		SSDFS_ERR("range (start %u, len %u) is not tiny\n",
			  range->start, range->len);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, range (start %u, len %u), state %#x\n",
		  blk_bmap, range->start, range->len, blk_state);

	err = ssdfs_cache_block_state(blk_bmap, range->start, blk_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to cache block %u: err %d\n",
			  range->start, err);
		return err;
	}

	err = ssdfs_set_range_in_cache(blk_bmap, range, blk_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set (start %u, len %u): err %d\n",
			  range->start, range->len, err);
		return err;
	}

	err = ssdfs_save_cache_in_storage(blk_bmap);
	if (unlikely(err)) {
		SSDFS_ERR("fail to save cache in pagevec: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * __ssdfs_set_range_in_memory() - set range of bits in memory
 * @blk_bmap: pointer on block bitmap
 * @page_index: index of memory page
 * @byte_offset: offset in bytes from the page's beginning
 * @byte_value: byte value for setting
 * @init_size: size in bytes for setting
 *
 * This function sets range of bits in memory.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_set_range_in_memory(struct ssdfs_block_bmap *blk_bmap,
				int page_index, u32 byte_offset,
				int byte_value, size_t init_size)
{
	void *kaddr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, page_index %d, byte_offset %u, "
		  "byte_value %#x, init_size %zu\n",
		  blk_bmap, page_index, byte_offset,
		  byte_value, init_size);

	switch (blk_bmap->storage.state) {
	case SSDFS_BLOCK_BMAP_STORAGE_PAGE_VEC:
		if (page_index >= pagevec_count(&blk_bmap->storage.pvec)) {
			SSDFS_ERR("invalid page index %d, pagevec size %d\n",
				  page_index,
				  pagevec_count(&blk_bmap->storage.pvec));
			return -EINVAL;
		}

		kaddr = kmap_atomic(blk_bmap->storage.pvec.pages[page_index]);
		memset((u8 *)kaddr + byte_offset, byte_value, init_size);
		kunmap_atomic(kaddr);
		break;

	case SSDFS_BLOCK_BMAP_STORAGE_BUFFER:
		if (page_index != 0) {
			SSDFS_ERR("invalid page index %d\n",
				  page_index);
			return -EINVAL;
		}

		kaddr = blk_bmap->storage.buf;
		memset((u8 *)kaddr + byte_offset, byte_value, init_size);
		break;

	default:
		SSDFS_ERR("unexpected state %#x\n",
				blk_bmap->storage.state);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_set_range_in_storage() - set range in storage by state
 * @blk_bmap: pointer on block bitmap
 * @range: range for set
 * @blk_state: state for set
 *
 * This function sets @range in storage by @blk_state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 */
static
int ssdfs_set_range_in_storage(struct ssdfs_block_bmap *blk_bmap,
				struct ssdfs_block_bmap_range *range,
				int blk_state)
{
	u32 aligned_start, aligned_end;
	size_t items_per_byte = SSDFS_ITEMS_PER_BYTE(SSDFS_BLK_STATE_BITS);
	int byte_value;
	size_t rest_items, items_per_page;
	u32 blk;
	int page_index;
	u32 item_offset, byte_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !range);

	if (blk_state >= SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return -EINVAL;
	}

	if (range_corrupted(blk_bmap, range)) {
		SSDFS_ERR("invalid range (start %u, len %u); items count %zu\n",
			  range->start, range->len,
			  blk_bmap->items_count);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, range (start %u, len %u), state %#x\n",
		  blk_bmap, range->start, range->len, blk_state);

	aligned_start = range->start + items_per_byte - 1;
	aligned_start >>= SSDFS_BLK_STATE_BITS;
	aligned_start <<= SSDFS_BLK_STATE_BITS;

	aligned_end = range->start + range->len;
	aligned_end >>= SSDFS_BLK_STATE_BITS;
	aligned_end <<= SSDFS_BLK_STATE_BITS;

	if (range->start != aligned_start) {
		struct ssdfs_block_bmap_range unaligned;

		unaligned.start = range->start;
		unaligned.len = aligned_start - range->start;

		err = ssdfs_set_uncached_tiny_range(blk_bmap, &unaligned,
						    blk_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set (start %u, len %u): err %d\n",
				  unaligned.start, unaligned.len, err);
			return err;
		}
	}

	byte_value = SSDFS_BLK_BMAP_BYTE(blk_state);
	items_per_page = PAGE_SIZE * items_per_byte;
	rest_items = aligned_end - aligned_start;
	page_index = aligned_start / items_per_page;
	item_offset = aligned_start % items_per_page;
	byte_offset = item_offset / items_per_byte;

	blk = aligned_start;
	while (blk < aligned_end) {
		size_t iter_items, init_size;

		if (rest_items == 0) {
			SSDFS_WARN("unexpected items absence: blk %u\n",
				   blk);
			break;
		}

		if (byte_offset >= PAGE_SIZE) {
			SSDFS_ERR("invalid byte offset %u\n", byte_offset);
			return -EINVAL;
		}

		iter_items = items_per_page - item_offset;
		iter_items = min_t(size_t, iter_items, rest_items);
		if (iter_items < items_per_page) {
			init_size = iter_items + items_per_byte - 1;
			init_size /= items_per_byte;
		} else
			init_size = PAGE_SIZE;

		err = __ssdfs_set_range_in_memory(blk_bmap, page_index,
						  byte_offset, byte_value,
						  init_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set range in memory: "
				  "page_index %d, byte_offset %u, "
				  "byte_value %#x, init_size %zu, "
				  "err %d\n",
				  page_index, byte_offset,
				  byte_value, init_size,
				  err);
			return err;
		}

		item_offset = 0;
		byte_offset = 0;
		page_index++;
		blk += iter_items;
		rest_items -= iter_items;
	};

	if (aligned_end != range->start + range->len) {
		struct ssdfs_block_bmap_range unaligned;

		unaligned.start = aligned_end;
		unaligned.len = (range->start + range->len) - aligned_end;

		err = ssdfs_set_uncached_tiny_range(blk_bmap, &unaligned,
						    blk_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set (start %u, len %u): err %d\n",
				  unaligned.start, unaligned.len, err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_block_bmap_find_range() - find range of block of requested state
 * @blk_bmap: pointer on block bitmap
 * @start: start block for search
 * @len: requested length of range
 * @max_blk: upper bound for search
 * @blk_state: requested state of blocks in range
 * @range: found range [out]
 *
 * This function searches @range of blocks with requested
 * @blk_state. If @blk_state has SSDFS_BLK_STATE_MAX value
 * then it needs to get a continuous @range of blocks
 * for detecting state of @range is began from @start
 * block.
 *
 * RETURN:
 * [success] - @range of found blocks.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 */
static
int ssdfs_block_bmap_find_range(struct ssdfs_block_bmap *blk_bmap,
				u32 start, u32 len, u32 max_blk,
				int blk_state,
				struct ssdfs_block_bmap_range *range)
{
	u32 found_start, found_end;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !range);

	if (blk_state > SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return -EINVAL;
	}

	if (start >= blk_bmap->items_count) {
		SSDFS_ERR("invalid start block %u\n", start);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, start %u, len %u, max_blk %u, "
		  "state %#x, range %p\n",
		  blk_bmap, start, len, max_blk, blk_state, range);

	range->start = U32_MAX;
	range->len = 0;

	if (start >= max_blk) {
		SSDFS_DBG("start %u >= max_blk %u\n", start, max_blk);
		return -ENODATA;
	}

	err = ssdfs_block_bmap_find_block(blk_bmap, start, max_blk,
					  blk_state, &found_start);
	if (err == -ENODATA) {
		SSDFS_DBG("unable to find block: "
			  "start %u, max_blk %u, state %#x, err %d\n",
			  start, max_blk, blk_state, err);
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find block: "
			  "start %u, max_blk %u, state %#x, err %d\n",
			  start, max_blk, blk_state, err);
		return err;
	}

	if (found_start >= blk_bmap->items_count) {
		SSDFS_ERR("invalid found start %u, items count %zu\n",
			  found_start, blk_bmap->items_count);
		return -EINVAL;
	}

	err = ssdfs_block_bmap_find_state_area_end(blk_bmap, found_start,
						   found_start + len,
						   blk_state,
						   &found_end);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find block: "
			  "start %u, max_blk %u, state %#x, err %d\n",
			  start, max_blk, blk_state, err);
		return err;
	}

	if (found_end <= found_start || found_end > blk_bmap->items_count) {
		SSDFS_ERR("invalid found (start %u, end %u), items count %zu\n",
			  found_start, found_end, blk_bmap->items_count);
		return -EINVAL;
	}

	range->start = found_start;
	range->len = min_t(u32, len, found_end - found_start);

	SSDFS_DBG("found_start %u, found_end %u, len %u, "
		  "range (start %u, len %u)\n",
		  found_start, found_end, len,
		  range->start, range->len);

	return 0;
}

/*
 * ssdfs_block_bmap_set_block_state() - set state of block
 * @blk_bmap: pointer on block bitmap
 * @blk: segment's block
 * @blk_state: state for set
 *
 * This function sets @blk by @blk_state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 */
static
int ssdfs_block_bmap_set_block_state(struct ssdfs_block_bmap *blk_bmap,
					u32 blk, int blk_state)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);

	if (blk_state >= SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return -EINVAL;
	}

	if (blk >= blk_bmap->items_count) {
		SSDFS_ERR("invalid block %u\n", blk);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, block %u, state %#x\n",
		  blk_bmap, blk, blk_state);

	if (!is_block_state_cached(blk_bmap, blk)) {
		err = ssdfs_cache_block_state(blk_bmap, blk, blk_state);
		if (unlikely(err)) {
			SSDFS_ERR("unable to cache block %u state: err %d\n",
				  blk, err);
			return err;
		}
	}

	err = ssdfs_set_block_state_in_cache(blk_bmap, blk, blk_state);
	if (unlikely(err)) {
		SSDFS_ERR("unable to set block %u state in cache: err %d\n",
			  blk, err);
		return err;
	}

	err = ssdfs_save_cache_in_storage(blk_bmap);
	if (unlikely(err)) {
		SSDFS_ERR("unable to save the cache in storage: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_block_bmap_set_range() - set state of blocks' range
 * @blk_bmap: pointer on block bitmap
 * @range: requested range
 * @blk_state: state for set
 *
 * This function sets blocks' @range by @blk_state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 */
static
int ssdfs_block_bmap_set_range(struct ssdfs_block_bmap *blk_bmap,
				struct ssdfs_block_bmap_range *range,
				int blk_state)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !range);

	if (blk_state >= SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return -EINVAL;
	}

	if (range_corrupted(blk_bmap, range)) {
		SSDFS_ERR("invalid range (start %u, len %u); items count %zu\n",
			  range->start, range->len,
			  blk_bmap->items_count);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, range (start %u, len %u), state %#x\n",
		  blk_bmap, range->start, range->len, blk_state);

	if (range->len == 1) {
		err = ssdfs_block_bmap_set_block_state(blk_bmap, range->start,
							blk_state);
		if (err) {
			SSDFS_ERR("fail to set (start %u, len %u) state %#x: "
				  "err %d\n",
				  range->start, range->len, blk_state, err);
			return err;
		}
	} else if (is_whole_range_cached(blk_bmap, range)) {
		err = ssdfs_set_range_in_cache(blk_bmap, range, blk_state);
		if (unlikely(err)) {
			SSDFS_ERR("unable to set (start %u, len %u) state %#x "
				  "in cache: err %d\n",
				  range->start, range->len, blk_state, err);
			return err;
		}

		err = ssdfs_save_cache_in_storage(blk_bmap);
		if (unlikely(err)) {
			SSDFS_ERR("unable to save the cache in storage: "
				  "err %d\n", err);
			return err;
		}
	} else {
		u32 next_blk;

		err = ssdfs_set_range_in_storage(blk_bmap, range, blk_state);
		if (unlikely(err)) {
			SSDFS_ERR("unable to set (start %u, len %u) state %#x "
				  "in storage: err %d\n",
				  range->start, range->len, blk_state, err);
			return err;
		}

		next_blk = range->start + range->len;
		if (next_blk == blk_bmap->items_count)
			next_blk--;

		err = ssdfs_cache_block_state(blk_bmap, next_blk, blk_state);
		if (unlikely(err)) {
			SSDFS_ERR("unable to cache block %u state: err %d\n",
				  next_blk, err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_block_bmap_test_block() - check state of block
 * @blk_bmap: pointer on block bitmap
 * @blk: segment's block
 * @blk_state: checked state
 *
 * This function checks that requested @blk has @blk_state.
 *
 * RETURN:
 * [true]  - requested @blk has @blk_state
 * [false] - requested @blk hasn't @blk_state or it took place
 *           some failure during checking.
 */
bool ssdfs_block_bmap_test_block(struct ssdfs_block_bmap *blk_bmap,
				 u32 blk, int blk_state)
{
	u32 found;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);

	if (blk_state >= SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return false;
	}

	if (blk >= blk_bmap->items_count) {
		SSDFS_ERR("invalid block %u\n", blk);
		return false;
	}

	BUG_ON(!mutex_is_locked(&blk_bmap->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, block %u, state %#x\n",
		  blk_bmap, blk, blk_state);

	BUG_ON(!is_block_bmap_initialized(blk_bmap));

	err = ssdfs_block_bmap_find_block(blk_bmap, blk, blk + 1, blk_state,
					  &found);
	if (err) {
		SSDFS_ERR("fail to find block %u, state %#x, err %d\n",
			  blk, blk_state, err);
		return false;
	}

	return (found != blk) ? false : true;
}

/*
 * ssdfs_block_bmap_test_range() - check state of blocks' range
 * @blk_bmap: pointer on block bitmap
 * @range: segment's blocks' range
 * @blk_state: checked state
 *
 * This function checks that all blocks in requested @range have
 * @blk_state.
 *
 * RETURN:
 * [true]  - all blocks in requested @range have @blk_state
 * [false] - requested @range contains blocks with various states or
 *           it took place some failure during checking.
 */
bool ssdfs_block_bmap_test_range(struct ssdfs_block_bmap *blk_bmap,
				 struct ssdfs_block_bmap_range *range,
				 int blk_state)
{
	struct ssdfs_block_bmap_range found;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !range);

	if (blk_state >= SSDFS_BLK_STATE_MAX) {
		SSDFS_ERR("invalid block state %#x\n", blk_state);
		return false;
	}

	if (range_corrupted(blk_bmap, range)) {
		SSDFS_ERR("invalid range (start %u, len %u); items count %zu\n",
			  range->start, range->len,
			  blk_bmap->items_count);
		return false;
	}

	BUG_ON(!mutex_is_locked(&blk_bmap->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, range (start %u, len %u), state %#x\n",
		  blk_bmap, range->start, range->len, blk_state);

	BUG_ON(!is_block_bmap_initialized(blk_bmap));

	err = ssdfs_block_bmap_find_range(blk_bmap, range->start, range->len,
					  range->start + range->len,
					  blk_state, &found);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find range: err %d\n", err);
		return false;
	}

	if (compare_block_bmap_ranges(&found, range) == 0)
		return true;

	return false;
}

/*
 * ssdfs_get_block_state() - detect state of block
 * @blk_bmap: pointer on block bitmap
 * @blk: segment's block
 *
 * This function retrieve state of @blk from block bitmap.
 *
 * RETURN:
 * [success] - state of block
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENODATA    - requsted @blk hasn't been found.
 * %-ENOENT     - block bitmap doesn't initialized.
 */
int ssdfs_get_block_state(struct ssdfs_block_bmap *blk_bmap, u32 blk)
{
	u32 found;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);

	if (blk >= blk_bmap->items_count) {
		SSDFS_ERR("invalid block %u\n", blk);
		return -EINVAL;
	}

	if (!mutex_is_locked(&blk_bmap->lock)) {
		SSDFS_WARN("block bitmap mutex should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, block %u\n", blk_bmap, blk);

	if (!is_block_bmap_initialized(blk_bmap)) {
		SSDFS_WARN("block bitmap hasn't been initialized\n");
		return -ENOENT;
	}

	err = ssdfs_block_bmap_find_block(blk_bmap, blk, blk + 1,
					    SSDFS_BLK_STATE_MAX,
					    &found);
	if (err) {
		SSDFS_ERR("fail to find block %u, err %d\n",
			  blk, err);
		return err;
	}

	if (found != blk) {
		SSDFS_DBG("found (%u) != blk (%u)\n", found, blk);
		return -ENODATA;
	}

	return ssdfs_get_block_state_from_cache(blk_bmap, blk);
}

/*
 * ssdfs_get_range_state() - detect state of blocks' range
 * @blk_bmap: pointer on block bitmap
 * @range: pointer on blocks' range
 *
 * This function retrieve state of @range from block bitmap.
 *
 * RETURN:
 * [success] - state of blocks' range
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-EOPNOTSUPP - requsted @range contains various state of blocks.
 * %-ENOENT     - block bitmap doesn't initialized.
 */
int ssdfs_get_range_state(struct ssdfs_block_bmap *blk_bmap,
			  struct ssdfs_block_bmap_range *range)
{
	struct ssdfs_block_bmap_range found;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !range);

	if (range_corrupted(blk_bmap, range)) {
		SSDFS_ERR("invalid range: start %u, len %u; items count %zu\n",
			  range->start, range->len,
			  blk_bmap->items_count);
		return -EINVAL;
	}

	if (!mutex_is_locked(&blk_bmap->lock)) {
		SSDFS_WARN("block bitmap mutex should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, range (start %u, len %u)\n",
		  blk_bmap, range->start, range->len);

	if (!is_block_bmap_initialized(blk_bmap)) {
		SSDFS_WARN("block bitmap hasn't been initialized\n");
		return -ENOENT;
	}

	err = ssdfs_block_bmap_find_range(blk_bmap, range->start, range->len,
					  range->start + range->len,
					  SSDFS_BLK_STATE_MAX, &found);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find range: err %d\n", err);
		return err;
	}

	if (compare_block_bmap_ranges(&found, range) != 0) {
		SSDFS_ERR("range contains various state of blocks\n");
		return -EOPNOTSUPP;
	}

	err = ssdfs_cache_block_state(blk_bmap, range->start,
					SSDFS_BLK_STATE_MAX);
	if (unlikely(err)) {
		SSDFS_ERR("fail to cache block %u: err %d\n",
			  range->start, err);
		return err;
	}

	return ssdfs_get_block_state_from_cache(blk_bmap, range->start);
}

/*
 * ssdfs_block_bmap_reserve_metadata_pages() - reserve metadata pages
 * @blk_bmap: pointer on block bitmap
 * @count: count of reserved metadata pages
 *
 * This function tries to reserve @count of metadata pages in
 * block bitmap's space.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENOENT     - block bitmap doesn't initialized.
 */
int ssdfs_block_bmap_reserve_metadata_pages(struct ssdfs_block_bmap *blk_bmap,
					    u16 count)
{
	u32 last_free_page = 0;
	u32 reserved_items;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);

	if (!mutex_is_locked(&blk_bmap->lock)) {
		SSDFS_WARN("block bitmap mutex should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, count %u\n", blk_bmap, count);

	if (!is_block_bmap_initialized(blk_bmap)) {
		SSDFS_WARN("block bitmap hasn't been initialized\n");
		return -ENOENT;
	}

	if (!is_cache_invalid(blk_bmap, SSDFS_BLK_FREE)) {
		err = ssdfs_define_last_free_page(blk_bmap, &last_free_page);
		if (unlikely(err)) {
			SSDFS_ERR("fail to define last free page: err %d\n",
				  err);
			return err;
		}
	}

	reserved_items = blk_bmap->metadata_items + count;
	if (last_free_page + reserved_items > blk_bmap->items_count) {
		SSDFS_ERR("fail to reserve metadata pages: "
			  "last_free_page %u, metadata_items %u, "
			  "count %u, items_count %zu\n",
			  last_free_page,
			  blk_bmap->metadata_items,
			  count,
			  blk_bmap->items_count);
		return -EINVAL;
	}

	blk_bmap->metadata_items += count;

	return 0;
}

/*
 * ssdfs_block_bmap_free_metadata_pages() - free metadata pages
 * @blk_bmap: pointer on block bitmap
 * @count: count of metadata pages for freeing
 *
 * This function tries to free @count of metadata pages in
 * block bitmap's space.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENOENT     - block bitmap doesn't initialized.
 * %-ERANGE     - internal error.
 */
int ssdfs_block_bmap_free_metadata_pages(struct ssdfs_block_bmap *blk_bmap,
					 u16 count)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);

	if (!mutex_is_locked(&blk_bmap->lock)) {
		SSDFS_WARN("block bitmap mutex should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, count %u\n", blk_bmap, count);

	if (!is_block_bmap_initialized(blk_bmap)) {
		SSDFS_WARN("block bitmap hasn't been initialized\n");
		return -ENOENT;
	}

	if (blk_bmap->metadata_items < count) {
		SSDFS_ERR("fail to free metadata pages: "
			  "metadata_items %u < count %u\n",
			  blk_bmap->metadata_items, count);
		return -ERANGE;
	}

	blk_bmap->metadata_items -= count;

	return 0;
}

/*
 * ssdfs_block_bmap_get_free_pages() - determine current free pages count
 * @blk_bmap: pointer on block bitmap
 *
 * This function tries to detect current free pages count
 * in block bitmap.
 *
 * RETURN:
 * [success] - count of free pages.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - invalid internal calculations.
 * %-ENOENT     - block bitmap doesn't initialized.
 */
int ssdfs_block_bmap_get_free_pages(struct ssdfs_block_bmap *blk_bmap)
{
	u32 found_blk;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);

	if (!mutex_is_locked(&blk_bmap->lock)) {
		SSDFS_WARN("block bitmap mutex should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p\n", blk_bmap);

	if (!is_block_bmap_initialized(blk_bmap)) {
		SSDFS_WARN("block bitmap hasn't been initialized\n");
		return -ENOENT;
	}

	if (is_cache_invalid(blk_bmap, SSDFS_BLK_FREE)) {
		SSDFS_DBG("cache for free states is invalid!!!\n");

		err = ssdfs_block_bmap_find_block(blk_bmap,
						  0, blk_bmap->items_count,
						  SSDFS_BLK_FREE, &found_blk);
	} else
		err = ssdfs_define_last_free_page(blk_bmap, &found_blk);

	if (unlikely(err)) {
		SSDFS_ERR("fail to find last free block: err %d\n",
			  err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (unlikely(found_blk > blk_bmap->items_count)) {
		SSDFS_ERR("found_blk %u > items_count %zu\n",
			  found_blk, blk_bmap->items_count);
		return -ERANGE;
	}

	WARN_ON(INT_MAX < (blk_bmap->items_count - found_blk));
#endif /* CONFIG_SSDFS_DEBUG */

	return blk_bmap->items_count - found_blk - blk_bmap->metadata_items;
}

/*
 * ssdfs_block_bmap_get_used_pages() - determine current used pages count
 * @blk_bmap: pointer on block bitmap
 *
 * This function tries to detect current used pages count
 * in block bitmap.
 *
 * RETURN:
 * [success] - count of used pages.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - invalid internal calculations.
 * %-ENOENT     - block bitmap doesn't initialized.
 */
int ssdfs_block_bmap_get_used_pages(struct ssdfs_block_bmap *blk_bmap)
{
	u32 found_blk;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);

	if (!mutex_is_locked(&blk_bmap->lock)) {
		SSDFS_WARN("block bitmap mutex should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p\n", blk_bmap);

	if (!is_block_bmap_initialized(blk_bmap)) {
		SSDFS_WARN("block bitmap hasn't been initialized\n");
		return -ENOENT;
	}

	err = ssdfs_define_last_free_page(blk_bmap, &found_blk);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find last free block: err %d\n",
			  err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (unlikely(found_blk > blk_bmap->items_count)) {
		SSDFS_ERR("found_blk %u > items_count %zu\n",
			  found_blk, blk_bmap->items_count);
		return -ERANGE;
	}

	if (unlikely(blk_bmap->invalid_blks > found_blk)) {
		SSDFS_ERR("invalid_blks %u > found_blk %u\n",
			  blk_bmap->invalid_blks, found_blk);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return found_blk - blk_bmap->invalid_blks;
}

/*
 * ssdfs_block_bmap_get_invalid_pages() - determine current invalid pages count
 * @blk_bmap: pointer on block bitmap
 *
 * This function tries to detect current invalid pages count
 * in block bitmap.
 *
 * RETURN:
 * [success] - count of invalid pages.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENOENT     - block bitmap doesn't initialized.
 */
int ssdfs_block_bmap_get_invalid_pages(struct ssdfs_block_bmap *blk_bmap)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);

	if (!mutex_is_locked(&blk_bmap->lock)) {
		SSDFS_WARN("block bitmap mutex should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p\n", blk_bmap);

	if (!is_block_bmap_initialized(blk_bmap)) {
		SSDFS_WARN("block bitmap hasn't been initialized\n");
		return -ENOENT;
	}

	return blk_bmap->invalid_blks;
}

/*
 * ssdfs_block_bmap_pre_allocate() - pre-allocate segment's range of blocks
 * @blk_bmap: pointer on block bitmap
 * @len: pointer on variable with requested length of range
 * @range: pointer on blocks' range [in | out]
 *
 * This function tries to find contiguous range of free blocks and
 * to set the found range in pre-allocated state.
 *
 * If pointer @len is NULL then it needs:
 * (1) check that requested range contains free blocks only;
 * (2) set the requested range of blocks in pre-allocated state.
 *
 * Otherwise, if pointer @len != NULL then it needs:
 * (1) find the range of free blocks of requested length or lesser;
 * (2) set the found range of blocks in pre-allocated state.
 *
 * RETURN:
 * [success] - @range of pre-allocated blocks.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENOENT     - block bitmap doesn't initialized.
 * %-ENOSPC     - block bitmap hasn't free blocks.
 */
int ssdfs_block_bmap_pre_allocate(struct ssdfs_block_bmap *blk_bmap, u32 *len,
				  struct ssdfs_block_bmap_range *range)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !range);
	if (!mutex_is_locked(&blk_bmap->lock)) {
		SSDFS_WARN("block bitmap mutex should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (len)
		SSDFS_DBG("blk_bmap %p, len %u\n", blk_bmap, *len);
	else {
		SSDFS_DBG("blk_bmap %p, range (start %u, len %u)\n",
			  blk_bmap, range->start, range->len);

		if (range_corrupted(blk_bmap, range)) {
			SSDFS_ERR("invalid range: start %u, len %u; "
				  "items count %zu\n",
				  range->start, range->len,
				  blk_bmap->items_count);
			return -EINVAL;
		}
	}

	if (!is_block_bmap_initialized(blk_bmap)) {
		SSDFS_WARN("block bitmap hasn't been initialized\n");
		return -ENOENT;
	}

	if (len) {
		u32 max_blk = blk_bmap->items_count - blk_bmap->metadata_items;
		u32 start_blk = 0;

		if (!is_cache_invalid(blk_bmap, SSDFS_BLK_FREE)) {
			err = ssdfs_define_last_free_page(blk_bmap, &start_blk);
			if (err) {
				SSDFS_ERR("fail to define start block: "
					  "err %d\n",
					  err);
				return err;
			}
		}

		err = ssdfs_block_bmap_find_range(blk_bmap, start_blk, *len,
						  max_blk,
						  SSDFS_BLK_FREE, range);
		if (err == -ENODATA) {
			SSDFS_DBG("unable to find free blocks: "
				  "start_blk %u, max_blk %u, len %u\n",
				  start_blk, max_blk, *len);
			return -ENOSPC;
		} else if (err) {
			SSDFS_ERR("fail to find free blocks: err %d\n", err);
			return err;
		}
	} else {
		if (!is_range_free(blk_bmap, range)) {
			SSDFS_ERR("range (start %u, len %u) is not free\n",
				  range->start, range->len);
			return -EINVAL;
		}
	}

	err = ssdfs_block_bmap_set_range(blk_bmap, range,
					 SSDFS_BLK_PRE_ALLOCATED);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set range (start %u, len %u): err %d\n",
			  range->start, range->len, err);
		return err;
	}

	set_block_bmap_dirty(blk_bmap);

	SSDFS_DBG("range (start %u, len %u) has been pre-allocated\n",
		  range->start, range->len);

	return 0;
}

/*
 * ssdfs_block_bmap_allocate() - allocate segment's range of blocks
 * @blk_bmap: pointer on block bitmap
 * @len: pointer on variable with requested length of range
 * @range: pointer on blocks' range [in | out]
 *
 * This function tries to find contiguous range of free
 * (or pre-allocated) blocks and to set the found range in
 * valid state.
 *
 * If pointer @len is NULL then it needs:
 * (1) check that requested range contains free or pre-allocated blocks;
 * (2) set the requested range of blocks in valid state.
 *
 * Otherwise, if pointer @len != NULL then it needs:
 * (1) find the range of free blocks of requested length or lesser;
 * (2) set the found range of blocks in valid state.
 *
 * RETURN:
 * [success] - @range of valid blocks.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENOENT     - block bitmap doesn't initialized.
 * %-ENOSPC     - block bitmap hasn't free blocks.
 */
int ssdfs_block_bmap_allocate(struct ssdfs_block_bmap *blk_bmap, u32 *len,
				struct ssdfs_block_bmap_range *range)
{
	int state = SSDFS_BLK_FREE;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !range);
	if (!mutex_is_locked(&blk_bmap->lock)) {
		SSDFS_WARN("block bitmap mutex should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (len)
		SSDFS_DBG("blk_bmap %p, len %u\n", blk_bmap, *len);
	else {
		SSDFS_DBG("blk_bmap %p, range (start %u, len %u)\n",
			  blk_bmap, range->start, range->len);

		if (range_corrupted(blk_bmap, range)) {
			SSDFS_ERR("invalid range: start %u, len %u; "
				  "items count %zu\n",
				  range->start, range->len,
				  blk_bmap->items_count);
			return -EINVAL;
		}
	}

	if (!is_block_bmap_initialized(blk_bmap)) {
		SSDFS_WARN("block bitmap hasn't been initialized\n");
		return -ENOENT;
	}

	if (len) {
		u32 max_blk = blk_bmap->items_count - blk_bmap->metadata_items;
		u32 start_blk = 0;

		if (!is_cache_invalid(blk_bmap, SSDFS_BLK_FREE)) {
			err = ssdfs_define_last_free_page(blk_bmap, &start_blk);
			if (err) {
				SSDFS_ERR("fail to define start block: "
					  "err %d\n",
					  err);
				return err;
			}
		}

		err = ssdfs_block_bmap_find_range(blk_bmap, start_blk, *len,
						  max_blk, SSDFS_BLK_FREE,
						  range);
		if (err == -ENODATA) {
			SSDFS_DBG("unable to find free blocks: "
				  "start_blk %u, max_blk %u, len %u\n",
				  start_blk, max_blk, *len);
			return -ENOSPC;
		} else if (err) {
			SSDFS_ERR("fail to find free blocks: err %d\n", err);
			return err;
		}
	} else {
		state = ssdfs_get_range_state(blk_bmap, range);

		if (state < 0) {
			SSDFS_ERR("fail to get range "
				  "(start %u, len %u) state: err %d\n",
				  range->start, range->len, state);
			return state;
		}

		if (state != SSDFS_BLK_FREE &&
		    state != SSDFS_BLK_PRE_ALLOCATED) {
			SSDFS_ERR("range (start %u, len %u) "
				  "can't be allocated\n",
				  range->start, range->len);
			return -EINVAL;
		}
	}

	err = ssdfs_block_bmap_set_range(blk_bmap, range,
					 SSDFS_BLK_VALID);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set range (start %u, len %u): err %d\n",
			  range->start, range->len, err);
		return err;
	}

	set_block_bmap_dirty(blk_bmap);

	SSDFS_DBG("range (start %u, len %u) has been allocated\n",
		  range->start, range->len);

	return 0;
}

/*
 * ssdfs_block_bmap_invalidate() - invalidate segment's range of blocks
 * @blk_bmap: pointer on block bitmap
 * @len: pointer on variable with requested length of range
 * @range: pointer on blocks' range [in | out]
 *
 * This function tries to set the requested range of blocks in
 * invalid state. At first, it checks that requested range contains
 * valid blocks only. And, then, it sets the requested range of blocks
 * in invalid state.
 *
 * RETURN:
 * [success] - @range of invalid blocks.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENOENT     - block bitmap doesn't initialized.
 */
int ssdfs_block_bmap_invalidate(struct ssdfs_block_bmap *blk_bmap,
				struct ssdfs_block_bmap_range *range)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !range);
	if (!mutex_is_locked(&blk_bmap->lock)) {
		SSDFS_WARN("block bitmap mutex should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, range (start %u, len %u)\n",
		  blk_bmap, range->start, range->len);

	if (!is_block_bmap_initialized(blk_bmap)) {
		SSDFS_WARN("block bitmap hasn't been initialized\n");
		return -ENOENT;
	}

	if (range_corrupted(blk_bmap, range)) {
		SSDFS_ERR("invalid range (start %u, len %u); items count %zu\n",
			  range->start, range->len, blk_bmap->items_count);
		return -EINVAL;
	}

	if (!is_range_valid(blk_bmap, range)) {
		SSDFS_ERR("range (start %u, len %u) hasn't valid blocks only\n",
			  range->start, range->len);
		return -EINVAL;
	}

	err = ssdfs_block_bmap_set_range(blk_bmap, range,
					 SSDFS_BLK_INVALID);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set range (start %u, len %u): err %d\n",
			  range->start, range->len, err);
		return err;
	}

	blk_bmap->invalid_blks += range->len;

	set_block_bmap_dirty(blk_bmap);

	SSDFS_DBG("range (start %u, len %u) has been invalidated\n",
		  range->start, range->len);

	return 0;
}

/*
 * ssdfs_block_bmap_collect_garbage() - find range of valid blocks for GC
 * @blk_bmap: pointer on block bitmap
 * @start: starting position for search
 * @max_len: maximum requested length of valid blocks' range
 * @blk_state: requested block state (pre-allocated or valid)
 * @range: pointer on blocks' range [out]
 *
 * This function tries to find range of valid blocks for GC.
 * The length of requested range is limited by @max_len.
 *
 * RETURN:
 * [success] - @range of invalid blocks.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENOENT     - block bitmap doesn't initialized.
 * %-ENODATA    - requested range hasn't valid blocks.
 */
int ssdfs_block_bmap_collect_garbage(struct ssdfs_block_bmap *blk_bmap,
				     u32 start, u32 max_len,
				     int blk_state,
				     struct ssdfs_block_bmap_range *range)
{
	u32 max_blk;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap || !range);
	if (!mutex_is_locked(&blk_bmap->lock)) {
		SSDFS_WARN("block bitmap mutex should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p, start %u, max_len %u\n",
		  blk_bmap, start, max_len);

	if (!is_block_bmap_initialized(blk_bmap)) {
		SSDFS_WARN("block bitmap hasn't been initialized\n");
		return -ENOENT;
	}

	max_blk = blk_bmap->items_count - blk_bmap->metadata_items;

	if (start >= max_blk) {
		SSDFS_ERR("invalid start %u; items count %u\n",
			  start, max_blk);
		return -EINVAL;
	}

	switch (blk_state) {
	case SSDFS_BLK_PRE_ALLOCATED:
	case SSDFS_BLK_VALID:
		/* valid block state */
		break;

	default:
		SSDFS_ERR("invalid block state: %#x\n",
			  blk_state);
		return -EINVAL;
	};

	err = ssdfs_block_bmap_find_range(blk_bmap, start, max_len, max_blk,
					  blk_state, range);
	if (err == -ENODATA) {
		SSDFS_DBG("range (start %u, len %u) hasn't valid blocks\n",
			  range->start, range->len);
		return err;
	} else if (err) {
		SSDFS_ERR("fail to find valid blocks: err %d\n", err);
		return err;
	}

	SSDFS_DBG("range (start %u, len %u) has been collected as garbage\n",
		  range->start, range->len);

	return 0;
}

/*
 * ssdfs_block_bmap_clean() - set all blocks as free/clean
 * @blk_bmap: pointer on block bitmap
 *
 * This function tries to clean the whole bitmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENOENT     - block bitmap doesn't initialized.
 */
int ssdfs_block_bmap_clean(struct ssdfs_block_bmap *blk_bmap)
{
	struct ssdfs_block_bmap_range range;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_bmap);
	if (!mutex_is_locked(&blk_bmap->lock)) {
		SSDFS_WARN("block bitmap mutex should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_bmap %p\n", blk_bmap);

	if (!is_block_bmap_initialized(blk_bmap)) {
		SSDFS_WARN("block bitmap hasn't been initialized\n");
		return -ENOENT;
	}

	blk_bmap->metadata_items = 0;
	blk_bmap->invalid_blks = 0;

	for (i = 0; i < SSDFS_SEARCH_TYPE_MAX; i++) {
		blk_bmap->last_search[i].page_index = PAGEVEC_SIZE;
		blk_bmap->last_search[i].offset = U16_MAX;
		blk_bmap->last_search[i].cache = 0;
	}

	range.start = 0;
	range.len = blk_bmap->items_count;

	err = ssdfs_set_range_in_storage(blk_bmap, &range, SSDFS_BLK_FREE);
	if (unlikely(err)) {
		SSDFS_ERR("fail to clean block bmap: "
			  "range (start %u, len %u), "
			  "err %d\n",
			  range.start, range.len, err);
		return err;
	}

	err = ssdfs_cache_block_state(blk_bmap, 0, SSDFS_BLK_FREE);
	if (unlikely(err)) {
		SSDFS_ERR("fail to cache last free page: err %d\n",
			  err);
		return err;
	}

	return 0;
}
