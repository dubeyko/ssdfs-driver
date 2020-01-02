//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/segment_bitmap.c - bitmap of segments implementation.
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

#include <linux/slab.h>
#include <linux/pagevec.h>
#include <linux/wait.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "page_array.h"
#include "peb.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "extents_tree.h"

extern const bool detect_clean_seg[U8_MAX + 1];
extern const bool detect_data_using_seg[U8_MAX + 1];
extern const bool detect_lnode_using_seg[U8_MAX + 1];
extern const bool detect_hnode_using_seg[U8_MAX + 1];
extern const bool detect_idxnode_using_seg[U8_MAX + 1];
extern const bool detect_used_seg[U8_MAX + 1];
extern const bool detect_pre_dirty_seg[U8_MAX + 1];
extern const bool detect_dirty_seg[U8_MAX + 1];
extern const bool detect_bad_seg[U8_MAX + 1];
extern const bool detect_clean_using_mask[U8_MAX + 1];
extern const bool detect_used_dirty_mask[U8_MAX + 1];

static
void ssdfs_segbmap_invalidatepage(struct page *page, unsigned int offset,
				  unsigned int length)
{
	SSDFS_DBG("do nothing: page_index %llu, offset %u, length %u\n",
		  (u64)page_index(page), offset, length);
}

static
int ssdfs_segbmap_releasepage(struct page *page, gfp_t mask)
{
	SSDFS_DBG("do nothing: page_index %llu, mask %#x\n",
		  (u64)page_index(page), mask);

	return 0;
}

const struct address_space_operations ssdfs_segbmap_aops = {
	.invalidatepage	= ssdfs_segbmap_invalidatepage,
	.releasepage	= ssdfs_segbmap_releasepage,
	.set_page_dirty	= __set_page_dirty_nobuffers,
};

/*
 * ssdfs_segbmap_mapping_init() - segment bitmap's mapping init
 */
static inline
void ssdfs_segbmap_mapping_init(struct address_space *mapping,
				struct inode *inode)
{
	address_space_init_once(mapping);
	mapping->a_ops = &ssdfs_segbmap_aops;
	mapping->host = inode;
	mapping->flags = 0;
	atomic_set(&mapping->i_mmap_writable, 0);
	mapping_set_gfp_mask(mapping, GFP_NOFS);
	mapping->private_data = NULL;
	mapping->writeback_index = 0;
	inode->i_mapping = mapping;
}

static const struct inode_operations def_segbmap_ino_iops;
static const struct file_operations def_segbmap_ino_fops;
static const struct address_space_operations def_segbmap_ino_aops;

/*
 * ssdfs_segbmap_get_inode() - create segment bitmap's inode object
 * @fsi: file system info object
 */
static
int ssdfs_segbmap_get_inode(struct ssdfs_fs_info *fsi)
{
	struct inode *inode;
	struct ssdfs_inode_info *ii;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p\n", fsi);

	inode = iget_locked(fsi->sb, SSDFS_SEG_BMAP_INO);
	if (unlikely(!inode)) {
		err = -ENOMEM;
		SSDFS_ERR("unable to allocate segment bitmap inode: "
			  "err %d\n",
			  err);
		return err;
	}

	BUG_ON(!(inode->i_state & I_NEW));

	inode->i_mode = S_IFREG;
	mapping_set_gfp_mask(inode->i_mapping, GFP_NOFS);

	inode->i_op = &def_segbmap_ino_iops;
	inode->i_fop = &def_segbmap_ino_fops;
	inode->i_mapping->a_ops = &def_segbmap_ino_aops;

	ii = SSDFS_I(inode);
	ii->birthtime = current_time(inode);
	ii->parent_ino = U64_MAX;

	down_write(&ii->lock);
	err = ssdfs_extents_tree_create(fsi, ii);
	up_write(&ii->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to create the extents tree: "
			  "err %d\n", err);
		unlock_new_inode(inode);
		iput(inode);
		return -ERANGE;
	}

	unlock_new_inode(inode);

	fsi->segbmap_inode = inode;

	return 0;
}

/*
 * ssdfs_segbmap_define_segments() - determine segment bitmap segment numbers
 * @fsi: file system info object
 * @array_type: array type (main or copy)
 * @segbmap: pointer on segment bitmap object [out]
 *
 * The method tries to retrieve segment numbers from volume header.
 *
 * RETURN:
 * [success] - count of valid segment numbers in the array.
 * [failure] - error code:
 *
 * %-EIO     - volume header is corrupted.
 */
static
int ssdfs_segbmap_define_segments(struct ssdfs_fs_info *fsi,
				  int array_type,
				  struct ssdfs_segment_bmap *segbmap)
{
	u64 seg;
	u8 count = 0;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !segbmap);
	BUG_ON(array_type >= SSDFS_SEGBMAP_SEG_COPY_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, array_type %#x, segbmap %p\n",
		  fsi, array_type, segbmap);

	for (i = 0; i < SSDFS_SEGBMAP_SEGS; i++)
		segbmap->seg_numbers[i][array_type] = U64_MAX;

	for (i = 0; i < SSDFS_SEGBMAP_SEGS; i++) {
		seg = le64_to_cpu(fsi->vh->segbmap.segs[i][array_type]);

		if (seg == U64_MAX)
			break;
		else if (seg >= fsi->nsegs) {
			SSDFS_ERR("invalid segment %llu, nsegs %llu\n",
				  seg, fsi->nsegs);
			return -EIO;
		}

		SSDFS_DBG("segbmap: seg[%d][%d] = %llu\n",
			  i, array_type, seg);

		segbmap->seg_numbers[i][array_type] = seg;
		count++;
	}

	SSDFS_DBG("segbmap segments count %u\n", count);

	return count;
}

/*
 * ssdfs_segbmap_create_segments() - create segbmap's segment objects
 * @fsi: file system info object
 * @array_type: array type (main or copy)
 * @segbmap: pointer on segment bitmap object [out]
 */
static
int ssdfs_segbmap_create_segments(struct ssdfs_fs_info *fsi,
				  int array_type,
				  struct ssdfs_segment_bmap *segbmap)
{
	u64 seg;
	struct ssdfs_segment_info **kaddr;
	u16 log_pages;
	u16 create_threads;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !segbmap);
	BUG_ON(array_type >= SSDFS_SEGBMAP_SEG_COPY_MAX);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, array_type %#x, segbmap %p\n",
		  fsi, array_type, segbmap);

	log_pages = le16_to_cpu(fsi->vh->segbmap_log_pages);

	/* TODO: make final desicion later */
	create_threads = SSDFS_CREATE_THREADS_DEFAULT;

	for (i = 0; i < segbmap->segs_count; i++) {
		seg = segbmap->seg_numbers[i][array_type];
		kaddr = &segbmap->segs[i][array_type];
		BUG_ON(*kaddr != NULL);

		*kaddr = ssdfs_segment_create_object(fsi, seg,
						    SSDFS_SEG_LEAF_NODE_USING,
						    SSDFS_SEGBMAP_SEG_TYPE,
						    log_pages,
						    create_threads);
		if (IS_ERR_OR_NULL(*kaddr)) {
			err = !*kaddr ? -ENOMEM : PTR_ERR(*kaddr);
			*kaddr = NULL;
			SSDFS_ERR("fail to create segment object: "
				  "seg %llu, err %d\n",
				  seg, err);
			return err;
		}

		ssdfs_segment_get_object(*kaddr);
	}

	return 0;
}

/*
 * ssdfs_segbmap_destroy_segments() - destroy segbmap's segment objects
 * @segbmap: pointer on segment bitmap object
 */
static
void ssdfs_segbmap_destroy_segments(struct ssdfs_segment_bmap *segbmap)
{
	struct ssdfs_segment_info *si;
	int i, j;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p\n", segbmap);

	for (i = 0; i < segbmap->segs_count; i++) {
		for (j = 0; j < SSDFS_SEGBMAP_SEG_COPY_MAX; j++) {
			si = segbmap->segs[i][j];

			if (!si)
				continue;

			ssdfs_segment_put_object(si);
			err = ssdfs_segment_destroy_object(si);
			if (unlikely(err == -EBUSY))
				BUG();
			else if (unlikely(err)) {
				SSDFS_WARN("issue during segment destroy: "
					   "err %d\n",
					   err);
			}
		}
	}
}

/*
 * ssdfs_segbmap_segment_init() - issue segbmap init command for PEBs
 * @si: segment object
 */
static
int ssdfs_segbmap_segment_init(struct ssdfs_segment_info *si)
{
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("si %p, seg %llu\n", si, si->seg_id);

	for (i = 0; i < si->pebs_count; i++) {
		struct ssdfs_peb_container *pebc = &si->peb_array[i];
		struct ssdfs_segment_request *req;

		SSDFS_DBG("i %d, pebc %p\n", i, pebc);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!pebc);
#endif /* CONFIG_SSDFS_DEBUG */

		req = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(req)) {
			err = (req == NULL ? -ENOMEM : PTR_ERR(req));
			req = NULL;
			SSDFS_ERR("fail to allocate segment request: err %d\n",
				  err);
			return err;
		}

		ssdfs_request_init(req);
		ssdfs_get_request(req);
		ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
						    SSDFS_READ_INIT_SEGBMAP,
						    SSDFS_REQ_ASYNC,
						    req);
		ssdfs_requests_queue_add_tail(&pebc->read_rq, req);
	}

	wake_up_all(&si->wait_queue[SSDFS_PEB_READ_THREAD]);

	return 0;
}

/*
 * ssdfs_segbmap_init() - issue segbmap init command for all segments
 * @segbmap: pointer on segment bitmap object
 */
static
int ssdfs_segbmap_init(struct ssdfs_segment_bmap *segbmap)
{
	struct ssdfs_segment_info *si;
	int i, j;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, segbmap->segs_count %u\n",
		  segbmap, segbmap->segs_count);

	for (i = 0; i < segbmap->segs_count; i++) {
		for (j = 0; j < SSDFS_SEGBMAP_SEG_COPY_MAX; j++) {
			si = segbmap->segs[i][j];

			SSDFS_DBG("i %d, j %d, si %p\n", i, j, si);

			if (!si)
				continue;

			err = ssdfs_segbmap_segment_init(si);
			if (unlikely(err)) {
				SSDFS_ERR("fail to init segment: "
					  "seg %llu, err %d\n",
					  si->seg_id, err);
				return err;
			}
		}
	}

	return 0;
}

/*
 * ssdfs_segbmap_create_fragment_bitmaps() - create fragment bitmaps
 * @segbmap: pointer on segment bitmap object
 */
static
int ssdfs_segbmap_create_fragment_bitmaps(struct ssdfs_segment_bmap *segbmap)
{
	size_t bmap_bytes;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
	BUG_ON(segbmap->fragments_count == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p\n", segbmap);

	bmap_bytes = segbmap->fragments_count + BITS_PER_LONG - 1;
	bmap_bytes /= BITS_PER_BYTE;

	for (i = 0; i < SSDFS_SEGBMAP_FBMAP_TYPE_MAX; i++) {
		unsigned long **ptr = &segbmap->fbmap[i];

		BUG_ON(*ptr);

		*ptr = kzalloc(bmap_bytes, GFP_KERNEL);
		if (!*ptr) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate fbmap: "
				  "index %d\n", i);
			goto free_fbmaps;
		}
	}

	return 0;

free_fbmaps:
	for (; i >= 0; i--)
		kfree(segbmap->fbmap[i]);

	return err;
}

/*
 * ssdfs_segbmap_destroy_fragment_bitmaps() - destroy fragment bitmaps
 * @segbmap: pointer on segment bitmap object
 */
static inline
void ssdfs_segbmap_destroy_fragment_bitmaps(struct ssdfs_segment_bmap *segbmap)
{
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p\n", segbmap);

	for (i = 0; i < SSDFS_SEGBMAP_FBMAP_TYPE_MAX; i++)
		kfree(segbmap->fbmap[i]);
}

/*
 * ssdfs_segbmap_create() - create segment bitmap object
 * @fsi: file system info object
 *
 * This method tries to create segment bitmap object.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - volume header is corrupted.
 * %-EROFS      - segbmap's flags contain error field.
 * %-EOPNOTSUPP - fragment size isn't supported.
 * %-ENOMEM     - fail to allocate memory.
 * %-ERANGE     - internal error.
 */
int ssdfs_segbmap_create(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_segment_bmap *ptr;
	size_t segbmap_obj_size = sizeof(struct ssdfs_segment_bmap);
	size_t frag_desc_size = sizeof(struct ssdfs_segbmap_fragment_desc);
	int count;
	u32 calculated;
	void *kaddr;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, segs_count %llu\n", fsi, fsi->nsegs);

	kaddr = kzalloc(segbmap_obj_size, GFP_KERNEL);
	if (!kaddr) {
		SSDFS_ERR("fail to allocate segment bitmap object\n");
		return -ENOMEM;
	}

	fsi->segbmap = ptr = (struct ssdfs_segment_bmap *)kaddr;

	ptr->fsi = fsi;

	init_rwsem(&fsi->segbmap->resize_lock);

	ptr->flags = le16_to_cpu(fsi->vh->segbmap.flags);
	if (ptr->flags & ~SSDFS_SEGBMAP_FLAGS_MASK) {
		err = -EIO;
		SSDFS_CRIT("segbmap header corrupted: "
			   "unknown flags %#x\n",
			   ptr->flags);
		goto free_segbmap_object;
	}

	if (ptr->flags & SSDFS_SEGBMAP_ERROR) {
		err = -EROFS;
		SSDFS_NOTICE("segment bitmap has corrupted state: "
			     "Please, run fsck utility\n");
		goto free_segbmap_object;
	}

	ptr->items_count = fsi->nsegs;

	ptr->bytes_count = le32_to_cpu(fsi->vh->segbmap.bytes_count);
	if (ptr->bytes_count != SEG_BMAP_BYTES(ptr->items_count)) {
		err = -EIO;
		SSDFS_CRIT("segbmap header corrupted: "
			   "bytes_count %u != calculated %u\n",
			   ptr->bytes_count,
			   SEG_BMAP_BYTES(ptr->items_count));
		goto free_segbmap_object;
	}

	ptr->fragment_size = le16_to_cpu(fsi->vh->segbmap.fragment_size);
	if (ptr->fragment_size != PAGE_SIZE) {
		err = -EOPNOTSUPP;
		SSDFS_ERR("fragment size %u isn't supported\n",
			  ptr->fragment_size);
		goto free_segbmap_object;
	}

	ptr->fragments_count = le16_to_cpu(fsi->vh->segbmap.fragments_count);
	if (ptr->fragments_count != SEG_BMAP_FRAGMENTS(ptr->items_count)) {
		err = -EIO;
		SSDFS_CRIT("segbmap header corrupted: "
			   "fragments_count %u != calculated %u\n",
			   ptr->fragments_count,
			   SEG_BMAP_FRAGMENTS(ptr->items_count));
		goto free_segbmap_object;
	}

	ptr->fragments_per_seg =
		le16_to_cpu(fsi->vh->segbmap.fragments_per_seg);
	calculated = (u32)ptr->fragments_per_seg * ptr->fragment_size;
	if (fsi->segsize < calculated) {
		err = -EIO;
		SSDFS_CRIT("segbmap header corrupted: "
			   "fragments_per_seg %u is invalid\n",
			   ptr->fragments_per_seg);
		goto free_segbmap_object;
	}

	ptr->fragments_per_peb =
		le16_to_cpu(fsi->vh->segbmap.fragments_per_peb);
	calculated = (u32)ptr->fragments_per_peb * ptr->fragment_size;
	if (fsi->erasesize < calculated) {
		err = -EIO;
		SSDFS_CRIT("segbmap header corrupted: "
			   "fragments_per_peb %u is invalid\n",
			   ptr->fragments_per_peb);
		goto free_segbmap_object;
	}

	init_rwsem(&ptr->search_lock);

	err = ssdfs_segbmap_create_fragment_bitmaps(ptr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create fragment bitmaps\n");
		goto free_segbmap_object;
	}

	kaddr = kcalloc(ptr->fragments_count, frag_desc_size, GFP_KERNEL);
	if (!kaddr) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate fragment descriptors array\n");
		goto free_fragment_bmaps;
	}

	ptr->desc_array = (struct ssdfs_segbmap_fragment_desc *)kaddr;

	for (i = 0; i < ptr->fragments_count; i++)
		init_completion(&ptr->desc_array[i].init_end);

	err = ssdfs_segbmap_get_inode(fsi);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create segment bitmap's inode: "
			  "err %d\n",
			  err);
		goto free_desc_array;
	}

	ssdfs_segbmap_mapping_init(&ptr->pages, fsi->segbmap_inode);

	count = ssdfs_segbmap_define_segments(fsi, SSDFS_MAIN_SEGBMAP_SEG,
					      ptr);
	if (count < 0) {
		err = count;
		SSDFS_ERR("fail to get segbmap segment numbers: err %d\n",
			  err);
		goto free_desc_array;
	} else if (count == 0 || count > SSDFS_SEGBMAP_SEGS) {
		err = -ERANGE;
		SSDFS_ERR("invalid segbmap segment numbers count %d\n",
			  count);
		goto forget_inode;
	}

	ptr->segs_count = le16_to_cpu(fsi->vh->segbmap.segs_count);
	if (ptr->segs_count != count) {
		err = -EIO;
		SSDFS_CRIT("segbmap header corrupted: "
			   "segs_count %u != calculated %u\n",
			   ptr->segs_count, count);
		goto forget_inode;
	}

	count = ssdfs_segbmap_define_segments(fsi, SSDFS_COPY_SEGBMAP_SEG,
					      ptr);
	if (count < 0) {
		err = count;
		SSDFS_ERR("fail to get segbmap segment numbers: err %d\n",
			  err);
		goto free_desc_array;
	} else if (count > SSDFS_SEGBMAP_SEGS) {
		err = -ERANGE;
		SSDFS_ERR("invalid segbmap segment numbers count %d\n",
			  count);
		goto forget_inode;
	}

	if (ptr->flags & SSDFS_SEGBMAP_HAS_COPY) {
		if (count == 0) {
			err = -EIO;
			SSDFS_CRIT("segbmap header corrupted: "
				   "copy segments' chain is absent\n");
			goto forget_inode;
		} else if (count != ptr->segs_count) {
			SSDFS_ERR("count %u != ptr->segs_count %u\n",
				  count, ptr->segs_count);
			goto forget_inode;
		}
	} else {
		if (count != 0) {
			err = -EIO;
			SSDFS_CRIT("segbmap header corrupted: "
				   "copy segments' chain is present\n");
			goto forget_inode;
		}
	}

	err = ssdfs_segbmap_create_segments(fsi, SSDFS_MAIN_SEGBMAP_SEG, ptr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create segbmap's segment objects: "
			  "err %d\n",
			  err);
		goto destroy_seg_objects;
	}

	if (ptr->flags & SSDFS_SEGBMAP_HAS_COPY) {
		err = ssdfs_segbmap_create_segments(fsi,
						    SSDFS_COPY_SEGBMAP_SEG,
						    ptr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create segbmap's segment objects: "
				  "err %d\n",
				  err);
			goto destroy_seg_objects;
		}
	}

	err = ssdfs_segbmap_init(ptr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init segment bitmap: err %d\n",
			  err);
		goto destroy_seg_objects;
	}

	SSDFS_DBG("DONE: create segment bitmap\n");

	return 0;

destroy_seg_objects:
	ssdfs_segbmap_destroy_segments(fsi->segbmap);

forget_inode:
	iput(fsi->segbmap_inode);

free_desc_array:
	kfree(fsi->segbmap->desc_array);

free_fragment_bmaps:
	ssdfs_segbmap_destroy_fragment_bitmaps(fsi->segbmap);

free_segbmap_object:
	kfree(fsi->segbmap);

	fsi->segbmap = NULL;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(err == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_segbmap_destroy() - destroy segment bitmap object
 * @fsi: file system info object
 *
 * This method destroys segment bitmap object.
 */
void ssdfs_segbmap_destroy(struct ssdfs_fs_info *fsi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p\n", fsi->segbmap);

	if (!fsi->segbmap)
		return;

	inode_lock(fsi->segbmap_inode);
	down_write(&fsi->segbmap->resize_lock);
	down_write(&fsi->segbmap->search_lock);

	ssdfs_segbmap_destroy_segments(fsi->segbmap);

	if (mapping_tagged(&fsi->segbmap->pages, PAGECACHE_TAG_DIRTY)) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"segment bitmap is dirty on destruction\n");
	}

	if (fsi->segbmap->pages.nrpages != 0)
		truncate_inode_pages(&fsi->segbmap->pages, 0);

	ssdfs_segbmap_destroy_fragment_bitmaps(fsi->segbmap);
	kfree(fsi->segbmap->desc_array);

	up_write(&fsi->segbmap->resize_lock);
	up_write(&fsi->segbmap->search_lock);
	inode_unlock(fsi->segbmap_inode);

	iput(fsi->segbmap_inode);
	kfree(fsi->segbmap);
	fsi->segbmap = NULL;
}

/*
 * ssdfs_segbmap_check_fragment_header() - check fragment's header
 * @pebc: pointer on PEB container
 * @seg_index: index of segment in segbmap's segments sequence
 * @sequence_id: sequence ID of fragment
 * @page: page contains fragment
 *
 * This method tries to check fragment's header.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO     - fragment is corrupted.
 */
int ssdfs_segbmap_check_fragment_header(struct ssdfs_peb_container *pebc,
					u16 seg_index,
					u16 sequence_id,
					struct page *page)
{
	struct ssdfs_segment_bmap *segbmap;
	struct ssdfs_segbmap_fragment_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_segbmap_fragment_header);
	void *kaddr;
	u16 fragment_bytes;
	__le32 old_csum, csum;
	u16 total_segs, calculated_segs;
	u16 clean_or_using_segs, used_or_dirty_segs, bad_segs;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, page %p\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  page);

	segbmap = pebc->parent_si->fsi->segbmap;

	kaddr = kmap(page);

	hdr = SSDFS_SBMP_FRAG_HDR(kaddr);

	if (le32_to_cpu(hdr->magic) != SSDFS_SEGBMAP_HDR_MAGIC) {
		err = -EIO;
		SSDFS_ERR("segbmap header is corrupted: "
			  "invalid magic\n");
		goto fragment_hdr_corrupted;
	}

	fragment_bytes = le16_to_cpu(hdr->fragment_bytes);
	if (fragment_bytes > segbmap->fragment_size) {
		err = -EIO;
		SSDFS_ERR("segbmap header is corrupted: "
			  "invalid fragment size %u\n",
			  fragment_bytes);
		goto fragment_hdr_corrupted;
	}

	old_csum = hdr->checksum;
	hdr->checksum = 0;
	csum = ssdfs_crc32_le(kaddr, fragment_bytes);
	hdr->checksum = old_csum;

	if (old_csum != csum) {
		err = -EIO;
		SSDFS_ERR("segbmap header is corrupted: "
			  "old_csum %u != csum %u\n",
			  le32_to_cpu(old_csum),
			  le32_to_cpu(csum));
		goto fragment_hdr_corrupted;
	}

	if (seg_index != le16_to_cpu(hdr->seg_index)) {
		err = -EIO;
		SSDFS_ERR("segbmap header is corrupted: "
			  "seg_index %u != hdr->seg_index %u\n",
			  seg_index, le16_to_cpu(hdr->seg_index));
		goto fragment_hdr_corrupted;
	}

	if (pebc->peb_index != le16_to_cpu(hdr->peb_index)) {
		err = -EIO;
		SSDFS_ERR("segbmap header is corrupted: "
			  "peb_index %u != hdr->peb_index %u\n",
			  pebc->peb_index,
			  le16_to_cpu(hdr->peb_index));
		goto fragment_hdr_corrupted;
	}

	if (hdr->seg_type >= SSDFS_SEGBMAP_SEG_COPY_MAX) {
		err = -EIO;
		SSDFS_ERR("segbmap header is corrupted: "
			  "invalid seg_type %u\n",
			  hdr->seg_type);
		goto fragment_hdr_corrupted;
	}

	if (sequence_id != le16_to_cpu(hdr->sequence_id)) {
		err = -EIO;
		SSDFS_ERR("segbmap header is corrupted: "
			  "sequence_id %u != hdr->sequence_id %u\n",
			  sequence_id,
			  le16_to_cpu(hdr->sequence_id));
		goto fragment_hdr_corrupted;
	}

	total_segs = le16_to_cpu(hdr->total_segs);
	if (fragment_bytes != (SEG_BMAP_BYTES(total_segs) + hdr_size)) {
		err = -EIO;
		SSDFS_ERR("segbmap header is corrupted: "
			  "invalid fragment's items count %u\n",
			  total_segs);
		goto fragment_hdr_corrupted;
	}

	clean_or_using_segs = le16_to_cpu(hdr->clean_or_using_segs);
	used_or_dirty_segs = le16_to_cpu(hdr->used_or_dirty_segs);
	bad_segs = le16_to_cpu(hdr->bad_segs);
	calculated_segs = clean_or_using_segs + used_or_dirty_segs + bad_segs;

	if (total_segs != calculated_segs) {
		err = -EIO;
		SSDFS_ERR("segbmap header is corrupted: "
			  "clean_or_using_segs %u, "
			  "used_or_dirty_segs %u, "
			  "bad_segs %u, total_segs %u\n",
			  clean_or_using_segs, used_or_dirty_segs,
			  bad_segs, total_segs);
		goto fragment_hdr_corrupted;
	}

fragment_hdr_corrupted:
	kunmap(page);

	return err;
}

/*
 * ssdfs_segbmap_fragment_init() - init segbmap's fragment
 * @pebc: pointer on PEB container
 * @sequence_id: sequence ID of fragment
 * @page: page contains fragment
 * @state: state of fragment
 */
int ssdfs_segbmap_fragment_init(struct ssdfs_peb_container *pebc,
				u16 sequence_id,
				struct page *page,
				int state)
{
	struct ssdfs_segment_bmap *segbmap;
	struct ssdfs_segbmap_fragment_header *hdr;
	struct ssdfs_segbmap_fragment_desc *desc;
	unsigned long *fbmap;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!pebc->parent_si->fsi->segbmap || !page);
	BUG_ON(state <= SSDFS_SEGBMAP_FRAG_CREATED ||
		state >= SSDFS_SEGBMAP_FRAG_DIRTY);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "sequence_id %u, page %p, "
		  "state %#x\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  sequence_id, page, state);

	segbmap = pebc->parent_si->fsi->segbmap;

	inode_lock_shared(pebc->parent_si->fsi->segbmap_inode);

	get_page(page);
	page->index = sequence_id;

	down_write(&segbmap->search_lock);

	desc = &segbmap->desc_array[sequence_id];

	xa_lock_irq(&segbmap->pages.i_pages);
	err = __xa_insert(&segbmap->pages.i_pages,
			 sequence_id, page, GFP_NOFS);
	if (unlikely(err < 0)) {
		SSDFS_DBG("fail to add page %u into address space: err %d\n",
			  sequence_id, err);
		page->mapping = NULL;
		put_page(page);
	} else {
		page->mapping = &segbmap->pages;
		segbmap->pages.nrpages++;
	}
	xa_unlock_irq(&segbmap->pages.i_pages);

	if (unlikely(err))
		goto unlock_search_lock;

	if (desc->state != SSDFS_SEGBMAP_FRAG_CREATED) {
		err = -ERANGE;
		SSDFS_ERR("fail to initialize segbmap fragment\n");
	} else {
		hdr = SSDFS_SBMP_FRAG_HDR(kmap_atomic(page));
		desc->total_segs = le16_to_cpu(hdr->total_segs);

		fbmap = segbmap->fbmap[SSDFS_SEGBMAP_CLEAN_USING_FBMAP];
		desc->clean_or_using_segs =
			le16_to_cpu(hdr->clean_or_using_segs);
		if (desc->clean_or_using_segs == 0)
			bitmap_clear(fbmap, sequence_id, 1);
		else
			bitmap_set(fbmap, sequence_id, 1);

		fbmap = segbmap->fbmap[SSDFS_SEGBMAP_USED_DIRTY_FBMAP];
		desc->used_or_dirty_segs =
			le16_to_cpu(hdr->used_or_dirty_segs);
		if (desc->used_or_dirty_segs == 0)
			bitmap_clear(fbmap, sequence_id, 1);
		else
			bitmap_set(fbmap, sequence_id, 1);

		fbmap = segbmap->fbmap[SSDFS_SEGBMAP_BAD_FBMAP];
		desc->bad_segs = le16_to_cpu(hdr->bad_segs);
		if (desc->bad_segs == 0)
			bitmap_clear(fbmap, sequence_id, 1);
		else
			bitmap_set(fbmap, sequence_id, 1);

		desc->state = state;
		kunmap_atomic(hdr);
	}

unlock_search_lock:
	complete_all(&desc->init_end);
	up_write(&segbmap->search_lock);
	inode_unlock_shared(pebc->parent_si->fsi->segbmap_inode);

	return err;
}

/*
 * ssdfs_sb_segbmap_header_correct_state() - save segbmap's state in superblock
 * @segbmap: pointer on segment bitmap object
 */
static
void ssdfs_sb_segbmap_header_correct_state(struct ssdfs_segment_bmap *segbmap)
{
	struct ssdfs_segbmap_sb_header *hdr;
	__le64 seg;
	int i, j;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
	BUG_ON(!rwsem_is_locked(&segbmap->resize_lock));
	BUG_ON(!rwsem_is_locked(&segbmap->fsi->volume_sem));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p\n",
		  segbmap);

	hdr = &segbmap->fsi->vh->segbmap;

	hdr->fragments_count = cpu_to_le16(segbmap->fragments_count);
	hdr->fragments_per_seg = cpu_to_le16(segbmap->fragments_per_seg);
	hdr->fragments_per_peb = cpu_to_le16(segbmap->fragments_per_peb);
	hdr->fragment_size = cpu_to_le16(segbmap->fragment_size);

	hdr->bytes_count = cpu_to_le32(segbmap->bytes_count);
	hdr->flags = cpu_to_le16(segbmap->flags);
	hdr->segs_count = cpu_to_le16(segbmap->segs_count);

	for (i = 0; i < segbmap->segs_count; i++) {
		j = SSDFS_MAIN_SEGBMAP_SEG;
		seg = cpu_to_le64(segbmap->seg_numbers[i][j]);
		hdr->segs[i][j] = seg;

		j = SSDFS_COPY_SEGBMAP_SEG;
		seg = cpu_to_le64(segbmap->seg_numbers[i][j]);
		hdr->segs[i][j] = seg;
	}
}

/*
 * ssdfs_segbmap_copy_dirty_fragment() - copy dirty fragment into request
 * @segbmap: pointer on segment bitmap object
 * @fragment_index: index of fragment
 * @page_index: index of page in request
 * @req: segment request
 *
 * This method tries to copy dirty fragment into request.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_segbmap_copy_dirty_fragment(struct ssdfs_segment_bmap *segbmap,
				      u16 fragment_index,
				      u16 page_index,
				      struct ssdfs_segment_request *req)
{
	struct ssdfs_segbmap_fragment_desc *desc;
	struct ssdfs_segbmap_fragment_header *hdr;
	struct page *dpage, *spage;
	void *kaddr1, *kaddr2;
	u16 fragment_bytes;
	__le32 old_csum, csum;
	u16 total_segs;
	u16 clean_or_using_segs;
	u16 used_or_dirty_segs;
	u16 bad_segs;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap || !req);
	BUG_ON(!rwsem_is_locked(&segbmap->search_lock));
	BUG_ON(page_index >= PAGEVEC_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, fragment_index %u, "
		  "page_index %u, req %p\n",
		  segbmap, fragment_index, page_index, req);

	desc = &segbmap->desc_array[fragment_index];

	if (desc->state != SSDFS_SEGBMAP_FRAG_DIRTY) {
		SSDFS_ERR("fragment %u isn't dirty\n",
			  fragment_index);
		return -ERANGE;
	}

	spage = find_lock_page(&segbmap->pages, fragment_index);
	if (!spage) {
		SSDFS_ERR("fail to find page: fragment_index %u\n",
			  fragment_index);
		return -ERANGE;
	}

	kaddr1 = kmap(spage);

	hdr = SSDFS_SBMP_FRAG_HDR(kaddr1);

	if (le32_to_cpu(hdr->magic) != SSDFS_SEGBMAP_HDR_MAGIC) {
		err = -ERANGE;
		SSDFS_ERR("segbmap header is corrupted: "
			  "invalid magic\n");
		goto fail_copy_fragment;
	}

	fragment_bytes = le16_to_cpu(hdr->fragment_bytes);

	old_csum = hdr->checksum;
	hdr->checksum = 0;
	csum = ssdfs_crc32_le(kaddr1, fragment_bytes);
	hdr->checksum = old_csum;

	if (old_csum != csum) {
		err = -ERANGE;
		SSDFS_ERR("segbmap header is corrupted: "
			  "old_csum %u != csum %u\n",
			  le32_to_cpu(old_csum),
			  le32_to_cpu(csum));
		goto fail_copy_fragment;
	}

	total_segs = desc->total_segs;
	if (total_segs != le16_to_cpu(hdr->total_segs)) {
		err = -ERANGE;
		SSDFS_ERR("segbmap header is corrupted: "
			  "desc->total_segs %u != hdr->total_segs %u\n",
			  desc->total_segs,
			  le16_to_cpu(hdr->total_segs));
		goto fail_copy_fragment;
	}

	clean_or_using_segs = desc->clean_or_using_segs;
	if (clean_or_using_segs != le16_to_cpu(hdr->clean_or_using_segs)) {
		err = -ERANGE;
		SSDFS_ERR("segbmap header is corrupted: "
			  "desc->clean_or_using_segs %u != "
			  "hdr->clean_or_using_segs %u\n",
			  desc->clean_or_using_segs,
			  le16_to_cpu(hdr->clean_or_using_segs));
		goto fail_copy_fragment;
	}

	used_or_dirty_segs = desc->used_or_dirty_segs;
	if (used_or_dirty_segs != le16_to_cpu(hdr->used_or_dirty_segs)) {
		err = -ERANGE;
		SSDFS_ERR("segbmap header is corrupted: "
			  "desc->used_or_dirty_segs %u != "
			  "hdr->used_or_dirty_segs %u\n",
			  desc->used_or_dirty_segs,
			  le16_to_cpu(hdr->used_or_dirty_segs));
		goto fail_copy_fragment;
	}

	bad_segs = desc->bad_segs;
	if (bad_segs != le16_to_cpu(hdr->bad_segs)) {
		err = -ERANGE;
		SSDFS_ERR("segbmap header is corrupted: "
			  "desc->bad_segs %u != "
			  "hdr->bad_segs %u\n",
			  desc->bad_segs,
			  le16_to_cpu(hdr->bad_segs));
		goto fail_copy_fragment;
	}

	dpage = req->result.pvec.pages[page_index];

	if (!dpage) {
		err = -ERANGE;
		SSDFS_ERR("invalid page: page_index %u\n",
			  page_index);
		goto fail_copy_fragment;
	}

	kaddr2 = kmap_atomic(dpage);
	memcpy(kaddr2, kaddr1, PAGE_SIZE);
	kunmap_atomic(kaddr2);

	SetPageUptodate(dpage);
	if (!PageDirty(dpage))
		__set_page_dirty_nobuffers(dpage);
	set_page_writeback(dpage);

	ssdfs_clear_dirty_page(spage);

	desc->state = SSDFS_SEGBMAP_FRAG_TOWRITE;

fail_copy_fragment:
	kunmap(spage);
	unlock_page(spage);
	put_page(spage);

	return err;
}

/*
 * ssdfs_segbmap_replicate_fragment() - replicate fragment between requests
 * @req1: source request
 * @page_index: index of replicated page in @req1
 * @req2: destination request
 */
static
void ssdfs_segbmap_replicate_fragment(struct ssdfs_segment_request *req1,
				     u16 page_index,
				     struct ssdfs_segment_request *req2)
{
	struct ssdfs_segbmap_fragment_header *hdr;
	u16 fragment_bytes;
	struct page *spage, *dpage;
	void *kaddr1, *kaddr2;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req1 || !req2);
	BUG_ON(page_index >= pagevec_count(&req1->result.pvec));
	BUG_ON(page_index >= pagevec_count(&req2->result.pvec));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("req1 %p, req2 %p, page_index %u\n",
		  req1, req2, page_index);

	spage = req1->result.pvec.pages[page_index];
	dpage = req2->result.pvec.pages[page_index];

	kaddr1 = kmap_atomic(spage);

	kaddr2 = kmap_atomic(dpage);
	memcpy(kaddr2, kaddr1, PAGE_SIZE);
	kunmap_atomic(kaddr1);

	hdr = SSDFS_SBMP_FRAG_HDR(kaddr2);
	hdr->seg_type = SSDFS_COPY_SEGBMAP_SEG;
	fragment_bytes = le16_to_cpu(hdr->fragment_bytes);
	hdr->checksum = 0;
	hdr->checksum = ssdfs_crc32_le(kaddr2, fragment_bytes);

	kunmap_atomic(kaddr2);

	SetPageUptodate(dpage);
	if (!PageDirty(dpage))
		__set_page_dirty_nobuffers(dpage);
	set_page_writeback(dpage);
}

/*
 * ssdfs_segbmap_define_volume_extent() - define volume extent for request
 * @segbmap: pointer on segment bitmap object
 * @req: segment request
 * @hdr: fragment's header
 * @fragments_count: count of fragments in the chunk
 * @seg_index: index of segment in segbmap's array [out]
 */
static
int ssdfs_segbmap_define_volume_extent(struct ssdfs_segment_bmap *segbmap,
				    struct ssdfs_segment_request *req,
				    struct ssdfs_segbmap_fragment_header *hdr,
				    u16 fragments_count,
				    u16 *seg_index)
{
	u16 sequence_id;
	u16 fragment_index;
	u32 pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap || !req || !hdr || !seg_index);
	BUG_ON(!rwsem_is_locked(&segbmap->search_lock));
	BUG_ON(!rwsem_is_locked(&segbmap->resize_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, req %p\n",
		  segbmap, req);

	*seg_index = le16_to_cpu(hdr->seg_index);
	sequence_id = le16_to_cpu(hdr->sequence_id);

	if (*seg_index != (sequence_id / segbmap->fragments_per_seg)) {
		SSDFS_ERR("invalid seg_index %u or sequence_id %u\n",
			  *seg_index, sequence_id);
		return -ERANGE;
	}

	fragment_index = sequence_id % segbmap->fragments_per_seg;
	pagesize = segbmap->fsi->pagesize;

	if (pagesize < segbmap->fragment_size) {
		u32 pages_per_item;

		pages_per_item = segbmap->fragment_size + pagesize - 1;
		pages_per_item /= pagesize;
		req->place.start.blk_index = fragment_index * pages_per_item;
		req->place.len = fragments_count * pages_per_item;
	} else if (pagesize > segbmap->fragment_size) {
		u32 items_per_page;

		items_per_page = pagesize + segbmap->fragment_size - 1;
		items_per_page /= segbmap->fragment_size;
		req->place.start.blk_index = fragment_index / items_per_page;
		req->place.len = fragments_count + items_per_page - 1;
		req->place.len /= items_per_page;
	} else {
		req->place.start.blk_index = fragment_index;
		req->place.len = fragments_count;
	}

	return 0;
}

/*
 * ssdfs_segbmap_issue_fragments_update() - issue fragment updates
 * @segbmap: pointer on segment bitmap object
 * @start_fragment: start fragment number for dirty bitmap
 * @fragment_size: size of fragment in bytes
 * @dirty_bmap: bitmap for dirty states searching
 *
 * This method tries to issue updates for all dirty fragments
 * in @dirty_bmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - @dirty_bmap hasn't dirty fragments.
 * %-ENOMEM     - fail to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_segbmap_issue_fragments_update(struct ssdfs_segment_bmap *segbmap,
					 u16 start_fragment,
					 u16 fragment_size,
					 unsigned long dirty_bmap)
{
	struct ssdfs_segment_request *req1 = NULL, *req2 = NULL;
	struct ssdfs_segbmap_fragment_desc *fragment;
	struct ssdfs_segbmap_fragment_header *hdr;
	struct ssdfs_segment_info *si;
	void *kaddr;
	bool is_bit_found;
	bool has_backup;
	u64 ino = SSDFS_SEG_BMAP_INO;
	u64 offset;
	u32 size;
	u16 fragments_count;
	u16 seg_index;
	int i = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
	BUG_ON(!rwsem_is_locked(&segbmap->search_lock));
	BUG_ON(!rwsem_is_locked(&segbmap->resize_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, start_fragment %u, dirty_bmap %#lx\n",
		  segbmap, start_fragment, dirty_bmap);

	if (dirty_bmap == 0) {
		SSDFS_DBG("bmap doesn't contain dirty bits\n");
		return -ENODATA;
	}

	has_backup = segbmap->flags & SSDFS_SEGBMAP_HAS_COPY;

	do {
		is_bit_found = test_bit(i, &dirty_bmap);

		if (!is_bit_found) {
			i++;
			continue;
		}

		fragment = &segbmap->desc_array[start_fragment + i];

		if (fragment->state != SSDFS_SEGBMAP_FRAG_DIRTY) {
			SSDFS_ERR("invalid fragment's state %#x\n",
				  fragment->state);
			return -ERANGE;
		}

		req1 = &fragment->flush_req1;
		req2 = &fragment->flush_req2;

		ssdfs_request_init(req1);
		ssdfs_get_request(req1);

		if (has_backup) {
			ssdfs_request_init(req2);
			ssdfs_get_request(req2);
		}

		err = ssdfs_request_add_allocated_page_locked(req1);
		if (!err && has_backup)
			err = ssdfs_request_add_allocated_page_locked(req2);

		if (unlikely(err)) {
			SSDFS_ERR("fail allocate memory page: err %d\n", err);
			goto fail_issue_fragment_updates;
		}

		err = ssdfs_segbmap_copy_dirty_fragment(segbmap,
							start_fragment + i,
							0, req1);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy dirty fragment: "
				  "fragment %u, err %d\n",
				  start_fragment + i, err);
			goto fail_issue_fragment_updates;
		}

		if (has_backup)
			ssdfs_segbmap_replicate_fragment(req1, 0, req2);

		i++;

		offset = (u64)start_fragment + i;
		offset *= fragment_size;
		size = fragment_size;

		ssdfs_request_prepare_logical_extent(ino, offset, size,
						     0, 0, req1);

		if (has_backup) {
			ssdfs_request_prepare_logical_extent(ino,
							     offset,
							     size,
							     0, 0,
							     req2);
		}

		fragments_count = (u16)pagevec_count(&req1->result.pvec);
		kaddr = kmap(req1->result.pvec.pages[0]);
		hdr = SSDFS_SBMP_FRAG_HDR(kaddr);
		err = ssdfs_segbmap_define_volume_extent(segbmap, req1,
							 hdr,
							 fragments_count,
							 &seg_index);
		kunmap(req1->result.pvec.pages[0]);

		if (unlikely(err)) {
			SSDFS_ERR("fail to define volume extent: "
				  "err %d\n",
				  err);
			goto fail_issue_fragment_updates;
		}

		if (has_backup) {
			memcpy(&req2->place, &req1->place,
				sizeof(struct ssdfs_volume_extent));
		}

		si = segbmap->segs[seg_index][SSDFS_MAIN_SEGBMAP_SEG];
		err = ssdfs_segment_update_extent_async(si,
							SSDFS_REQ_ASYNC_NO_FREE,
							req1);
		si = segbmap->segs[seg_index][SSDFS_COPY_SEGBMAP_SEG];
		if (!err && has_backup) {
			err = ssdfs_segment_update_extent_async(si,
							SSDFS_REQ_ASYNC_NO_FREE,
							req2);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to update extent: "
				  "seg_index %u, err %d\n",
				  seg_index, err);
			goto fail_issue_fragment_updates;
		}
	} while (i < BITS_PER_LONG);

	return 0;

fail_issue_fragment_updates:
	ssdfs_request_unlock_and_remove_pages(req1);
	ssdfs_put_request(req1);

	if (has_backup) {
		ssdfs_request_unlock_and_remove_pages(req2);
		ssdfs_put_request(req2);
	}

	return err;
}

/*
 * ssdfs_segbmap_flush_dirty_fragments() - flush dirty fragments
 * @segbmap: pointer on segment bitmap object
 * @fragments_count: count of fragments in segbmap
 * @fragment_size: size of fragment in bytes
 *
 * This method tries to flush all dirty fragments.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - segbmap hasn't dirty fragments.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_segbmap_flush_dirty_fragments(struct ssdfs_segment_bmap *segbmap,
					u16 fragments_count,
					u16 fragment_size)
{
	unsigned long *fbmap;
	int size;
	unsigned long *found;
	u16 start_fragment;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
	BUG_ON(!rwsem_is_locked(&segbmap->search_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, fragments_count %u, fragment_size %u\n",
		  segbmap, fragments_count, fragment_size);

	fbmap = segbmap->fbmap[SSDFS_SEGBMAP_MODIFICATION_FBMAP];

	size = fragments_count;
	err = ssdfs_find_first_dirty_fragment(fbmap, size, &found);
	if (err == -ENODATA) {
		SSDFS_DBG("segbmap hasn't dirty fragments\n");
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find dirty fragments: "
			  "err %d\n",
			  err);
		return err;
	} else if (!found) {
		SSDFS_ERR("invalid bitmap pointer\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(((found - fbmap) * BITS_PER_LONG) >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	start_fragment = (u16)((found - fbmap) * BITS_PER_LONG);

	err = ssdfs_segbmap_issue_fragments_update(segbmap, start_fragment,
						   fragment_size, *found);
	if (unlikely(err)) {
		SSDFS_ERR("fail to issue fragments update: "
			  "start_fragment %u, found %#lx, err %d\n",
			  start_fragment, *found, err);
		return err;
	}

	err = ssdfs_clear_dirty_state(found);
	if (unlikely(err)) {
		SSDFS_ERR("fail to clear dirty state: "
			  "err %d\n",
			  err);
		return err;
	}

	size = fragments_count - (start_fragment + BITS_PER_LONG);
	while (size > 0) {
		err = ssdfs_find_first_dirty_fragment(++found, size,
						      &found);
		if (err == -ENODATA)
			return 0;
		else if (unlikely(err)) {
			SSDFS_ERR("fail to find dirty fragments: "
				  "err %d\n",
				  err);
			return err;
		} else if (!found) {
			SSDFS_ERR("invalid bitmap pointer\n");
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(((found - fbmap) * BITS_PER_LONG) >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		start_fragment = (u16)((found - fbmap) * BITS_PER_LONG);

		err = ssdfs_segbmap_issue_fragments_update(segbmap,
							   start_fragment,
							   fragment_size,
							   *found);
		if (unlikely(err)) {
			SSDFS_ERR("fail to issue fragments update: "
				  "start_fragment %u, found %#lx, err %d\n",
				  start_fragment, *found, err);
			return err;
		}

		err = ssdfs_clear_dirty_state(found);
		if (unlikely(err)) {
			SSDFS_ERR("fail to clear dirty state: "
				  "err %d\n",
				  err);
			return err;
		}

		size = fragments_count - (start_fragment + BITS_PER_LONG);
	}

	return 0;
}

/*
 * ssdfs_segbmap_wait_flush_end() - wait flush ending
 * @segbmap: pointer on segment bitmap object
 * @fragments_count: count of fragments in segbmap
 *
 * This method is waiting the end of flush operation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_segbmap_wait_flush_end(struct ssdfs_segment_bmap *segbmap,
				 u16 fragments_count)
{
	struct ssdfs_segbmap_fragment_desc *fragment;
	struct ssdfs_segment_request *req1 = NULL, *req2 = NULL;
	bool has_backup;
	atomic_t *refs_count;
	wait_queue_head_t *wq = NULL;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
	BUG_ON(!rwsem_is_locked(&segbmap->search_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, fragments_count %u\n",
		  segbmap, fragments_count);

	has_backup = segbmap->flags & SSDFS_SEGBMAP_HAS_COPY;

	for (i = 0; i < fragments_count; i++) {
		fragment = &segbmap->desc_array[i];

		switch (fragment->state) {
		case SSDFS_SEGBMAP_FRAG_DIRTY:
			SSDFS_ERR("found unprocessed dirty fragment: "
				  "index %d\n", i);
			return -ERANGE;

		case SSDFS_SEGBMAP_FRAG_TOWRITE:
			req1 = &fragment->flush_req1;
			req2 = &fragment->flush_req2;

check_req1_state:
			switch (atomic_read(&req1->result.state)) {
			case SSDFS_REQ_CREATED:
			case SSDFS_REQ_STARTED:
				refs_count = &req1->private.refs_count;
				wq = &req1->private.wait_queue;

				if (atomic_read(refs_count) != 0) {
					err = wait_event_killable_timeout(*wq,
						atomic_read(refs_count) == 0,
						SSDFS_DEFAULT_TIMEOUT);
					if (err < 0)
						WARN_ON(err < 0);
					else
						err = 0;

					goto check_req1_state;
				} else {
					SSDFS_ERR("invalid refs_count %d\n",
						  atomic_read(refs_count));
					return -ERANGE;
				}
				break;

			case SSDFS_REQ_FINISHED:
				/* do nothing */
				break;

			case SSDFS_REQ_FAILED:
				err = req1->result.err;

				if (!err) {
					err = -ERANGE;
					SSDFS_ERR("error code is absent\n");
				}

				SSDFS_ERR("flush request is failed: "
					  "err %d\n", err);
				return err;

			default:
				SSDFS_ERR("invalid result's state %#x\n",
				    atomic_read(&req1->result.state));
				return -ERANGE;
			}

			if (!has_backup)
				goto finish_fragment_check;

check_req2_state:
			switch (atomic_read(&req2->result.state)) {
			case SSDFS_REQ_CREATED:
			case SSDFS_REQ_STARTED:
				refs_count = &req2->private.refs_count;
				wq = &req2->private.wait_queue;

				if (atomic_read(refs_count) != 0) {
					err = wait_event_killable_timeout(*wq,
						atomic_read(refs_count) == 0,
						SSDFS_DEFAULT_TIMEOUT);
					if (err < 0)
						WARN_ON(err < 0);
					else
						err = 0;

					goto check_req2_state;
				} else {
					SSDFS_ERR("invalid refs_count %d\n",
						  atomic_read(refs_count));
					return -ERANGE;
				}
				break;

			case SSDFS_REQ_FINISHED:
				/* do nothing */
				break;

			case SSDFS_REQ_FAILED:
				err = req2->result.err;

				if (!err) {
					err = -ERANGE;
					SSDFS_ERR("error code is absent\n");
				}

				SSDFS_ERR("flush request is failed: "
					  "err %d\n", err);
				return err;

			default:
				SSDFS_ERR("invalid result's state %#x\n",
				    atomic_read(&req2->result.state));
				return -ERANGE;
			}

finish_fragment_check:
			break;

		default:
			/* do nothing */
			break;
		}
	}

	return 0;
}

/*
 * ssdfs_segbmap_issue_commit_logs() - request logs commit
 * @segbmap: pointer on segment bitmap object
 * @fragments_count: count of fragments in segbmap
 * @fragment_size: size of fragment in bytes
 *
 * This method tries to issue the commit logs operation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_segbmap_issue_commit_logs(struct ssdfs_segment_bmap *segbmap,
				    u16 fragments_count,
				    u16 fragment_size)
{
	struct ssdfs_segbmap_fragment_desc *fragment;
	struct ssdfs_segbmap_fragment_header *hdr;
	struct ssdfs_segment_request *req1 = NULL, *req2 = NULL;
	struct ssdfs_segment_info *si;
	struct page *page;
	void *kaddr;
	u64 ino = SSDFS_SEG_BMAP_INO;
	bool has_backup;
	u64 offset;
	u16 seg_index;
	int copy_id;
	u16 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
	BUG_ON(!rwsem_is_locked(&segbmap->search_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, fragments_count %u, fragment_size %u\n",
		  segbmap, fragments_count, fragment_size);

	has_backup = segbmap->flags & SSDFS_SEGBMAP_HAS_COPY;

	for (i = 0; i < fragments_count; i++) {
		fragment = &segbmap->desc_array[i];

		switch (fragment->state) {
		case SSDFS_SEGBMAP_FRAG_DIRTY:
			SSDFS_ERR("found unprocessed dirty fragment: "
				  "index %d\n", i);
			return -ERANGE;

		case SSDFS_SEGBMAP_FRAG_TOWRITE:
			req1 = &fragment->flush_req1;
			req2 = &fragment->flush_req2;

			ssdfs_request_init(req1);
			ssdfs_get_request(req1);

			offset = (u64)i;
			offset *= fragment_size;

			ssdfs_request_prepare_logical_extent(ino, offset,
							     0, 0, 0, req1);

			page = find_lock_page(&segbmap->pages, i);
			if (!page) {
				err = -ERANGE;
				SSDFS_ERR("fail to find page: "
					  "fragment_index %u\n",
					  i);
				goto fail_issue_commit_logs;
			}

			kaddr = kmap(page);

			hdr = SSDFS_SBMP_FRAG_HDR(kaddr);

			err = ssdfs_segbmap_define_volume_extent(segbmap, req1,
								 hdr, 1,
								 &seg_index);
			if (unlikely(err)) {
				SSDFS_ERR("fail to define volume extent: "
					  "err %d\n",
					  err);
			}

			kunmap(page);
			unlock_page(page);
			put_page(page);

			if (unlikely(err))
				goto fail_issue_commit_logs;

			copy_id = SSDFS_MAIN_SEGBMAP_SEG;
			si = segbmap->segs[seg_index][copy_id];

			err = ssdfs_segment_commit_log_async(si,
							SSDFS_REQ_ASYNC_NO_FREE,
							req1);
			if (unlikely(err)) {
				SSDFS_ERR("fail to issue the commit log: "
					  "seg_index %u, err %d\n",
					  seg_index, err);
				goto fail_issue_commit_logs;
			}

			if (has_backup) {
				ssdfs_request_init(req2);
				ssdfs_get_request(req2);

				ssdfs_request_prepare_logical_extent(ino,
								     offset,
								     0, 0, 0,
								     req2);

				memcpy(&req2->place, &req1->place,
					sizeof(struct ssdfs_volume_extent));

				copy_id = SSDFS_COPY_SEGBMAP_SEG;
				si = segbmap->segs[seg_index][copy_id];

				err = ssdfs_segment_commit_log_async(si,
							SSDFS_REQ_ASYNC_NO_FREE,
							req2);
				if (unlikely(err)) {
					SSDFS_ERR("fail to issue log commit: "
						  "seg_index %u, err %d\n",
						  seg_index, err);
					goto fail_issue_commit_logs;
				}
			}
			break;

		default:
			/* do nothing */
			break;
		}
	}

	return 0;

fail_issue_commit_logs:
	ssdfs_put_request(req1);

	if (has_backup)
		ssdfs_put_request(req2);

	return err;
}

/*
 * ssdfs_segbmap_wait_finish_commit_logs() - wait commit logs ending
 * @segbmap: pointer on segment bitmap object
 * @fragments_count: count of fragments in segbmap
 *
 * This method is waiting the end of commit logs operation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_segbmap_wait_finish_commit_logs(struct ssdfs_segment_bmap *segbmap,
					  u16 fragments_count)
{
	struct ssdfs_segbmap_fragment_desc *fragment;
	struct ssdfs_segment_request *req1 = NULL, *req2 = NULL;
	bool has_backup;
	atomic_t *refs_count;
	wait_queue_head_t *wq = NULL;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
	BUG_ON(!rwsem_is_locked(&segbmap->search_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, fragments_count %u\n",
		  segbmap, fragments_count);

	has_backup = segbmap->flags & SSDFS_SEGBMAP_HAS_COPY;

	for (i = 0; i < fragments_count; i++) {
		fragment = &segbmap->desc_array[i];

		switch (fragment->state) {
		case SSDFS_SEGBMAP_FRAG_DIRTY:
			SSDFS_ERR("found unprocessed dirty fragment: "
				  "index %d\n", i);
			return -ERANGE;

		case SSDFS_SEGBMAP_FRAG_TOWRITE:
			req1 = &fragment->flush_req1;
			req2 = &fragment->flush_req2;

check_req1_state:
			switch (atomic_read(&req1->result.state)) {
			case SSDFS_REQ_CREATED:
			case SSDFS_REQ_STARTED:
				refs_count = &req1->private.refs_count;
				wq = &req1->private.wait_queue;

				if (atomic_read(refs_count) != 0) {
					err = wait_event_killable_timeout(*wq,
						atomic_read(refs_count) == 0,
						SSDFS_DEFAULT_TIMEOUT);
					if (err < 0)
						WARN_ON(err < 0);
					else
						err = 0;

					goto check_req1_state;
				} else {
					SSDFS_ERR("invalid refs_count %d\n",
						  atomic_read(refs_count));
					return -ERANGE;
				}
				break;

			case SSDFS_REQ_FINISHED:
				/* do nothing */
				break;

			case SSDFS_REQ_FAILED:
				err = req1->result.err;

				if (!err) {
					err = -ERANGE;
					SSDFS_ERR("error code is absent\n");
				}

				SSDFS_ERR("flush request is failed: "
					  "err %d\n", err);
				return err;

			default:
				SSDFS_ERR("invalid result's state %#x\n",
				    atomic_read(&req1->result.state));
				return -ERANGE;
			}

			if (!has_backup)
				goto finish_fragment_check;

check_req2_state:
			switch (atomic_read(&req2->result.state)) {
			case SSDFS_REQ_CREATED:
			case SSDFS_REQ_STARTED:
				refs_count = &req2->private.refs_count;
				wq = &req2->private.wait_queue;

				if (atomic_read(refs_count) != 0) {
					err = wait_event_killable_timeout(*wq,
						atomic_read(refs_count) == 0,
						SSDFS_DEFAULT_TIMEOUT);
					if (err < 0)
						WARN_ON(err < 0);
					else
						err = 0;

					goto check_req2_state;
				} else {
					SSDFS_ERR("invalid refs_count %d\n",
						  atomic_read(refs_count));
					return -ERANGE;
				}
				break;

			case SSDFS_REQ_FINISHED:
				/* do nothing */
				break;

			case SSDFS_REQ_FAILED:
				err = req2->result.err;

				if (!err) {
					err = -ERANGE;
					SSDFS_ERR("error code is absent\n");
				}

				SSDFS_ERR("flush request is failed: "
					  "err %d\n", err);
				return err;

			default:
				SSDFS_ERR("invalid result's state %#x\n",
				    atomic_read(&req2->result.state));
				return -ERANGE;
			}

finish_fragment_check:
			fragment->state = SSDFS_SEGBMAP_FRAG_INITIALIZED;
			break;

		default:
			/* do nothing */
			break;
		}
	}

	return 0;
}

/* TODO: copy all fragments' headers into checkpoint */
/* TODO: mark superblock as dirty */
/* TODO: new checkpoint should be stored into superblock segment */
static
int ssdfs_segbmap_create_checkpoint(struct ssdfs_segment_bmap *segbmap)
{
	/* TODO: implement */
	SSDFS_DBG("TODO: implement %s\n", __func__);
	return 0 /*-ENOSYS*/;
}

/*
 * ssdfs_segbmap_flush() - flush segbmap current state
 * @segbmap: pointer on segment bitmap object
 *
 * This method tries to flush current state of segbmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EFAULT     - segbmap has corrupted state.
 * %-ERANGE     - internal error.
 */
int ssdfs_segbmap_flush(struct ssdfs_segment_bmap *segbmap)
{
	u16 fragments_count;
	u16 fragment_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p\n",
		  segbmap);

	inode_lock_shared(segbmap->fsi->segbmap_inode);
	down_read(&segbmap->resize_lock);

	if (segbmap->flags & SSDFS_SEGBMAP_ERROR) {
		err = -EFAULT;
		ssdfs_fs_error(segbmap->fsi->sb,
				__FILE__, __func__, __LINE__,
				"segbmap has corrupted state\n");
		goto finish_segbmap_flush;
	}

	fragments_count = segbmap->fragments_count;
	fragment_size = segbmap->fragment_size;

	ssdfs_sb_segbmap_header_correct_state(segbmap);

	down_write(&segbmap->search_lock);

	err = ssdfs_segbmap_flush_dirty_fragments(segbmap,
						  fragments_count,
						  fragment_size);
	if (err == -ENODATA) {
		err = 0;
		up_write(&segbmap->search_lock);
		SSDFS_DBG("segbmap hasn't dirty fragments\n");
		goto finish_segbmap_flush;
	} else if (unlikely(err)) {
		up_write(&segbmap->search_lock);
		ssdfs_fs_error(segbmap->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to flush segbmap: err %d\n",
				err);
		goto finish_segbmap_flush;
	}

	err = ssdfs_segbmap_wait_flush_end(segbmap, fragments_count);
	if (unlikely(err)) {
		up_write(&segbmap->search_lock);
		ssdfs_fs_error(segbmap->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to flush segbmap: err %d\n",
				err);
		goto finish_segbmap_flush;
	}

	err = ssdfs_segbmap_issue_commit_logs(segbmap,
					      fragments_count,
					      fragment_size);
	if (unlikely(err)) {
		up_write(&segbmap->search_lock);
		ssdfs_fs_error(segbmap->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to flush segbmap: err %d\n",
				err);
		goto finish_segbmap_flush;
	}

	err = ssdfs_segbmap_wait_finish_commit_logs(segbmap,
						    fragments_count);
	if (unlikely(err)) {
		up_write(&segbmap->search_lock);
		ssdfs_fs_error(segbmap->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to flush segbmap: err %d\n",
				err);
		goto finish_segbmap_flush;
	}

	downgrade_write(&segbmap->search_lock);

	err = ssdfs_segbmap_create_checkpoint(segbmap);
	if (unlikely(err)) {
		ssdfs_fs_error(segbmap->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to create segbmap's checkpoint: "
				"err %d\n",
				err);
	}

	up_read(&segbmap->search_lock);

finish_segbmap_flush:
	up_read(&segbmap->resize_lock);
	inode_unlock_shared(segbmap->fsi->segbmap_inode);

	return err;
}

int ssdfs_segbmap_resize(struct ssdfs_segment_bmap *segbmap,
			 u64 new_items_count)
{
	/* TODO: implement */
	SSDFS_DBG("TODO: implement %s\n", __func__);
	return -ENOSYS;
}

/*
 * ssdfs_segbmap_check_fragment_validity() - check fragment validity
 * @segbmap: pointer on segment bitmap object
 * @fragment_index: fragment index
 *
 * This method checks that fragment is ready for operations.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EFAULT     - fragment initialization has failed.
 */
static
int ssdfs_segbmap_check_fragment_validity(struct ssdfs_segment_bmap *segbmap,
					  pgoff_t fragment_index)
{
	struct ssdfs_segbmap_fragment_desc *fragment;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
	BUG_ON(!rwsem_is_locked(&segbmap->search_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, fragment_index %lu\n",
		  segbmap, fragment_index);

	fragment = &segbmap->desc_array[fragment_index];

	switch (fragment->state) {
	case SSDFS_SEGBMAP_FRAG_CREATED:
		return -EAGAIN;

	case SSDFS_SEGBMAP_FRAG_INIT_FAILED:
		return -EFAULT;

	case SSDFS_SEGBMAP_FRAG_INITIALIZED:
	case SSDFS_SEGBMAP_FRAG_DIRTY:
		/* do nothing */
		break;

	default:
		BUG();
	}

	return 0;
}

/*
 * ssdfs_segbmap_get_state_from_byte() - retrieve state of item from byte
 * @byte_ptr: pointer on byte
 * @byte_item: index of item in byte
 */
static inline
int ssdfs_segbmap_get_state_from_byte(u8 *byte_ptr, u32 byte_item)
{
	u32 shift;

	SSDFS_DBG("byte_ptr %p, byte_item %u\n",
		  byte_ptr, byte_item);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!byte_ptr);
	BUG_ON(byte_item >= SSDFS_ITEMS_PER_BYTE(SSDFS_SEG_STATE_BITS));
#endif /* CONFIG_SSDFS_DEBUG */

	shift = byte_item * SSDFS_SEG_STATE_BITS;
	return (int)((*byte_ptr >> shift) & SSDFS_SEG_STATE_MASK);
}

/*
 * ssdfs_segbmap_get_state() - get segment state
 * @segbmap: pointer on segment bitmap object
 * @seg: segment number
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to get state of @seg.
 *
 * RETURN:
 * [success] - segment state
 * [failure] - error code:
 *
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EFAULT     - segbmap has inconsistent state.
 * %-ERANGE     - internal error.
 */
int ssdfs_segbmap_get_state(struct ssdfs_segment_bmap *segbmap,
			    u64 seg, struct completion **end)
{
	u32 items_per_byte = SSDFS_ITEMS_PER_BYTE(SSDFS_SEG_STATE_BITS);
	u32 hdr_size = sizeof(struct ssdfs_segbmap_fragment_header);
	u64 items_count;
	u16 fragments_count;
	u16 fragment_size;
	pgoff_t fragment_index;
	struct page *page;
	u64 page_item;
	u32 byte_offset;
	void *kaddr;
	u8 *byte_ptr;
	u32 byte_item;
	int state = SSDFS_SEG_STATE_MAX;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, seg %llu\n",
		  segbmap, seg);

	*end = NULL;

	inode_lock_shared(segbmap->fsi->segbmap_inode);
	down_read(&segbmap->resize_lock);

	items_count = segbmap->items_count;
	fragments_count = segbmap->fragments_count;
	fragment_size = segbmap->fragment_size;

	if (segbmap->flags & SSDFS_SEGBMAP_ERROR) {
		err = -EFAULT;
		ssdfs_fs_error(segbmap->fsi->sb,
				__FILE__, __func__, __LINE__,
				"segbmap has corrupted state\n");
		goto finish_segment_check;
	}

	if (seg >= items_count) {
		err = -ERANGE;
		SSDFS_ERR("seg %llu >= items_count %llu\n",
			  seg, items_count);
		goto finish_segment_check;
	}

	fragment_index = ssdfs_segbmap_seg_2_fragment_index(seg);
	if (fragment_index >= fragments_count) {
		err = -EFAULT;
		ssdfs_fs_error(segbmap->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fragment_index %lu >= fragments_count %u\n",
				fragment_index, fragments_count);
		goto finish_segment_check;
	}

	down_read(&segbmap->search_lock);

	*end = &segbmap->desc_array[fragment_index].init_end;

	err = ssdfs_segbmap_check_fragment_validity(segbmap, fragment_index);
	if (err == -EAGAIN) {
		SSDFS_DBG("fragment %lu is not initialized yet\n",
			  fragment_index);
		goto finish_get_state;
	} else if (unlikely(err)) {
		SSDFS_ERR("fragment %lu init has failed\n",
			  fragment_index);
		goto finish_get_state;
	}

	page = find_lock_page(&segbmap->pages, fragment_index);
	if (!page) {
		err = -ERANGE;
		SSDFS_ERR("fail to get fragment %lu page\n",
			  fragment_index);
		goto finish_get_state;
	}

	page_item = ssdfs_segbmap_define_first_fragment_item(fragment_index,
							     fragment_size);
	if (seg < page_item) {
		err = -ERANGE;
		SSDFS_ERR("seg %llu < page_item %llu\n",
			  seg, page_item);
		goto free_page;
	}

	page_item = seg - page_item;

	if (page_item >= ssdfs_segbmap_items_per_fragment(fragment_size)) {
		err = -ERANGE;
		SSDFS_ERR("invalid page_item %llu\n",
			  page_item);
		goto free_page;
	}

	byte_offset = ssdfs_segbmap_get_item_byte_offset(page_item);

	if (byte_offset >= PAGE_SIZE) {
		err = -ERANGE;
		SSDFS_ERR("invalid byte_offset %u\n",
			  byte_offset);
		goto free_page;
	}

	byte_item = page_item - ((byte_offset - hdr_size) * items_per_byte);

	kaddr = kmap_atomic(page);
	byte_ptr = (u8 *)kaddr + byte_offset;
	state = ssdfs_segbmap_get_state_from_byte(byte_ptr, byte_item);
	kunmap_atomic(kaddr);

free_page:
	unlock_page(page);
	put_page(page);

finish_get_state:
	up_read(&segbmap->search_lock);

finish_segment_check:
	up_read(&segbmap->resize_lock);
	inode_unlock_shared(segbmap->fsi->segbmap_inode);

	if (unlikely(err))
		return err;

	return state;
}

/*
 * ssdfs_segbmap_check_state() - check segment state
 * @segbmap: pointer on segment bitmap object
 * @seg: segment number
 * @state: checking state
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method checks that @seg has @state.
 *
 * RETURN:
 * [success] - segment has (1) or hasn't (0) requested @state
 * [failure] - error code:
 *
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EFAULT     - segbmap has inconsistent state.
 * %-ERANGE     - internal error.
 */
int ssdfs_segbmap_check_state(struct ssdfs_segment_bmap *segbmap,
				u64 seg, int state,
				struct completion **end)
{
	int res;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
	BUG_ON(state <= SSDFS_SEG_CLEAN ||
		state >= SSDFS_SEG_STATE_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, seg %llu, state %#x\n",
		  segbmap, seg, state);

	res = ssdfs_segbmap_get_state(segbmap, seg, end);
	if (res == -EAGAIN) {
		SSDFS_DBG("fragment is not initialized yet\n");
		return res;
	} else if (unlikely(res < 0)) {
		SSDFS_WARN("fail to get segment %llu state: err %d\n",
			   seg, res);
		return res;
	} else if (res != state) {
		SSDFS_DBG("res %#x != state %#x\n",
			  res, state);
		return 0;
	}

	return 1;
}

/*
 * ssdfs_segbmap_set_state_in_byte() - set state of item in byte
 * @byte_ptr: pointer on byte
 * @byte_item: index of item in byte
 * @old_state: pointer on old state value [in|out]
 * @new_state: new state value
 */
static inline
int ssdfs_segbmap_set_state_in_byte(u8 *byte_ptr, u32 byte_item,
				    int *old_state, int new_state)
{
	u8 value;
	int shift = byte_item * SSDFS_SEG_STATE_BITS;

	SSDFS_DBG("byte_ptr %p, byte_item %u, "
		  "old_state %p, new_state %#x\n",
		  byte_ptr, byte_item,
		  old_state, new_state);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!byte_ptr || !old_state);
	BUG_ON(byte_item >= SSDFS_ITEMS_PER_BYTE(SSDFS_SEG_STATE_BITS));
#endif /* CONFIG_SSDFS_DEBUG */

	*old_state = (int)((*byte_ptr >> shift) & SSDFS_SEG_STATE_MASK);

	if (*old_state < SSDFS_SEG_CLEAN ||
	    *old_state >= SSDFS_SEG_STATE_MAX) {
		SSDFS_ERR("invalid old_state %#x\n",
			  *old_state);
		return -ERANGE;
	}

	value = new_state & SSDFS_SEG_STATE_MASK;
	value <<= shift;

	*byte_ptr &= ~(SSDFS_SEG_STATE_MASK << shift);
	*byte_ptr |= value;

	return 0;
}

/*
 * ssdfs_segbmap_correct_fragment_header() - correct fragment's header
 * @segbmap: pointer on segment bitmap object
 * @fragment_index: fragment index
 * @old_state: old state value
 * @new_state: new state value
 * @kaddr: pointer on fragment's buffer
 */
static
void ssdfs_segbmap_correct_fragment_header(struct ssdfs_segment_bmap *segbmap,
					   pgoff_t fragment_index,
					   int old_state, int new_state,
					   void *kaddr)
{
	struct ssdfs_segbmap_fragment_desc *fragment;
	struct ssdfs_segbmap_fragment_header *hdr;
	unsigned long *fbmap;
	u16 fragment_bytes;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap || !kaddr);
	BUG_ON(!rwsem_is_locked(&segbmap->search_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, fragment_index %lu, "
		  "old_state %#x, new_state %#x, kaddr %p\n",
		  segbmap, fragment_index,
		  old_state, new_state, kaddr);

	fragment = &segbmap->desc_array[fragment_index];
	hdr = SSDFS_SBMP_FRAG_HDR(kaddr);
	fragment_bytes = le16_to_cpu(hdr->fragment_bytes);

	fragment->state = SSDFS_SEGBMAP_FRAG_DIRTY;

	switch (old_state) {
	case SSDFS_SEG_CLEAN:
	case SSDFS_SEG_DATA_USING:
	case SSDFS_SEG_LEAF_NODE_USING:
	case SSDFS_SEG_HYBRID_NODE_USING:
	case SSDFS_SEG_INDEX_NODE_USING:
		fbmap = segbmap->fbmap[SSDFS_SEGBMAP_CLEAN_USING_FBMAP];
		BUG_ON(fragment->clean_or_using_segs == 0);
		fragment->clean_or_using_segs--;
		if (fragment->clean_or_using_segs == 0)
			bitmap_clear(fbmap, fragment_index, 1);
		break;

	case SSDFS_SEG_USED:
	case SSDFS_SEG_RESERVED:
	case SSDFS_SEG_PRE_DIRTY:
	case SSDFS_SEG_DIRTY:
		fbmap = segbmap->fbmap[SSDFS_SEGBMAP_USED_DIRTY_FBMAP];
		BUG_ON(fragment->used_or_dirty_segs == 0);
		fragment->used_or_dirty_segs--;
		if (fragment->used_or_dirty_segs == 0)
			bitmap_clear(fbmap, fragment_index, 1);
		break;

	case SSDFS_SEG_BAD:
		fbmap = segbmap->fbmap[SSDFS_SEGBMAP_BAD_FBMAP];
		BUG_ON(fragment->bad_segs == 0);
		fragment->bad_segs--;
		if (fragment->bad_segs == 0)
			bitmap_clear(fbmap, fragment_index, 1);
		break;

	default:
		BUG();
	}

	switch (new_state) {
	case SSDFS_SEG_CLEAN:
	case SSDFS_SEG_DATA_USING:
	case SSDFS_SEG_LEAF_NODE_USING:
	case SSDFS_SEG_HYBRID_NODE_USING:
	case SSDFS_SEG_INDEX_NODE_USING:
		fbmap = segbmap->fbmap[SSDFS_SEGBMAP_CLEAN_USING_FBMAP];
		if (fragment->clean_or_using_segs == 0)
			bitmap_set(fbmap, fragment_index, 1);
		BUG_ON((fragment->clean_or_using_segs + 1) == U16_MAX);
		fragment->clean_or_using_segs++;
		break;

	case SSDFS_SEG_USED:
	case SSDFS_SEG_RESERVED:
	case SSDFS_SEG_PRE_DIRTY:
	case SSDFS_SEG_DIRTY:
		fbmap = segbmap->fbmap[SSDFS_SEGBMAP_USED_DIRTY_FBMAP];
		if (fragment->used_or_dirty_segs == 0)
			bitmap_set(fbmap, fragment_index, 1);
		BUG_ON((fragment->used_or_dirty_segs + 1) == U16_MAX);
		fragment->used_or_dirty_segs++;
		break;

	case SSDFS_SEG_BAD:
		fbmap = segbmap->fbmap[SSDFS_SEGBMAP_BAD_FBMAP];
		if (fragment->bad_segs == 0)
			bitmap_set(fbmap, fragment_index, 1);
		BUG_ON((fragment->bad_segs + 1) == U16_MAX);
		fragment->bad_segs++;
		break;

	default:
		BUG();
	}

	hdr->clean_or_using_segs = cpu_to_le16(fragment->clean_or_using_segs);
	hdr->used_or_dirty_segs = cpu_to_le16(fragment->used_or_dirty_segs);
	hdr->bad_segs = cpu_to_le16(fragment->bad_segs);

	hdr->checksum = 0;
	hdr->checksum = ssdfs_crc32_le(kaddr, fragment_bytes);

	fbmap = segbmap->fbmap[SSDFS_SEGBMAP_MODIFICATION_FBMAP];
	bitmap_set(fbmap, fragment_index, 1);
}

/*
 * __ssdfs_segbmap_change_state() - change segment state
 * @segbmap: pointer on segment bitmap object
 * @seg: segment number
 * @new_state: new state
 * @fragment_index: index of fragment
 * @fragment_size: size of fragment in bytes
 *
 * This method tries to change state of @seg.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EFAULT     - segbmap has inconsistent state.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_segbmap_change_state(struct ssdfs_segment_bmap *segbmap,
				 u64 seg, int new_state,
				 pgoff_t fragment_index,
				 u16 fragment_size)
{
	u32 items_per_byte = SSDFS_ITEMS_PER_BYTE(SSDFS_SEG_STATE_BITS);
	struct page *page;
	u64 page_item;
	u32 byte_offset;
	u32 byte_item;
	void *kaddr;
	u8 *byte_ptr;
	int old_state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
	BUG_ON(!rwsem_is_locked(&segbmap->search_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, seg %llu, new_state %#x, "
		  "fragment_index %lu, fragment_size %u\n",
		  segbmap, seg, new_state,
		  fragment_index, fragment_size);

	err = ssdfs_segbmap_check_fragment_validity(segbmap, fragment_index);
	if (err == -EAGAIN) {
		SSDFS_DBG("fragment %lu is not initialized yet\n",
			  fragment_index);
		goto finish_set_state;
	} else if (unlikely(err)) {
		SSDFS_ERR("fragment %lu init has failed\n",
			  fragment_index);
		goto finish_set_state;
	}

	page = find_lock_page(&segbmap->pages, fragment_index);
	if (!page) {
		err = -ERANGE;
		SSDFS_ERR("fail to get fragment %lu page\n",
			  fragment_index);
		goto finish_set_state;
	}

	page_item = ssdfs_segbmap_define_first_fragment_item(fragment_index,
							     fragment_size);
	if (seg < page_item) {
		err = -ERANGE;
		SSDFS_ERR("seg %llu < page_item %llu\n",
			  seg, page_item);
		goto free_page;
	}

	page_item = seg - page_item;

	if (page_item >= ssdfs_segbmap_items_per_fragment(fragment_size)) {
		err = -ERANGE;
		SSDFS_ERR("invalid page_item %llu\n",
			  page_item);
		goto free_page;
	}

	byte_offset = ssdfs_segbmap_get_item_byte_offset(page_item);

	if (byte_offset >= PAGE_SIZE) {
		err = -ERANGE;
		SSDFS_ERR("invalid byte_offset %u\n",
			  byte_offset);
		goto free_page;
	}

	div_u64_rem(page_item, items_per_byte, &byte_item);

	kaddr = kmap_atomic(page);
	byte_ptr = (u8 *)kaddr + byte_offset;
	err = ssdfs_segbmap_set_state_in_byte(byte_ptr, byte_item,
					      &old_state, new_state);
	if (!err) {
		ssdfs_segbmap_correct_fragment_header(segbmap, fragment_index,
							old_state, new_state,
							kaddr);
	}
	kunmap_atomic(kaddr);

	if (unlikely(err)) {
		SSDFS_ERR("fail to set state: "
			  "seg %llu, new_state %#x, err %d\n",
			  seg, new_state, err);
		goto free_page;
	}

	SetPageUptodate(page);
	if (!PageDirty(page))
		__set_page_dirty_nobuffers(page);

free_page:
	unlock_page(page);
	put_page(page);

finish_set_state:
	return err;
}

/*
 * ssdfs_segbmap_change_state() - change segment state
 * @segbmap: pointer on segment bitmap object
 * @seg: segment number
 * @new_state: new state
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to change state of @seg.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EFAULT     - segbmap has inconsistent state.
 * %-ERANGE     - internal error.
 */
int ssdfs_segbmap_change_state(struct ssdfs_segment_bmap *segbmap,
				u64 seg, int new_state,
				struct completion **end)
{
	u64 items_count;
	u16 fragments_count;
	u16 fragment_size;
	pgoff_t fragment_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, seg %llu, new_state %#x\n",
		  segbmap, seg, new_state);

	*end = NULL;

	inode_lock_shared(segbmap->fsi->segbmap_inode);
	down_read(&segbmap->resize_lock);

	items_count = segbmap->items_count;
	fragments_count = segbmap->fragments_count;
	fragment_size = segbmap->fragment_size;

	if (segbmap->flags & SSDFS_SEGBMAP_ERROR) {
		err = -EFAULT;
		ssdfs_fs_error(segbmap->fsi->sb,
				__FILE__, __func__, __LINE__,
				"segbmap has corrupted state\n");
		goto finish_segment_check;
	}

	if (seg >= items_count) {
		err = -ERANGE;
		SSDFS_ERR("seg %llu >= items_count %llu\n",
			  seg, items_count);
		goto finish_segment_check;
	}

	fragment_index = ssdfs_segbmap_seg_2_fragment_index(seg);
	if (fragment_index >= fragments_count) {
		err = -EFAULT;
		ssdfs_fs_error(segbmap->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fragment_index %lu >= fragments_count %u\n",
				fragment_index, fragments_count);
		goto finish_segment_check;
	}

	down_write(&segbmap->search_lock);
	*end = &segbmap->desc_array[fragment_index].init_end;
	err = __ssdfs_segbmap_change_state(segbmap, seg, new_state,
					   fragment_index, fragment_size);
	up_write(&segbmap->search_lock);

finish_segment_check:
	up_read(&segbmap->resize_lock);
	inode_unlock_shared(segbmap->fsi->segbmap_inode);

	return err;
}

/*
 * ssdfs_segbmap_choose_fbmap() - choose fragment bitmap
 * @segbmap: pointer on segment bitmap object
 * @state: requested state
 * @mask: requested mask
 *
 * RETURN:
 * [success] - pointer on fragment bitmap
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EOPNOTSUPP - operation is not supported.
 */
static
unsigned long *ssdfs_segbmap_choose_fbmap(struct ssdfs_segment_bmap *segbmap,
					  int state, int mask)
{
	unsigned long *fbmap;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap);
	BUG_ON(!rwsem_is_locked(&segbmap->search_lock));

	if (state < SSDFS_SEG_CLEAN || state >= SSDFS_SEG_STATE_MAX) {
		SSDFS_ERR("unknown segment state %#x\n", state);
		return ERR_PTR(-EINVAL);
	}

	if ((mask & SSDFS_SEG_CLEAN_USING_MASK) != mask &&
	    (mask & SSDFS_SEG_USED_DIRTY_MASK) != mask &&
	    (mask & SSDFS_SEG_BAD_STATE_MASK) != mask) {
		SSDFS_ERR("unsupported set of flags %#x\n",
			  mask);
		return ERR_PTR(-EOPNOTSUPP);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, state %#x, mask %#x\n",
		  segbmap, state, mask);

	if (mask & SSDFS_SEG_CLEAN_USING_MASK) {
		fbmap = segbmap->fbmap[SSDFS_SEGBMAP_CLEAN_USING_FBMAP];

		switch (state) {
		case SSDFS_SEG_CLEAN:
		case SSDFS_SEG_DATA_USING:
		case SSDFS_SEG_LEAF_NODE_USING:
		case SSDFS_SEG_HYBRID_NODE_USING:
		case SSDFS_SEG_INDEX_NODE_USING:
			return fbmap;

		default:
			return ERR_PTR(-EOPNOTSUPP);
		}
	} else if (mask & SSDFS_SEG_USED_DIRTY_MASK) {
		fbmap = segbmap->fbmap[SSDFS_SEGBMAP_USED_DIRTY_FBMAP];

		switch (state) {
		case SSDFS_SEG_USED:
		case SSDFS_SEG_PRE_DIRTY:
		case SSDFS_SEG_DIRTY:
			return fbmap;

		default:
			return ERR_PTR(-EOPNOTSUPP);
		}
	} else if (mask & SSDFS_SEG_BAD_STATE_MASK) {
		fbmap = segbmap->fbmap[SSDFS_SEGBMAP_BAD_FBMAP];

		switch (state) {
		case SSDFS_SEG_BAD:
			return fbmap;

		default:
			return ERR_PTR(-EOPNOTSUPP);
		}
	}

	return ERR_PTR(-EOPNOTSUPP);
}

/*
 * ssdfs_segbmap_find_fragment() - find fragment
 * @segbmap: pointer on segment bitmap object
 * @fbmap: bitmap of fragments
 * @start_fragment: start fragment for search
 * @max_fragment: upper bound for fragment search
 * @found_fragment: found fragment index [out]
 *
 * This method tries to find fragment in bitmap of
 * fragments.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EFAULT     - segbmap has inconsistent state.
 * %-ENODATA    - bitmap hasn't any valid fragment.
 */
static
int ssdfs_segbmap_find_fragment(struct ssdfs_segment_bmap *segbmap,
				unsigned long *fbmap,
				u16 start_fragment, u16 max_fragment,
				int *found_fragment)
{
	unsigned long *addr;
	u16 long_offset;
	u16 first_fragment;
	u16 checking_fragment;
	u16 size, requested_size, checked_size;
	unsigned long found;
	u16 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap || !fbmap || !found_fragment);
	BUG_ON(!rwsem_is_locked(&segbmap->search_lock));

	if (start_fragment >= max_fragment) {
		SSDFS_ERR("start_fragment %u >= max_fragment %u\n",
			  start_fragment, max_fragment);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fbmap %p, start_fragment %u, max_fragment %u\n",
		  fbmap, start_fragment, max_fragment);

	*found_fragment = U16_MAX;

	long_offset = (start_fragment + BITS_PER_LONG - 1) / BITS_PER_LONG;
	first_fragment = long_offset * BITS_PER_LONG;

	checking_fragment = min_t(u16, start_fragment, first_fragment);
	checked_size = max_fragment - checking_fragment;

	for (i = 0; i < checked_size; i++) {
		struct ssdfs_segbmap_fragment_desc *desc;
		u16 index = checking_fragment + i;

		desc = &segbmap->desc_array[index];

		switch (desc->state) {
		case SSDFS_SEGBMAP_FRAG_INITIALIZED:
		case SSDFS_SEGBMAP_FRAG_DIRTY:
			/*
			 * We can use this fragment.
			 * Simply go ahead.
			 */
			break;

		case SSDFS_SEGBMAP_FRAG_CREATED:
			/* It needs to wait the fragment's init */
			err = -EAGAIN;
			checked_size = index - checking_fragment;
			goto check_presence_valid_fragments;
			break;

		case SSDFS_SEGBMAP_FRAG_INIT_FAILED:
			err = -EFAULT;
			*found_fragment = index;
			SSDFS_ERR("fragment %u is corrupted\n",
				  index);
			checked_size = 0;
			goto check_presence_valid_fragments;
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid fragment's state %#x\n",
				  desc->state);
			goto check_presence_valid_fragments;
			break;
		}
	}

check_presence_valid_fragments:
	if (err == -ERANGE || err == -EFAULT) {
		/* Simply return the error */
		return err;
	} else if (err == -EAGAIN) {
		if (checked_size == 0) {
			SSDFS_DBG("no valid fragments yet\n");
			return err;
		} else
			err = 0;
	}

	if (start_fragment < first_fragment) {
		unsigned long value = *(fbmap + (long_offset - 1));

		size = start_fragment - ((long_offset - 1) * BITS_PER_LONG);
		size = min_t(u16, size, checked_size);
		bitmap_clear(&value, 0, size);

		if (!value) {
			found = __ffs(value);
			*found_fragment = start_fragment + (u16)(found - size);
			return 0;
		}
	} else {
		/* first_fragment <= start_fragment */
		addr = fbmap + long_offset;
		requested_size = max_fragment - first_fragment;
		size = min_t(u16, requested_size, checked_size);

		if (size == 0) {
			SSDFS_DBG("no valid fragments yet\n");
			return -EAGAIN;
		}

		found = find_first_bit(addr, size);

		if (found >= size) {
			if (size < requested_size) {
				SSDFS_DBG("Wait init of fragment %lu\n",
					  found);
				return -EAGAIN;
			} else {
				SSDFS_DBG("unable to find fragment: "
					  "found %lu, size %u\n",
					  found, size);
				return -ENODATA;
			}
		}

		found += first_fragment;
		BUG_ON(found >= U16_MAX);
		*found_fragment = found;
		return 0;
	}

	return -ERANGE;
}

/*
 * ssdfs_segbmap_correct_search_start() - correct start item for search
 * @fragment_index: index of fragment
 * @old_start: old start value
 * @max: upper bound for search
 * @fragment_size: size of fragment in bytes
 */
static
u64 ssdfs_segbmap_correct_search_start(u16 fragment_index,
					u64 old_start, u64 max,
					u16 fragment_size)
{
	u64 first_item, corrected_value;

#ifdef CONFIG_SSDFS_DEBUG
	if (old_start >= max) {
		SSDFS_ERR("old_start %llu >= max %llu\n",
			  old_start, max);
		return U64_MAX;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fragment_index %u, old_start %llu, max %llu\n",
		  fragment_index, old_start, max);

	first_item = ssdfs_segbmap_define_first_fragment_item(fragment_index,
							      fragment_size);

	if (first_item >= max) {
		SSDFS_DBG("first_item %llu >= max %llu\n",
			  first_item, max);
		return U64_MAX;
	}

	corrected_value = first_item > old_start ? first_item : old_start;

	SSDFS_DBG("corrected_value %llu\n", corrected_value);

	return corrected_value;
}

/*
 * ssdfs_segbmap_define_items_count() - define items count for state/mask
 * @desc: fragment descriptor
 * @state: requested state
 * @mask: requested mask
 */
static inline
u16 ssdfs_segbmap_define_items_count(struct ssdfs_segbmap_fragment_desc *desc,
				     int state, int mask)
{
	int complex_mask;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
	BUG_ON(!mask);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("desc %p, state %#x, mask %#x\n",
		  desc, state, mask);

	switch (state) {
	case SSDFS_SEG_CLEAN:
		complex_mask = SSDFS_SEG_CLEAN_STATE_FLAG | mask;
		break;

	case SSDFS_SEG_DATA_USING:
		complex_mask = SSDFS_SEG_DATA_USING_STATE_FLAG | mask;
		break;

	case SSDFS_SEG_LEAF_NODE_USING:
		complex_mask = SSDFS_SEG_LEAF_NODE_USING_STATE_FLAG | mask;
		break;

	case SSDFS_SEG_HYBRID_NODE_USING:
		complex_mask = SSDFS_SEG_HYBRID_NODE_USING_STATE_FLAG | mask;
		break;

	case SSDFS_SEG_INDEX_NODE_USING:
		complex_mask = SSDFS_SEG_INDEX_NODE_USING_STATE_FLAG | mask;
		break;

	case SSDFS_SEG_USED:
		complex_mask = SSDFS_SEG_USED_STATE_FLAG | mask;
		break;

	case SSDFS_SEG_PRE_DIRTY:
		complex_mask = SSDFS_SEG_PRE_DIRTY_STATE_FLAG | mask;
		break;

	case SSDFS_SEG_DIRTY:
		complex_mask = SSDFS_SEG_DIRTY_STATE_FLAG | mask;
		break;

	case SSDFS_SEG_BAD:
		complex_mask = SSDFS_SEG_BAD_STATE_FLAG | mask;
		break;

	default:
		BUG();
	}

	if ((complex_mask & SSDFS_SEG_CLEAN_USING_MASK) != complex_mask &&
	    (complex_mask & SSDFS_SEG_USED_DIRTY_MASK) != complex_mask &&
	    (complex_mask & SSDFS_SEG_BAD_STATE_MASK) != complex_mask) {
		SSDFS_ERR("unsupported set of flags %#x\n",
			  complex_mask);
		return U16_MAX;
	}

	if (complex_mask & SSDFS_SEG_CLEAN_USING_MASK)
		return desc->clean_or_using_segs;
	else if (complex_mask & SSDFS_SEG_USED_DIRTY_MASK)
		return desc->used_or_dirty_segs;
	else if (complex_mask & SSDFS_SEG_BAD_STATE_MASK)
		return desc->bad_segs;

	return U16_MAX;
}

/*
 * BYTE_CONTAINS_STATE() - check that byte contains requested state
 * @value: pointer on byte
 * @state: requested state
 */
static inline
bool BYTE_CONTAINS_STATE(u8 *value, int state)
{
	switch (state) {
	case SSDFS_SEG_CLEAN:
		return detect_clean_seg[*value];

	case SSDFS_SEG_DATA_USING:
		return detect_data_using_seg[*value];

	case SSDFS_SEG_LEAF_NODE_USING:
		return detect_lnode_using_seg[*value];

	case SSDFS_SEG_HYBRID_NODE_USING:
		return detect_hnode_using_seg[*value];

	case SSDFS_SEG_INDEX_NODE_USING:
		return detect_idxnode_using_seg[*value];

	case SSDFS_SEG_USED:
		return detect_used_seg[*value];

	case SSDFS_SEG_PRE_DIRTY:
		return detect_pre_dirty_seg[*value];

	case SSDFS_SEG_DIRTY:
		return detect_dirty_seg[*value];

	case SSDFS_SEG_BAD:
		return detect_bad_seg[*value];
	};

	return false;
}

/*
 * BYTE_CONTAINS_MASK() - check that byte contains any state under mask
 * @value: pointer on byte
 * @mask: requested mask
 */
static inline
bool BYTE_CONTAINS_MASK(u8 *value, int mask)
{
	if (mask & SSDFS_SEG_CLEAN_USING_MASK)
		return detect_clean_using_mask[*value];
	else if (mask & SSDFS_SEG_USED_DIRTY_MASK)
		return detect_used_dirty_mask[*value];
	else if (mask & SSDFS_SEG_BAD_STATE_MASK)
		return detect_bad_seg[*value];

	return false;
}

/*
 * FIND_FIRST_ITEM_IN_FRAGMENT() - find first item in fragment
 * @hdr: pointer on segbmap fragment's header
 * @fragment: pointer on bitmap in fragment
 * @start_item: start segment number for search
 * @max_item: upper bound of segment number for search
 * @state: primary state for search
 * @mask: mask of additonal states that can be retrieved too
 * @found_seg: found segment number [out]
 * @found_for_mask: found segment number for mask [out]
 * @found_state_for_mask: found state for mask [out]
 *
 * This method tries to find first item with requested
 * state in fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - found segment number for the mask.
 * %-ENODATA    - fragment doesn't include segment with requested state/mask.
 */
static
int FIND_FIRST_ITEM_IN_FRAGMENT(struct ssdfs_segbmap_fragment_header *hdr,
				u8 *fragment, u64 start_item, u64 max_item,
				int state, int mask,
				u64 *found_seg, u64 *found_for_mask,
				int *found_state_for_mask)
{
	u32 items_per_byte = SSDFS_ITEMS_PER_BYTE(SSDFS_SEG_STATE_BITS);
	u64 fragment_start_item;
	u64 aligned_start, aligned_end;
	u32 byte_index, search_bytes;
	u64 byte_range;
	u8 start_offset;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hdr || !fragment || !found_seg || !found_for_mask);

	if (start_item >= max_item) {
		SSDFS_ERR("start_item %llu >= max_item %llu\n",
			  start_item, max_item);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("hdr %p, fragment %p, "
		  "start_item %llu, max_item %llu, "
		  "state %#x, mask %#x, "
		  "found_seg %p, found_for_mask %p\n",
		  hdr, fragment, start_item, max_item,
		  state, mask, found_seg, found_for_mask);

	*found_seg = U64_MAX;
	*found_for_mask = U64_MAX;
	*found_state_for_mask = SSDFS_SEG_STATE_MAX;

	fragment_start_item = le64_to_cpu(hdr->start_item);

	if (fragment_start_item == U64_MAX) {
		SSDFS_ERR("invalid fragment start item\n");
		return -ERANGE;
	}

	search_bytes = le16_to_cpu(hdr->fragment_bytes) -
			sizeof(struct ssdfs_segbmap_fragment_header);

	if (search_bytes == 0 || search_bytes > PAGE_SIZE) {
		SSDFS_ERR("invalid fragment_bytes %u\n",
			  search_bytes);
		return -ERANGE;
	}

	aligned_start = ALIGNED_START_ITEM(start_item, SSDFS_SEG_STATE_BITS);
	aligned_end = ALIGNED_END_ITEM(max_item, SSDFS_SEG_STATE_BITS);

	byte_range = (aligned_end - fragment_start_item) / items_per_byte;
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(byte_range >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	search_bytes = min_t(u32, search_bytes, (u32)byte_range);

	if (fragment_start_item <= aligned_start) {
		u32 items_range = aligned_start - fragment_start_item;
		byte_index = items_range / items_per_byte;
		start_offset = (u8)(start_item - aligned_start);
	} else {
		byte_index = 0;
		start_offset = 0;
	}

	for (; byte_index < search_bytes; byte_index++) {
		u8 *value = fragment + byte_index;
		u8 found_offset;

		err = FIND_FIRST_ITEM_IN_BYTE(value, state,
					      SSDFS_SEG_STATE_BITS,
					      SSDFS_SEG_STATE_MASK,
					      start_offset,
					      BYTE_CONTAINS_STATE,
					      FIRST_STATE_IN_BYTE,
					      &found_offset);

		if (err != -ENODATA || *found_for_mask != U64_MAX)
			goto ignore_search_for_mask;

		err = FIND_FIRST_ITEM_IN_BYTE(value, mask,
					      SSDFS_SEG_STATE_BITS,
					      SSDFS_SEG_STATE_MASK,
					      start_offset,
					      BYTE_CONTAINS_MASK,
					      FIRST_MASK_IN_BYTE,
					      &found_offset);
		if (!err && found_offset != U64_MAX) {
			err = -ENODATA;

			*found_for_mask = fragment_start_item;
			*found_for_mask += byte_index * items_per_byte;
			*found_for_mask += found_offset;

			if (*found_for_mask >= max_item) {
				*found_for_mask = U64_MAX;
				goto ignore_search_for_mask;
			}

			*found_state_for_mask =
				ssdfs_segbmap_get_state_from_byte(value,
								  found_offset);

			SSDFS_DBG("found_for_mask %llu, "
				  "found_state_for_mask %#x\n",
				  *found_for_mask,
				  *found_state_for_mask);
		}

ignore_search_for_mask:
		if (err == -ENODATA) {
			start_offset = 0;
			continue;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find items in byte: "
				  "start_offset %u, state %#x, "
				  "err %d\n",
				  start_offset, state, err);
			goto end_search;
		}

		*found_seg = fragment_start_item;
		*found_seg += byte_index * items_per_byte;
		*found_seg += found_offset;

		if (*found_seg >= max_item)
			*found_seg = U64_MAX;

		break;
	}

	if (*found_seg == U64_MAX && *found_for_mask == U64_MAX)
		err = -ENODATA;
	else if (*found_seg == U64_MAX && *found_for_mask != U64_MAX)
		err = -ENOENT;

	if (!err) {
		SSDFS_DBG("found_seg %llu, found_for_mask %llu\n",
			  *found_seg, *found_for_mask);
	} else
		SSDFS_DBG("nothing was found: err %d\n", err);

end_search:
	return err;
}

/*
 * ssdfs_segbmap_find_in_fragment() - find segment with state in fragment
 * @segbmap: pointer on segment bitmap object
 * @fragment_index: index of fragment
 * @fragment_size: size of fragment in bytes
 * @start: start segment number for search
 * @max: upper bound of segment number for search
 * @state: primary state for search
 * @mask: mask of additonal states that can be retrieved too
 * @found_seg: found segment number [out]
 * @found_for_mask: found segment number for mask [out]
 * @found_state_for_mask: found state for mask [out]
 *
 * This method tries to find segment number for requested state
 * in fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EFAULT     - fragment has inconsistent state.
 */
static
int ssdfs_segbmap_find_in_fragment(struct ssdfs_segment_bmap *segbmap,
				   u16 fragment_index,
				   u16 fragment_size,
				   u64 start, u64 max,
				   int state, int mask,
				   u64 *found_seg, u64 *found_for_mask,
				   int *found_state_for_mask)
{
	struct ssdfs_segbmap_fragment_desc *fragment;
	size_t hdr_size = sizeof(struct ssdfs_segbmap_fragment_header);
	struct page *page;
	u64 first_item;
	u32 items_per_fragment;
	u16 items_count;
	void *kaddr;
	unsigned long *bmap;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap || !found_seg || !found_for_mask);
	BUG_ON(!rwsem_is_locked(&segbmap->search_lock));

	if (start >= max) {
		SSDFS_ERR("start %llu >= max %llu\n",
			  start, max);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, fragment_index %u, "
		  "fragment_size %u, start %llu, max %llu, "
		  "found_seg %p, found_for_mask %p\n",
		  segbmap, fragment_index, fragment_size,
		  start, max,
		  found_seg, found_for_mask);

	*found_seg = U64_MAX;
	*found_for_mask = U64_MAX;

	first_item = ssdfs_segbmap_define_first_fragment_item(fragment_index,
							      fragment_size);
	items_per_fragment = ssdfs_segbmap_items_per_fragment(fragment_size);

	if (first_item >= max) {
		SSDFS_ERR("first_item %llu >= max %llu\n",
			  first_item, max);
		return -ERANGE;
	} else if ((first_item + items_per_fragment) <= start) {
		SSDFS_ERR("first_item %llu, items_per_fragment %u, "
			  "start %llu\n",
			  first_item, items_per_fragment, start);
		return -ERANGE;
	}

	err = ssdfs_segbmap_check_fragment_validity(segbmap, fragment_index);
	if (err == -EAGAIN) {
		SSDFS_DBG("fragment %u is not initilaized yet\n",
			  fragment_index);
		return err;
	} else if (err == -EFAULT) {
		SSDFS_DBG("fragment %u initialization was failed\n",
			  fragment_index);
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fragment %u is corrupted: err %d\n",
			  fragment_index, err);
		return err;
	}

	fragment = &segbmap->desc_array[fragment_index];

	items_count = ssdfs_segbmap_define_items_count(fragment, state, mask);
	if (items_count == U16_MAX || items_count == 0) {
		SSDFS_ERR("segbmap has inconsistent state\n");
		return -ERANGE;
	}

	items_count = fragment->total_segs;

	if (items_count == 0 || items_count > items_per_fragment) {
		SSDFS_ERR("invalid total_segs %u\n", items_count);
		return -ERANGE;
	}

	page = find_lock_page(&segbmap->pages, fragment_index);
	if (!page) {
		SSDFS_ERR("fragment %u hasn't memory page\n",
			  fragment_index);
		return -ERANGE;
	}

	kaddr = kmap(page);
	bmap = (unsigned long *)((u8 *)kaddr + hdr_size);

	err = FIND_FIRST_ITEM_IN_FRAGMENT(SSDFS_SBMP_FRAG_HDR(kaddr),
					  (u8 *)bmap, start, max, state, mask,
					  found_seg, found_for_mask,
					  found_state_for_mask);

	kunmap(page);
	unlock_page(page);
	put_page(page);
	return err;
}

/*
 * __ssdfs_segbmap_find() - find segment with state
 * @segbmap: pointer on segment bitmap object
 * @start: start segment number for search
 * @max: upper bound of segment number for search
 * @state: primary state for search
 * @mask: mask of additonal states that can be retrieved too
 * @fragment_size: fragment size in bytes
 * @seg: found segment number [out]
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to find segment number for requested state.
 *
 * RETURN:
 * [success] - found segment state
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EOPNOTSUPP - operation is not supported.
 * %-ENOMEM     - fail to allocate memory.
 * %-EFAULT     - segbmap has inconsistent state.
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to find segment as for state as for mask.
 */
static
int __ssdfs_segbmap_find(struct ssdfs_segment_bmap *segbmap,
			 u64 start, u64 max,
			 int state, int mask,
			 u16 fragment_size,
			 u64 *seg, struct completion **end)
{
	unsigned long *fbmap;
	int start_fragment, max_fragment, found_fragment;
	u64 found = U64_MAX, found_for_mask = U64_MAX;
	int found_state_for_mask = SSDFS_SEG_STATE_MAX;
	int err = -ENODATA;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap || !seg);
	BUG_ON(!rwsem_is_locked(&segbmap->search_lock));

	if (start >= max) {
		SSDFS_ERR("start %llu >= max %llu\n",
			  start, max);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, start %llu, max %llu, "
		  "state %#x, mask %#x, fragment_size %u, seg %p\n",
		  segbmap, start, max, state, mask,
		  fragment_size, seg);

	*end = NULL;

	fbmap = ssdfs_segbmap_choose_fbmap(segbmap, state, mask);
	if (IS_ERR_OR_NULL(fbmap)) {
		err = (fbmap == NULL ? -ENOMEM : PTR_ERR(fbmap));
		SSDFS_ERR("unable to choose fragment bitmap: err %d\n",
			  err);
		return err;
	}

	start_fragment = SEG_BMAP_FRAGMENTS(start);
	if (start_fragment > 0)
		start_fragment -= 1;

	max_fragment = SEG_BMAP_FRAGMENTS(max);

	do {
		u64 found_for_iter = U64_MAX;
		int found_state_for_iter = -1;

		err = ssdfs_segbmap_find_fragment(segbmap,
						  fbmap,
						  start_fragment,
						  max_fragment,
						  &found_fragment);
		if (err == -ENODATA) {
			SSDFS_DBG("unable to find fragment: "
				  "state %#x, mask %#x, "
				  "start_fragment %d, max_fragment %d\n",
				  state, mask,
				  start_fragment, max_fragment);
			goto finish_seg_search;
		} else if (err == -EFAULT) {
			ssdfs_fs_error(segbmap->fsi->sb,
					__FILE__, __func__, __LINE__,
					"segbmap inconsistent state: "
					"found_fragment %d\n",
					found_fragment);
			goto finish_seg_search;
		} else if (err == -EAGAIN) {
			if (found_fragment >= U16_MAX) {
				/* select the first fragment by default */
				found_fragment = 0;
			}

			*end = &segbmap->desc_array[found_fragment].init_end;
			SSDFS_DBG("fragment %u is not initilaized yet\n",
				  found_fragment);
			goto finish_seg_search;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find fragment: "
				  "start_fragment %d, max_fragment %d, "
				  "err %d\n",
				  start_fragment, max_fragment, err);
			goto finish_seg_search;
		} else if (found_fragment >= U16_MAX) {
			err = -ERANGE;
			SSDFS_ERR("fail to find fragment: "
				  "start_fragment %d, max_fragment %d, "
				  "err %d\n",
				  start_fragment, max_fragment, err);
			goto finish_seg_search;
		}

		start = ssdfs_segbmap_correct_search_start(found_fragment,
							   start, max,
							   fragment_size);
		if (start == U64_MAX || start >= max) {
			SSDFS_DBG("break search: start %llu, max %llu\n",
				  start, max);
			break;
		}

		*end = &segbmap->desc_array[found_fragment].init_end;

		err = ssdfs_segbmap_find_in_fragment(segbmap, found_fragment,
						     fragment_size,
						     start, max,
						     state, mask,
						     &found, &found_for_iter,
						     &found_state_for_iter);
		if (err == -ENODATA) {
			err = -EFAULT;
			ssdfs_fs_error(segbmap->fsi->sb,
					__FILE__, __func__, __LINE__,
					"segbmap inconsistent state: "
					"found_fragment %d, start %llu, "
					"max %llu\n",
					found_fragment, start, max);
			goto finish_seg_search;
		} else if (err == -ENOENT) {
			SSDFS_DBG("mask %#x, found_for_mask %llu, "
				  "found_for_iter %llu, "
				  "found_state %#x\n",
				  mask, found_for_mask, found_for_iter,
				  found_state_for_iter);
			if (found_for_mask == U64_MAX) {
				found_for_mask = found_for_iter;
				found_state_for_mask = found_state_for_iter;
			}
		} else if (err == -EFAULT) {
			/* Just try another iteration */
			SSDFS_DBG("fragment %d is inconsistent\n",
				  found_fragment);
		} else if (err == -EAGAIN) {
			SSDFS_DBG("fragment %u is not initilaized yet\n",
				  found_fragment);
			goto finish_seg_search;
		} else if (unlikely(err < 0)) {
			SSDFS_ERR("fail to find segment: "
				  "found_fragment %d, start %llu, "
				  "max %llu, err %d\n",
				  found_fragment, start, max, err);
			goto finish_seg_search;
		} else if (found == U64_MAX) {
			err = -ERANGE;
			SSDFS_ERR("invalid segment number: "
				  "found_fragment %d, start %llu, "
				  "max %llu\n",
				  found_fragment, start, max);
			goto finish_seg_search;
		} else
			break;

		start_fragment = found_fragment + 1;
	} while (start_fragment <= max_fragment);

	if (unlikely(err < 0)) {
		/* we have some error */
		goto finish_seg_search;
	} else if (found == U64_MAX) {
		if (found_for_mask == U64_MAX) {
			err = -ENODATA;
			SSDFS_DBG("fail to find segment\n");
		} else {
			*seg = found_for_mask;
			err = found_state_for_mask;
			SSDFS_DBG("found for mask %llu, state %#x\n",
				  *seg, err);
		}
	} else {
		*seg = found;
		err = state;
		SSDFS_DBG("found segment %llu\n", *seg);
	}

finish_seg_search:
	return err;
}

/*
 * ssdfs_segbmap_find() - find segment with state
 * @segbmap: pointer on segment bitmap object
 * @start: start segment number for search
 * @max: upper bound of segment number for search
 * @state: primary state for search
 * @mask: mask of additonal states that can be retrieved too
 * @seg: found segment number [out]
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to find segment number for requested state.
 *
 * RETURN:
 * [success] - found segment state
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EOPNOTSUPP - operation is not supported.
 * %-ENOMEM     - fail to allocate memory.
 * %-EFAULT     - segbmap has inconsistent state.
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to find segment as for state as for mask.
 */
int ssdfs_segbmap_find(struct ssdfs_segment_bmap *segbmap,
			u64 start, u64 max,
			int state, int mask,
			u64 *seg, struct completion **end)
{
	u64 items_count;
	u16 fragment_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap || !seg);

	if (start >= segbmap->items_count) {
		SSDFS_ERR("start %llu >= items_count %llu\n",
			  start, segbmap->items_count);
		return -EINVAL;
	}

	if (start >= max) {
		SSDFS_ERR("start %llu >= max %llu\n",
			  start, max);
		return -EINVAL;
	}

	if (state < SSDFS_SEG_CLEAN || state >= SSDFS_SEG_STATE_MAX) {
		SSDFS_ERR("unknown segment state %#x\n", state);
		return -EINVAL;
	}

	if ((mask & SSDFS_SEG_CLEAN_USING_MASK) != mask &&
	    (mask & SSDFS_SEG_USED_DIRTY_MASK) != mask &&
	    (mask & SSDFS_SEG_BAD_STATE_MASK) != mask) {
		SSDFS_ERR("unsupported set of flags %#x\n",
			  mask);
		return -EOPNOTSUPP;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, start %llu, max %llu, "
		  "state %#x, mask %#x, seg %p\n",
		  segbmap, start, max, state, mask, seg);

	*end = NULL;

	inode_lock_shared(segbmap->fsi->segbmap_inode);
	down_read(&segbmap->resize_lock);

	items_count = segbmap->items_count;
	fragment_size = segbmap->fragment_size;

	if (segbmap->flags & SSDFS_SEGBMAP_ERROR) {
		err = -EFAULT;
		ssdfs_fs_error(segbmap->fsi->sb,
				__FILE__, __func__, __LINE__,
				"segbmap has corrupted state\n");
		goto finish_search_preparation;
	}

	max = min_t(u64, max, items_count);

	down_read(&segbmap->search_lock);
	err = __ssdfs_segbmap_find(segbmap, start, max, state, mask,
				   fragment_size, seg, end);
	up_read(&segbmap->search_lock);

finish_search_preparation:
	up_read(&segbmap->resize_lock);
	inode_unlock_shared(segbmap->fsi->segbmap_inode);

	return err;
}

/*
 * ssdfs_segbmap_find_and_set() - find segment and change state
 * @segbmap: pointer on segment bitmap object
 * @start: start segment number for search
 * @max: upper bound of segment number for search
 * @state: primary state for search
 * @mask: mask of additonal states that can be retrieved too
 * @new_state: new state of segment
 * @seg: found segment number [out]
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to find segment number for requested state
 * and to set segment state as @new_state.
 *
 * RETURN:
 * [success] - found segment state before changing
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EOPNOTSUPP - operation is not supported.
 * %-ENOMEM     - fail to allocate memory.
 * %-EFAULT     - segbmap has inconsistent state.
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to find segment as for state as for mask.
 */
int ssdfs_segbmap_find_and_set(struct ssdfs_segment_bmap *segbmap,
				u64 start, u64 max,
				int state, int mask,
				int new_state,
				u64 *seg, struct completion **end)
{
	u64 items_count;
	u16 fragments_count;
	u16 fragment_size;
	pgoff_t fragment_index;
	int err = 0, res;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap || !seg);

	if (start >= segbmap->items_count) {
		SSDFS_ERR("start %llu >= items_count %llu\n",
			  start, segbmap->items_count);
		return -EINVAL;
	}

	if (start >= max) {
		SSDFS_ERR("start %llu >= max %llu\n",
			  start, max);
		return -EINVAL;
	}

	if (state < SSDFS_SEG_CLEAN || state >= SSDFS_SEG_STATE_MAX) {
		SSDFS_ERR("unknown segment state %#x\n", state);
		return -EINVAL;
	}

	if ((mask & SSDFS_SEG_CLEAN_USING_MASK) != mask &&
	    (mask & SSDFS_SEG_USED_DIRTY_MASK) != mask &&
	    (mask & SSDFS_SEG_BAD_STATE_MASK) != mask) {
		SSDFS_ERR("unsupported set of flags %#x\n",
			  mask);
		return -EOPNOTSUPP;
	}

	if (new_state < SSDFS_SEG_CLEAN || new_state >= SSDFS_SEG_STATE_MAX) {
		SSDFS_ERR("unknown new segment state %#x\n", new_state);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, start %llu, max %llu, "
		  "state %#x, mask %#x, new_state %#x, seg %p\n",
		  segbmap, start, max, state, mask, new_state, seg);

	*end = NULL;

	inode_lock_shared(segbmap->fsi->segbmap_inode);
	down_read(&segbmap->resize_lock);

	items_count = segbmap->items_count;
	fragments_count = segbmap->fragments_count;
	fragment_size = segbmap->fragment_size;

	if (segbmap->flags & SSDFS_SEGBMAP_ERROR) {
		err = -EFAULT;
		ssdfs_fs_error(segbmap->fsi->sb,
				__FILE__, __func__, __LINE__,
				"segbmap has corrupted state\n");
		goto finish_search_preparation;
	}

	max = min_t(u64, max, items_count);

	down_write(&segbmap->search_lock);

	res = __ssdfs_segbmap_find(segbmap, start, max,
				   state, mask,
				   fragment_size, seg, end);
	if (res == -ENODATA) {
		err = res;
		SSDFS_DBG("unable to find any segment\n");
		goto finish_find_set;
	} else if (res == -EAGAIN) {
		err = res;
		SSDFS_DBG("fragment is not initilaized yet\n");
		goto finish_find_set;
	} else if (unlikely(res < 0)) {
		err = res;
		SSDFS_ERR("fail to find clean segment: err %d\n",
			  err);
		goto finish_find_set;
	}

	if (res == new_state)
		goto finish_find_set;

	if (*seg >= items_count) {
		err = -ERANGE;
		SSDFS_ERR("seg %llu >= items_count %llu\n",
			  *seg, items_count);
		goto finish_find_set;
	}

	fragment_index = ssdfs_segbmap_seg_2_fragment_index(*seg);
	if (fragment_index >= fragments_count) {
		err = -EFAULT;
		ssdfs_fs_error(segbmap->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fragment_index %lu >= fragments_count %u\n",
				fragment_index, fragments_count);
		goto finish_find_set;
	}

	err = __ssdfs_segbmap_change_state(segbmap, *seg,
					   new_state,
					   fragment_index,
					   fragment_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to reserve segment: err %d\n",
			  err);
		goto finish_find_set;
	}

finish_find_set:
	up_write(&segbmap->search_lock);

finish_search_preparation:
	up_read(&segbmap->resize_lock);
	inode_unlock_shared(segbmap->fsi->segbmap_inode);

	if (unlikely(err))
		return err;

	return res;
}

/*
 * ssdfs_segbmap_reserve_clean_segment() - reserve clean segment
 * @segbmap: pointer on segment bitmap object
 * @start: start segment number for search
 * @max: upper bound of segment number for search
 * @seg: found segment number [out]
 * @end: pointer on completion for waiting init ending [out]
 *
 * This method tries to find clean segment and to reserve it.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EAGAIN     - fragment is under initialization yet.
 * %-EOPNOTSUPP - operation is not supported.
 * %-ENOMEM     - fail to allocate memory.
 * %-EFAULT     - segbmap has inconsistent state.
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to find segment.
 */
int ssdfs_segbmap_reserve_clean_segment(struct ssdfs_segment_bmap *segbmap,
					u64 start, u64 max,
					u64 *seg, struct completion **end)
{
	u64 items_count;
	u16 fragments_count;
	u16 fragment_size;
	pgoff_t fragment_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!segbmap || !seg);

	if (start >= segbmap->items_count) {
		SSDFS_ERR("start %llu >= items_count %llu\n",
			  start, segbmap->items_count);
		return -EINVAL;
	}

	if (start >= max) {
		SSDFS_ERR("start %llu >= max %llu\n",
			  start, max);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("segbmap %p, start %llu, max %llu, "
		  "seg %p\n",
		  segbmap, start, max, seg);

	*end = NULL;

	inode_lock_shared(segbmap->fsi->segbmap_inode);
	down_read(&segbmap->resize_lock);

	items_count = segbmap->items_count;
	fragments_count = segbmap->fragments_count;
	fragment_size = segbmap->fragment_size;

	if (segbmap->flags & SSDFS_SEGBMAP_ERROR) {
		err = -EFAULT;
		ssdfs_fs_error(segbmap->fsi->sb,
				__FILE__, __func__, __LINE__,
				"segbmap has corrupted state\n");
		goto finish_segment_check;
	}

	down_write(&segbmap->search_lock);

	err = __ssdfs_segbmap_find(segbmap, start, max,
				   SSDFS_SEG_CLEAN,
				   SSDFS_SEG_CLEAN_STATE_FLAG,
				   fragment_size, seg, end);
	if (err == -ENODATA) {
		SSDFS_DBG("unable to find clean segment\n");
		goto finish_reserve_segment;
	} else if (err == -EAGAIN) {
		SSDFS_DBG("fragment is not initilaized yet\n");
		goto finish_reserve_segment;
	} else if (unlikely(err < 0)) {
		SSDFS_ERR("fail to find clean segment: err %d\n",
			  err);
		goto finish_reserve_segment;
	}

	if (*seg >= items_count) {
		err = -ERANGE;
		SSDFS_ERR("seg %llu >= items_count %llu\n",
			  *seg, items_count);
		goto finish_reserve_segment;
	}

	fragment_index = ssdfs_segbmap_seg_2_fragment_index(*seg);
	if (fragment_index >= fragments_count) {
		err = -EFAULT;
		ssdfs_fs_error(segbmap->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fragment_index %lu >= fragments_count %u\n",
				fragment_index, fragments_count);
		goto finish_reserve_segment;
	}

	err = __ssdfs_segbmap_change_state(segbmap, *seg,
					   SSDFS_SEG_RESERVED,
					   fragment_index,
					   fragment_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to reserve segment: err %d\n",
			  err);
		goto finish_reserve_segment;
	}

finish_reserve_segment:
	up_write(&segbmap->search_lock);

finish_segment_check:
	up_read(&segbmap->resize_lock);
	inode_unlock_shared(segbmap->fsi->segbmap_inode);

	return err;
}
