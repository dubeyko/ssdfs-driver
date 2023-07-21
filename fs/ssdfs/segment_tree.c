// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/segment_tree.c - segment tree implementation.
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

#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "page_vector.h"
#include "ssdfs.h"
#include "segment_bitmap.h"
#include "page_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "extents_tree.h"
#include "segment_tree.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_seg_tree_page_leaks;
atomic64_t ssdfs_seg_tree_folio_leaks;
atomic64_t ssdfs_seg_tree_memory_leaks;
atomic64_t ssdfs_seg_tree_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_seg_tree_cache_leaks_increment(void *kaddr)
 * void ssdfs_seg_tree_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_seg_tree_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_seg_tree_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_seg_tree_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_seg_tree_kfree(void *kaddr)
 * struct page *ssdfs_seg_tree_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_seg_tree_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_seg_tree_free_page(struct page *page)
 * void ssdfs_seg_tree_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(seg_tree)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(seg_tree)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_seg_tree_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_seg_tree_page_leaks, 0);
	atomic64_set(&ssdfs_seg_tree_folio_leaks, 0);
	atomic64_set(&ssdfs_seg_tree_memory_leaks, 0);
	atomic64_set(&ssdfs_seg_tree_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_seg_tree_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_seg_tree_page_leaks) != 0) {
		SSDFS_ERR("SEGMENT TREE: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_seg_tree_page_leaks));
	}

	if (atomic64_read(&ssdfs_seg_tree_folio_leaks) != 0) {
		SSDFS_ERR("SEGMENT TREE: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_seg_tree_folio_leaks));
	}

	if (atomic64_read(&ssdfs_seg_tree_memory_leaks) != 0) {
		SSDFS_ERR("SEGMENT TREE: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_seg_tree_memory_leaks));
	}

	if (atomic64_read(&ssdfs_seg_tree_cache_leaks) != 0) {
		SSDFS_ERR("SEGMENT TREE: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_seg_tree_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/******************************************************************************
 *                        SEGMENTS TREE FUNCTIONALITY                         *
 ******************************************************************************/

static
void ssdfs_segment_tree_invalidate_folio(struct folio *folio, size_t offset,
					 size_t length)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("do nothing: offset %zu, length %zu\n",
		  offset, length);
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * ssdfs_segment_tree_release_folio() - Release fs-specific metadata on a folio.
 * @folio: The folio which the kernel is trying to free.
 * @gfp: Memory allocation flags (and I/O mode).
 *
 * The address_space is trying to release any data attached to a folio
 * (presumably at folio->private).
 *
 * This will also be called if the private_2 flag is set on a page,
 * indicating that the folio has other metadata associated with it.
 *
 * The @gfp argument specifies whether I/O may be performed to release
 * this page (__GFP_IO), and whether the call may block
 * (__GFP_RECLAIM & __GFP_FS).
 *
 * Return: %true if the release was successful, otherwise %false.
 */
static
bool ssdfs_segment_tree_release_folio(struct folio *folio, gfp_t gfp)
{
	return false;
}

static
bool ssdfs_segment_tree_noop_dirty_folio(struct address_space *mapping,
					 struct folio *folio)
{
	return true;
}

const struct address_space_operations ssdfs_segment_tree_aops = {
	.invalidate_folio	= ssdfs_segment_tree_invalidate_folio,
	.release_folio		= ssdfs_segment_tree_release_folio,
	.dirty_folio		= ssdfs_segment_tree_noop_dirty_folio,
};

/*
 * ssdfs_segment_tree_mapping_init() - segment tree's mapping init
 */
static inline
void ssdfs_segment_tree_mapping_init(struct address_space *mapping,
				     struct inode *inode)
{
	address_space_init_once(mapping);
	mapping->a_ops = &ssdfs_segment_tree_aops;
	mapping->host = inode;
	mapping->flags = 0;
	atomic_set(&mapping->i_mmap_writable, 0);
	mapping_set_gfp_mask(mapping, GFP_KERNEL | __GFP_ZERO);
	mapping->private_data = NULL;
	mapping->writeback_index = 0;
	inode->i_mapping = mapping;
}

static const struct inode_operations def_segment_tree_ino_iops;
static const struct file_operations def_segment_tree_ino_fops;
static const struct address_space_operations def_segment_tree_ino_aops;

/*
 * ssdfs_create_segment_tree_inode() - create segments tree's inode
 * @fsi: pointer on shared file system object
 */
static
int ssdfs_create_segment_tree_inode(struct ssdfs_fs_info *fsi)
{
	struct inode *inode;
	struct ssdfs_inode_info *ii;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	inode = iget_locked(fsi->sb, SSDFS_SEG_TREE_INO);
	if (unlikely(!inode)) {
		err = -ENOMEM;
		SSDFS_ERR("unable to allocate segment tree inode: err %d\n",
			  err);
		return err;
	}

	BUG_ON(!(inode->i_state & I_NEW));

	inode->i_mode = S_IFREG;
	mapping_set_gfp_mask(inode->i_mapping, GFP_KERNEL);

	inode->i_op = &def_segment_tree_ino_iops;
	inode->i_fop = &def_segment_tree_ino_fops;
	inode->i_mapping->a_ops = &def_segment_tree_ino_aops;

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

	fsi->segs_tree_inode = inode;

	return 0;
}

/*
 * ssdfs_segment_tree_create() - create segments tree
 * @fsi: pointer on shared file system object
 */
int ssdfs_segment_tree_create(struct ssdfs_fs_info *fsi)
{
	size_t dentries_desc_size =
		sizeof(struct ssdfs_dentries_btree_descriptor);
	size_t extents_desc_size =
		sizeof(struct ssdfs_extents_btree_descriptor);
	size_t xattr_desc_size =
		sizeof(struct ssdfs_xattr_btree_descriptor);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi->segs_tree =
		ssdfs_seg_tree_kzalloc(sizeof(struct ssdfs_segment_tree),
					GFP_KERNEL);
	if (!fsi->segs_tree) {
		SSDFS_ERR("fail to allocate segment tree's root object\n");
		return -ENOMEM;
	}

	ssdfs_memcpy(&fsi->segs_tree->dentries_btree,
		     0, dentries_desc_size,
		     &fsi->vh->dentries_btree,
		     0, dentries_desc_size,
		     dentries_desc_size);
	ssdfs_memcpy(&fsi->segs_tree->extents_btree, 0, extents_desc_size,
		     &fsi->vh->extents_btree, 0, extents_desc_size,
		     extents_desc_size);
	ssdfs_memcpy(&fsi->segs_tree->xattr_btree, 0, xattr_desc_size,
		     &fsi->vh->xattr_btree, 0, xattr_desc_size,
		     xattr_desc_size);

	err = ssdfs_create_segment_tree_inode(fsi);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create segment tree's inode: "
			  "err %d\n",
			  err);
		goto free_memory;
	}

	fsi->segs_tree->lnodes_seg_log_pages =
		le16_to_cpu(fsi->vh->lnodes_seg_log_pages);
	fsi->segs_tree->hnodes_seg_log_pages =
		le16_to_cpu(fsi->vh->hnodes_seg_log_pages);
	fsi->segs_tree->inodes_seg_log_pages =
		le16_to_cpu(fsi->vh->inodes_seg_log_pages);
	fsi->segs_tree->user_data_log_pages =
		le16_to_cpu(fsi->vh->user_data_log_pages);
	fsi->segs_tree->default_log_pages = SSDFS_LOG_PAGES_DEFAULT;

	ssdfs_segment_tree_mapping_init(&fsi->segs_tree->pages,
					fsi->segs_tree_inode);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("DONE: create segment tree\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;

free_memory:
	ssdfs_seg_tree_kfree(fsi->segs_tree);
	fsi->segs_tree = NULL;

	return err;
}

/*
 * ssdfs_segment_tree_destroy_objects_in_page() - destroy objects in page
 * @fsi: pointer on shared file system object
 * @page: pointer on memory page
 */
static
void ssdfs_segment_tree_destroy_objects_in_page(struct ssdfs_fs_info *fsi,
						struct page *page)
{
	struct ssdfs_segment_info **kaddr;
	size_t ptr_size = sizeof(struct ssdfs_segment_info *);
	size_t ptrs_per_page = PAGE_SIZE / ptr_size;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page || !fsi || !fsi->segs_tree);

	SSDFS_DBG("page %p\n", page);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_lock_page(page);

	kaddr = (struct ssdfs_segment_info **)kmap_local_page(page);

	for (i = 0; i < ptrs_per_page; i++) {
		struct ssdfs_segment_info *si = *(kaddr + i);

		if (si) {
			wait_queue_head_t *wq = &si->object_queue;
			int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("si %p, seg_id %llu\n", si, si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

			if (atomic_read(&si->refs_count) > 0) {
				ssdfs_unlock_page(page);

				err = wait_event_killable_timeout(*wq,
					atomic_read(&si->refs_count) <= 0,
					SSDFS_DEFAULT_TIMEOUT);
				if (err < 0)
					WARN_ON(err < 0);
				else
					err = 0;

				ssdfs_lock_page(page);
			}

			err = ssdfs_segment_destroy_object(si);
			if (err) {
				SSDFS_WARN("fail to destroy segment object: "
					   "seg %llu, err %d\n",
					   si->seg_id, err);
			}
		}

	}

	kunmap_local(kaddr);

	__ssdfs_clear_dirty_page(page);

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
	SSDFS_DBG("page_index %ld, flags %#lx\n",
		  page->index, page->flags);
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * ssdfs_segment_tree_destroy_objects_in_array() - destroy objects in array
 * @fsi: pointer on shared file system object
 * @array: pointer on array of pages
 * @pages_count: count of pages in array
 */
static
void ssdfs_segment_tree_destroy_objects_in_array(struct ssdfs_fs_info *fsi,
						 struct page **array,
						 size_t pages_count)
{
	struct page *page;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !fsi);

	SSDFS_DBG("array %p, pages_count %zu\n",
		  array, pages_count);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < pages_count; i++) {
		page = array[i];

		if (!page) {
			SSDFS_WARN("page pointer is NULL: "
				   "index %d\n",
				   i);
			continue;
		}

		ssdfs_segment_tree_destroy_objects_in_page(fsi, page);
	}
}

#define SSDFS_MEM_PAGE_ARRAY_SIZE	(16)

/*
 * ssdfs_segment_tree_destroy_segment_objects() - destroy all segment objects
 * @fsi: pointer on shared file system object
 */
static
void ssdfs_segment_tree_destroy_segment_objects(struct ssdfs_fs_info *fsi)
{
	pgoff_t start = 0;
	pgoff_t end = -1;
	size_t pages_count = 0;
	struct page *array[SSDFS_MEM_PAGE_ARRAY_SIZE] = {0};

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->segs_tree);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	do {
		pages_count = find_get_pages_range_tag(&fsi->segs_tree->pages,
					    &start, end,
					    PAGECACHE_TAG_DIRTY,
					    SSDFS_MEM_PAGE_ARRAY_SIZE,
					    &array[0]);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start %lu, pages_count %zu\n",
			  start, pages_count);
#endif /* CONFIG_SSDFS_DEBUG */

		if (pages_count != 0) {
			ssdfs_segment_tree_destroy_objects_in_array(fsi,
								&array[0],
								pages_count);

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!array[pages_count - 1]);
#endif /* CONFIG_SSDFS_DEBUG */

			start = page_index(array[pages_count - 1]) + 1;
		}
	} while (pages_count != 0);
}

/*
 * ssdfs_segment_tree_destroy() - destroy segments tree
 * @fsi: pointer on shared file system object
 */
void ssdfs_segment_tree_destroy(struct ssdfs_fs_info *fsi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->segs_tree);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	inode_lock(fsi->segs_tree_inode);

	ssdfs_destroy_btree_of_inode(fsi->segs_tree_inode);

	ssdfs_segment_tree_destroy_segment_objects(fsi);

	if (fsi->segs_tree->pages.nrpages != 0)
		truncate_inode_pages(&fsi->segs_tree->pages, 0);

	inode_unlock(fsi->segs_tree_inode);

	iput(fsi->segs_tree_inode);
	ssdfs_seg_tree_kfree(fsi->segs_tree);
	fsi->segs_tree = NULL;
}

/*
 * ssdfs_segment_tree_add() - add segment object into the tree
 * @fsi: pointer on shared file system object
 * @si: pointer on segment object
 *
 * This method tries to add the valid pointer on segment
 * object into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM  - fail to allocate memory.
 * %-EEXIST  - segment has been added already.
 */
int ssdfs_segment_tree_add(struct ssdfs_fs_info *fsi,
			   struct ssdfs_segment_info *si)
{
	pgoff_t page_index;
	u32 object_index;
	struct page *page;
	struct ssdfs_segment_info **kaddr, *object;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->segs_tree || !si);

	SSDFS_DBG("fsi %p, si %p, seg %llu\n",
		  fsi, si, si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = div_u64_rem(si->seg_id, SSDFS_SEG_OBJ_PTR_PER_PAGE,
				 &object_index);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page_index %lu, object_index %u\n",
		  page_index, object_index);
#endif /* CONFIG_SSDFS_DEBUG */

	inode_lock(fsi->segs_tree_inode);

	page = grab_cache_page(&fsi->segs_tree->pages, page_index);
	if (!page) {
		err = -ENOMEM;
		SSDFS_ERR("fail to grab page: page_index %lu\n",
			  page_index);
		goto finish_add_segment;
	}

	ssdfs_account_locked_page(page);

	kaddr = (struct ssdfs_segment_info **)kmap_local_page(page);
	object = *(kaddr + object_index);
	if (object) {
		err = -EEXIST;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("object exists for segment %llu\n",
			  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
	} else
		*(kaddr + object_index) = si;
	kunmap_local(kaddr);

	SetPageUptodate(page);
	if (!PageDirty(page))
		ssdfs_set_page_dirty(page);

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
	SSDFS_DBG("page_index %ld, flags %#lx\n",
		  page->index, page->flags);
#endif /* CONFIG_SSDFS_DEBUG */

finish_add_segment:
	inode_unlock(fsi->segs_tree_inode);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_segment_tree_remove() - remove segment object from the tree
 * @fsi: pointer on shared file system object
 * @si: pointer on segment object
 *
 * This method tries to remove the valid pointer on segment
 * object from the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA  - segment tree hasn't object for @si.
 */
int ssdfs_segment_tree_remove(struct ssdfs_fs_info *fsi,
			      struct ssdfs_segment_info *si)
{
	pgoff_t page_index;
	u32 object_index;
	struct page *page;
	struct ssdfs_segment_info **kaddr, *object;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->segs_tree || !si);

	SSDFS_DBG("fsi %p, si %p, seg %llu\n",
		  fsi, si, si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = div_u64_rem(si->seg_id, SSDFS_SEG_OBJ_PTR_PER_PAGE,
				 &object_index);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page_index %lu, object_index %u\n",
		  page_index, object_index);
#endif /* CONFIG_SSDFS_DEBUG */

	inode_lock(fsi->segs_tree_inode);

	page = find_lock_page(&fsi->segs_tree->pages, page_index);
	if (!page) {
		err = -ENODATA;
		SSDFS_ERR("failed to remove segment object: "
			  "seg %llu\n",
			  si->seg_id);
		goto finish_remove_segment;
	}

	ssdfs_account_locked_page(page);
	kaddr = (struct ssdfs_segment_info **)kmap_local_page(page);
	object = *(kaddr + object_index);
	if (!object) {
		err = -ENODATA;
		SSDFS_WARN("object ptr is NULL: "
			   "seg %llu\n",
			   si->seg_id);
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(object != si);
#endif /* CONFIG_SSDFS_DEBUG */
		*(kaddr + object_index) = NULL;
	}
	kunmap_local(kaddr);

	SetPageUptodate(page);
	if (!PageDirty(page))
		ssdfs_set_page_dirty(page);

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	/*
	 * Prevent from error of creation
	 * the same segment in another thread.
	 */
	ssdfs_sysfs_delete_seg_group(si);

finish_remove_segment:
	inode_unlock(fsi->segs_tree_inode);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_segment_tree_find() - find segment object in the tree
 * @fsi: pointer on shared file system object
 * @seg_id: segment number
 *
 * This method tries to find the valid pointer on segment
 * object for @seg_id.
 *
 * RETURN:
 * [success] - pointer on found segment object
 * [failure] - error code:
 *
 * %-EINVAL   - invalid input.
 * %-ENODATA  - segment tree hasn't object for @seg_id.
 */
struct ssdfs_segment_info *
ssdfs_segment_tree_find(struct ssdfs_fs_info *fsi, u64 seg_id)
{
	pgoff_t page_index;
	u32 object_index;
	struct page *page;
	struct ssdfs_segment_info **kaddr, *object;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->segs_tree);

	if (seg_id >= fsi->nsegs) {
		SSDFS_ERR("seg_id %llu >= fsi->nsegs %llu\n",
			  seg_id, fsi->nsegs);
		return ERR_PTR(-EINVAL);
	}

	SSDFS_DBG("fsi %p, seg_id %llu\n",
		  fsi, seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = div_u64_rem(seg_id, SSDFS_SEG_OBJ_PTR_PER_PAGE,
				 &object_index);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page_index %lu, object_index %u\n",
		  page_index, object_index);
#endif /* CONFIG_SSDFS_DEBUG */

	inode_lock_shared(fsi->segs_tree_inode);

	page = find_lock_page(&fsi->segs_tree->pages, page_index);
	if (!page) {
		object = ERR_PTR(-ENODATA);
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find segment object: "
			  "seg %llu\n",
			  seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_find_segment;
	}

	ssdfs_account_locked_page(page);
	kaddr = (struct ssdfs_segment_info **)kmap_local_page(page);
	object = *(kaddr + object_index);
	if (!object) {
		object = ERR_PTR(-ENODATA);
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find segment object: "
			  "seg %llu\n",
			  seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
	}
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

finish_find_segment:
	inode_unlock_shared(fsi->segs_tree_inode);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return object;
}
