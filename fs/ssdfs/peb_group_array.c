//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_group_array.c - PEBs group array implementation.
 *
 * Copyright (c) 2021-2022 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "segment_bitmap.h"
#include "offset_translation_table.h"
#include "page_array.h"
#include "segment.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "extents_tree.h"
#include "peb_group.h"
#include "peb_group_array.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_peb_group_array_page_leaks;
atomic64_t ssdfs_peb_group_array_memory_leaks;
atomic64_t ssdfs_peb_group_array_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_peb_group_array_cache_leaks_increment(void *kaddr)
 * void ssdfs_peb_group_array_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_peb_group_array_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_peb_group_array_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_peb_group_array_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_peb_group_array_kfree(void *kaddr)
 * struct page *ssdfs_peb_group_array_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_peb_group_array_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_peb_group_array_free_page(struct page *page)
 * void ssdfs_peb_group_array_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(peb_group_array)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(peb_group_array)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_peb_group_array_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_peb_group_array_page_leaks, 0);
	atomic64_set(&ssdfs_peb_group_array_memory_leaks, 0);
	atomic64_set(&ssdfs_peb_group_array_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_peb_group_array_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_peb_group_array_page_leaks) != 0) {
		SSDFS_ERR("PEB GROUP ARRAY: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_peb_group_array_page_leaks));
	}

	if (atomic64_read(&ssdfs_peb_group_array_memory_leaks) != 0) {
		SSDFS_ERR("PEB GROUP ARRAY: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_peb_group_array_memory_leaks));
	}

	if (atomic64_read(&ssdfs_peb_group_array_cache_leaks) != 0) {
		SSDFS_ERR("PEB GROUP ARRAY: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_peb_group_array_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static struct kmem_cache *ssdfs_peb_group_cachep;

static
void ssdfs_init_peb_group_once(void *obj)
{
	struct ssdfs_peb_group *group_obj = obj;

	memset(group_obj, 0, sizeof(struct ssdfs_peb_group));
}

void ssdfs_shrink_peb_group_cache(void)
{
	if (ssdfs_peb_group_cachep)
		kmem_cache_shrink(ssdfs_peb_group_cachep);
}

void ssdfs_destroy_peb_group_cache(void)
{
	if (ssdfs_peb_group_cachep)
		kmem_cache_destroy(ssdfs_peb_group_cachep);
}

int ssdfs_init_peb_group_cache(void)
{
	ssdfs_peb_group_cachep =
		kmem_cache_create("ssdfs_peb_group_cache",
				  sizeof(struct ssdfs_peb_group), 0,
				  SLAB_RECLAIM_ACCOUNT |
				  SLAB_MEM_SPREAD |
				  SLAB_ACCOUNT,
				  ssdfs_init_peb_group_once);
	if (!ssdfs_peb_group_cachep) {
		SSDFS_ERR("unable to create PEB group objects cache\n");
		return -ENOMEM;
	}

	return 0;
}

/*
 * ssdfs_peb_mapping_info_alloc() - allocate memory for PEB group object
 */
static
struct ssdfs_peb_group *ssdfs_peb_group_alloc(void)
{
	struct ssdfs_peb_group *ptr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_peb_group_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr = kmem_cache_alloc(ssdfs_peb_group_cachep, GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate memory for PEB group\n");
		return ERR_PTR(-ENOMEM);
	}

	ssdfs_peb_group_array_cache_leaks_increment(ptr);

	return ptr;
}

/*
 * ssdfs_peb_group_free() - free memory for PEB group object
 */
void ssdfs_peb_group_free(struct ssdfs_peb_group *group)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_peb_group_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!group)
		return;

	ssdfs_peb_group_array_cache_leaks_decrement(group);
	kmem_cache_free(ssdfs_peb_group_cachep, group);
}

/******************************************************************************
 *                        PEB GROUP ARRAY FUNCTIONALITY                       *
 ******************************************************************************/

static
void ssdfs_peb_group_array_invalidatepage(struct page *page,
					  unsigned int offset,
					  unsigned int length)
{
	SSDFS_DBG("do nothing: page_index %llu, offset %u, length %u\n",
		  (u64)page_index(page), offset, length);
}

static
int ssdfs_peb_group_array_releasepage(struct page *page, gfp_t mask)
{
	SSDFS_DBG("do nothing: page_index %llu, mask %#x\n",
		  (u64)page_index(page), mask);

	return 0;
}

const struct address_space_operations ssdfs_peb_group_array_aops = {
	.invalidatepage	= ssdfs_peb_group_array_invalidatepage,
	.releasepage	= ssdfs_peb_group_array_releasepage,
	.set_page_dirty	= __set_page_dirty_nobuffers,
};

/*
 * ssdfs_peb_group_array_mapping_init() - PEB group array's mapping init
 */
static inline
void ssdfs_peb_group_array_mapping_init(struct address_space *mapping,
					struct inode *inode)
{
	address_space_init_once(mapping);
	mapping->a_ops = &ssdfs_peb_group_array_aops;
	mapping->host = inode;
	mapping->flags = 0;
	atomic_set(&mapping->i_mmap_writable, 0);
	mapping_set_gfp_mask(mapping, GFP_KERNEL | __GFP_ZERO);
	mapping->private_data = NULL;
	mapping->writeback_index = 0;
	inode->i_mapping = mapping;
}

static const struct inode_operations def_peb_group_array_ino_iops;
static const struct file_operations def_peb_group_array_ino_fops;
static const struct address_space_operations def_peb_group_array_ino_aops;

/*
 * ssdfs_create_peb_group_array_inode() - create PEB group array's inode
 * @fsi: pointer on shared file system object
 */
static
int ssdfs_create_peb_group_array_inode(struct ssdfs_fs_info *fsi)
{
	struct inode *inode;
	struct ssdfs_inode_info *ii;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p\n", fsi);

	inode = iget_locked(fsi->sb, SSDFS_PEB_GROUP_ARRAY_INO);
	if (unlikely(!inode)) {
		err = -ENOMEM;
		SSDFS_ERR("unable to allocate PEB group array inode: "
			  "err %d\n", err);
		return err;
	}

	BUG_ON(!(inode->i_state & I_NEW));

	inode->i_mode = S_IFREG;
	mapping_set_gfp_mask(inode->i_mapping, GFP_KERNEL);

	inode->i_op = &def_peb_group_array_ino_iops;
	inode->i_fop = &def_peb_group_array_ino_fops;
	inode->i_mapping->a_ops = &def_peb_group_array_ino_aops;

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

	fsi->peb_group_array_inode = inode;

	return 0;
}

/*
 * ssdfs_peb_group_array_create() - create PEB group array
 * @fsi: pointer on shared file system object
 */
int ssdfs_peb_group_array_create(struct ssdfs_fs_info *fsi)
{
	size_t desc_size = sizeof(struct ssdfs_peb_group_array);
	u64 nsegs;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p\n", fsi);

	fsi->peb_group_array = ssdfs_peb_group_array_kzalloc(desc_size,
							     GFP_KERNEL);
	if (!fsi->peb_group_array) {
		SSDFS_ERR("fail to allocate PEB group array's object\n");
		return -ENOMEM;
	}

	err = ssdfs_create_peb_group_array_inode(fsi);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create PEB group array's inode: "
			  "err %d\n", err);
		goto free_memory;
	}

	ssdfs_peb_group_array_mapping_init(&fsi->peb_group_array->pages,
					   fsi->peb_group_array_inode);

	fsi->peb_group_array->pebs_per_group = fsi->pebs_per_group;

	mutex_lock(&fsi->resize_mutex);
	nsegs = fsi->nsegs;
	mutex_unlock(&fsi->resize_mutex);

	fsi->peb_group_array->groups_per_volume =
		div64_u64(nsegs * fsi->pebs_per_seg, fsi->pebs_per_group);

	init_rwsem(&fsi->peb_group_array->pga_lock);

	SSDFS_DBG("nsegs %llu, pebs_per_group %u, "
		  "groups_per_volume %llu\n",
		  nsegs, fsi->pebs_per_group,
		  fsi->peb_group_array->groups_per_volume);

	SSDFS_DBG("DONE: create PEB group array\n");

	return 0;

free_memory:
	ssdfs_peb_group_array_kfree(fsi->peb_group_array);
	fsi->peb_group_array = NULL;

	return err;
}

/*
 * ssdfs_peb_group_array_destroy_objects_in_page() - destroy objects in page
 * @fsi: pointer on shared file system object
 * @page: pointer on memory page
 */
static
void ssdfs_peb_group_array_destroy_objects_in_page(struct ssdfs_fs_info *fsi,
						   struct page *page)
{
	struct ssdfs_peb_group **kaddr;
	struct ssdfs_peb_group *group;
	size_t ptr_size = sizeof(struct ssdfs_peb_group *);
	size_t ptrs_per_page = PAGE_SIZE / ptr_size;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page || !fsi || !fsi->peb_group_array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("page %p\n", page);

	ssdfs_lock_page(page);

	kaddr = (struct ssdfs_peb_group **)kmap(page);

	for (i = 0; i < ptrs_per_page; i++) {
		group = *(kaddr + i);
		*(kaddr + i) = NULL;

		ssdfs_unlock_page(page);

		if (group) {
			ssdfs_peb_group_destroy(group);
			ssdfs_peb_group_free(group);
		}

		ssdfs_lock_page(page);
	}

	kunmap(page);

	ssdfs_clear_dirty_page(page);

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
	SSDFS_DBG("page_index %ld, flags %#lx\n",
		  page->index, page->flags);
}

/*
 * ssdfs_peb_group_array_destroy_objects_in_pages() - destroy objects in array
 * @fsi: pointer on shared file system object
 * @array: pointer on array of pages
 * @pages_count: count of pages in array
 */
static
void ssdfs_peb_group_array_destroy_objects_in_pages(struct ssdfs_fs_info *fsi,
						    struct page **array,
						    size_t pages_count)
{
	struct page *page;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, pages_count %zu\n",
		  array, pages_count);

	for (i = 0; i < pages_count; i++) {
		page = array[i];

		if (!page) {
			SSDFS_WARN("page pointer is NULL: "
				   "index %d\n",
				   i);
			continue;
		}

		ssdfs_peb_group_array_destroy_objects_in_page(fsi, page);
	}
}

#define SSDFS_MEM_PAGE_ARRAY_SIZE	(16)

/*
 * ssdfs_peb_group_array_destroy_peb_group_objects() - destroy all PEB groups
 * @fsi: pointer on shared file system object
 */
static
void ssdfs_peb_group_array_destroy_peb_group_objects(struct ssdfs_fs_info *fsi)
{
	pgoff_t start = 0;
	pgoff_t end = -1;
	size_t pages_count = 0;
	struct page *array[SSDFS_MEM_PAGE_ARRAY_SIZE] = {0};

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->peb_group_array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p\n", fsi);

	do {
		pages_count =
			find_get_pages_range_tag(&fsi->peb_group_array->pages,
						 &start, end,
						 PAGECACHE_TAG_DIRTY,
						 SSDFS_MEM_PAGE_ARRAY_SIZE,
						 &array[0]);

		SSDFS_DBG("start %lu, pages_count %zu\n",
			  start, pages_count);

		if (pages_count != 0) {
			ssdfs_peb_group_array_destroy_objects_in_pages(fsi,
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
 * ssdfs_peb_group_array_destroy() - destroy PEB group array
 * @fsi: pointer on shared file system object
 */
void ssdfs_peb_group_array_destroy(struct ssdfs_fs_info *fsi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->peb_group_array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p\n", fsi);

	inode_lock(fsi->peb_group_array_inode);

	down_write(&fsi->peb_group_array->pga_lock);
	ssdfs_peb_group_array_destroy_peb_group_objects(fsi);
	up_write(&fsi->peb_group_array->pga_lock);

	if (fsi->peb_group_array->pages.nrpages != 0)
		truncate_inode_pages(&fsi->peb_group_array->pages, 0);

	inode_unlock(fsi->peb_group_array_inode);

	iput(fsi->peb_group_array_inode);
	ssdfs_peb_group_array_kfree(fsi->peb_group_array);
	fsi->peb_group_array = NULL;
}

/*
 * ssdfs_peb_group_array_get() - find PEB group in the array
 * @fsi: pointer on shared file system object
 * @group_id: PEB group ID
 *
 * This method tries to get the requested PEB group.
 * If no such group then it will be allocated and initialized.
 *
 * RETURN:
 * [success] - pointer on PEB group object
 * [failure] - error code:
 *
 * %-EINVAL   - invalid input.
 * %-ERANGE   - internal error.
 * %-ENOMEM   - no free memory to allocate an object.
 */
struct ssdfs_peb_group *
ssdfs_peb_group_array_get(struct ssdfs_fs_info *fsi, u64 group_id)
{
	pgoff_t page_index;
	u32 object_index;
	struct page *page;
	struct ssdfs_peb_group **kaddr, *object = NULL;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->peb_group_array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, group_id %llu\n",
		  fsi, group_id);

	if (group_id >= fsi->peb_group_array->groups_per_volume) {
		SSDFS_ERR("group_id %llu >= groups_per_volume %llu\n",
			  group_id,
			  fsi->peb_group_array->groups_per_volume);
		return ERR_PTR(-EINVAL);
	}

	page_index = div_u64_rem(group_id, SSDFS_PEB_GRP_ARRAY_PTR_PER_PAGE,
				 &object_index);

	SSDFS_DBG("page_index %lu, object_index %u\n",
		  page_index, object_index);

	inode_lock_shared(fsi->peb_group_array_inode);

	page = grab_cache_page(&fsi->peb_group_array->pages, page_index);
	if (!page) {
		object = ERR_PTR(-ENOMEM);
		SSDFS_ERR("fail to grab page: page_index %lu\n",
			  page_index);
		goto finish_get_peb_group;
	}

	ssdfs_account_locked_page(page);

	down_read(&fsi->peb_group_array->pga_lock);
	kaddr = (struct ssdfs_peb_group **)kmap_atomic(page);
	object = *(kaddr + object_index);
	kunmap_atomic(kaddr);
	up_read(&fsi->peb_group_array->pga_lock);

	if (!object) {
		down_write(&fsi->peb_group_array->pga_lock);

		kaddr = (struct ssdfs_peb_group **)kmap_atomic(page);
		object = *(kaddr + object_index);
		kunmap_atomic(kaddr);

		if (object != NULL)
			goto finish_peb_group_creation;

		object = ssdfs_peb_group_alloc();
		if (IS_ERR_OR_NULL(object)) {
			err = (object == NULL ? -ENOMEM : PTR_ERR(object));
			SSDFS_ERR("fail to allocate PEB group: err %d\n",
				  err);
			goto finish_peb_group_creation;
		}

		err = ssdfs_peb_group_create(fsi, object, group_id);
		if (unlikely(err)) {
			ssdfs_peb_group_free(object);
			object = ERR_PTR(err);
			SSDFS_ERR("fail to create PEB group: "
				  "group_id %llu, err %d\n",
				  group_id, err);
			goto finish_peb_group_creation;
		}

		kaddr = (struct ssdfs_peb_group **)kmap_atomic(page);
		*(kaddr + object_index) = object;
		kunmap_atomic(kaddr);

finish_peb_group_creation:
		up_write(&fsi->peb_group_array->pga_lock);
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));

finish_get_peb_group:
	inode_unlock_shared(fsi->segs_tree_inode);

	SSDFS_DBG("finished\n");

	return object;
}
