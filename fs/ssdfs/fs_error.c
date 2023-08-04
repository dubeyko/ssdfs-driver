// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/fs_error.c - logic for the case of file system errors detection.
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

#include <linux/page-flags.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "page_vector.h"
#include "ssdfs.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_fs_error_page_leaks;
atomic64_t ssdfs_fs_error_folio_leaks;
atomic64_t ssdfs_fs_error_memory_leaks;
atomic64_t ssdfs_fs_error_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_fs_error_cache_leaks_increment(void *kaddr)
 * void ssdfs_fs_error_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_fs_error_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_fs_error_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_fs_error_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_fs_error_kfree(void *kaddr)
 * struct page *ssdfs_fs_error_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_fs_error_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_fs_error_free_page(struct page *page)
 * void ssdfs_fs_error_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(fs_error)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(fs_error)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_fs_error_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_fs_error_page_leaks, 0);
	atomic64_set(&ssdfs_fs_error_folio_leaks, 0);
	atomic64_set(&ssdfs_fs_error_memory_leaks, 0);
	atomic64_set(&ssdfs_fs_error_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_fs_error_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_fs_error_page_leaks) != 0) {
		SSDFS_ERR("FS ERROR: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_fs_error_page_leaks));
	}

	if (atomic64_read(&ssdfs_fs_error_folio_leaks) != 0) {
		SSDFS_ERR("FS ERROR: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_fs_error_folio_leaks));
	}

	if (atomic64_read(&ssdfs_fs_error_memory_leaks) != 0) {
		SSDFS_ERR("FS ERROR: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_fs_error_memory_leaks));
	}

	if (atomic64_read(&ssdfs_fs_error_cache_leaks) != 0) {
		SSDFS_ERR("FS ERROR: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_fs_error_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static void ssdfs_handle_error(struct super_block *sb)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);

	if (sb->s_flags & SB_RDONLY)
		return;

	spin_lock(&fsi->volume_state_lock);
	fsi->fs_state = SSDFS_ERROR_FS;
	spin_unlock(&fsi->volume_state_lock);

	if (ssdfs_test_opt(fsi->mount_opts, ERRORS_PANIC)) {
		panic("SSDFS (device %s): panic forced after error\n",
			fsi->devops->device_name(sb));
	} else if (ssdfs_test_opt(fsi->mount_opts, ERRORS_RO)) {
		SSDFS_CRIT("Remounting filesystem read-only\n");
		/*
		 * Make sure updated value of ->s_mount_flags will be visible
		 * before ->s_flags update
		 */
		smp_wmb();
		sb->s_flags |= SB_RDONLY;
	}
}

void ssdfs_fs_error(struct super_block *sb, const char *file,
		    const char *function, unsigned int line,
		    const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	pr_crit("SSDFS error (device %s): pid %d:%s:%d %s(): comm %s: %pV",
		SSDFS_FS_I(sb)->devops->device_name(sb), current->pid,
		file, line, function, current->comm, &vaf);
	va_end(args);

	ssdfs_handle_error(sb);
}

int ssdfs_set_page_dirty(struct page *page)
{
	struct address_space *mapping = page->mapping;
	unsigned long flags;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page_index: %llu, mapping %p\n",
		  (u64)page_index(page), mapping);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!PageLocked(page)) {
		SSDFS_WARN("page isn't locked: "
			   "page_index %llu, mapping %p\n",
			   (u64)page_index(page), mapping);
		return -ERANGE;
	}

	SetPageDirty(page);

	if (mapping) {
		xa_lock_irqsave(&mapping->i_pages, flags);
		__xa_set_mark(&mapping->i_pages, page_index(page),
				PAGECACHE_TAG_DIRTY);
		xa_unlock_irqrestore(&mapping->i_pages, flags);
	}

	return 0;
}

int ssdfs_set_folio_dirty(struct folio *folio)
{
	struct address_space *mapping = folio->mapping;
	unsigned long flags;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio_index: %llu, mapping %p\n",
		  (u64)folio_index(folio), mapping);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!folio_test_locked(folio)) {
		SSDFS_WARN("folio isn't locked: "
			   "folio_index %llu, mapping %p\n",
			   (u64)folio_index(folio), mapping);
		return -ERANGE;
	}

	folio_set_dirty(folio);

	if (mapping) {
		xa_lock_irqsave(&mapping->i_pages, flags);
		__xa_set_mark(&mapping->i_pages, folio_index(folio),
				PAGECACHE_TAG_DIRTY);
		xa_unlock_irqrestore(&mapping->i_pages, flags);
	}

	return 0;
}

int __ssdfs_clear_dirty_page(struct page *page)
{
	struct address_space *mapping = page->mapping;
	unsigned long flags;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page_index: %llu, mapping %p\n",
		  (u64)page_index(page), mapping);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!PageLocked(page)) {
		SSDFS_WARN("page isn't locked: "
			   "page_index %llu, mapping %p\n",
			   (u64)page_index(page), mapping);
		return -ERANGE;
	}

	if (mapping) {
		xa_lock_irqsave(&mapping->i_pages, flags);
		if (test_bit(PG_dirty, &page->flags)) {
			__xa_clear_mark(&mapping->i_pages,
					page_index(page),
					PAGECACHE_TAG_DIRTY);
		}
		xa_unlock_irqrestore(&mapping->i_pages, flags);
	}

	TestClearPageDirty(page);

	return 0;
}

int __ssdfs_clear_dirty_folio(struct folio *folio)
{
	struct address_space *mapping = folio->mapping;
	unsigned long flags;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio_index: %llu, mapping %p\n",
		  (u64)folio_index(folio), mapping);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!folio_test_locked(folio)) {
		SSDFS_WARN("folio isn't locked: "
			   "folio_index %llu, mapping %p\n",
			   (u64)folio_index(folio), mapping);
		return -ERANGE;
	}

	if (mapping) {
		xa_lock_irqsave(&mapping->i_pages, flags);
		if (test_bit(PG_dirty, &folio->flags)) {
			__xa_clear_mark(&mapping->i_pages,
					folio_index(folio),
					PAGECACHE_TAG_DIRTY);
		}
		xa_unlock_irqrestore(&mapping->i_pages, flags);
	}

	folio_test_clear_dirty(folio);

	return 0;
}

int ssdfs_clear_dirty_page(struct page *page)
{
	struct address_space *mapping = page->mapping;
	unsigned long flags;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page_index: %llu, mapping %p\n",
		  (u64)page_index(page), mapping);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!PageLocked(page)) {
		SSDFS_WARN("page isn't locked: "
			   "page_index %llu, mapping %p\n",
			   (u64)page_index(page), mapping);
		return -ERANGE;
	}

	if (mapping) {
		xa_lock_irqsave(&mapping->i_pages, flags);
		if (test_bit(PG_dirty, &page->flags)) {
			__xa_clear_mark(&mapping->i_pages,
					page_index(page),
					PAGECACHE_TAG_DIRTY);
			xa_unlock_irqrestore(&mapping->i_pages, flags);
			return clear_page_dirty_for_io(page);
		}
		xa_unlock_irqrestore(&mapping->i_pages, flags);
		return 0;
	}

	TestClearPageDirty(page);

	return 0;
}

/*
 * ssdfs_clear_dirty_pages - discard dirty pages in address space
 * @mapping: address space with dirty pages for discarding
 */
void ssdfs_clear_dirty_pages(struct address_space *mapping)
{
	struct pagevec pvec;
	unsigned int i;
	pgoff_t index = 0;
	int err;

	pagevec_init(&pvec);

	while (pagevec_lookup_tag(&pvec, mapping, &index,
				  PAGECACHE_TAG_DIRTY)) {
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];

			ssdfs_lock_page(page);
			err = ssdfs_clear_dirty_page(page);
			ssdfs_unlock_page(page);

			if (unlikely(err)) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("fail clear page dirty: "
					  "page_index %llu\n",
					  (u64)page_index(page));
#endif /* CONFIG_SSDFS_DEBUG */
			}
		}
		ssdfs_fs_error_pagevec_release(&pvec);
		cond_resched();
	}
}
