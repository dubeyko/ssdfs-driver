//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/fs_error.c - logic for the case of file system errors detection.
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

#include <linux/page-flags.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"

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

int ssdfs_clear_dirty_page(struct page *page)
{
	struct address_space *mapping = page->mapping;

	SSDFS_DBG("page_index: %llu, mapping %p\n",
		  (u64)page_index(page), mapping);

	if (!PageLocked(page)) {
		SSDFS_WARN("page isn't locked: "
			   "page_index %llu, mapping %p\n",
			   (u64)page_index(page), mapping);
		return -ERANGE;
	}

	if (mapping) {
		xa_lock_irq(&mapping->i_pages);
		if (test_bit(PG_dirty, &page->flags)) {
			__xa_clear_mark(&mapping->i_pages,
					page_index(page),
					PAGECACHE_TAG_DIRTY);
			xa_unlock_irq(&mapping->i_pages);
			return clear_page_dirty_for_io(page);
		}
		xa_unlock_irq(&mapping->i_pages);
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

			lock_page(page);
			err = ssdfs_clear_dirty_page(page);
			unlock_page(page);

			if (unlikely(err)) {
				SSDFS_DBG("fail clear page dirty: "
					  "page_index %llu\n",
					  (u64)page_index(page));
			}
		}
		pagevec_release(&pvec);
		cond_resched();
	}
}
