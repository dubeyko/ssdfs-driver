//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/diff_on_write.h - Diff-On-Write approach declarations.
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

#ifndef _SSDFS_DIFF_ON_WRITE_H
#define _SSDFS_DIFF_ON_WRITE_H

/*
 * The struct page has union with field "private" and related fields.
 * It is possible to use this field with PG_private flag.
 * If ssdfs_write_begin() is called then it needs to copy current page
 * state into the backup memory page (this page should be shadowed inside
 * of "private" field). If ssdfs_write_end() is called then it needs
 * to extract diff (delta) and to save into structure is associated
 * with "private" field. Finally, gathered diffs are chained into
 * "private" field should be store during ssdfs_write_page() call.
 */


/*
 * Diff-On-Write approach API
 */

#ifdef CONFIG_SSDFS_DIFF_ON_WRITE

/* TODO: freeze memory page state */
int ssdfs_dow_freeze_page_state(struct page *page);

/* TODO: extract delta between old and new states */
int ssdfs_dow_extract_delta(struct page *page, struct page *delta);

/* TODO: forget memory page state */
int ssdfs_dow_forget_page_state(struct page *page);

#else
static inline
int ssdfs_dow_freeze_page_state(struct page *page)
{
	return 0;
}

static inline
int ssdfs_dow_extract_delta(struct page *page, struct page *delta)
{
	return 0;
}

static inline
int ssdfs_dow_forget_page_state(struct page *page)
{
	return 0;
}
#endif /* CONFIG_SSDFS_DIFF_ON_WRITE */

#endif /* _SSDFS_DIFF_ON_WRITE_H */
