// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/diff_on_write.h - Diff-On-Write approach declarations.
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

#ifndef _SSDFS_DIFF_ON_WRITE_H
#define _SSDFS_DIFF_ON_WRITE_H

#define SSDFS_DIFF_ON_WRITE_PCT_THRESHOLD	(25)

#define SSDFS_DIRTY_ITEM	(0x1)
#define SSDFS_DIRTY_ITEM_MASK	(0x1)

/*
 * Diff-On-Write approach API
 */

#ifdef CONFIG_SSDFS_DIFF_ON_WRITE

bool can_diff_on_write_metadata_be_used(struct ssdfs_btree_node *node);

/* TODO: freeze memory page state */
int ssdfs_dow_freeze_page_state(struct page *page);

/* TODO: extract delta between old and new states */
int ssdfs_dow_extract_delta(struct page *page, struct page *delta);

/* TODO: forget memory page state */
int ssdfs_dow_forget_page_state(struct page *page);

#else
static inline
bool can_diff_on_write_metadata_be_used(struct ssdfs_btree_node *node)
{
	return false;
}

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

#ifdef CONFIG_SSDFS_DIFF_ON_WRITE_METADATA
int ssdfs_btree_node_prepare_diff(struct ssdfs_btree_node *node);
int ssdfs_btree_node_apply_diffs(struct ssdfs_peb_info *pebi,
				 struct ssdfs_segment_request *req);
#else
static inline
int ssdfs_btree_node_prepare_diff(struct ssdfs_btree_node *node)
{
	SSDFS_ERR("Diff-On-Write (metadata case) is not supported. "
		  "Please, enable CONFIG_SSDFS_DIFF_ON_WRITE_METADATA option.\n");
	return -EOPNOTSUPP;
}
static inline
int ssdfs_btree_node_apply_diffs(struct ssdfs_peb_info *pebi,
				 struct ssdfs_segment_request *req)
{
	if (folio_batch_count(&req->result.diffs) > 0) {
		ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
			__FILE__, __func__, __LINE__,
			"Diff-On-Write (metadata case) is not supported. "
			"Please, enable CONFIG_SSDFS_DIFF_ON_WRITE_METADATA option.\n");
		return -EOPNOTSUPP;
	} else
		return 0;
}
#endif /* CONFIG_SSDFS_DIFF_ON_WRITE_METADATA */

#ifdef CONFIG_SSDFS_DIFF_ON_WRITE_USER_DATA
int ssdfs_user_data_prepare_diff(struct ssdfs_peb_container *pebc,
				 struct ssdfs_phys_offset_descriptor *desc_off,
				 struct ssdfs_offset_position *pos,
				 struct ssdfs_segment_request *req);
int ssdfs_user_data_apply_diffs(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req);
#else
static inline
int ssdfs_user_data_prepare_diff(struct ssdfs_peb_container *pebc,
				 struct ssdfs_phys_offset_descriptor *desc_off,
				 struct ssdfs_offset_position *pos,
				 struct ssdfs_segment_request *req)
{
	SSDFS_ERR("Diff-On-Write (user data case) is not supported. "
		  "Please, enable CONFIG_SSDFS_DIFF_ON_WRITE_USER_DATA option.\n");
	return -EOPNOTSUPP;
}
static inline
int ssdfs_user_data_apply_diffs(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req)
{
	if (folio_batch_count(&req->result.diffs) > 0) {
		ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
			__FILE__, __func__, __LINE__,
			"Diff-On-Write (user data case) is not supported. "
			"Please, enable CONFIG_SSDFS_DIFF_ON_WRITE_USER_DATA option.\n");
		return -EOPNOTSUPP;
	} else
		return 0;
}
#endif /* CONFIG_SSDFS_DIFF_ON_WRITE_USER_DATA */

#endif /* _SSDFS_DIFF_ON_WRITE_H */
