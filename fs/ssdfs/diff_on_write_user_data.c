//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/diff_on_write_user_data.c - Diff-On-Write user data implementation.
 *
 * Copyright (c) 2021-2022 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "common_bitmap.h"
#include "offset_translation_table.h"
#include "page_array.h"
#include "peb.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "request_queue.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "diff_on_write.h"

int ssdfs_user_data_apply_diffs(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				struct pagevec *diff)
{
	if (pagevec_count(diff) > 0) {
		ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
			__FILE__, __func__, __LINE__,
			"Diff-On-Write (user data case) is not supported. "
			"Please, enable CONFIG_SSDFS_DIFF_ON_WRITE_USER_DATA option.\n");
		return -EOPNOTSUPP;
	} else
		return 0;
}
