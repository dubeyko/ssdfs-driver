/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/testing.h - testing infrastructure's declarations.
 *
 * Copyright (c) 2019-2026 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_TESTING_H
#define _SSDFS_TESTING_H

#include "common_bitmap.h"
#include "request_queue.h"

/*
 * struct ssdfs_dentries_tree_testing - dentries tree testing environment
 * @files_number_threshold: maximum number of files
 */
struct ssdfs_dentries_tree_testing {
	u64 files_number_threshold;
};

/*
 * struct ssdfs_extents_tree_testing - extents tree testing environment
 * @file_size_threshold: maximum size of file in bytes
 * @extent_len_threshold: maximum extent length in logical blocks
 */
struct ssdfs_extents_tree_testing {
	u64 file_size_threshold;
	u16 extent_len_threshold;
};

/*
 * struct ssdfs_block_bitmap_testing - block bitmap testing environment
 * @capacity: items capacity in block bitmap
 * @pre_alloc_blks_per_iteration: pre-allocate blocks per iteration
 * @alloc_blks_per_iteration: allocate blocks per iteration
 * @invalidate_blks_per_iteration: invalidate blocks per iteration
 * @reserved_metadata_blks_per_iteration: reserve metadata blocks per iteration
 */
struct ssdfs_block_bitmap_testing {
	u32 capacity;
	u32 pre_alloc_blks_per_iteration;
	u32 alloc_blks_per_iteration;
	u32 invalidate_blks_per_iteration;
	u32 reserved_metadata_blks_per_iteration;
};

/*
 * struct ssdfs_blk2off_testing - blk2off table testing environment
 * @capacity: items capacity in the blk2off table
 */
struct ssdfs_blk2off_testing {
	u32 capacity;
};

/*
 * struct ssdfs_peb_mapping_table_testing - PEB mapping table testing environment
 * @iterations_number: total iterations number
 * @peb_mappings_per_iteration: number of mapping operations per iteration
 * @add_migrations_per_iteration: number of migrating PEBs per iteration
 * @exclude_migrations_per_iteration: number of finishing PEB migrations
 */
struct ssdfs_peb_mapping_table_testing {
	u32 iterations_number;
	u32 peb_mappings_per_iteration;
	u32 add_migrations_per_iteration;
	u32 exclude_migrations_per_iteration;
};

/*
 * struct ssdfs_memory_primitives_testing - memory primitives testing environment
 * @iterations_number: total iterations number
 * @capacity: total capacity of items
 * @count: total count of items
 * @item_size: item size in bytes
 * @test_types: type of tests
 */
struct ssdfs_memory_primitives_testing {
	u32 iterations_number;
	u64 capacity;
	u64 count;
	u32 item_size;
	u32 test_types;
};

/* Types of memory primitives tests */
#define SSDFS_ENABLE_FOLIO_VECTOR_TESTING	(1 << 0)
#define SSDFS_ENABLE_FOLIO_ARRAY_TESTING	(1 << 1)
#define SSDFS_ENABLE_DYNAMIC_ARRAY_TESTING	(1 << 2)

/*
 * struct ssdfs_segment_bitmap_testing - segment bitmap testing environment
 * @iterations_number: total iterations number
 * @using_segs_per_iteration: number of using segments per iteration
 * @used_segs_per_iteration: number of used segments per iteration
 * @pre_dirty_segs_per_iteration: number of pre-dirty segments per iteration
 * @dirty_segs_per_iteration: number of dirty segments per iteration
 * @cleaned_segs_per_iteration: number of cleaned segments per iteration
 */
struct ssdfs_segment_bitmap_testing {
	u32 iterations_number;
	u32 using_segs_per_iteration;
	u32 used_segs_per_iteration;
	u32 pre_dirty_segs_per_iteration;
	u32 dirty_segs_per_iteration;
	u32 cleaned_segs_per_iteration;
};

/*
 * struct ssdfs_shared_dictionary_testing - shared dictionary testing environment
 * @names_number: count of generated names
 * @name_len: length of the name
 * @step_factor: growing factor of symbol calulation
 */
struct ssdfs_shared_dictionary_testing {
	u32 names_number;
	u32 name_len;
	u32 step_factor;
};

/*
 * struct ssdfs_xattr_tree_testing - xattr tree testing environment
 * @xattrs_number: number of extended attributes
 * @name_len: length of the name
 * @step_factor: growing factor of symbol calulation
 * @blob_len: length of blob
 * @blob_pattern: pattern to generate the blob
 */
struct ssdfs_xattr_tree_testing {
	u32 xattrs_number;
	u32 name_len;
	u32 step_factor;
	u32 blob_len;
	u64 blob_pattern;
};

/*
 * struct ssdfs_shextree_testing - shared extents tree testing environment
 * @extents_number_threshold: maximum number of shared extents
 * @extent_len: extent length
 * @ref_count_threshold: upper bound for reference counter of shared extent
 */
struct ssdfs_shextree_testing {
	u64 extents_number_threshold;
	u32 extent_len;
	u32 ref_count_threshold;
};

/*
 * struct ssdfs_snapshots_tree_testing - snapshots tree testing environment
 * @snapshots_number_threshold: maximum number of snapshots
 */
struct ssdfs_snapshots_tree_testing {
	u64 snapshots_number_threshold;
};

/*
 * struct ssdfs_testing_environment - define testing environment
 * @subsystems: enable testing particular subsystems
 * @page_size: logical block size in bytes
 *
 * @dentries_tree: dentries tree testing environment
 * @extents_tree: extents tree testing environment
 * @block_bitmap: block bitmap testing environment
 * @blk2off_table: blk2off table testing environment
 * @mapping_table: mapping table testing environment
 * @memory_primitives: memory primitives testing environment
 * @segment_bitmap: segment bitmap testing environment
 * @shared_dictionary: shared dictionary testing environment
 * @xattr_tree: xattr tree testing environment
 * @shextree: shared extents tree testing environment
 * @snapshots_tree: snaphots tree testing environment
 */
struct ssdfs_testing_environment {
	u64 subsystems;
	u32 page_size;

	struct ssdfs_dentries_tree_testing dentries_tree;
	struct ssdfs_extents_tree_testing extents_tree;
	struct ssdfs_block_bitmap_testing block_bitmap;
	struct ssdfs_blk2off_testing blk2off_table;
	struct ssdfs_peb_mapping_table_testing mapping_table;
	struct ssdfs_memory_primitives_testing memory_primitives;
	struct ssdfs_segment_bitmap_testing segment_bitmap;
	struct ssdfs_shared_dictionary_testing shared_dictionary;
	struct ssdfs_xattr_tree_testing xattr_tree;
	struct ssdfs_shextree_testing shextree;
	struct ssdfs_snapshots_tree_testing snapshots_tree;
};

/* Subsystem tests */
#define SSDFS_ENABLE_EXTENTS_TREE_TESTING	(1 << 0)
#define SSDFS_ENABLE_DENTRIES_TREE_TESTING	(1 << 1)
#define SSDFS_ENABLE_BLOCK_BMAP_TESTING		(1 << 2)
#define SSDFS_ENABLE_BLK2OFF_TABLE_TESTING	(1 << 3)
#define SSDFS_ENABLE_PEB_MAPPING_TABLE_TESTING	(1 << 4)
#define SSDFS_ENABLE_MEMORY_PRIMITIVES_TESTING	(1 << 5)
#define SSDFS_ENABLE_SEGMENT_BITMAP_TESTING	(1 << 6)
#define SSDFS_ENABLE_SHARED_DICTIONARY_TESTING	(1 << 7)
#define SSDFS_ENABLE_XATTR_TREE_TESTING		(1 << 8)
#define SSDFS_ENABLE_SHEXTREE_TESTING		(1 << 9)
#define SSDFS_ENABLE_SNAPSHOTS_TREE_TESTING	(1 << 10)

#ifdef CONFIG_SSDFS_TESTING
int ssdfs_do_testing(struct ssdfs_fs_info *fsi,
		     struct ssdfs_testing_environment *env);
#else
static inline
int ssdfs_do_testing(struct ssdfs_fs_info *fsi,
		     struct ssdfs_testing_environment *env)
{
	SSDFS_ERR("Testing is not supported. "
		  "Please, enable CONFIG_SSDFS_TESTING option.\n");

	return -EOPNOTSUPP;
}
#endif /* CONFIG_SSDFS_TESTING */

#endif /* _SSDFS_TESTING_H */
