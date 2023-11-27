// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ssdfs.h - in-core declarations.
 *
 * Copyright (c) 2019-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_H
#define _SSDFS_H

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kobject.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/crc32.h>
#include <linux/pagemap.h>
#include <linux/ssdfs_fs.h>

#include "ssdfs_constants.h"
#include "ssdfs_thread_info.h"
#include "ssdfs_inode_info.h"
#include "snapshot.h"
#include "snapshot_requests_queue.h"
#include "snapshot_rules.h"
#include "ssdfs_fs_info.h"
#include "ssdfs_inline.h"
#include "fingerprint_array.h"

/*
 * struct ssdfs_value_pair - value/position pair
 * @value: some value
 * @pos: position of value
 */
struct ssdfs_value_pair {
	int value;
	int pos;
};

/*
 * struct ssdfs_min_max_pair - minimum and maximum values pair
 * @min: minimum value/position pair
 * @max: maximum value/position pair
 */
struct ssdfs_min_max_pair {
	struct ssdfs_value_pair min;
	struct ssdfs_value_pair max;
};

/*
 * struct ssdfs_block_bmap_range - block bitmap items range
 * @start: begin item
 * @len: count of items in the range
 */
struct ssdfs_block_bmap_range {
	u32 start;
	u32 len;
};

/*
 * struct ssdfs_blk2off_range - extent of logical blocks
 * @start_lblk: start logical block number
 * @len: count of logical blocks in extent
 */
struct ssdfs_blk2off_range {
	u16 start_lblk;
	u16 len;
};

struct ssdfs_peb_info;
struct ssdfs_peb_container;
struct ssdfs_segment_info;
struct ssdfs_peb_blk_bmap;

/* btree_node.c */
void ssdfs_zero_btree_node_obj_cache_ptr(void);
int ssdfs_init_btree_node_obj_cache(void);
void ssdfs_shrink_btree_node_obj_cache(void);
void ssdfs_destroy_btree_node_obj_cache(void);

/* btree_search.c */
void ssdfs_zero_btree_search_obj_cache_ptr(void);
int ssdfs_init_btree_search_obj_cache(void);
void ssdfs_shrink_btree_search_obj_cache(void);
void ssdfs_destroy_btree_search_obj_cache(void);

/* compression.c */
int ssdfs_compressors_init(void);
void ssdfs_free_workspaces(void);
void ssdfs_compressors_exit(void);

/* dev_bdev.c */
struct bio *ssdfs_bdev_bio_alloc(struct block_device *bdev,
				 unsigned int nr_iovecs,
				 unsigned int op,
				 gfp_t gfp_mask);
void ssdfs_bdev_bio_put(struct bio *bio);
int ssdfs_bdev_bio_add_folio(struct bio *bio, struct folio *folio,
			    unsigned int offset);
int ssdfs_bdev_read_block(struct super_block *sb, struct folio *folio,
			  loff_t offset);
int ssdfs_bdev_read_blocks(struct super_block *sb, struct folio_batch *batch,
			   loff_t offset);
int ssdfs_bdev_read(struct super_block *sb, u32 block_size, loff_t offset,
		    size_t len, void *buf);
int ssdfs_bdev_can_write_block(struct super_block *sb, u32 block_size,
				loff_t offset, bool need_check);
int ssdfs_bdev_write_block(struct super_block *sb, loff_t offset,
			   struct folio *folio);
int ssdfs_bdev_write_blocks(struct super_block *sb, loff_t offset,
			    struct folio_batch *batch);

/* dev_zns.c */
u64 ssdfs_zns_zone_size(struct super_block *sb, loff_t offset);
u64 ssdfs_zns_zone_capacity(struct super_block *sb, loff_t offset);
u64 ssdfs_zns_zone_write_pointer(struct super_block *sb, loff_t offset);

/* dir.c */
int ssdfs_inode_by_name(struct inode *dir,
			const struct qstr *child,
			ino_t *ino);
int ssdfs_create(struct mnt_idmap *idmap,
		 struct inode *dir, struct dentry *dentry,
		 umode_t mode, bool excl);

/* file.c */
int ssdfs_allocate_inline_file_buffer(struct inode *inode);
void ssdfs_destroy_inline_file_buffer(struct inode *inode);
int ssdfs_fsync(struct file *file, loff_t start, loff_t end, int datasync);

/* fs_error.c */
extern __printf(5, 6)
void ssdfs_fs_error(struct super_block *sb, const char *file,
		    const char *function, unsigned int line,
		    const char *fmt, ...);
int ssdfs_set_folio_dirty(struct folio *folio);
int __ssdfs_clear_dirty_folio(struct folio *folio);
int ssdfs_clear_dirty_folio(struct folio *folio);
void ssdfs_clear_dirty_folios(struct address_space *mapping);

/* inode.c */
bool is_raw_inode_checksum_correct(struct ssdfs_fs_info *fsi,
				   void *buf, size_t size);
struct inode *ssdfs_iget(struct super_block *sb, ino_t ino);
struct inode *ssdfs_new_inode(struct mnt_idmap *idmap,
			      struct inode *dir, umode_t mode,
			      const struct qstr *qstr);
int ssdfs_getattr(struct mnt_idmap *idmap,
		  const struct path *path, struct kstat *stat,
		  u32 request_mask, unsigned int query_flags);
int ssdfs_setattr(struct mnt_idmap *idmap,
		  struct dentry *dentry, struct iattr *attr);
void ssdfs_evict_inode(struct inode *inode);
int ssdfs_write_inode(struct inode *inode, struct writeback_control *wbc);
int ssdfs_statfs(struct dentry *dentry, struct kstatfs *buf);
void ssdfs_set_inode_flags(struct inode *inode);

/* inodes_tree.c */
void ssdfs_zero_free_ino_desc_cache_ptr(void);
int ssdfs_init_free_ino_desc_cache(void);
void ssdfs_shrink_free_ino_desc_cache(void);
void ssdfs_destroy_free_ino_desc_cache(void);

/* ioctl.c */
long ssdfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/* log_footer.c */
bool __is_ssdfs_log_footer_magic_valid(struct ssdfs_signature *magic);
bool is_ssdfs_log_footer_magic_valid(struct ssdfs_log_footer *footer);
bool is_ssdfs_log_footer_csum_valid(void *buf, size_t buf_size);
bool is_ssdfs_volume_state_info_consistent(struct ssdfs_fs_info *fsi,
					   void *buf,
					   struct ssdfs_log_footer *footer,
					   u64 dev_size);
int ssdfs_read_unchecked_log_footer(struct ssdfs_fs_info *fsi,
				    u64 peb_id, u32 block_size, u32 bytes_off,
				    void *buf, bool silent,
				    u32 *log_pages);
int ssdfs_check_log_footer(struct ssdfs_fs_info *fsi,
			   void *buf,
			   struct ssdfs_log_footer *footer,
			   bool silent);
int ssdfs_read_checked_log_footer(struct ssdfs_fs_info *fsi, void *log_hdr,
				  u64 peb_id, u32 block_size, u32 bytes_off,
				  void *buf, bool silent);
int ssdfs_prepare_current_segment_ids(struct ssdfs_fs_info *fsi,
					__le64 *array,
					size_t size);
int ssdfs_prepare_volume_state_info_for_commit(struct ssdfs_fs_info *fsi,
						u16 fs_state,
						__le64 *cur_segs,
						size_t size,
						u64 last_log_time,
						u64 last_log_cno,
						struct ssdfs_volume_state *vs);
int ssdfs_prepare_log_footer_for_commit(struct ssdfs_fs_info *fsi,
					u32 block_size,
					u32 log_pages,
					u32 log_flags,
					u64 last_log_time,
					u64 last_log_cno,
					struct ssdfs_log_footer *footer);

/* offset_translation_table.c */
void ssdfs_zero_blk2off_frag_obj_cache_ptr(void);
int ssdfs_init_blk2off_frag_obj_cache(void);
void ssdfs_shrink_blk2off_frag_obj_cache(void);
void ssdfs_destroy_blk2off_frag_obj_cache(void);

/* options.c */
int ssdfs_parse_options(struct ssdfs_fs_info *fs_info, char *data);
void ssdfs_initialize_fs_errors_option(struct ssdfs_fs_info *fsi);
int ssdfs_show_options(struct seq_file *seq, struct dentry *root);

/* peb_migration_scheme.c */
int ssdfs_peb_start_migration(struct ssdfs_peb_container *pebc);
bool is_peb_under_migration(struct ssdfs_peb_container *pebc);
bool is_pebs_relation_alive(struct ssdfs_peb_container *pebc);
bool has_peb_migration_done(struct ssdfs_peb_container *pebc);
bool should_migration_be_finished(struct ssdfs_peb_container *pebc);
int ssdfs_peb_finish_migration(struct ssdfs_peb_container *pebc);
bool has_ssdfs_source_peb_valid_blocks(struct ssdfs_peb_container *pebc);
int ssdfs_peb_prepare_range_migration(struct ssdfs_peb_container *pebc,
				      u32 range_len, int blk_type);
int ssdfs_peb_migrate_valid_blocks_range(struct ssdfs_segment_info *si,
					 struct ssdfs_peb_container *pebc,
					 struct ssdfs_peb_blk_bmap *peb_blkbmap,
					 struct ssdfs_block_bmap_range *range);

/* readwrite.c */
int ssdfs_read_folio_from_volume(struct ssdfs_fs_info *fsi,
				 u64 peb_id, u32 bytes_offset,
				 struct folio *folio);
int ssdfs_read_folio_batch_from_volume(struct ssdfs_fs_info *fsi,
					u64 peb_id, u32 bytes_offset,
					struct folio_batch *batch);
int ssdfs_aligned_read_buffer(struct ssdfs_fs_info *fsi,
			      u64 peb_id, u32 block_size, u32 bytes_off,
			      void *buf, size_t size,
			      size_t *read_bytes);
int ssdfs_unaligned_read_buffer(struct ssdfs_fs_info *fsi,
				u64 peb_id, u32 block_size, u32 bytes_off,
				void *buf, size_t size);
int ssdfs_can_write_sb_log(struct super_block *sb,
			   struct ssdfs_peb_extent *sb_log);
int ssdfs_unaligned_read_folio_batch(struct folio_batch *batch,
				     u32 offset, u32 size,
				     void *buf);
int ssdfs_unaligned_write_folio_batch(struct ssdfs_fs_info *fsi,
				      struct folio_batch *batch,
				      u32 offset, u32 size,
				      void *buf);
int ssdfs_unaligned_read_folio_vector(struct ssdfs_fs_info *fsi,
				      struct ssdfs_folio_vector *vec,
				      u32 offset, u32 size,
				      void *buf);
int ssdfs_unaligned_write_folio_vector(struct ssdfs_fs_info *fsi,
					struct ssdfs_folio_vector *batch,
					u32 offset, u32 size,
					void *buf);

/* recovery.c */
int ssdfs_init_sb_info(struct ssdfs_fs_info *fsi,
			struct ssdfs_sb_info *sbi);
void ssdfs_destruct_sb_info(struct ssdfs_sb_info *sbi);
void ssdfs_backup_sb_info(struct ssdfs_fs_info *fsi);
void ssdfs_restore_sb_info(struct ssdfs_fs_info *fsi);
int ssdfs_gather_superblock_info(struct ssdfs_fs_info *fsi, int silent);

/* segment.c */
void ssdfs_zero_seg_obj_cache_ptr(void);
int ssdfs_init_seg_obj_cache(void);
void ssdfs_shrink_seg_obj_cache(void);
void ssdfs_destroy_seg_obj_cache(void);
int ssdfs_segment_get_used_data_pages(struct ssdfs_segment_info *si);

/* super.c */
void ssdfs_destroy_btree_of_inode(struct inode *inode);
void ssdfs_destroy_and_decrement_btree_of_inode(struct inode *inode);

/* sysfs.c */
int ssdfs_sysfs_init(void);
void ssdfs_sysfs_exit(void);
int ssdfs_sysfs_create_device_group(struct super_block *sb);
void ssdfs_sysfs_delete_device_group(struct ssdfs_fs_info *fsi);
int ssdfs_sysfs_create_seg_group(struct ssdfs_segment_info *si);
void ssdfs_sysfs_delete_seg_group(struct ssdfs_segment_info *si);
int ssdfs_sysfs_create_peb_group(struct ssdfs_peb_container *pebc);
void ssdfs_sysfs_delete_peb_group(struct ssdfs_peb_container *pebc);

/* volume_header.c */
bool __is_ssdfs_segment_header_magic_valid(struct ssdfs_signature *magic);
bool is_ssdfs_segment_header_magic_valid(struct ssdfs_segment_header *hdr);
bool is_ssdfs_partial_log_header_magic_valid(struct ssdfs_signature *magic);
bool is_ssdfs_volume_header_csum_valid(void *vh_buf, size_t buf_size);
bool is_ssdfs_partial_log_header_csum_valid(void *plh_buf, size_t buf_size);
bool is_ssdfs_volume_header_consistent(struct ssdfs_fs_info *fsi,
					struct ssdfs_volume_header *vh,
					u64 dev_size);
int ssdfs_check_segment_header(struct ssdfs_fs_info *fsi,
				struct ssdfs_segment_header *hdr,
				bool silent);
int ssdfs_read_checked_segment_header(struct ssdfs_fs_info *fsi,
					u64 peb_id, u32 block_size,
					u32 pages_off,
					void *buf, bool silent);
int ssdfs_check_partial_log_header(struct ssdfs_fs_info *fsi,
				   struct ssdfs_partial_log_header *hdr,
				   bool silent);
void ssdfs_create_volume_header(struct ssdfs_fs_info *fsi,
				struct ssdfs_volume_header *vh);
int ssdfs_prepare_volume_header_for_commit(struct ssdfs_fs_info *fsi,
					   struct ssdfs_volume_header *vh);
int ssdfs_prepare_segment_header_for_commit(struct ssdfs_fs_info *fsi,
					    u32 log_pages,
					    u16 seg_type,
					    u32 seg_flags,
					    u64 last_log_time,
					    u64 last_log_cno,
					    struct ssdfs_segment_header *hdr);
int ssdfs_prepare_partial_log_header_for_commit(struct ssdfs_fs_info *fsi,
					int sequence_id,
					u32 log_pages,
					u16 seg_type,
					u32 flags,
					u64 last_log_time,
					u64 last_log_cno,
					struct ssdfs_partial_log_header *hdr);

/* memory leaks checker */
void ssdfs_acl_memory_leaks_init(void);
void ssdfs_acl_check_memory_leaks(void);
void ssdfs_block_bmap_memory_leaks_init(void);
void ssdfs_block_bmap_check_memory_leaks(void);
void ssdfs_blk2off_memory_leaks_init(void);
void ssdfs_blk2off_check_memory_leaks(void);
void ssdfs_btree_memory_leaks_init(void);
void ssdfs_btree_check_memory_leaks(void);
void ssdfs_btree_hierarchy_memory_leaks_init(void);
void ssdfs_btree_hierarchy_check_memory_leaks(void);
void ssdfs_btree_node_memory_leaks_init(void);
void ssdfs_btree_node_check_memory_leaks(void);
void ssdfs_btree_search_memory_leaks_init(void);
void ssdfs_btree_search_check_memory_leaks(void);
void ssdfs_lzo_memory_leaks_init(void);
void ssdfs_lzo_check_memory_leaks(void);
void ssdfs_zlib_memory_leaks_init(void);
void ssdfs_zlib_check_memory_leaks(void);
void ssdfs_compr_memory_leaks_init(void);
void ssdfs_compr_check_memory_leaks(void);
void ssdfs_cur_seg_memory_leaks_init(void);
void ssdfs_cur_seg_check_memory_leaks(void);
void ssdfs_dentries_memory_leaks_init(void);
void ssdfs_dentries_check_memory_leaks(void);
void ssdfs_dev_bdev_memory_leaks_init(void);
void ssdfs_dev_bdev_check_memory_leaks(void);
void ssdfs_dev_zns_memory_leaks_init(void);
void ssdfs_dev_zns_check_memory_leaks(void);
void ssdfs_dev_mtd_memory_leaks_init(void);
void ssdfs_dev_mtd_check_memory_leaks(void);
void ssdfs_dir_memory_leaks_init(void);
void ssdfs_dir_check_memory_leaks(void);
void ssdfs_diff_memory_leaks_init(void);
void ssdfs_diff_check_memory_leaks(void);
void ssdfs_ext_queue_memory_leaks_init(void);
void ssdfs_ext_queue_check_memory_leaks(void);
void ssdfs_ext_tree_memory_leaks_init(void);
void ssdfs_ext_tree_check_memory_leaks(void);
void ssdfs_farray_memory_leaks_init(void);
void ssdfs_farray_check_memory_leaks(void);
void ssdfs_folio_vector_memory_leaks_init(void);
void ssdfs_folio_vector_check_memory_leaks(void);
#ifdef CONFIG_SSDFS_PEB_DEDUPLICATION
void ssdfs_fingerprint_array_memory_leaks_init(void);
void ssdfs_fingerprint_array_check_memory_leaks(void);
#endif /* CONFIG_SSDFS_PEB_DEDUPLICATION */
void ssdfs_file_memory_leaks_init(void);
void ssdfs_file_check_memory_leaks(void);
void ssdfs_fs_error_memory_leaks_init(void);
void ssdfs_fs_error_check_memory_leaks(void);
void ssdfs_flush_memory_leaks_init(void);
void ssdfs_flush_check_memory_leaks(void);
void ssdfs_gc_memory_leaks_init(void);
void ssdfs_gc_check_memory_leaks(void);
#ifdef CONFIG_SSDFS_ONLINE_FSCK
void ssdfs_fsck_memory_leaks_init(void);
void ssdfs_fsck_check_memory_leaks(void);
#endif /* CONFIG_SSDFS_ONLINE_FSCK */
void ssdfs_inode_memory_leaks_init(void);
void ssdfs_inode_check_memory_leaks(void);
void ssdfs_ino_tree_memory_leaks_init(void);
void ssdfs_ino_tree_check_memory_leaks(void);
void ssdfs_invext_tree_memory_leaks_init(void);
void ssdfs_invext_tree_check_memory_leaks(void);
void ssdfs_parray_memory_leaks_init(void);
void ssdfs_parray_check_memory_leaks(void);
void ssdfs_page_vector_memory_leaks_init(void);
void ssdfs_page_vector_check_memory_leaks(void);
void ssdfs_map_queue_memory_leaks_init(void);
void ssdfs_map_queue_check_memory_leaks(void);
void ssdfs_map_tbl_memory_leaks_init(void);
void ssdfs_map_tbl_check_memory_leaks(void);
void ssdfs_map_cache_memory_leaks_init(void);
void ssdfs_map_cache_check_memory_leaks(void);
void ssdfs_map_thread_memory_leaks_init(void);
void ssdfs_map_thread_check_memory_leaks(void);
void ssdfs_migration_memory_leaks_init(void);
void ssdfs_migration_check_memory_leaks(void);
void ssdfs_peb_memory_leaks_init(void);
void ssdfs_peb_check_memory_leaks(void);
void ssdfs_read_memory_leaks_init(void);
void ssdfs_read_check_memory_leaks(void);
void ssdfs_recovery_memory_leaks_init(void);
void ssdfs_recovery_check_memory_leaks(void);
void ssdfs_req_queue_memory_leaks_init(void);
void ssdfs_req_queue_check_memory_leaks(void);
void ssdfs_seg_obj_memory_leaks_init(void);
void ssdfs_seg_obj_check_memory_leaks(void);
void ssdfs_seg_bmap_memory_leaks_init(void);
void ssdfs_seg_bmap_check_memory_leaks(void);
void ssdfs_seg_blk_memory_leaks_init(void);
void ssdfs_seg_blk_check_memory_leaks(void);
void ssdfs_seg_tree_memory_leaks_init(void);
void ssdfs_seg_tree_check_memory_leaks(void);
void ssdfs_seq_arr_memory_leaks_init(void);
void ssdfs_seq_arr_check_memory_leaks(void);
void ssdfs_dict_memory_leaks_init(void);
void ssdfs_dict_check_memory_leaks(void);
void ssdfs_shextree_memory_leaks_init(void);
void ssdfs_shextree_check_memory_leaks(void);
void ssdfs_snap_reqs_queue_memory_leaks_init(void);
void ssdfs_snap_reqs_queue_check_memory_leaks(void);
void ssdfs_snap_rules_list_memory_leaks_init(void);
void ssdfs_snap_rules_list_check_memory_leaks(void);
void ssdfs_snap_tree_memory_leaks_init(void);
void ssdfs_snap_tree_check_memory_leaks(void);
void ssdfs_xattr_memory_leaks_init(void);
void ssdfs_xattr_check_memory_leaks(void);

#endif /* _SSDFS_H */
