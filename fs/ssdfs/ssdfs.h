//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ssdfs.h - in-core declarations.
 *
 * Copyright (c) 2019-2020 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include "ssdfs_fs_info.h"
#include "ssdfs_inline.h"

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

struct ssdfs_peb_info;
struct ssdfs_peb_container;
struct ssdfs_segment_info;

/* btree_node.c */
int ssdfs_init_btree_node_obj_cache(void);
void ssdfs_destroy_btree_node_obj_cache(void);
int ssdfs_init_btree_search_obj_cache(void);
void ssdfs_destroy_btree_search_obj_cache(void);

/* compression.c */
int ssdfs_compressors_init(void);
void ssdfs_compressors_exit(void);

/* dir.c */
int ssdfs_inode_by_name(struct inode *dir,
			const struct qstr *child,
			ino_t *ino);

/* file.c */
int ssdfs_fsync(struct file *file, loff_t start, loff_t end, int datasync);

/* fs_error.c */
extern __printf(5, 6)
void ssdfs_fs_error(struct super_block *sb, const char *file,
		    const char *function, unsigned int line,
		    const char *fmt, ...);
int ssdfs_clear_dirty_page(struct page *page);
void ssdfs_clear_dirty_pages(struct address_space *mapping);

/* inode.c */
bool is_raw_inode_checksum_correct(struct ssdfs_fs_info *fsi,
				   void *buf, size_t size);
struct inode *ssdfs_iget(struct super_block *sb, ino_t ino);
struct inode *ssdfs_new_inode(struct inode *dir, umode_t mode,
			      const struct qstr *qstr);
int ssdfs_getattr(const struct path *path, struct kstat *stat,
		  u32 request_mask, unsigned int query_flags);
int ssdfs_setattr(struct dentry *dentry, struct iattr *attr);
void ssdfs_evict_inode(struct inode *inode);
int ssdfs_write_inode(struct inode *inode, struct writeback_control *wbc);
int ssdfs_statfs(struct dentry *dentry, struct kstatfs *buf);
void ssdfs_set_inode_flags(struct inode *inode);

/* inodes_tree.c */
int ssdfs_init_free_ino_desc_cache(void);
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
				    u64 peb_id, u32 bytes_off,
				    void *buf, bool silent,
				    u32 *log_pages);
int ssdfs_check_log_footer(struct ssdfs_fs_info *fsi,
			   void *buf,
			   struct ssdfs_log_footer *footer,
			   bool silent);
int ssdfs_read_checked_log_footer(struct ssdfs_fs_info *fsi, void *log_hdr,
				  u64 peb_id, u32 bytes_off, void *buf,
				  bool silent);
int ssdfs_prepare_current_segment_ids(struct ssdfs_fs_info *fsi,
					__le64 *array,
					size_t size);
int ssdfs_prepare_volume_state_info_for_commit(struct ssdfs_fs_info *fsi,
						u16 fs_state,
						__le64 *cur_segs,
						size_t size,
						struct ssdfs_volume_state *vs);
int ssdfs_prepare_log_footer_for_commit(struct ssdfs_fs_info *fsi,
					u32 log_pages,
					u32 log_flags,
					struct ssdfs_log_footer *footer);


/* offset_translation_table.c */
int ssdfs_init_blk2off_frag_obj_cache(void);
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

/* readwrite.c */
int ssdfs_read_page_from_volume(struct ssdfs_fs_info *fsi,
				u64 peb_id, u32 bytes_off,
				struct page *page);
int ssdfs_aligned_read_buffer(struct ssdfs_fs_info *fsi,
			      u64 peb_id, u32 bytes_off,
			      void *buf, size_t size,
			      size_t *read_bytes);
int ssdfs_unaligned_read_buffer(struct ssdfs_fs_info *fsi,
				u64 peb_id, u32 bytes_off,
				void *buf, size_t size);
int ssdfs_can_write_sb_log(struct super_block *sb,
			   struct ssdfs_peb_extent *sb_log);

/* recovery.c */
int ssdfs_init_sb_info(struct ssdfs_sb_info *sbi);
void ssdfs_destruct_sb_info(struct ssdfs_sb_info *sbi);
void ssdfs_backup_sb_info(struct ssdfs_fs_info *fsi);
void ssdfs_restore_sb_info(struct ssdfs_fs_info *fsi);
int ssdfs_gather_superblock_info(struct ssdfs_fs_info *fsi, int silent);

/* segment.c */
int ssdfs_init_seg_obj_cache(void);
void ssdfs_destroy_seg_obj_cache(void);
int ssdfs_segment_get_used_data_pages(struct ssdfs_segment_info *si);

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
bool is_ssdfs_volume_header_consistent(struct ssdfs_volume_header *vh,
					u64 dev_size);
int ssdfs_check_segment_header(struct ssdfs_fs_info *fsi,
				struct ssdfs_segment_header *hdr,
				bool silent);
int ssdfs_read_checked_segment_header(struct ssdfs_fs_info *fsi,
					u64 peb_id, u32 pages_off,
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
					    struct ssdfs_segment_header *hdr);
int ssdfs_prepare_partial_log_header_for_commit(struct ssdfs_fs_info *fsi,
					u8 sequence_id,
					u32 log_pages,
					u16 seg_type,
					u32 flags,
					struct ssdfs_partial_log_header *hdr);

#endif /* _SSDFS_H */
