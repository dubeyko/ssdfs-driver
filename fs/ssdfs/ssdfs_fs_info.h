//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ssdfs_fs_info.h - in-core fs information.
 *
 * Copyright (c) 2019-2020 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_FS_INFO_H
#define _SSDFS_FS_INFO_H

/*
 * struct ssdfs_volume_block - logical block
 * @seg_id: segment ID
 * @blk_index: block index in segment
 */
struct ssdfs_volume_block {
	u64 seg_id;
	u16 blk_index;
};

/*
 * struct ssdfs_volume_extent - logical extent
 * @start: initial logical block
 * @len: extent length
 */
struct ssdfs_volume_extent {
	struct ssdfs_volume_block start;
	u16 len;
};

/*
 * struct ssdfs_peb_extent - PEB's extent
 * @leb_id: LEB ID
 * @peb_id: PEB ID
 * @page_offset: offset in pages
 * @pages_count: pages count
 */
struct ssdfs_peb_extent {
	u64 leb_id;
	u64 peb_id;
	u32 page_offset;
	u32 pages_count;
};

/*
 * struct ssdfs_sb_info - superblock info
 * @vh_buf: volume header buffer
 * @vs_buf: volume state buffer
 * @last_log: latest sb log
 */
struct ssdfs_sb_info {
	void *vh_buf;
	void *vs_buf;
	struct ssdfs_peb_extent last_log;
};

/*
 * struct ssdfs_device_ops - device operations
 * @device_name: get device name
 * @device_size: get device size in bytes
 * @read: read from device
 * @readpage: read page
 * @readpages: read sequence of pages
 * @can_write_page: can we write into page?
 * @writepage: write page to device
 * @writepages: write sequence of pages to device
 * @erase: erase block
 * @trim: support of background erase operation
 * @peb_isbad: check that physical erase block is bad
 * @sync: synchronize page cache with device
 */
struct ssdfs_device_ops {
	const char * (*device_name)(struct super_block *sb);
	__u64 (*device_size)(struct super_block *sb);
	int (*read)(struct super_block *sb, loff_t offset, size_t len,
		    void *buf);
	int (*readpage)(struct super_block *sb, struct page *page,
			loff_t offset);
	int (*readpages)(struct super_block *sb, struct pagevec *pvec,
			 loff_t offset);
	int (*can_write_page)(struct super_block *sb, loff_t offset,
				bool need_check);
	int (*writepage)(struct super_block *sb, loff_t to_off,
			 struct page *page, u32 from_off, size_t len);
	int (*writepages)(struct super_block *sb, loff_t to_off,
			  struct pagevec *pvec, u32 from_off, size_t len);
	int (*erase)(struct super_block *sb, loff_t offset, size_t len);
	int (*trim)(struct super_block *sb, loff_t offset, size_t len);
	int (*peb_isbad)(struct super_block *sb, loff_t offset);
	int (*mark_peb_bad)(struct super_block *sb, loff_t offset);
	void (*sync)(struct super_block *sb);
};

/*
 * struct ssdfs_fs_info - in-core fs information
 * @log_pagesize: log2(page size)
 * @pagesize: page size in bytes
 * @log_erasesize: log2(erase block size)
 * @erasesize: physical erase block size in bytes
 * @log_segsize: log2(segment size)
 * @segsize: segment size in bytes
 * @log_pebs_per_seg: log2(erase blocks per segment)
 * @pebs_per_seg: physical erase blocks per segment
 * @pages_per_peb: pages per physical erase block
 * @pages_per_seg: pages per segment
 * @fs_ctime: volume create timestamp (mkfs phase)
 * @fs_cno: volume create checkpoint
 * @mount_opts: mount options
 * @volume_sem: volume semaphore
 * @last_vh: buffer for last valid volume header
 * @vh: volume header
 * @vs: volume state
 * @sbi: superblock info
 * @sbi_backup: backup copy of superblock info
 * @sb_seg_log_pages: full log size in sb segment (pages count)
 * @segbmap_log_pages: full log size in segbmap segment (pages count)
 * @maptbl_log_pages: full log size in maptbl segment (pages count)
 * @lnodes_seg_log_pages: full log size in leaf nodes segment (pages count)
 * @hnodes_seg_log_pages: full log size in hybrid nodes segment (pages count)
 * @inodes_seg_log_pages: full log size in index nodes segment (pages count)
 * @user_data_log_pages: full log size in user data segment (pages count)
 * @volume_state_lock: lock for mutable volume metadata
 * @free_pages: free pages count on the volume
 * @fs_mount_time: file system mount timestamp
 * @fs_mod_time: last write timestamp
 * @fs_mount_cno: mount checkpoint
 * @boot_vs_mount_timediff: difference between boottime and mounttime
 * @fs_flags: file system flags
 * @fs_state: file system state
 * @fs_errors: behaviour when detecting errors
 * @fs_feature_compat: compatible feature set
 * @fs_feature_compat_ro: read-only compatible feature set
 * @fs_feature_incompat: incompatible feature set
 * @fs_uuid: 128-bit volume's uuid
 * @fs_label: volume name
 * @migration_threshold: default value of destination PEBs in migration
 * @resize_mutex: resize mutex
 * @nsegs: number of segments on the volume
 * @sb_segs_sem: semaphore for superblock's array of LEB/PEB numbers
 * @sb_lebs: array of LEB ID numbers
 * @sb_pebs: array of PEB ID numbers
 * @segbmap: segment bitmap object
 * @segbmap_inode: segment bitmap inode
 * @maptbl: PEB mapping table object
 * @maptbl_cache: maptbl cache
 * @segs_tree: tree of segment objects
 * @segs_tree_inode: segment tree inode
 * @cur_segs: array of current segments
 * @shextree: shared extents tree
 * @shdictree: shared dictionary
 * @inodes_tree: inodes btree
 * @sb: pointer on VFS superblock object
 * @mtd: MTD info
 * @devops: device access operations
 * @pending_bios: count of pending BIOs (dev_bdev.c ONLY)
 * @erase_page: page with content for erase operation (dev_bdev.c ONLY)
 * @dev_kobj: /sys/fs/ssdfs/<device> kernel object
 * @dev_kobj_unregister: completion state for <device> kernel object
 * @dev_subgroups: <device> subgroups pointer
 */
struct ssdfs_fs_info {
	u8 log_pagesize;
	u32 pagesize;
	u8 log_erasesize;
	u32 erasesize;
	u8 log_segsize;
	u32 segsize;
	u8 log_pebs_per_seg;
	u32 pebs_per_seg;
	u32 pages_per_peb;
	u32 pages_per_seg;
	u64 fs_ctime;
	u64 fs_cno;

	unsigned long mount_opts;

	struct rw_semaphore volume_sem;
	struct ssdfs_volume_header last_vh;
	struct ssdfs_volume_header *vh;
	struct ssdfs_volume_state *vs;
	struct ssdfs_sb_info sbi;
	struct ssdfs_sb_info sbi_backup;
	u16 sb_seg_log_pages;
	u16 segbmap_log_pages;
	u16 maptbl_log_pages;
	u16 lnodes_seg_log_pages;
	u16 hnodes_seg_log_pages;
	u16 inodes_seg_log_pages;
	u16 user_data_log_pages;

	spinlock_t volume_state_lock;
	u64 free_pages;
	u64 fs_mount_time;
	u64 fs_mod_time;
	u64 fs_mount_cno;
	u64 boot_vs_mount_timediff;
	u32 fs_flags;
	u16 fs_state;
	u16 fs_errors;
	u64 fs_feature_compat;
	u64 fs_feature_compat_ro;
	u64 fs_feature_incompat;
	unsigned char fs_uuid[SSDFS_UUID_SIZE];
	char fs_label[SSDFS_VOLUME_LABEL_MAX];
	u16 migration_threshold;

	struct mutex resize_mutex;
	u64 nsegs;

	struct rw_semaphore sb_segs_sem;
	u64 sb_lebs[SSDFS_SB_CHAIN_MAX][SSDFS_SB_SEG_COPY_MAX];
	u64 sb_pebs[SSDFS_SB_CHAIN_MAX][SSDFS_SB_SEG_COPY_MAX];

	struct ssdfs_segment_bmap *segbmap;
	struct inode *segbmap_inode;

	struct ssdfs_peb_mapping_table *maptbl;
	struct ssdfs_maptbl_cache maptbl_cache;

	struct ssdfs_segment_tree *segs_tree;
	struct inode *segs_tree_inode;

	struct ssdfs_current_segs_array *cur_segs;

	struct ssdfs_shared_extents_tree *shextree;
	struct ssdfs_shared_dict_btree_info *shdictree;
	struct ssdfs_inodes_btree_info *inodes_tree;

	struct super_block *sb;

	struct mtd_info *mtd;
	const struct ssdfs_device_ops *devops;
	atomic_t pending_bios;			/* for dev_bdev.c */
	struct page *erase_page;		/* for dev_bdev.c */

	/* /sys/fs/ssdfs/<device> */
	struct kobject dev_kobj;
	struct completion dev_kobj_unregister;
	struct ssdfs_sysfs_dev_subgroups *dev_subgroups;
};

#define SSDFS_FS_I(sb) \
	((struct ssdfs_fs_info *)(sb->s_fs_info))

/*
 * Device operations
 */
extern const struct ssdfs_device_ops ssdfs_mtd_devops;
extern const struct ssdfs_device_ops ssdfs_bdev_devops;

#endif /* _SSDFS_FS_INFO_H */
