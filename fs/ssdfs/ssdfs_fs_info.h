// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ssdfs_fs_info.h - in-core fs information.
 *
 * Copyright (c) 2019-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_FS_INFO_H
#define _SSDFS_FS_INFO_H

/* Global FS states */
enum {
	SSDFS_UNKNOWN_GLOBAL_FS_STATE,
	SSDFS_REGULAR_FS_OPERATIONS,
	SSDFS_METADATA_GOING_FLUSHING,
	SSDFS_METADATA_UNDER_FLUSH,
	SSDFS_GLOBAL_FS_STATE_MAX
};

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
 * struct ssdfs_zone_fragment - zone fragment
 * @ino: inode identification number
 * @logical_blk_offset: logical offset from file's beginning in blocks
 * @extent: zone fragment descriptor
 */
struct ssdfs_zone_fragment {
	u64 ino;
	u64 logical_blk_offset;
	struct ssdfs_raw_extent extent;
};

/*
 * struct ssdfs_metadata_options - metadata options
 * @blk_bmap.flags: block bitmap's flags
 * @blk_bmap.compression: compression type
 *
 * @blk2off_tbl.flags: offset transaltion table's flags
 * @blk2off_tbl.compression: compression type
 *
 * @user_data.flags: user data's flags
 * @user_data.compression: compression type
 * @user_data.migration_threshold: default value of destination PEBs in migration
 */
struct ssdfs_metadata_options {
	struct {
		u16 flags;
		u8 compression;
	} blk_bmap;

	struct {
		u16 flags;
		u8 compression;
	} blk2off_tbl;

	struct {
		u16 flags;
		u8 compression;
		u16 migration_threshold;
	} user_data;
};

/*
 * struct ssdfs_sb_info - superblock info
 * @vh_buf: volume header buffer
 * @vh_buf_size: size of volume header buffer in bytes
 * @vs_buf: volume state buffer
 * @vs_buf_size: size of volume state buffer in bytes
 * @last_log: latest sb log
 */
struct ssdfs_sb_info {
	void *vh_buf;
	size_t vh_buf_size;
	void *vs_buf;
	size_t vs_buf_size;
	struct ssdfs_peb_extent last_log;
};

/*
 * struct ssdfs_device_ops - device operations
 * @device_name: get device name
 * @device_size: get device size in bytes
 * @open_zone: open zone
 * @reopen_zone: reopen closed zone
 * @close_zone: close zone
 * @read: read from device
 * @read_block: read logical block
 * @read_blocks: read sequence of logical blocks
 * @can_write_block: can we write into logical block?
 * @write_block: write logical block to device
 * @write_blocks: write sequence of logical blocks to device
 * @erase: erase block
 * @trim: support of background erase operation
 * @peb_isbad: check that physical erase block is bad
 * @sync: synchronize page cache with device
 */
struct ssdfs_device_ops {
	const char * (*device_name)(struct super_block *sb);
	__u64 (*device_size)(struct super_block *sb);
	int (*open_zone)(struct super_block *sb, loff_t offset);
	int (*reopen_zone)(struct super_block *sb, loff_t offset);
	int (*close_zone)(struct super_block *sb, loff_t offset);
	int (*read)(struct super_block *sb, u32 block_size,
		    loff_t offset, size_t len, void *buf);
	int (*read_block)(struct super_block *sb, struct folio *folio,
			  loff_t offset);
	int (*read_blocks)(struct super_block *sb, struct folio_batch *batch,
			   loff_t offset);
	int (*can_write_block)(struct super_block *sb, u32 block_size,
				loff_t offset, bool need_check);
	int (*write_block)(struct super_block *sb, loff_t offset,
			   struct folio *folio);
	int (*write_blocks)(struct super_block *sb, loff_t offset,
			    struct folio_batch *batch);
	int (*erase)(struct super_block *sb, loff_t offset, size_t len);
	int (*trim)(struct super_block *sb, loff_t offset, size_t len);
	int (*peb_isbad)(struct super_block *sb, loff_t offset);
	int (*mark_peb_bad)(struct super_block *sb, loff_t offset);
	void (*sync)(struct super_block *sb);
};

/*
 * struct ssdfs_snapshot_subsystem - snapshots subsystem
 * @reqs_queue: snapshot requests queue
 * @rules_list: snapshot rules list
 * @tree: snapshots btree
 */
struct ssdfs_snapshot_subsystem {
	struct ssdfs_snapshot_reqs_queue reqs_queue;
	struct ssdfs_snapshot_rules_list rules_list;
	struct ssdfs_snapshots_btree_info *tree;
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
 * @leb_pages_capacity: maximal number of logical blocks per LEB
 * @peb_pages_capacity: maximal number of NAND pages can be written per PEB
 * @lebs_per_peb_index: difference of LEB IDs between PEB indexes in segment
 * @fs_ctime: volume create timestamp (mkfs phase)
 * @fs_cno: volume create checkpoint
 * @raw_inode_size: raw inode size in bytes
 * @create_threads_per_seg: number of creation threads per segment
 * @mount_opts: mount options
 * @metadata_options: metadata options
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
 * @reserved_new_user_data_pages: reserved pages of growing files' content
 * @updated_user_data_pages: number of updated pages of files' content
 * @flushing_user_data_requests: number of user data processing flush request
 * @pending_wq: wait queue for flush threads of user data segments
 * @finish_user_data_flush_wq: wait queue for waiting the end of user data flush
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
 * @invextree: invalidated extents btree
 * @snapshots: snapshots subsystem
 * @gc_thread: array of GC threads
 * @gc_wait_queue: array of GC threads' wait queues
 * @gc_should_act: array of counters that define necessity of GC activity
 * @flush_reqs: current number of flush requests
 * @sb: pointer on VFS superblock object
 * @mtd: MTD info
 * @devops: device access operations
 * @pending_bios: count of pending BIOs (dev_bdev.c ONLY)
 * @erase_folio: folio with content for erase operation (dev_bdev.c ONLY)
 * @is_zns_device: file system volume is on ZNS device
 * @zone_size: zone size in bytes
 * @zone_capacity: zone capacity in bytes available for write operations
 * @max_open_zones: open zones limitation (upper bound)
 * @open_zones: current number of opened zones
 * @fsck_priority: define priority of FSCK operations
 * @dev_kobj: /sys/fs/ssdfs/<device> kernel object
 * @dev_kobj_unregister: completion state for <device> kernel object
 * @maptbl_kobj: /sys/fs/<ssdfs>/<device>/maptbl kernel object
 * @maptbl_kobj_unregister: completion state for maptbl kernel object
 * @segbmap_kobj: /sys/fs/<ssdfs>/<device>/segbmap kernel object
 * @segbmap_kobj_unregister: completion state for segbmap kernel object
 * @segments_kobj: /sys/fs/<ssdfs>/<device>/segments kernel object
 * @segments_kobj_unregister: completion state for segments kernel object
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
	u32 leb_pages_capacity;
	u32 peb_pages_capacity;
	u32 lebs_per_peb_index;
	u64 fs_ctime;
	u64 fs_cno;
	u16 raw_inode_size;
	u16 create_threads_per_seg;

	unsigned long mount_opts;
	struct ssdfs_metadata_options metadata_options;

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

	atomic_t global_fs_state;

	spinlock_t volume_state_lock;
	u64 free_pages;
	u64 reserved_new_user_data_pages;
	u64 updated_user_data_pages;
	u64 flushing_user_data_requests;
	wait_queue_head_t pending_wq;
	wait_queue_head_t finish_user_data_flush_wq;
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
	struct ssdfs_invextree_info *invextree;

	struct ssdfs_snapshot_subsystem snapshots;

	struct ssdfs_thread_info gc_thread[SSDFS_GC_THREAD_TYPE_MAX];
	wait_queue_head_t gc_wait_queue[SSDFS_GC_THREAD_TYPE_MAX];
	atomic_t gc_should_act[SSDFS_GC_THREAD_TYPE_MAX];
	atomic64_t flush_reqs;

	struct super_block *sb;

	struct mtd_info *mtd;
	const struct ssdfs_device_ops *devops;
	atomic_t pending_bios;			/* for dev_bdev.c */
	struct folio *erase_folio;		/* for dev_bdev.c */

	bool is_zns_device;
	u64 zone_size;
	u64 zone_capacity;
	u32 max_open_zones;
	atomic_t open_zones;

#ifdef CONFIG_SSDFS_ONLINE_FSCK
	atomic_t fsck_priority;
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

	/* /sys/fs/ssdfs/<device> */
	struct kobject dev_kobj;
	struct completion dev_kobj_unregister;

	/* /sys/fs/<ssdfs>/<device>/maptbl */
	struct kobject maptbl_kobj;
	struct completion maptbl_kobj_unregister;

	/* /sys/fs/<ssdfs>/<device>/segbmap */
	struct kobject segbmap_kobj;
	struct completion segbmap_kobj_unregister;

	/* /sys/fs/<ssdfs>/<device>/segments */
	struct kobject segments_kobj;
	struct completion segments_kobj_unregister;

#ifdef CONFIG_SSDFS_TESTING
	struct address_space testing_pages;
	struct inode *testing_inode;
	bool do_fork_invalidation;
#endif /* CONFIG_SSDFS_TESTING */
};

#define SSDFS_FS_I(sb) \
	((struct ssdfs_fs_info *)(sb->s_fs_info))

/*
 * GC constants
 */
#define SSDFS_GC_LOW_BOUND_THRESHOLD	(50)
#define SSDFS_GC_UPPER_BOUND_THRESHOLD	(1000)
#define SSDFS_GC_DISTANCE_THRESHOLD	(5)
#define SSDFS_GC_DEFAULT_SEARCH_STEP	(100)
#define SSDFS_GC_DIRTY_SEG_SEARCH_STEP	(1000)
#define SSDFS_GC_DIRTY_SEG_DEFAULT_OPS	(50)

/*
 * GC possible states
 */
enum {
	SSDFS_UNDEFINED_GC_STATE,
	SSDFS_COLLECT_GARBAGE_NOW,
	SSDFS_WAIT_IDLE_STATE,
	SSDFS_STOP_GC_ACTIVITY_NOW,
	SSDFS_GC_STATE_MAX
};

/*
 * FSCK possible states
 */
enum {
	SSDFS_UNDEFINED_FSCK_STATE = SSDFS_UNDEFINED_GC_STATE,
	SSDFS_DO_FSCK_CHECK_NOW = SSDFS_COLLECT_GARBAGE_NOW,
	SSDFS_FSCK_WAIT_IDLE_STATE = SSDFS_WAIT_IDLE_STATE,
	SSDFS_STOP_FSCK_ACTIVITY_NOW = SSDFS_STOP_GC_ACTIVITY_NOW,
	SSDFS_FSCK_STATE_MAX
};

/*
 * struct ssdfs_io_load_stats - I/O load estimation
 * @measurements: number of executed measurements
 * @reqs_count: number of I/O requests for every measurement
 */
struct ssdfs_io_load_stats {
	u32 measurements;
#define SSDFS_MEASUREMENTS_MAX		(10)
	s64 reqs_count[SSDFS_MEASUREMENTS_MAX];
};

/*
 * GC thread functions
 */
int ssdfs_using_seg_gc_thread_func(void *data);
int ssdfs_used_seg_gc_thread_func(void *data);
int ssdfs_pre_dirty_seg_gc_thread_func(void *data);
int ssdfs_dirty_seg_gc_thread_func(void *data);
int ssdfs_start_gc_thread(struct ssdfs_fs_info *fsi, int type);
int ssdfs_stop_gc_thread(struct ssdfs_fs_info *fsi, int type);
int is_time_collect_garbage(struct ssdfs_fs_info *fsi,
			    struct ssdfs_io_load_stats *io_stats);

/*
 * Device operations
 */
extern const struct ssdfs_device_ops ssdfs_mtd_devops;
extern const struct ssdfs_device_ops ssdfs_bdev_devops;
extern const struct ssdfs_device_ops ssdfs_zns_devops;

#endif /* _SSDFS_FS_INFO_H */
