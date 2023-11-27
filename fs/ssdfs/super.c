// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/super.c - module and superblock management.
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/super.h>
#include <linux/exportfs.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/delay.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "version.h"
#include "segment_bitmap.h"
#include "folio_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment.h"
#include "segment_tree.h"
#include "current_segment.h"
#include "peb_mapping_table.h"
#include "extents_queue.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "inodes_tree.h"
#include "shared_extents_tree.h"
#include "shared_dictionary.h"
#include "extents_tree.h"
#include "dentries_tree.h"
#include "xattr_tree.h"
#include "xattr.h"
#include "acl.h"
#include "snapshots_tree.h"
#include "invalidated_extents_tree.h"

#define CREATE_TRACE_POINTS
#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_allocated_folios;
atomic64_t ssdfs_memory_leaks;
atomic64_t ssdfs_super_folio_leaks;
atomic64_t ssdfs_super_memory_leaks;
atomic64_t ssdfs_super_cache_leaks;

atomic64_t ssdfs_locked_folios;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_super_cache_leaks_increment(void *kaddr)
 * void ssdfs_super_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_super_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_super_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_super_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_super_kfree(void *kaddr)
 * struct folio *ssdfs_super_alloc_folio(gfp_t gfp_mask,
 *                                       unsigned int order)
 * struct folio *ssdfs_super_add_batch_folio(struct folio_batch *batch,
 *                                           unsigned int order)
 * void ssdfs_super_free_folio(struct folio *folio)
 * void ssdfs_super_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(super)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(super)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_super_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_super_folio_leaks, 0);
	atomic64_set(&ssdfs_super_memory_leaks, 0);
	atomic64_set(&ssdfs_super_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_super_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_super_folio_leaks) != 0) {
		SSDFS_ERR("SUPER: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_super_folio_leaks));
	}

	if (atomic64_read(&ssdfs_super_memory_leaks) != 0) {
		SSDFS_ERR("SUPER: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_super_memory_leaks));
	}

	if (atomic64_read(&ssdfs_super_cache_leaks) != 0) {
		SSDFS_ERR("SUPER: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_super_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

struct ssdfs_payload_content {
	struct folio_batch batch;
	u32 bytes_count;
};

struct ssdfs_sb_log_payload {
	struct ssdfs_payload_content maptbl_cache;
};

static struct kmem_cache *ssdfs_inode_cachep;

static int ssdfs_prepare_sb_log(struct super_block *sb,
				struct ssdfs_peb_extent *last_sb_log);
static int ssdfs_snapshot_sb_log_payload(struct super_block *sb,
					 struct ssdfs_sb_log_payload *payload);
static int ssdfs_commit_super(struct super_block *sb, u16 fs_state,
				struct ssdfs_peb_extent *last_sb_log,
				struct ssdfs_sb_log_payload *payload);
static void ssdfs_put_super(struct super_block *sb);
static void ssdfs_check_memory_leaks(void);

static void init_once(void *foo)
{
	struct ssdfs_inode_info *ii = (struct ssdfs_inode_info *)foo;

	inode_init_once(&ii->vfs_inode);
}

/*
 * This method is called by inode_alloc() to allocate memory
 * for struct inode and initialize it
 */
struct inode *ssdfs_alloc_inode(struct super_block *sb)
{
	struct ssdfs_inode_info *ii;

	ii = alloc_inode_sb(sb, ssdfs_inode_cachep, GFP_KERNEL);
	if (!ii)
		return NULL;

	ssdfs_super_cache_leaks_increment(ii);

	init_once((void *)ii);

	atomic_set(&ii->private_flags, 0);
	init_rwsem(&ii->lock);
	ii->parent_ino = U64_MAX;
	ii->flags = 0;
	ii->name_hash = 0;
	ii->name_len = 0;
	ii->extents_tree = NULL;
	ii->dentries_tree = NULL;
	ii->xattrs_tree = NULL;
	ii->inline_file = NULL;
	memset(&ii->raw_inode, 0, sizeof(struct ssdfs_inode));

	return &ii->vfs_inode;
}

void ssdfs_destroy_btree_of_inode(struct inode *inode)
{
	struct ssdfs_inode_info *ii = SSDFS_I(inode);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu\n", inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	if (ii->extents_tree) {
		ssdfs_extents_tree_destroy(ii);
		ii->extents_tree = NULL;
	}

	if (ii->dentries_tree) {
		ssdfs_dentries_tree_destroy(ii);
		ii->dentries_tree = NULL;
	}

	if (ii->xattrs_tree) {
		ssdfs_xattrs_tree_destroy(ii);
		ii->xattrs_tree = NULL;
	}

	if (ii->inline_file) {
		ssdfs_destroy_inline_file_buffer(inode);
		ii->inline_file = NULL;
	}
}

void ssdfs_destroy_and_decrement_btree_of_inode(struct inode *inode)
{
	struct ssdfs_inode_info *ii = SSDFS_I(inode);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu\n", inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_destroy_btree_of_inode(inode);

	if (inode->i_ino == SSDFS_SEG_BMAP_INO ||
	    inode->i_ino == SSDFS_SEG_TREE_INO ||
	    inode->i_ino == SSDFS_TESTING_INO) {
		ssdfs_super_cache_leaks_decrement(ii);
	} else
		BUG();
}

static void ssdfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu\n", inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_destroy_btree_of_inode(inode);

	if (inode->i_ino == SSDFS_SEG_BMAP_INO ||
	    inode->i_ino == SSDFS_SEG_TREE_INO ||
	    inode->i_ino == SSDFS_TESTING_INO) {
		/*
		 * Do nothing.
		 * The ssdfs_destroy_and_decrement_btree_of_inode did it already.
		 */
	} else {
		ssdfs_super_cache_leaks_decrement(ii);
	}

	kmem_cache_free(ssdfs_inode_cachep, ii);
}

/*
 * This method is called by destroy_inode() to release
 * resources allocated for struct inode
 */
static void ssdfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, ssdfs_i_callback);
}

static void ssdfs_init_inode_once(void *obj)
{
	struct ssdfs_inode_info *ii = obj;
	inode_init_once(&ii->vfs_inode);
}

static int ssdfs_remount_fs(struct super_block *sb, int *flags, char *data)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	struct ssdfs_peb_extent last_sb_log = {0};
	struct ssdfs_sb_log_payload payload;
	unsigned long old_sb_flags;
	unsigned long old_mount_opts;
	int err;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("sb %p, flags %#x, data %p\n", sb, *flags, data);
#else
	SSDFS_DBG("sb %p, flags %#x, data %p\n", sb, *flags, data);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	old_sb_flags = sb->s_flags;
	old_mount_opts = fsi->mount_opts;

	folio_batch_init(&payload.maptbl_cache.batch);

	err = ssdfs_parse_options(fsi, data);
	if (err)
		goto restore_opts;

	set_posix_acl_flag(sb);

	if ((*flags & SB_RDONLY) == (sb->s_flags & SB_RDONLY))
		goto out;

	if (*flags & SB_RDONLY) {
		down_write(&fsi->volume_sem);

		err = ssdfs_prepare_sb_log(sb, &last_sb_log);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare sb log: err %d\n",
				  err);
		}

		err = ssdfs_snapshot_sb_log_payload(sb, &payload);
		if (unlikely(err)) {
			SSDFS_ERR("fail to snapshot sb log's payload: err %d\n",
				  err);
		}

		if (!err) {
			err = ssdfs_commit_super(sb, SSDFS_VALID_FS,
						 &last_sb_log,
						 &payload);
		} else {
			SSDFS_ERR("fail to prepare sb log payload: "
				  "err %d\n", err);
		}

		up_write(&fsi->volume_sem);

		if (err)
			SSDFS_ERR("fail to commit superblock info\n");

		sb->s_flags |= SB_RDONLY;
		SSDFS_DBG("remount in RO mode\n");
	} else {
		down_write(&fsi->volume_sem);

		err = ssdfs_prepare_sb_log(sb, &last_sb_log);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare sb log: err %d\n",
				  err);
		}

		err = ssdfs_snapshot_sb_log_payload(sb, &payload);
		if (unlikely(err)) {
			SSDFS_ERR("fail to snapshot sb log's payload: err %d\n",
				  err);
		}

		if (!err) {
			err = ssdfs_commit_super(sb, SSDFS_MOUNTED_FS,
						 &last_sb_log,
						 &payload);
		} else {
			SSDFS_ERR("fail to prepare sb log payload: "
				  "err %d\n", err);
		}

		up_write(&fsi->volume_sem);

		if (err) {
			SSDFS_NOTICE("fail to commit superblock info\n");
			goto restore_opts;
		}

		sb->s_flags &= ~SB_RDONLY;
		SSDFS_DBG("remount in RW mode\n");
	}
out:
	ssdfs_super_folio_batch_release(&payload.maptbl_cache.batch);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;

restore_opts:
	sb->s_flags = old_sb_flags;
	fsi->mount_opts = old_mount_opts;
	ssdfs_super_folio_batch_release(&payload.maptbl_cache.batch);
	return err;
}

static inline
bool unfinished_user_data_requests_exist(struct ssdfs_fs_info *fsi)
{
	u64 flush_requests = 0;

	spin_lock(&fsi->volume_state_lock);
	flush_requests = fsi->flushing_user_data_requests;
	spin_unlock(&fsi->volume_state_lock);

	return flush_requests > 0;
}

static int ssdfs_sync_fs(struct super_block *sb, int wait)
{
	struct ssdfs_fs_info *fsi;
	int err = 0;

	fsi = SSDFS_FS_I(sb);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("sb %p\n", sb);
#else
	SSDFS_DBG("sb %p\n", sb);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

#ifdef CONFIG_SSDFS_SHOW_CONSUMED_MEMORY
	SSDFS_ERR("SYNCFS is starting...\n");
	ssdfs_check_memory_leaks();
#endif /* CONFIG_SSDFS_SHOW_CONSUMED_MEMORY */

	atomic_set(&fsi->global_fs_state, SSDFS_METADATA_GOING_FLUSHING);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("SSDFS_METADATA_GOING_FLUSHING\n");
#endif /* CONFIG_SSDFS_DEBUG */

	wake_up_all(&fsi->pending_wq);

	if (unfinished_user_data_requests_exist(fsi)) {
		wait_queue_head_t *wq = &fsi->finish_user_data_flush_wq;

		err = wait_event_killable_timeout(*wq,
				!unfinished_user_data_requests_exist(fsi),
				SSDFS_DEFAULT_TIMEOUT);
		if (err < 0)
			WARN_ON(err < 0);
		else
			err = 0;

		if (unfinished_user_data_requests_exist(fsi))
			BUG();
	}

	atomic_set(&fsi->global_fs_state, SSDFS_METADATA_UNDER_FLUSH);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("SSDFS_METADATA_UNDER_FLUSH\n");
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&fsi->volume_sem);

	if (fsi->fs_feature_compat &
			SSDFS_HAS_INVALID_EXTENTS_TREE_COMPAT_FLAG) {
		err = ssdfs_invextree_flush(fsi);
		if (err) {
			SSDFS_ERR("fail to flush invalidated extents btree: "
				  "err %d\n", err);
		}
	}

	if (fsi->fs_feature_compat & SSDFS_HAS_SHARED_EXTENTS_COMPAT_FLAG) {
		err = ssdfs_shextree_flush(fsi);
		if (err) {
			SSDFS_ERR("fail to flush shared extents btree: "
				  "err %d\n", err);
		}
	}

	if (fsi->fs_feature_compat & SSDFS_HAS_INODES_TREE_COMPAT_FLAG) {
		err = ssdfs_inodes_btree_flush(fsi->inodes_tree);
		if (err) {
			SSDFS_ERR("fail to flush inodes btree: "
				  "err %d\n", err);
		}
	}

	if (fsi->fs_feature_compat & SSDFS_HAS_SHARED_DICT_COMPAT_FLAG) {
		err = ssdfs_shared_dict_btree_flush(fsi->shdictree);
		if (err) {
			SSDFS_ERR("fail to flush shared dictionary: "
				  "err %d\n", err);
		}
	}

	err = ssdfs_execute_create_snapshots(fsi);
	if (err) {
		SSDFS_ERR("fail to process the snapshots creation\n");
	}

	if (fsi->fs_feature_compat & SSDFS_HAS_SNAPSHOTS_TREE_COMPAT_FLAG) {
		err = ssdfs_snapshots_btree_flush(fsi);
		if (err) {
			SSDFS_ERR("fail to flush snapshots btree: "
				  "err %d\n", err);
		}
	}

	if (fsi->fs_feature_compat & SSDFS_HAS_SEGBMAP_COMPAT_FLAG) {
		err = ssdfs_segbmap_flush(fsi->segbmap);
		if (err) {
			SSDFS_ERR("fail to flush segment bitmap: "
				  "err %d\n", err);
		}
	}

	if (fsi->fs_feature_compat & SSDFS_HAS_MAPTBL_COMPAT_FLAG) {
		err = ssdfs_maptbl_flush(fsi->maptbl);
		if (err) {
			SSDFS_ERR("fail to flush mapping table: "
				  "err %d\n", err);
		}
	}

	up_write(&fsi->volume_sem);

	atomic_set(&fsi->global_fs_state, SSDFS_REGULAR_FS_OPERATIONS);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("SSDFS_REGULAR_FS_OPERATIONS\n");
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_SHOW_CONSUMED_MEMORY
	SSDFS_ERR("SYNCFS has been finished...\n");
	ssdfs_check_memory_leaks();
#endif /* CONFIG_SSDFS_SHOW_CONSUMED_MEMORY */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (unlikely(err))
		goto fail_sync_fs;

	trace_ssdfs_sync_fs(sb, wait);

	return 0;

fail_sync_fs:
	trace_ssdfs_sync_fs_exit(sb, wait, err);
	return err;
}

static struct inode *ssdfs_nfs_get_inode(struct super_block *sb,
					 u64 ino, u32 generation)
{
	struct inode *inode;

	if (ino < SSDFS_ROOT_INO)
		return ERR_PTR(-ESTALE);

	inode = ssdfs_iget(sb, ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);
	if (generation && inode->i_generation != generation) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}
	return inode;
}

static struct dentry *ssdfs_fh_to_dentry(struct super_block *sb,
					 struct fid *fid,
					 int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    ssdfs_nfs_get_inode);
}

static struct dentry *ssdfs_fh_to_parent(struct super_block *sb,
					 struct fid *fid,
					 int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    ssdfs_nfs_get_inode);
}

static struct dentry *ssdfs_get_parent(struct dentry *child)
{
	struct qstr dotdot = QSTR_INIT("..", 2);
	ino_t ino;
	int err;

	err = ssdfs_inode_by_name(d_inode(child), &dotdot, &ino);
	if (unlikely(err))
		return ERR_PTR(err);

	return d_obtain_alias(ssdfs_iget(child->d_sb, ino));
}

static const struct export_operations ssdfs_export_ops = {
	.get_parent	= ssdfs_get_parent,
	.fh_to_dentry	= ssdfs_fh_to_dentry,
	.fh_to_parent	= ssdfs_fh_to_parent,
};

static const struct super_operations ssdfs_super_operations = {
	.alloc_inode	= ssdfs_alloc_inode,
	.destroy_inode	= ssdfs_destroy_inode,
	.evict_inode	= ssdfs_evict_inode,
	.write_inode	= ssdfs_write_inode,
	.statfs		= ssdfs_statfs,
	.show_options	= ssdfs_show_options,
	.put_super	= ssdfs_put_super,
	.remount_fs	= ssdfs_remount_fs,
	.sync_fs	= ssdfs_sync_fs,
};

static inline
u32 ssdfs_sb_payload_size(struct folio_batch *batch)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct folio *folio;
	void *kaddr;
	u16 fragment_bytes_count;
	u32 bytes_count = 0;
	int i;

	for (i = 0; i < folio_batch_count(batch); i++) {
		folio = batch->folios[i];

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);
		hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
		fragment_bytes_count = le16_to_cpu(hdr->bytes_count);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);

#ifdef CONFIG_SSDFS_DEBUG
		WARN_ON(fragment_bytes_count > PAGE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

		bytes_count += fragment_bytes_count;
	}

	return bytes_count;
}

static u32 ssdfs_define_sb_log_size(struct super_block *sb)
{
	struct ssdfs_fs_info *fsi;
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	u32 inline_capacity;
	u32 log_size = 0;
	u32 payload_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb);

	SSDFS_DBG("sb %p\n", sb);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = SSDFS_FS_I(sb);
	payload_size = ssdfs_sb_payload_size(&fsi->maptbl_cache.batch);
	inline_capacity = PAGE_SIZE - hdr_size;

	if (payload_size > inline_capacity) {
		log_size += PAGE_SIZE;
		log_size += atomic_read(&fsi->maptbl_cache.bytes_count);
		log_size += PAGE_SIZE;
	} else {
		log_size += PAGE_SIZE;
		log_size += PAGE_SIZE;
	}

	log_size = (log_size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	return log_size;
}

static int ssdfs_snapshot_sb_log_payload(struct super_block *sb,
					 struct ssdfs_sb_log_payload *payload)
{
	struct ssdfs_fs_info *fsi;
	struct folio *sfolio, *dfolio;
	unsigned folios_count;
	unsigned i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !payload);
	BUG_ON(folio_batch_count(&payload->maptbl_cache.batch) != 0);

	SSDFS_DBG("sb %p, payload %p\n",
		  sb, payload);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = SSDFS_FS_I(sb);

	down_read(&fsi->maptbl_cache.lock);

	folios_count = folio_batch_count(&fsi->maptbl_cache.batch);

	for (i = 0; i < folios_count; i++) {
		dfolio = ssdfs_super_add_batch_folio(&payload->maptbl_cache.batch,
						     get_order(PAGE_SIZE));
		if (unlikely(IS_ERR_OR_NULL(dfolio))) {
			err = !dfolio ? -ENOMEM : PTR_ERR(dfolio);
			SSDFS_ERR("fail to add folio into batch: "
				  "index %u, err %d\n",
				  i, err);
			goto finish_maptbl_snapshot;
		}

		sfolio = fsi->maptbl_cache.batch.folios[i];
		if (unlikely(!sfolio)) {
			err = -ERANGE;
			SSDFS_ERR("source folio is absent: index %u\n",
				  i);
			goto finish_maptbl_snapshot;
		}

		ssdfs_folio_lock(sfolio);
		ssdfs_folio_lock(dfolio);
		__ssdfs_memcpy_folio(dfolio, 0, PAGE_SIZE,
				     sfolio, 0, PAGE_SIZE,
				     PAGE_SIZE);
		ssdfs_folio_unlock(dfolio);
		ssdfs_folio_unlock(sfolio);
	}

	payload->maptbl_cache.bytes_count =
		atomic_read(&fsi->maptbl_cache.bytes_count);

finish_maptbl_snapshot:
	up_read(&fsi->maptbl_cache.lock);

	if (unlikely(err))
		ssdfs_super_folio_batch_release(&payload->maptbl_cache.batch);

	return err;
}

static int ssdfs_define_next_sb_log_place(struct super_block *sb,
					  struct ssdfs_peb_extent *last_sb_log)
{
	struct ssdfs_fs_info *fsi;
	u32 offset;
	u32 log_size;
	u64 cur_peb, prev_peb;
	u64 cur_leb;
	u32 pages_per_peb;
	int i;
	int err = 0;

	fsi = SSDFS_FS_I(sb);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !last_sb_log);

	SSDFS_DBG("sb %p, last_sb_log %p\n",
		  sb, last_sb_log);
	SSDFS_DBG("fsi->sbi.last_log.leb_id %llu, "
		  "fsi->sbi.last_log.peb_id %llu, "
		  "fsi->sbi.last_log.page_offset %u, "
		  "fsi->sbi.last_log.pages_count %u\n",
		  fsi->sbi.last_log.leb_id,
		  fsi->sbi.last_log.peb_id,
		  fsi->sbi.last_log.page_offset,
		  fsi->sbi.last_log.pages_count);
#endif /* CONFIG_SSDFS_DEBUG */

	/*
	 * Superblock segment uses 4KB page always.
	 * It needs to calculate pages_per_peb value.
	 */
	pages_per_peb = fsi->erasesize / PAGE_SIZE;

	offset = fsi->sbi.last_log.page_offset;

	log_size = ssdfs_define_sb_log_size(sb);
	if (log_size > pages_per_peb) {
		SSDFS_ERR("log_size %u > pages_per_peb %u\n",
			  log_size, pages_per_peb);
		return -ERANGE;
	}

	log_size = max_t(u32, log_size, fsi->sbi.last_log.pages_count);

	if (offset > pages_per_peb || offset > (UINT_MAX - log_size)) {
		SSDFS_ERR("inconsistent metadata state: "
			  "last_sb_log.page_offset %u, "
			  "pages_per_peb %u, log_size %u\n",
			  offset, pages_per_peb, log_size);
		return -EINVAL;
	}

	for (err = -EINVAL, i = 0; i < SSDFS_SB_SEG_COPY_MAX; i++) {
		cur_peb = fsi->sb_pebs[SSDFS_CUR_SB_SEG][i];
		prev_peb = fsi->sb_pebs[SSDFS_PREV_SB_SEG][i];
		cur_leb = fsi->sb_lebs[SSDFS_CUR_SB_SEG][i];

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cur_peb %llu, prev_peb %llu, "
			  "last_sb_log.peb_id %llu, err %d\n",
			  cur_peb, prev_peb, fsi->sbi.last_log.peb_id, err);
#endif /* CONFIG_SSDFS_DEBUG */

		if (fsi->sbi.last_log.peb_id == cur_peb) {
			if ((offset + (2 * log_size)) > pages_per_peb) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("sb PEB %llu is full: "
					  "(offset %u + (2 * log_size %u)) > "
					  "pages_per_peb %u\n",
					  cur_peb, offset, log_size,
					  pages_per_peb);
#endif /* CONFIG_SSDFS_DEBUG */
				return -EFBIG;
			}

			last_sb_log->leb_id = cur_leb;
			last_sb_log->peb_id = cur_peb;
			last_sb_log->page_offset = offset + log_size;
			last_sb_log->pages_count = log_size;

			err = 0;
			break;
		} else if (fsi->sbi.last_log.peb_id != cur_peb &&
			   fsi->sbi.last_log.peb_id == prev_peb) {

			last_sb_log->leb_id = cur_leb;
			last_sb_log->peb_id = cur_peb;
			last_sb_log->page_offset = 0;
			last_sb_log->pages_count = log_size;

			err = 0;
			break;
		} else {
			/* continue to check */
			err = -ERANGE;
		}
	}

	if (err) {
		SSDFS_ERR("inconsistent metadata state: "
			  "cur_peb %llu, prev_peb %llu, "
			  "last_sb_log.peb_id %llu\n",
			  cur_peb, prev_peb, fsi->sbi.last_log.peb_id);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("last_sb_log->leb_id %llu, "
		  "last_sb_log->peb_id %llu, "
		  "last_sb_log->page_offset %u, "
		  "last_sb_log->pages_count %u\n",
		  fsi->sbi.last_log.leb_id,
		  fsi->sbi.last_log.peb_id,
		  fsi->sbi.last_log.page_offset,
		  fsi->sbi.last_log.pages_count);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < SSDFS_SB_SEG_COPY_MAX; i++) {
		last_sb_log->leb_id = fsi->sb_lebs[SSDFS_CUR_SB_SEG][i];
		last_sb_log->peb_id = fsi->sb_pebs[SSDFS_CUR_SB_SEG][i];
		err = ssdfs_can_write_sb_log(sb, last_sb_log);
		if (err) {
			SSDFS_ERR("fail to write sb log into PEB %llu: "
				  "last_sb_log->page_offset %u, "
				  "last_sb_log->pages_count %u\n",
				  last_sb_log->peb_id,
				  last_sb_log->page_offset,
				  last_sb_log->pages_count);
			return err;
		}
	}

	last_sb_log->leb_id = cur_leb;
	last_sb_log->peb_id = cur_peb;

	return 0;
}

static bool ssdfs_sb_seg_exhausted(struct ssdfs_fs_info *fsi,
				   u64 cur_leb, u64 next_leb)
{
	u64 cur_seg, next_seg;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(cur_leb == U64_MAX || next_leb == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	cur_seg = SSDFS_LEB2SEG(fsi, cur_leb);
	next_seg = SSDFS_LEB2SEG(fsi, next_leb);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("cur_seg %llu, cur_leb %llu, "
		  "next_seg %llu, next_leb %llu\n",
		  cur_seg, cur_leb, next_seg, next_leb);
#endif /* CONFIG_SSDFS_DEBUG */

	if (cur_seg >= U64_MAX || next_seg >= U64_MAX)
		return true;

	return cur_seg != next_seg;
}

#ifndef CONFIG_SSDFS_FIXED_SUPERBLOCK_SEGMENTS_SET
static u64 ssdfs_correct_start_leb_id(struct ssdfs_fs_info *fsi,
				      int seg_type, u64 leb_id)
{
	struct completion *init_end;
	struct ssdfs_maptbl_peb_relation pebr;
	struct ssdfs_maptbl_peb_descriptor *ptr;
	u8 peb_type = SSDFS_MAPTBL_UNKNOWN_PEB_TYPE;
	u32 pebs_per_seg;
	u64 seg_id;
	u64 cur_leb;
	u64 peb_id1, peb_id2;
	u64 found_peb_id;
	u64 peb_id_off;
	u16 pebs_per_fragment;
	u16 pebs_per_stripe;
	u16 stripes_per_fragment;
	u64 calculated_leb_id = leb_id;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p, seg_type %#x, leb_id %llu\n",
		  fsi, seg_type, leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	found_peb_id = leb_id;
	peb_type = SEG2PEB_TYPE(seg_type);
	pebs_per_seg = fsi->pebs_per_seg;

	seg_id = ssdfs_get_seg_id_for_leb_id(fsi, leb_id);
	if (unlikely(seg_id >= U64_MAX)) {
		SSDFS_ERR("invalid seg_id: "
			  "leb_id %llu\n", leb_id);
		return -ERANGE;
	}

	err = ssdfs_maptbl_define_fragment_info(fsi, leb_id,
						&pebs_per_fragment,
						&pebs_per_stripe,
						&stripes_per_fragment);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define fragment info: "
			  "err %d\n", err);
		return err;
	}

	for (i = 0; i < pebs_per_seg; i++) {
		cur_leb = ssdfs_get_leb_id_for_peb_index(fsi, seg_id, i);
		if (cur_leb >= U64_MAX) {
			SSDFS_ERR("fail to convert PEB index into LEB ID: "
				  "seg %llu, peb_index %u\n",
				  seg_id, i);
			return -ERANGE;
		}

		err = ssdfs_maptbl_convert_leb2peb(fsi, cur_leb,
						   peb_type, &pebr,
						   &init_end);
		if (err == -EAGAIN) {
			err = SSDFS_WAIT_COMPLETION(init_end);
			if (unlikely(err)) {
				SSDFS_ERR("maptbl init failed: "
					  "err %d\n", err);
				goto finish_leb_id_correction;
			}

			err = ssdfs_maptbl_convert_leb2peb(fsi, cur_leb,
							   peb_type, &pebr,
							   &init_end);
		}

		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("LEB is not mapped: leb_id %llu\n",
				  cur_leb);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_leb_id_correction;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to convert LEB to PEB: "
				  "leb_id %llu, peb_type %#x, err %d\n",
				  cur_leb, peb_type, err);
			goto finish_leb_id_correction;
		}

		ptr = &pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX];
		peb_id1 = ptr->peb_id;
		ptr = &pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX];
		peb_id2 = ptr->peb_id;

		if (peb_id1 < U64_MAX)
			found_peb_id = max_t(u64, peb_id1, found_peb_id);

		if (peb_id2 < U64_MAX)
			found_peb_id = max_t(u64, peb_id2, found_peb_id);

		peb_id_off = found_peb_id % pebs_per_stripe;
		if (peb_id_off >= (pebs_per_stripe / 2)) {
			calculated_leb_id = found_peb_id / pebs_per_stripe;
			calculated_leb_id++;
			calculated_leb_id *= pebs_per_stripe;
		} else {
			calculated_leb_id = found_peb_id;
			calculated_leb_id++;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("found_peb_id %llu, pebs_per_stripe %u, "
			  "calculated_leb_id %llu\n",
			  found_peb_id, pebs_per_stripe,
			  calculated_leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
	}

finish_leb_id_correction:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("leb_id %llu, calculated_leb_id %llu\n",
		  leb_id, calculated_leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	return calculated_leb_id;
}
#endif /* CONFIG_SSDFS_FIXED_SUPERBLOCK_SEGMENTS_SET */

#ifndef CONFIG_SSDFS_FIXED_SUPERBLOCK_SEGMENTS_SET
static int __ssdfs_reserve_clean_segment(struct ssdfs_fs_info *fsi,
					 int sb_seg_type,
					 u64 start_search_id,
					 u64 *reserved_seg)
{
	struct ssdfs_segment_bmap *segbmap = fsi->segbmap;
	u64 start_seg = start_search_id;
	u64 end_seg = U64_MAX;
	struct ssdfs_maptbl_peb_relation pebr;
	struct completion *end;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!reserved_seg);
	BUG_ON(sb_seg_type >= SSDFS_SB_SEG_COPY_MAX);

	SSDFS_DBG("fsi %p, sb_seg_type %#x, start_search_id %llu\n",
		  fsi, sb_seg_type, start_search_id);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (sb_seg_type) {
	case SSDFS_MAIN_SB_SEG:
	case SSDFS_COPY_SB_SEG:
		err = ssdfs_segment_detect_search_range(fsi,
							&start_seg,
							&end_seg);
		if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find fragment for search: "
				  "start_seg %llu, end_seg %llu\n",
				  start_seg, end_seg);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to define a search range: "
				  "start_seg %llu, err %d\n",
				  start_seg, err);
			return err;
		}
		break;

	default:
		BUG();
	};

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_seg %llu, end_seg %llu\n",
		  start_seg, end_seg);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_segbmap_reserve_clean_segment(segbmap,
						  start_seg, end_seg,
						  reserved_seg, &end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("segbmap init failed: "
				  "err %d\n", err);
			goto finish_search;
		}

		err = ssdfs_segbmap_reserve_clean_segment(segbmap,
							  start_seg, end_seg,
							  reserved_seg,
							  &end);
	}

	if (err == -ENODATA) {
		err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to reserve segment: "
			  "type %#x, start_seg %llu, end_seg %llu\n",
			  sb_seg_type, start_seg, end_seg);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_search;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to reserve segment: "
			  "type %#x, start_seg %llu, "
			   "end_seg %llu, err %d\n",
			  sb_seg_type, start_seg, end_seg, err);
		goto finish_search;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("reserved_seg %llu\n", *reserved_seg);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < fsi->pebs_per_seg; i++) {
		u8 peb_type = SSDFS_MAPTBL_SBSEG_PEB_TYPE;
		u64 leb_id;

		leb_id = ssdfs_get_leb_id_for_peb_index(fsi, *reserved_seg, i);
		if (leb_id >= U64_MAX) {
			err = -ERANGE;
			SSDFS_ERR("fail to convert PEB index into LEB ID: "
				  "seg %llu, peb_index %u\n",
				  *reserved_seg, i);
			goto finish_search;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("leb_id %llu\n", leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_maptbl_map_leb2peb(fsi, leb_id, peb_type,
						&pebr, &end);
		if (err == -EAGAIN) {
			err = SSDFS_WAIT_COMPLETION(end);
			if (unlikely(err)) {
				SSDFS_ERR("maptbl init failed: "
					  "err %d\n", err);
				goto finish_search;
			}

			err = ssdfs_maptbl_map_leb2peb(fsi, leb_id,
							peb_type,
							&pebr, &end);
		}

		if (err == -EACCES || err == -ENOENT) {
			if (i == 0) {
				SSDFS_ERR("fail to map LEB to PEB: "
					  "reserved_seg %llu, leb_id %llu, "
					  "err %d\n",
					  *reserved_seg, leb_id, err);
				goto finish_search;
			} else
				goto finish_search;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to map LEB to PEB: "
				  "reserved_seg %llu, leb_id %llu, "
				  "err %d\n",
				  *reserved_seg, leb_id, err);
			goto finish_search;
		}
	}

finish_search:
	if (err == -ENOENT)
		*reserved_seg = end_seg;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("reserved_seg %llu\n", *reserved_seg);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}
#endif /* CONFIG_SSDFS_FIXED_SUPERBLOCK_SEGMENTS_SET */

#ifndef CONFIG_SSDFS_FIXED_SUPERBLOCK_SEGMENTS_SET
static int ssdfs_reserve_clean_segment(struct super_block *sb,
					int sb_seg_type, u64 start_leb,
					u64 *reserved_seg)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	u64 start_search_id;
	u64 cur_id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!reserved_seg);
	BUG_ON(sb_seg_type >= SSDFS_SB_SEG_COPY_MAX);

	SSDFS_DBG("sb %p, sb_seg_type %#x, start_leb %llu\n",
		  sb, sb_seg_type, start_leb);
#endif /* CONFIG_SSDFS_DEBUG */

	*reserved_seg = U64_MAX;

	start_leb = ssdfs_correct_start_leb_id(fsi,
						SSDFS_SB_SEG_TYPE,
						start_leb);

	start_search_id = SSDFS_LEB2SEG(fsi, start_leb);
	if (start_search_id >= fsi->nsegs)
		start_search_id = 0;

	cur_id = start_search_id;

	while (cur_id < fsi->nsegs) {
		err = __ssdfs_reserve_clean_segment(fsi, sb_seg_type,
						    cur_id, reserved_seg);
		if (err == -ENOENT) {
			err = 0;
			cur_id = *reserved_seg;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cur_id %llu\n", cur_id);
#endif /* CONFIG_SSDFS_DEBUG */
			continue;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find a new segment: "
				  "cur_id %llu, err %d\n",
				  cur_id, err);
			return err;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("found seg_id %llu\n", *reserved_seg);
#endif /* CONFIG_SSDFS_DEBUG */
			return 0;
		}
	}

	cur_id = 0;

	while (cur_id < start_search_id) {
		err = __ssdfs_reserve_clean_segment(fsi, sb_seg_type,
						    cur_id, reserved_seg);
		if (err == -ENOENT) {
			err = 0;
			cur_id = *reserved_seg;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cur_id %llu\n", cur_id);
#endif /* CONFIG_SSDFS_DEBUG */
			continue;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find a new segment: "
				  "cur_id %llu, err %d\n",
				  cur_id, err);
			return err;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("found seg_id %llu\n", *reserved_seg);
#endif /* CONFIG_SSDFS_DEBUG */
			return 0;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("no free space for a new segment\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return -ENOSPC;
}
#endif /* CONFIG_SSDFS_FIXED_SUPERBLOCK_SEGMENTS_SET */

typedef u64 sb_pebs_array[SSDFS_SB_CHAIN_MAX][SSDFS_SB_SEG_COPY_MAX];

static int ssdfs_erase_dirty_prev_sb_segs(struct ssdfs_fs_info *fsi,
					  u64 prev_leb)
{
	struct completion *init_end;
	u8 peb_type = SSDFS_MAPTBL_UNKNOWN_PEB_TYPE;
	u32 pebs_per_seg;
	u64 seg_id;
	u64 cur_leb;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p, prev_leb %llu\n",
		  fsi, prev_leb);
#endif /* CONFIG_SSDFS_DEBUG */

	peb_type = SEG2PEB_TYPE(SSDFS_SB_SEG_TYPE);
	pebs_per_seg = fsi->pebs_per_seg;

	seg_id = SSDFS_LEB2SEG(fsi, prev_leb);
	if (seg_id >= U64_MAX) {
		SSDFS_ERR("invalid seg_id for leb_id %llu\n",
			  prev_leb);
		return -ERANGE;
	}

	for (i = 0; i < pebs_per_seg; i++) {
		cur_leb = ssdfs_get_leb_id_for_peb_index(fsi, seg_id, i);
		if (cur_leb >= U64_MAX) {
			SSDFS_ERR("invalid leb_id for seg_id %llu\n",
				  seg_id);
			return -ERANGE;
		}

		err = ssdfs_maptbl_erase_reserved_peb_now(fsi,
							  cur_leb,
							  peb_type,
							  &init_end);
		if (err == -EAGAIN) {
			err = SSDFS_WAIT_COMPLETION(init_end);
			if (unlikely(err)) {
				SSDFS_ERR("maptbl init failed: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_maptbl_erase_reserved_peb_now(fsi,
								  cur_leb,
								  peb_type,
								  &init_end);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to erase reserved dirty PEB: "
				  "leb_id %llu, err %d\n",
				  cur_leb, err);
			return err;
		}
	}

	return 0;
}

static int ssdfs_move_on_next_peb_in_sb_seg(struct super_block *sb,
					    int sb_seg_type,
					    sb_pebs_array *sb_lebs,
					    sb_pebs_array *sb_pebs)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	u64 prev_leb, cur_leb, next_leb, reserved_leb;
	u64 prev_peb, cur_peb, next_peb, reserved_peb;
#ifdef CONFIG_SSDFS_DEBUG
	u64 new_leb = U64_MAX, new_peb = U64_MAX;
#endif /* CONFIG_SSDFS_DEBUG */
	struct ssdfs_maptbl_peb_relation pebr;
	u8 peb_type = SSDFS_MAPTBL_SBSEG_PEB_TYPE;
	struct completion *end = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !sb_lebs || !sb_pebs);

	if (sb_seg_type >= SSDFS_SB_SEG_COPY_MAX) {
		SSDFS_ERR("invalid sb_seg_type %#x\n",
			  sb_seg_type);
		return -EINVAL;
	}

	SSDFS_DBG("sb %p, sb_seg_type %#x\n", sb, sb_seg_type);
#endif /* CONFIG_SSDFS_DEBUG */

	prev_leb = (*sb_lebs)[SSDFS_PREV_SB_SEG][sb_seg_type];
	cur_leb = (*sb_lebs)[SSDFS_CUR_SB_SEG][sb_seg_type];
	next_leb = cur_leb + 1;
	reserved_leb = (*sb_lebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type];

	prev_peb = (*sb_pebs)[SSDFS_PREV_SB_SEG][sb_seg_type];
	cur_peb = (*sb_pebs)[SSDFS_CUR_SB_SEG][sb_seg_type];
	next_peb = U64_MAX;
	reserved_peb = (*sb_pebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type];

	err = ssdfs_maptbl_convert_leb2peb(fsi, next_leb,
					   peb_type,
					   &pebr, &end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("maptbl init failed: "
				  "err %d\n", err);
			goto finish_move_sb_seg;
		}

		err = ssdfs_maptbl_convert_leb2peb(fsi, next_leb,
						   peb_type,
						   &pebr, &end);
	}

	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("LEB %llu doesn't mapped\n", next_leb);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_move_sb_seg;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to convert LEB %llu to PEB: err %d\n",
			  next_leb, err);
		goto finish_move_sb_seg;
	}

	next_peb = pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(next_peb == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	(*sb_lebs)[SSDFS_PREV_SB_SEG][sb_seg_type] = cur_leb;
	(*sb_pebs)[SSDFS_PREV_SB_SEG][sb_seg_type] = cur_peb;

	(*sb_lebs)[SSDFS_CUR_SB_SEG][sb_seg_type] = next_leb;
	(*sb_pebs)[SSDFS_CUR_SB_SEG][sb_seg_type] = next_peb;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("cur_leb %llu, cur_peb %llu, "
		  "next_leb %llu, next_peb %llu, "
		  "prev_leb %llu, prev_peb %llu, "
		  "reserved_leb %llu, reserved_peb %llu, "
		  "new_leb %llu, new_peb %llu\n",
		  cur_leb, cur_peb,
		  next_leb, next_peb,
		  prev_leb, prev_peb,
		  reserved_leb, reserved_peb,
		  new_leb, new_peb);
#endif /* CONFIG_SSDFS_DEBUG */

	if (prev_leb == U64_MAX)
		goto finish_move_sb_seg;
	else {
		err = ssdfs_erase_dirty_prev_sb_segs(fsi, prev_leb);
		if (unlikely(err)) {
			SSDFS_ERR("fail erase dirty PEBs: "
				  "prev_leb %llu, err %d\n",
				  prev_leb, err);
			goto finish_move_sb_seg;
		}
	}

finish_move_sb_seg:
	return err;
}

#ifdef CONFIG_SSDFS_FIXED_SUPERBLOCK_SEGMENTS_SET
static int ssdfs_move_on_first_peb_next_sb_seg(struct super_block *sb,
						int sb_seg_type,
						sb_pebs_array *sb_lebs,
						sb_pebs_array *sb_pebs)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	u64 prev_leb, cur_leb, next_leb, reserved_leb;
	u64 prev_peb, cur_peb, next_peb, reserved_peb;
	u64 seg_id;
	struct ssdfs_maptbl_peb_relation pebr;
	u8 peb_type = SSDFS_MAPTBL_SBSEG_PEB_TYPE;
	loff_t offset;
	struct completion *end = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !sb_lebs || !sb_pebs);

	if (sb_seg_type >= SSDFS_SB_SEG_COPY_MAX) {
		SSDFS_ERR("invalid sb_seg_type %#x\n",
			  sb_seg_type);
		return -EINVAL;
	}

	SSDFS_DBG("sb %p, sb_seg_type %#x\n", sb, sb_seg_type);
#endif /* CONFIG_SSDFS_DEBUG */

	prev_leb = (*sb_lebs)[SSDFS_PREV_SB_SEG][sb_seg_type];
	cur_leb = (*sb_lebs)[SSDFS_CUR_SB_SEG][sb_seg_type];
	next_leb = (*sb_lebs)[SSDFS_NEXT_SB_SEG][sb_seg_type];
	reserved_leb = (*sb_lebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type];

	prev_peb = (*sb_pebs)[SSDFS_PREV_SB_SEG][sb_seg_type];
	cur_peb = (*sb_pebs)[SSDFS_CUR_SB_SEG][sb_seg_type];
	next_peb = (*sb_pebs)[SSDFS_NEXT_SB_SEG][sb_seg_type];
	reserved_peb = (*sb_pebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type];

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("cur_peb %llu, next_peb %llu, "
		  "cur_leb %llu, next_leb %llu\n",
		  cur_peb, next_peb, cur_leb, next_leb);
#endif /* CONFIG_SSDFS_DEBUG */

	(*sb_lebs)[SSDFS_CUR_SB_SEG][sb_seg_type] = next_leb;
	(*sb_pebs)[SSDFS_CUR_SB_SEG][sb_seg_type] = next_peb;

	if (prev_leb >= U64_MAX) {
		(*sb_lebs)[SSDFS_PREV_SB_SEG][sb_seg_type] = cur_leb;
		(*sb_pebs)[SSDFS_PREV_SB_SEG][sb_seg_type] = cur_peb;

		if (fsi->pebs_per_seg == 1) {
			(*sb_lebs)[SSDFS_NEXT_SB_SEG][sb_seg_type] =
								reserved_leb;
			(*sb_pebs)[SSDFS_NEXT_SB_SEG][sb_seg_type] =
								reserved_peb;

			(*sb_lebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type] =
									U64_MAX;
			(*sb_pebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type] =
									U64_MAX;
		} else {
			/*
			 * do nothing
			 */
		}
	} else {
		err = ssdfs_erase_dirty_prev_sb_segs(fsi, prev_leb);
		if (unlikely(err)) {
			SSDFS_ERR("fail erase dirty PEBs: "
				  "prev_leb %llu, err %d\n",
				  prev_leb, err);
			goto finish_move_sb_seg;
		}

		if (fsi->pebs_per_seg == 1) {
			(*sb_lebs)[SSDFS_NEXT_SB_SEG][sb_seg_type] =
								prev_leb;
			(*sb_pebs)[SSDFS_NEXT_SB_SEG][sb_seg_type] =
								prev_peb;

			(*sb_lebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type] =
									U64_MAX;
			(*sb_pebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type] =
									U64_MAX;

			(*sb_lebs)[SSDFS_PREV_SB_SEG][sb_seg_type] = cur_leb;
			(*sb_pebs)[SSDFS_PREV_SB_SEG][sb_seg_type] = cur_peb;
		} else {
			(*sb_lebs)[SSDFS_NEXT_SB_SEG][sb_seg_type] =
								reserved_leb;
			(*sb_pebs)[SSDFS_NEXT_SB_SEG][sb_seg_type] =
								reserved_peb;

			seg_id = SSDFS_LEB2SEG(fsi, prev_leb);
			if (seg_id >= U64_MAX) {
				err = -ERANGE;
				SSDFS_ERR("invalid seg_id for leb_id %llu\n",
					  prev_leb);
				goto finish_move_sb_seg;
			}

			prev_leb = ssdfs_get_leb_id_for_peb_index(fsi, seg_id, 0);
			if (prev_leb >= U64_MAX) {
				err = -ERANGE;
				SSDFS_ERR("invalid leb_id for seg_id %llu\n",
					  seg_id);
				goto finish_move_sb_seg;
			}

			err = ssdfs_maptbl_convert_leb2peb(fsi, prev_leb,
							   peb_type,
							   &pebr, &end);
			if (err == -EAGAIN) {
				err = SSDFS_WAIT_COMPLETION(end);
				if (unlikely(err)) {
					SSDFS_ERR("maptbl init failed: "
						  "err %d\n", err);
					goto finish_move_sb_seg;
				}

				err = ssdfs_maptbl_convert_leb2peb(fsi,
								   prev_leb,
								   peb_type,
								   &pebr, &end);
			}

			if (unlikely(err)) {
				SSDFS_ERR("fail to convert LEB %llu to PEB: "
					  "err %d\n", prev_leb, err);
				goto finish_move_sb_seg;
			}

			prev_peb = pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id;

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(prev_peb == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

			(*sb_lebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type] =
									prev_leb;
			(*sb_pebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type] =
									prev_peb;

			(*sb_lebs)[SSDFS_PREV_SB_SEG][sb_seg_type] = cur_leb;
			(*sb_pebs)[SSDFS_PREV_SB_SEG][sb_seg_type] = cur_peb;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("cur_leb %llu, cur_peb %llu, "
		  "next_leb %llu, next_peb %llu, "
		  "reserved_leb %llu, reserved_peb %llu, "
		  "prev_leb %llu, prev_peb %llu\n",
		  (*sb_lebs)[SSDFS_CUR_SB_SEG][sb_seg_type],
		  (*sb_pebs)[SSDFS_CUR_SB_SEG][sb_seg_type],
		  (*sb_lebs)[SSDFS_NEXT_SB_SEG][sb_seg_type],
		  (*sb_pebs)[SSDFS_NEXT_SB_SEG][sb_seg_type],
		  (*sb_lebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type],
		  (*sb_pebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type],
		  (*sb_lebs)[SSDFS_PREV_SB_SEG][sb_seg_type],
		  (*sb_pebs)[SSDFS_PREV_SB_SEG][sb_seg_type]);
#endif /* CONFIG_SSDFS_DEBUG */

	if (fsi->is_zns_device) {
		cur_peb = (*sb_pebs)[SSDFS_CUR_SB_SEG][sb_seg_type];
		offset = cur_peb * fsi->erasesize;

		err = fsi->devops->open_zone(fsi->sb, offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to open zone: "
				  "offset %llu, err %d\n",
				  offset, err);
			return err;
		}
	}

finish_move_sb_seg:
	return err;
}
#else
static int ssdfs_move_on_first_peb_next_sb_seg(struct super_block *sb,
						int sb_seg_type,
						sb_pebs_array *sb_lebs,
						sb_pebs_array *sb_pebs)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	struct ssdfs_segment_bmap *segbmap = fsi->segbmap;
	struct ssdfs_maptbl_cache *maptbl_cache = &fsi->maptbl_cache;
	u64 prev_leb, cur_leb, next_leb, reserved_leb;
	u64 prev_peb, cur_peb, next_peb, reserved_peb;
	u64 new_leb = U64_MAX, new_peb = U64_MAX;
	u64 reserved_seg;
	u64 prev_seg, cur_seg;
	struct ssdfs_maptbl_peb_relation pebr;
	u8 peb_type = SSDFS_MAPTBL_SBSEG_PEB_TYPE;
	struct completion *end = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !sb_lebs || !sb_pebs);

	if (sb_seg_type >= SSDFS_SB_SEG_COPY_MAX) {
		SSDFS_ERR("invalid sb_seg_type %#x\n",
			  sb_seg_type);
		return -EINVAL;
	}

	SSDFS_DBG("sb %p, sb_seg_type %#x\n", sb, sb_seg_type);
#endif /* CONFIG_SSDFS_DEBUG */

	prev_leb = (*sb_lebs)[SSDFS_PREV_SB_SEG][sb_seg_type];
	cur_leb = (*sb_lebs)[SSDFS_CUR_SB_SEG][sb_seg_type];
	next_leb = (*sb_lebs)[SSDFS_NEXT_SB_SEG][sb_seg_type];
	reserved_leb = (*sb_lebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type];

	prev_peb = (*sb_pebs)[SSDFS_PREV_SB_SEG][sb_seg_type];
	cur_peb = (*sb_pebs)[SSDFS_CUR_SB_SEG][sb_seg_type];
	next_peb = (*sb_pebs)[SSDFS_NEXT_SB_SEG][sb_seg_type];
	reserved_peb = (*sb_pebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type];

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("cur_peb %llu, next_peb %llu, "
		  "cur_leb %llu, next_leb %llu\n",
		  cur_peb, next_peb, cur_leb, next_leb);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_reserve_clean_segment(sb, sb_seg_type, cur_leb,
					  &reserved_seg);
	if (unlikely(err)) {
		SSDFS_ERR("fail to reserve clean segment: err %d\n", err);
		goto finish_move_sb_seg;
	}

	new_leb = ssdfs_get_leb_id_for_peb_index(fsi, reserved_seg, 0);
	if (new_leb >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("fail to convert PEB index into LEB ID: "
			  "seg %llu\n", reserved_seg);
		goto finish_move_sb_seg;
	}

	err = ssdfs_maptbl_convert_leb2peb(fsi, new_leb,
					   peb_type,
					   &pebr, &end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("maptbl init failed: "
				  "err %d\n", err);
			goto finish_move_sb_seg;
		}

		err = ssdfs_maptbl_convert_leb2peb(fsi, new_leb,
						   peb_type,
						   &pebr, &end);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to convert LEB %llu to PEB: err %d\n",
			  new_leb, err);
		goto finish_move_sb_seg;
	}

	new_peb = pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(new_peb == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	(*sb_lebs)[SSDFS_PREV_SB_SEG][sb_seg_type] = cur_leb;
	(*sb_pebs)[SSDFS_PREV_SB_SEG][sb_seg_type] = cur_peb;

	(*sb_lebs)[SSDFS_CUR_SB_SEG][sb_seg_type] = next_leb;
	(*sb_pebs)[SSDFS_CUR_SB_SEG][sb_seg_type] = next_peb;

	(*sb_lebs)[SSDFS_NEXT_SB_SEG][sb_seg_type] = reserved_leb;
	(*sb_pebs)[SSDFS_NEXT_SB_SEG][sb_seg_type] = reserved_peb;

	(*sb_lebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type] = new_leb;
	(*sb_pebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type] = new_peb;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("cur_leb %llu, cur_peb %llu, "
		  "next_leb %llu, next_peb %llu, "
		  "reserved_leb %llu, reserved_peb %llu, "
		  "new_leb %llu, new_peb %llu\n",
		  cur_leb, cur_peb,
		  next_leb, next_peb,
		  reserved_leb, reserved_peb,
		  new_leb, new_peb);
#endif /* CONFIG_SSDFS_DEBUG */

	if (prev_leb == U64_MAX)
		goto finish_move_sb_seg;

	prev_seg = SSDFS_LEB2SEG(fsi, prev_leb);
	cur_seg = SSDFS_LEB2SEG(fsi, cur_leb);

	if (prev_seg != cur_seg) {
		err = ssdfs_segbmap_change_state(segbmap, prev_seg,
						 SSDFS_SEG_DIRTY, &end);
		if (err == -EAGAIN) {
			err = SSDFS_WAIT_COMPLETION(end);
			if (unlikely(err)) {
				SSDFS_ERR("segbmap init failed: "
					  "err %d\n", err);
				goto finish_move_sb_seg;
			}

			err = ssdfs_segbmap_change_state(segbmap, prev_seg,
							 SSDFS_SEG_DIRTY, &end);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to change segment state: "
				  "seg %llu, state %#x, err %d\n",
				  prev_seg, SSDFS_SEG_DIRTY, err);
			goto finish_move_sb_seg;
		}
	}

	err = ssdfs_maptbl_change_peb_state(fsi, prev_leb, peb_type,
					    SSDFS_MAPTBL_DIRTY_PEB_STATE,
					    &end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("maptbl init failed: "
				  "err %d\n", err);
			goto finish_move_sb_seg;
		}

		err = ssdfs_maptbl_change_peb_state(fsi,
						prev_leb, peb_type,
						SSDFS_MAPTBL_DIRTY_PEB_STATE,
						&end);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to change the PEB state: "
			  "leb_id %llu, new_state %#x, err %d\n",
			  prev_leb, SSDFS_MAPTBL_DIRTY_PEB_STATE, err);
		goto finish_move_sb_seg;
	}

	err = ssdfs_maptbl_cache_forget_leb2peb(maptbl_cache, prev_leb,
						SSDFS_PEB_STATE_CONSISTENT);
	if (unlikely(err)) {
		SSDFS_ERR("fail to forget prev_leb %llu, err %d\n",
			  prev_leb, err);
		goto finish_move_sb_seg;
	}

finish_move_sb_seg:
	return err;
}
#endif /* CONFIG_SSDFS_FIXED_SUPERBLOCK_SEGMENTS_SET */

static int ssdfs_move_on_next_sb_seg(struct super_block *sb,
				     int sb_seg_type,
				     sb_pebs_array *sb_lebs,
				     sb_pebs_array *sb_pebs)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	u64 cur_leb, next_leb;
	u64 cur_peb;
	u8 peb_type = SSDFS_MAPTBL_SBSEG_PEB_TYPE;
	struct completion *end = NULL;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !sb_lebs || !sb_pebs);

	if (sb_seg_type >= SSDFS_SB_SEG_COPY_MAX) {
		SSDFS_ERR("invalid sb_seg_type %#x\n",
			  sb_seg_type);
		return -EINVAL;
	}

	SSDFS_DBG("sb %p, sb_seg_type %#x\n", sb, sb_seg_type);
#endif /* CONFIG_SSDFS_DEBUG */

	cur_leb = (*sb_lebs)[SSDFS_CUR_SB_SEG][sb_seg_type];
	cur_peb = (*sb_pebs)[SSDFS_CUR_SB_SEG][sb_seg_type];

	next_leb = cur_leb + 1;

	err = ssdfs_maptbl_change_peb_state(fsi, cur_leb, peb_type,
					    SSDFS_MAPTBL_USED_PEB_STATE,
					    &end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("maptbl init failed: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_maptbl_change_peb_state(fsi,
					cur_leb, peb_type,
					SSDFS_MAPTBL_USED_PEB_STATE,
					&end);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to change the PEB state: "
			  "leb_id %llu, new_state %#x, err %d\n",
			  cur_leb, SSDFS_MAPTBL_USED_PEB_STATE, err);
		return err;
	}

	if (!ssdfs_sb_seg_exhausted(fsi, cur_leb, next_leb)) {
		err = ssdfs_move_on_next_peb_in_sb_seg(sb, sb_seg_type,
							sb_lebs, sb_pebs);
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to move on next PEB of segment: "
				  "cur_leb %llu, next_leb %llu\n",
				  cur_leb, next_leb);
#endif /* CONFIG_SSDFS_DEBUG */
			goto try_move_on_first_peb_next_sb_seg;
		}
	} else {
try_move_on_first_peb_next_sb_seg:
		err = ssdfs_move_on_first_peb_next_sb_seg(sb, sb_seg_type,
							sb_lebs, sb_pebs);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to move on next sb segment: "
			  "sb_seg_type %#x, cur_leb %llu, "
			  "cur_peb %llu, err %d\n",
			  sb_seg_type, cur_leb,
			  cur_peb, err);
		return err;
	}

	return 0;
}

static int ssdfs_move_on_next_sb_segs_pair(struct super_block *sb)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	sb_pebs_array sb_lebs;
	sb_pebs_array sb_pebs;
	size_t array_size;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p", sb);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(fsi->fs_feature_compat & SSDFS_HAS_SEGBMAP_COMPAT_FLAG) ||
	    !(fsi->fs_feature_compat & SSDFS_HAS_MAPTBL_COMPAT_FLAG)) {
		SSDFS_ERR("volume hasn't segbmap or maptbl\n");
		return -EIO;
	}

	array_size = sizeof(u64);
	array_size *= SSDFS_SB_CHAIN_MAX;
	array_size *= SSDFS_SB_SEG_COPY_MAX;

	down_read(&fsi->sb_segs_sem);
	ssdfs_memcpy(sb_lebs, 0, array_size,
		     fsi->sb_lebs, 0, array_size,
		     array_size);
	ssdfs_memcpy(sb_pebs, 0, array_size,
		     fsi->sb_pebs, 0, array_size,
		     array_size);
	up_read(&fsi->sb_segs_sem);

	for (i = 0; i < SSDFS_SB_SEG_COPY_MAX; i++) {
		err = ssdfs_move_on_next_sb_seg(sb, i, &sb_lebs, &sb_pebs);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move on next sb PEB: err %d\n",
				  err);
			return err;
		}
	}

	down_write(&fsi->sb_segs_sem);
	ssdfs_memcpy(fsi->sb_lebs, 0, array_size,
		     sb_lebs, 0, array_size,
		     array_size);
	ssdfs_memcpy(fsi->sb_pebs, 0, array_size,
		     sb_pebs, 0, array_size,
		     array_size);
	up_write(&fsi->sb_segs_sem);

	return 0;
}

static
int ssdfs_prepare_sb_log(struct super_block *sb,
			 struct ssdfs_peb_extent *last_sb_log)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !last_sb_log);

	SSDFS_DBG("sb %p, last_sb_log %p\n",
		  sb, last_sb_log);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_define_next_sb_log_place(sb, last_sb_log);
	switch (err) {
	case -EFBIG: /* current sb segment is exhausted */
	case -EIO: /* current sb segment is corrupted */
		err = ssdfs_move_on_next_sb_segs_pair(sb);
		if (err) {
			SSDFS_ERR("fail to move on next sb segs pair: err %d\n",
				  err);
			return err;
		}
		err = ssdfs_define_next_sb_log_place(sb, last_sb_log);
		if (unlikely(err)) {
			SSDFS_ERR("unable to define next sb log place: err %d\n",
				  err);
			return err;
		}
		break;

	default:
		if (err) {
			SSDFS_ERR("unable to define next sb log place: err %d\n",
				  err);
			return err;
		}
		break;
	}

	return 0;
}

static void
ssdfs_prepare_maptbl_cache_descriptor(struct ssdfs_metadata_descriptor *desc,
				      u32 offset,
				      struct ssdfs_payload_content *payload,
				      u32 payload_size)
{
	unsigned i;
	u32 csum = ~0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !payload);

	SSDFS_DBG("desc %p, offset %u, payload %p\n",
		  desc, offset, payload);
#endif /* CONFIG_SSDFS_DEBUG */

	desc->offset = cpu_to_le32(offset);
	desc->size = cpu_to_le32(payload_size);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(payload_size >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	desc->check.bytes = cpu_to_le16((u16)payload_size);
	desc->check.flags = cpu_to_le16(SSDFS_CRC32);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(folio_batch_count(&payload->batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < folio_batch_count(&payload->batch); i++) {
		struct folio *folio = payload->batch.folios[i];
		struct ssdfs_maptbl_cache_header *hdr;
		void *kaddr;
		u16 bytes_count;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);

		hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
		bytes_count = le16_to_cpu(hdr->bytes_count);

		csum = crc32(csum, kaddr, bytes_count);

		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);
	}

	desc->check.csum = cpu_to_le32(csum);
}

static
int ssdfs_prepare_snapshot_rules_for_commit(struct ssdfs_fs_info *fsi,
					struct ssdfs_metadata_descriptor *desc,
					u32 offset)
{
	struct ssdfs_snapshot_rules_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_snapshot_rules_header);
	size_t info_size = sizeof(struct ssdfs_snapshot_rule_info);
	struct ssdfs_snapshot_rule_item *item = NULL;
	u32 payload_off;
	u32 item_off;
	u32 pagesize = fsi->pagesize;
	u16 items_count = 0;
	u16 items_capacity = 0;
	u32 area_size = 0;
	struct list_head *this, *next;
	u32 csum = ~0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !desc);

	SSDFS_DBG("fsi %p, offset %u\n",
		  fsi, offset);
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_ssdfs_snapshot_rules_list_empty(&fsi->snapshots.rules_list)) {
		SSDFS_DBG("snapshot rules list is empty\n");
		return -ENODATA;
	}

	payload_off = offsetof(struct ssdfs_log_footer, payload);
	hdr = SSDFS_SNRU_HDR((u8 *)fsi->sbi.vs_buf + payload_off);
	memset(hdr, 0, hdr_size);
	area_size = pagesize - payload_off;
	item_off = payload_off + hdr_size;

	items_capacity = (u16)((area_size - hdr_size) / info_size);
	area_size = min_t(u32, area_size, (u32)items_capacity * info_size);

	spin_lock(&fsi->snapshots.rules_list.lock);
	list_for_each_safe(this, next, &fsi->snapshots.rules_list.list) {
		item = list_entry(this, struct ssdfs_snapshot_rule_item, list);

		err = ssdfs_memcpy(fsi->sbi.vs_buf, item_off, pagesize,
				   &item->rule, 0, info_size,
				   info_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: err %d\n", err);
			goto finish_copy_items;
		}

		item_off += info_size;
		items_count++;
	}
finish_copy_items:
	spin_unlock(&fsi->snapshots.rules_list.lock);

	if (unlikely(err))
		return err;

	hdr->magic = cpu_to_le32(SSDFS_SNAPSHOT_RULES_MAGIC);
	hdr->item_size = cpu_to_le16(info_size);
	hdr->flags = cpu_to_le16(0);

	if (items_count == 0 || items_count > items_capacity) {
		SSDFS_ERR("invalid items number: "
			  "items_count %u, items_capacity %u, "
			  "area_size %u, item_size %zu\n",
			  items_count, items_capacity,
			  area_size, info_size);
		return -ERANGE;
	}

	hdr->items_count = cpu_to_le16(items_count);
	hdr->items_capacity = cpu_to_le16(items_capacity);
	hdr->area_size = cpu_to_le16(area_size);

	desc->offset = cpu_to_le32(offset);
	desc->size = cpu_to_le32(area_size);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(area_size >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	desc->check.bytes = cpu_to_le16(area_size);
	desc->check.flags = cpu_to_le16(SSDFS_CRC32);

	csum = crc32(csum, hdr, area_size);
	desc->check.csum = cpu_to_le32(csum);

	return 0;
}

static int __ssdfs_commit_sb_log(struct super_block *sb,
				 u64 timestamp, u64 cno,
				 struct ssdfs_peb_extent *last_sb_log,
				 struct ssdfs_sb_log_payload *payload)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor hdr_desc[SSDFS_SEG_HDR_DESC_MAX];
	struct ssdfs_metadata_descriptor footer_desc[SSDFS_LOG_FOOTER_DESC_MAX];
	size_t desc_size = sizeof(struct ssdfs_metadata_descriptor);
	size_t hdr_array_bytes = desc_size * SSDFS_SEG_HDR_DESC_MAX;
	size_t footer_array_bytes = desc_size * SSDFS_LOG_FOOTER_DESC_MAX;
	struct ssdfs_metadata_descriptor *cur_hdr_desc;
	struct folio *folio;
	struct ssdfs_segment_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	struct ssdfs_log_footer *footer;
	size_t footer_size = sizeof(struct ssdfs_log_footer);
#ifdef CONFIG_SSDFS_DEBUG
	void *kaddr = NULL;
#endif /* CONFIG_SSDFS_DEBUG */
	loff_t peb_offset, offset;
	u32 flags = 0;
	u32 written = 0;
	unsigned i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !last_sb_log);
	BUG_ON(!SSDFS_FS_I(sb)->devops);
	BUG_ON(!SSDFS_FS_I(sb)->devops->write_block);
	BUG_ON((last_sb_log->page_offset + last_sb_log->pages_count) >
		(ULLONG_MAX >> PAGE_SHIFT));
	BUG_ON((last_sb_log->leb_id * SSDFS_FS_I(sb)->pebs_per_seg) >=
		SSDFS_FS_I(sb)->nsegs);
	BUG_ON(last_sb_log->peb_id >
		div_u64(ULLONG_MAX, SSDFS_FS_I(sb)->pages_per_peb));
	BUG_ON((last_sb_log->peb_id * SSDFS_FS_I(sb)->pages_per_peb) >
		(ULLONG_MAX >> SSDFS_FS_I(sb)->log_pagesize));

	SSDFS_DBG("sb %p, last_sb_log->leb_id %llu, last_sb_log->peb_id %llu, "
		  "last_sb_log->page_offset %u, last_sb_log->pages_count %u\n",
		  sb, last_sb_log->leb_id, last_sb_log->peb_id,
		  last_sb_log->page_offset, last_sb_log->pages_count);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = SSDFS_FS_I(sb);
	hdr = SSDFS_SEG_HDR(fsi->sbi.vh_buf);
	footer = SSDFS_LF(fsi->sbi.vs_buf);

	memset(hdr_desc, 0, hdr_array_bytes);
	memset(footer_desc, 0, footer_array_bytes);

	offset = (loff_t)last_sb_log->page_offset << PAGE_SHIFT;
	offset += PAGE_SIZE;

	cur_hdr_desc = &hdr_desc[SSDFS_MAPTBL_CACHE_INDEX];
	ssdfs_prepare_maptbl_cache_descriptor(cur_hdr_desc, (u32)offset,
					     &payload->maptbl_cache,
					     payload->maptbl_cache.bytes_count);

	offset += payload->maptbl_cache.bytes_count;

	cur_hdr_desc = &hdr_desc[SSDFS_LOG_FOOTER_INDEX];
	cur_hdr_desc->offset = cpu_to_le32(offset);
	cur_hdr_desc->size = cpu_to_le32(footer_size);

	ssdfs_memcpy(hdr->desc_array, 0, hdr_array_bytes,
		     hdr_desc, 0, hdr_array_bytes,
		     hdr_array_bytes);

	hdr->peb_migration_id[SSDFS_PREV_MIGRATING_PEB] =
					SSDFS_PEB_UNKNOWN_MIGRATION_ID;
	hdr->peb_migration_id[SSDFS_CUR_MIGRATING_PEB] =
					SSDFS_PEB_UNKNOWN_MIGRATION_ID;

	err = ssdfs_prepare_segment_header_for_commit(fsi,
						     last_sb_log->pages_count,
						     SSDFS_SB_SEG_TYPE,
						     SSDFS_LOG_HAS_FOOTER |
						     SSDFS_LOG_HAS_MAPTBL_CACHE,
						     timestamp, cno,
						     hdr);
	if (err) {
		SSDFS_ERR("fail to prepare segment header: err %d\n", err);
		return err;
	}

	offset += offsetof(struct ssdfs_log_footer, payload);
	cur_hdr_desc = &footer_desc[SSDFS_SNAPSHOT_RULES_AREA_INDEX];

	err = ssdfs_prepare_snapshot_rules_for_commit(fsi, cur_hdr_desc,
						      (u32)offset);
	if (err == -ENODATA) {
		err = 0;
		SSDFS_DBG("snapshot rules list is empty\n");
	} else if (err) {
		SSDFS_ERR("fail to prepare snapshot rules: err %d\n", err);
		return err;
	} else
		flags |= SSDFS_LOG_FOOTER_HAS_SNAPSHOT_RULES;

	ssdfs_memcpy(footer->desc_array, 0, footer_array_bytes,
		     footer_desc, 0, footer_array_bytes,
		     footer_array_bytes);

	err = ssdfs_prepare_log_footer_for_commit(fsi, PAGE_SIZE,
						  last_sb_log->pages_count,
						  flags, timestamp,
						  cno, footer);
	if (err) {
		SSDFS_ERR("fail to prepare log footer: err %d\n", err);
		return err;
	}

	folio = ssdfs_super_alloc_folio(GFP_KERNEL | __GFP_ZERO,
					get_order(PAGE_SIZE));
	if (IS_ERR_OR_NULL(folio)) {
		err = (folio == NULL ? -ENOMEM : PTR_ERR(folio));
		SSDFS_ERR("unable to allocate memory folio\n");
		return err;
	}

	/* ->writepage() calls put_folio() */
	ssdfs_folio_get(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	/* write segment header */
	ssdfs_folio_lock(folio);
	__ssdfs_memcpy_to_folio(folio, 0, PAGE_SIZE,
				fsi->sbi.vh_buf, 0, hdr_size,
				hdr_size);
	ssdfs_set_folio_private(folio, 0);
	folio_mark_uptodate(folio);
	folio_set_dirty(folio);
	ssdfs_folio_unlock(folio);

	peb_offset = last_sb_log->peb_id * fsi->pages_per_peb;
	peb_offset <<= fsi->log_pagesize;
	offset = (loff_t)last_sb_log->page_offset << PAGE_SHIFT;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(peb_offset > (ULLONG_MAX - (offset + PAGE_SIZE)));
#endif /* CONFIG_SSDFS_DEBUG */

	offset += peb_offset;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("offset %llu\n", offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = fsi->devops->write_block(sb, offset, folio);
	if (err) {
		SSDFS_ERR("fail to write segment header: "
			  "offset %llu, size %zu\n",
			  (u64)offset, hdr_size);
		goto cleanup_after_failure;
	}

	ssdfs_folio_lock(folio);
	folio_clear_uptodate(folio);
	ssdfs_clear_folio_private(folio, 0);
	ssdfs_folio_unlock(folio);

	offset += PAGE_SIZE;
	written = 0;

	for (i = 0; i < folio_batch_count(&payload->maptbl_cache.batch); i++) {
		struct folio *payload_folio =
				payload->maptbl_cache.batch.folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!payload_folio);
#endif /* CONFIG_SSDFS_DEBUG */

		/* ->writepage() calls put_folio() */
		ssdfs_folio_get(payload_folio);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  payload_folio,
			  folio_ref_count(payload_folio));

		kaddr = kmap_local_folio(payload_folio, 0);
		SSDFS_DBG("PAYLOAD FOLIO %d\n", i);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr, PAGE_SIZE);
		kunmap_local(kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(payload_folio);
		ssdfs_set_folio_private(payload_folio, 0);
		folio_mark_uptodate(payload_folio);
		folio_set_dirty(payload_folio);
		ssdfs_folio_unlock(payload_folio);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("offset %llu\n", offset);
#endif /* CONFIG_SSDFS_DEBUG */

		err = fsi->devops->write_block(sb, offset, payload_folio);
		if (err) {
			SSDFS_ERR("fail to write maptbl cache page: "
				  "offset %llu, folio_index %u, size %zu\n",
				  (u64)offset, i, PAGE_SIZE);
			goto cleanup_after_failure;
		}

		ssdfs_folio_lock(payload_folio);
		folio_clear_uptodate(payload_folio);
		ssdfs_clear_folio_private(folio, 0);
		ssdfs_folio_unlock(payload_folio);

		offset += PAGE_SIZE;
	}

	/* TODO: write metadata payload */

	/* ->writepage() calls put_folio() */
	ssdfs_folio_get(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	/* write log footer */
	ssdfs_folio_lock(folio);
	__ssdfs_memset_folio(folio, 0, PAGE_SIZE,
			     0, PAGE_SIZE);
	__ssdfs_memcpy_to_folio(folio, 0, PAGE_SIZE,
				fsi->sbi.vs_buf, 0, fsi->sbi.vs_buf_size,
				PAGE_SIZE);
	ssdfs_set_folio_private(folio, 0);
	folio_mark_uptodate(folio);
	folio_set_dirty(folio);
	ssdfs_folio_unlock(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("offset %llu\n", offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = fsi->devops->write_block(sb, offset, folio);
	if (err) {
		SSDFS_ERR("fail to write log footer: "
			  "offset %llu, size %zu\n",
			  (u64)offset, fsi->sbi.vs_buf_size);
		goto cleanup_after_failure;
	}

	ssdfs_folio_lock(folio);
	folio_clear_uptodate(folio);
	ssdfs_clear_folio_private(folio, 0);
	ssdfs_folio_unlock(folio);

	ssdfs_super_free_folio(folio);
	return 0;

cleanup_after_failure:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_super_free_folio(folio);

	return err;
}

static int
__ssdfs_commit_sb_log_inline(struct super_block *sb,
			     u64 timestamp, u64 cno,
			     struct ssdfs_peb_extent *last_sb_log,
			     struct ssdfs_sb_log_payload *payload,
			     u32 payload_size)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor hdr_desc[SSDFS_SEG_HDR_DESC_MAX];
	struct ssdfs_metadata_descriptor footer_desc[SSDFS_LOG_FOOTER_DESC_MAX];
	size_t desc_size = sizeof(struct ssdfs_metadata_descriptor);
	size_t hdr_array_bytes = desc_size * SSDFS_SEG_HDR_DESC_MAX;
	size_t footer_array_bytes = desc_size * SSDFS_LOG_FOOTER_DESC_MAX;
	struct ssdfs_metadata_descriptor *cur_hdr_desc;
	struct folio *folio;
	struct folio *payload_folio;
	struct ssdfs_segment_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	struct ssdfs_log_footer *footer;
	size_t footer_size = sizeof(struct ssdfs_log_footer);
	void *kaddr = NULL;
	loff_t peb_offset, offset;
	u32 inline_capacity;
	void *payload_buf;
	u32 flags = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !last_sb_log);
	BUG_ON(!SSDFS_FS_I(sb)->devops);
	BUG_ON(!SSDFS_FS_I(sb)->devops->write_block);
	BUG_ON((last_sb_log->page_offset + last_sb_log->pages_count) >
		(ULLONG_MAX >> PAGE_SHIFT));
	BUG_ON((last_sb_log->leb_id * SSDFS_FS_I(sb)->pebs_per_seg) >=
		SSDFS_FS_I(sb)->nsegs);
	BUG_ON(last_sb_log->peb_id >
		    div_u64(ULLONG_MAX, SSDFS_FS_I(sb)->pages_per_peb));
	BUG_ON((last_sb_log->peb_id * SSDFS_FS_I(sb)->pages_per_peb) >
				(ULLONG_MAX >> SSDFS_FS_I(sb)->log_pagesize));

	SSDFS_DBG("sb %p, last_sb_log->leb_id %llu, last_sb_log->peb_id %llu, "
		  "last_sb_log->page_offset %u, last_sb_log->pages_count %u\n",
		  sb, last_sb_log->leb_id, last_sb_log->peb_id,
		  last_sb_log->page_offset, last_sb_log->pages_count);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = SSDFS_FS_I(sb);
	hdr = SSDFS_SEG_HDR(fsi->sbi.vh_buf);
	footer = SSDFS_LF(fsi->sbi.vs_buf);

	memset(hdr_desc, 0, hdr_array_bytes);
	memset(footer_desc, 0, footer_array_bytes);

	offset = (loff_t)last_sb_log->page_offset << PAGE_SHIFT;
	offset += hdr_size;

	cur_hdr_desc = &hdr_desc[SSDFS_MAPTBL_CACHE_INDEX];
	ssdfs_prepare_maptbl_cache_descriptor(cur_hdr_desc, (u32)offset,
					      &payload->maptbl_cache,
					      payload_size);

	offset += payload_size;

	offset += PAGE_SIZE - 1;
	offset = (offset >> PAGE_SHIFT) << PAGE_SHIFT;

	cur_hdr_desc = &hdr_desc[SSDFS_LOG_FOOTER_INDEX];
	cur_hdr_desc->offset = cpu_to_le32(offset);
	cur_hdr_desc->size = cpu_to_le32(footer_size);

	ssdfs_memcpy(hdr->desc_array, 0, hdr_array_bytes,
		     hdr_desc, 0, hdr_array_bytes,
		     hdr_array_bytes);

	hdr->peb_migration_id[SSDFS_PREV_MIGRATING_PEB] =
					SSDFS_PEB_UNKNOWN_MIGRATION_ID;
	hdr->peb_migration_id[SSDFS_CUR_MIGRATING_PEB] =
					SSDFS_PEB_UNKNOWN_MIGRATION_ID;

	err = ssdfs_prepare_segment_header_for_commit(fsi,
						     last_sb_log->pages_count,
						     SSDFS_SB_SEG_TYPE,
						     SSDFS_LOG_HAS_FOOTER |
						     SSDFS_LOG_HAS_MAPTBL_CACHE,
						     timestamp, cno,
						     hdr);
	if (err) {
		SSDFS_ERR("fail to prepare segment header: err %d\n", err);
		return err;
	}

	offset += offsetof(struct ssdfs_log_footer, payload);
	cur_hdr_desc = &footer_desc[SSDFS_SNAPSHOT_RULES_AREA_INDEX];

	err = ssdfs_prepare_snapshot_rules_for_commit(fsi, cur_hdr_desc,
						      (u32)offset);
	if (err == -ENODATA) {
		err = 0;
		SSDFS_DBG("snapshot rules list is empty\n");
	} else if (err) {
		SSDFS_ERR("fail to prepare snapshot rules: err %d\n", err);
		return err;
	} else
		flags |= SSDFS_LOG_FOOTER_HAS_SNAPSHOT_RULES;

	ssdfs_memcpy(footer->desc_array, 0, footer_array_bytes,
		     footer_desc, 0, footer_array_bytes,
		     footer_array_bytes);

	err = ssdfs_prepare_log_footer_for_commit(fsi, PAGE_SIZE,
						  last_sb_log->pages_count,
						  flags, timestamp,
						  cno, footer);
	if (err) {
		SSDFS_ERR("fail to prepare log footer: err %d\n", err);
		return err;
	}

	if (folio_batch_count(&payload->maptbl_cache.batch) != 1) {
		SSDFS_WARN("payload contains several memory folios\n");
		return -ERANGE;
	}

	inline_capacity = PAGE_SIZE - hdr_size;

	if (payload_size > inline_capacity) {
		SSDFS_ERR("payload_size %u > inline_capacity %u\n",
			  payload_size, inline_capacity);
		return -ERANGE;
	}

	payload_buf = ssdfs_super_kmalloc(inline_capacity, GFP_KERNEL);
	if (!payload_buf) {
		SSDFS_ERR("fail to allocate payload buffer\n");
		return -ENOMEM;
	}

	folio = ssdfs_super_alloc_folio(GFP_KERNEL | __GFP_ZERO,
					get_order(PAGE_SIZE));
	if (IS_ERR_OR_NULL(folio)) {
		err = (folio == NULL ? -ENOMEM : PTR_ERR(folio));
		SSDFS_ERR("unable to allocate memory folio\n");
		ssdfs_super_kfree(payload_buf);
		return err;
	}

	/* ->writepage() calls put_folio() */
	ssdfs_folio_get(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	payload_folio = payload->maptbl_cache.batch.folios[0];
	if (!payload_folio) {
		err = -ERANGE;
		SSDFS_ERR("invalid payload folio\n");
		goto free_payload_buffer;
	}

	ssdfs_folio_lock(payload_folio);
	err = __ssdfs_memcpy_from_folio(payload_buf, 0, inline_capacity,
					payload_folio, 0, PAGE_SIZE,
					payload_size);
	ssdfs_folio_unlock(payload_folio);

	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		goto free_payload_buffer;
	}

	/* write segment header + payload */
	ssdfs_folio_lock(folio);
	kaddr = kmap_local_folio(folio, 0);
	ssdfs_memcpy(kaddr, 0, PAGE_SIZE,
		     fsi->sbi.vh_buf, 0, hdr_size,
		     hdr_size);
	err = ssdfs_memcpy(kaddr, hdr_size, PAGE_SIZE,
			   payload_buf, 0, inline_capacity,
			   payload_size);
	flush_dcache_folio(folio);
	kunmap_local(kaddr);
	if (!err) {
		ssdfs_set_folio_private(folio, 0);
		folio_mark_uptodate(folio);
		folio_set_dirty(folio);
	}
	ssdfs_folio_unlock(folio);

	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		goto free_payload_buffer;
	}

free_payload_buffer:
	ssdfs_super_kfree(payload_buf);

	if (unlikely(err))
		goto cleanup_after_failure;

	peb_offset = last_sb_log->peb_id * fsi->pages_per_peb;
	peb_offset <<= fsi->log_pagesize;
	offset = (loff_t)last_sb_log->page_offset << PAGE_SHIFT;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(peb_offset > (ULLONG_MAX - (offset + PAGE_SIZE)));
#endif /* CONFIG_SSDFS_DEBUG */

	offset += peb_offset;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("offset %llu\n", offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = fsi->devops->write_block(sb, offset, folio);
	if (err) {
		SSDFS_ERR("fail to write segment header: "
			  "offset %llu, size %zu\n",
			  (u64)offset, hdr_size + payload_size);
		goto cleanup_after_failure;
	}

	ssdfs_folio_lock(folio);
	folio_clear_uptodate(folio);
	ssdfs_clear_folio_private(folio, 0);
	ssdfs_folio_unlock(folio);

	offset += PAGE_SIZE;

	/* ->writepage() calls put_folio() */
	ssdfs_folio_get(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	/* write log footer */
	ssdfs_folio_lock(folio);
	__ssdfs_memset_folio(folio, 0, PAGE_SIZE,
			     0, PAGE_SIZE);
	__ssdfs_memcpy_to_folio(folio, 0, PAGE_SIZE,
				fsi->sbi.vs_buf, 0, fsi->sbi.vs_buf_size,
				PAGE_SIZE);
	ssdfs_set_folio_private(folio, 0);
	folio_mark_uptodate(folio);
	folio_set_dirty(folio);
	ssdfs_folio_unlock(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("offset %llu\n", offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = fsi->devops->write_block(sb, offset, folio);
	if (err) {
		SSDFS_ERR("fail to write log footer: "
			  "offset %llu, size %zu\n",
			  (u64)offset, fsi->sbi.vs_buf_size);
		goto cleanup_after_failure;
	}

	ssdfs_folio_lock(folio);
	folio_clear_uptodate(folio);
	ssdfs_clear_folio_private(folio, 0);
	ssdfs_folio_unlock(folio);

	ssdfs_super_free_folio(folio);
	return 0;

cleanup_after_failure:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_super_free_folio(folio);

	return err;
}

static int ssdfs_commit_sb_log(struct super_block *sb,
				u64 timestamp, u64 cno,
				struct ssdfs_peb_extent *last_sb_log,
				struct ssdfs_sb_log_payload *payload)
{
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	u32 inline_capacity;
	u32 payload_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !last_sb_log || !payload);

	SSDFS_DBG("sb %p, last_sb_log->leb_id %llu, last_sb_log->peb_id %llu, "
		  "last_sb_log->page_offset %u, last_sb_log->pages_count %u\n",
		  sb, last_sb_log->leb_id, last_sb_log->peb_id,
		  last_sb_log->page_offset, last_sb_log->pages_count);
#endif /* CONFIG_SSDFS_DEBUG */

	inline_capacity = PAGE_SIZE - hdr_size;
	payload_size = ssdfs_sb_payload_size(&payload->maptbl_cache.batch);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("inline_capacity %u, payload_size %u\n",
		  inline_capacity, payload_size);
#endif /* CONFIG_SSDFS_DEBUG */

	if (payload_size > inline_capacity) {
		err = __ssdfs_commit_sb_log(sb, timestamp, cno,
					    last_sb_log, payload);
	} else {
		err = __ssdfs_commit_sb_log_inline(sb, timestamp, cno,
						   last_sb_log,
						   payload, payload_size);
	}

	if (unlikely(err))
		SSDFS_ERR("fail to commit sb log: err %d\n", err);

	return err;
}

static
int ssdfs_commit_super(struct super_block *sb, u16 fs_state,
			struct ssdfs_peb_extent *last_sb_log,
			struct ssdfs_sb_log_payload *payload)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	__le64 cur_segs[SSDFS_CUR_SEGS_COUNT];
	size_t size = sizeof(__le64) * SSDFS_CUR_SEGS_COUNT;
	u64 timestamp = ssdfs_current_timestamp();
	u64 cno = ssdfs_current_cno(sb);
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !last_sb_log || !payload);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("sb %p, fs_state %u", sb, fs_state);
#else
	SSDFS_DBG("sb %p, fs_state %u", sb, fs_state);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	BUG_ON(fs_state > SSDFS_LAST_KNOWN_FS_STATE);

	if (le16_to_cpu(fsi->vs->state) == SSDFS_ERROR_FS &&
	    !ssdfs_test_opt(fsi->mount_opts, IGNORE_FS_STATE)) {
		SSDFS_DBG("refuse commit superblock: fs erroneous state\n");
		return 0;
	}

	err = ssdfs_prepare_volume_header_for_commit(fsi, fsi->vh);
	if (unlikely(err)) {
		SSDFS_CRIT("volume header is inconsistent: err %d\n", err);
		goto finish_commit_super;
	}

	err = ssdfs_prepare_current_segment_ids(fsi, cur_segs, size);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to prepare current segments IDs: err %d\n",
			   err);
		goto finish_commit_super;
	}

	err = ssdfs_prepare_volume_state_info_for_commit(fsi, fs_state,
							 cur_segs, size,
							 timestamp,
							 cno,
							 fsi->vs);
	if (unlikely(err)) {
		SSDFS_CRIT("volume state info is inconsistent: err %d\n", err);
		goto finish_commit_super;
	}

	for (i = 0; i < SSDFS_SB_SEG_COPY_MAX; i++) {
		last_sb_log->leb_id = fsi->sb_lebs[SSDFS_CUR_SB_SEG][i];
		last_sb_log->peb_id = fsi->sb_pebs[SSDFS_CUR_SB_SEG][i];
		err = ssdfs_commit_sb_log(sb, timestamp, cno,
					  last_sb_log, payload);
		if (err) {
			SSDFS_ERR("fail to commit superblock log: "
				  "leb_id %llu, peb_id %llu, "
				  "page_offset %u, pages_count %u, "
				  "err %d\n",
				  last_sb_log->leb_id,
				  last_sb_log->peb_id,
				  last_sb_log->page_offset,
				  last_sb_log->pages_count,
				  err);
			goto finish_commit_super;
		}
	}

	last_sb_log->leb_id = fsi->sb_lebs[SSDFS_CUR_SB_SEG][SSDFS_MAIN_SB_SEG];
	last_sb_log->peb_id = fsi->sb_pebs[SSDFS_CUR_SB_SEG][SSDFS_MAIN_SB_SEG];

	ssdfs_memcpy(&fsi->sbi.last_log,
		     0, sizeof(struct ssdfs_peb_extent),
		     last_sb_log,
		     0, sizeof(struct ssdfs_peb_extent),
		     sizeof(struct ssdfs_peb_extent));

finish_commit_super:
#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

static void ssdfs_memory_folio_locks_checker_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_locked_folios, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static void ssdfs_check_memory_folio_locks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_locked_folios) != 0) {
		SSDFS_WARN("Lock keeps %lld memory folios\n",
			   atomic64_read(&ssdfs_locked_folios));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static void ssdfs_memory_leaks_checker_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_allocated_folios, 0);
	atomic64_set(&ssdfs_memory_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

#ifdef CONFIG_SSDFS_POSIX_ACL
	ssdfs_acl_memory_leaks_init();
#endif /* CONFIG_SSDFS_POSIX_ACL */

	ssdfs_block_bmap_memory_leaks_init();
	ssdfs_btree_memory_leaks_init();
	ssdfs_btree_hierarchy_memory_leaks_init();
	ssdfs_btree_node_memory_leaks_init();
	ssdfs_btree_search_memory_leaks_init();

#ifdef CONFIG_SSDFS_ZLIB
	ssdfs_zlib_memory_leaks_init();
#endif /* CONFIG_SSDFS_ZLIB */

#ifdef CONFIG_SSDFS_LZO
	ssdfs_lzo_memory_leaks_init();
#endif /* CONFIG_SSDFS_LZO */

	ssdfs_compr_memory_leaks_init();
	ssdfs_cur_seg_memory_leaks_init();
	ssdfs_dentries_memory_leaks_init();

#ifdef CONFIG_SSDFS_MTD_DEVICE
	ssdfs_dev_mtd_memory_leaks_init();
#elif defined(CONFIG_SSDFS_BLOCK_DEVICE)
	ssdfs_dev_bdev_memory_leaks_init();
	ssdfs_dev_zns_memory_leaks_init();
#else
	BUILD_BUG();
#endif

	ssdfs_dir_memory_leaks_init();

#ifdef CONFIG_SSDFS_DIFF_ON_WRITE_USER_DATA
	ssdfs_diff_memory_leaks_init();
#endif /* CONFIG_SSDFS_DIFF_ON_WRITE_USER_DATA */

	ssdfs_ext_queue_memory_leaks_init();
	ssdfs_ext_tree_memory_leaks_init();

#ifdef CONFIG_SSDFS_PEB_DEDUPLICATION
	ssdfs_fingerprint_array_memory_leaks_init();
#endif /* CONFIG_SSDFS_PEB_DEDUPLICATION */

	ssdfs_file_memory_leaks_init();
	ssdfs_fs_error_memory_leaks_init();

#ifdef CONFIG_SSDFS_ONLINE_FSCK
	ssdfs_fsck_memory_leaks_init();
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

	ssdfs_inode_memory_leaks_init();
	ssdfs_ino_tree_memory_leaks_init();
	ssdfs_invext_tree_memory_leaks_init();
	ssdfs_blk2off_memory_leaks_init();
	ssdfs_farray_memory_leaks_init();
	ssdfs_folio_vector_memory_leaks_init();
	ssdfs_flush_memory_leaks_init();
	ssdfs_gc_memory_leaks_init();
	ssdfs_map_queue_memory_leaks_init();
	ssdfs_map_tbl_memory_leaks_init();
	ssdfs_map_cache_memory_leaks_init();
	ssdfs_map_thread_memory_leaks_init();
	ssdfs_migration_memory_leaks_init();
	ssdfs_peb_memory_leaks_init();
	ssdfs_read_memory_leaks_init();
	ssdfs_recovery_memory_leaks_init();
	ssdfs_req_queue_memory_leaks_init();
	ssdfs_seg_obj_memory_leaks_init();
	ssdfs_seg_bmap_memory_leaks_init();
	ssdfs_seg_blk_memory_leaks_init();
	ssdfs_seg_tree_memory_leaks_init();
	ssdfs_seq_arr_memory_leaks_init();
	ssdfs_dict_memory_leaks_init();
	ssdfs_shextree_memory_leaks_init();
	ssdfs_super_memory_leaks_init();
	ssdfs_xattr_memory_leaks_init();
	ssdfs_snap_reqs_queue_memory_leaks_init();
	ssdfs_snap_rules_list_memory_leaks_init();
	ssdfs_snap_tree_memory_leaks_init();
}

static void ssdfs_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_POSIX_ACL
	ssdfs_acl_check_memory_leaks();
#endif /* CONFIG_SSDFS_POSIX_ACL */

	ssdfs_block_bmap_check_memory_leaks();
	ssdfs_btree_check_memory_leaks();
	ssdfs_btree_hierarchy_check_memory_leaks();
	ssdfs_btree_node_check_memory_leaks();
	ssdfs_btree_search_check_memory_leaks();

#ifdef CONFIG_SSDFS_ZLIB
	ssdfs_zlib_check_memory_leaks();
#endif /* CONFIG_SSDFS_ZLIB */

#ifdef CONFIG_SSDFS_LZO
	ssdfs_lzo_check_memory_leaks();
#endif /* CONFIG_SSDFS_LZO */

	ssdfs_compr_check_memory_leaks();
	ssdfs_cur_seg_check_memory_leaks();
	ssdfs_dentries_check_memory_leaks();

#ifdef CONFIG_SSDFS_MTD_DEVICE
	ssdfs_dev_mtd_check_memory_leaks();
#elif defined(CONFIG_SSDFS_BLOCK_DEVICE)
	ssdfs_dev_bdev_check_memory_leaks();
	ssdfs_dev_zns_check_memory_leaks();
#else
	BUILD_BUG();
#endif

	ssdfs_dir_check_memory_leaks();

#ifdef CONFIG_SSDFS_DIFF_ON_WRITE_USER_DATA
	ssdfs_diff_check_memory_leaks();
#endif /* CONFIG_SSDFS_DIFF_ON_WRITE_USER_DATA */

	ssdfs_ext_queue_check_memory_leaks();
	ssdfs_ext_tree_check_memory_leaks();

#ifdef CONFIG_SSDFS_PEB_DEDUPLICATION
	ssdfs_fingerprint_array_check_memory_leaks();
#endif /* CONFIG_SSDFS_PEB_DEDUPLICATION */

	ssdfs_file_check_memory_leaks();
	ssdfs_fs_error_check_memory_leaks();

#ifdef CONFIG_SSDFS_ONLINE_FSCK
	ssdfs_fsck_check_memory_leaks();
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

	ssdfs_inode_check_memory_leaks();
	ssdfs_ino_tree_check_memory_leaks();
	ssdfs_invext_tree_check_memory_leaks();
	ssdfs_blk2off_check_memory_leaks();
	ssdfs_farray_check_memory_leaks();
	ssdfs_folio_vector_check_memory_leaks();
	ssdfs_flush_check_memory_leaks();
	ssdfs_gc_check_memory_leaks();
	ssdfs_map_queue_check_memory_leaks();
	ssdfs_map_tbl_check_memory_leaks();
	ssdfs_map_cache_check_memory_leaks();
	ssdfs_map_thread_check_memory_leaks();
	ssdfs_migration_check_memory_leaks();
	ssdfs_peb_check_memory_leaks();
	ssdfs_read_check_memory_leaks();
	ssdfs_recovery_check_memory_leaks();
	ssdfs_req_queue_check_memory_leaks();
	ssdfs_seg_obj_check_memory_leaks();
	ssdfs_seg_bmap_check_memory_leaks();
	ssdfs_seg_blk_check_memory_leaks();
	ssdfs_seg_tree_check_memory_leaks();
	ssdfs_seq_arr_check_memory_leaks();
	ssdfs_dict_check_memory_leaks();
	ssdfs_shextree_check_memory_leaks();
	ssdfs_super_check_memory_leaks();
	ssdfs_xattr_check_memory_leaks();
	ssdfs_snap_reqs_queue_check_memory_leaks();
	ssdfs_snap_rules_list_check_memory_leaks();
	ssdfs_snap_tree_check_memory_leaks();

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
#ifdef CONFIG_SSDFS_SHOW_CONSUMED_MEMORY
	if (atomic64_read(&ssdfs_allocated_folios) != 0) {
		SSDFS_ERR("Memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_allocated_folios));
	}

	if (atomic64_read(&ssdfs_memory_leaks) != 0) {
		SSDFS_ERR("Memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_memory_leaks));
	}
#else
	if (atomic64_read(&ssdfs_allocated_folios) != 0) {
		SSDFS_WARN("Memory leaks include %lld folios\n",
			   atomic64_read(&ssdfs_allocated_folios));
	}

	if (atomic64_read(&ssdfs_memory_leaks) != 0) {
		SSDFS_WARN("Memory allocator suffers from %lld leaks\n",
			   atomic64_read(&ssdfs_memory_leaks));
	}
#endif /* CONFIG_SSDFS_SHOW_CONSUMED_MEMORY */
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static int ssdfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct ssdfs_fs_info *fs_info;
	struct ssdfs_peb_extent last_sb_log = {0};
	struct ssdfs_sb_log_payload payload;
	struct inode *root_i;
	u64 fs_feature_compat;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("sb %p, data %p, silent %#x\n", sb, data, silent);
#else
	SSDFS_DBG("sb %p, data %p, silent %#x\n", sb, data, silent);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("segment header size %zu, "
		  "partial log header size %zu, "
		  "footer size %zu\n",
		  sizeof(struct ssdfs_segment_header),
		  sizeof(struct ssdfs_partial_log_header),
		  sizeof(struct ssdfs_log_footer));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_memory_folio_locks_checker_init();
	ssdfs_memory_leaks_checker_init();

	fs_info = ssdfs_super_kzalloc(sizeof(*fs_info), GFP_KERNEL);
	if (!fs_info)
		return -ENOMEM;

	/* set initial block size value for valid log search */
	fs_info->log_pagesize = ilog2(SSDFS_4KB);
	fs_info->pagesize = SSDFS_4KB;

#ifdef CONFIG_SSDFS_TESTING
	fs_info->do_fork_invalidation = true;
#endif /* CONFIG_SSDFS_TESTING */

	fs_info->max_open_zones = 0;
	fs_info->is_zns_device = false;
	fs_info->zone_size = U64_MAX;
	fs_info->zone_capacity = U64_MAX;
	atomic_set(&fs_info->open_zones, 0);

#ifdef CONFIG_SSDFS_ONLINE_FSCK
	atomic_set(&fs_info->fsck_priority, 0);
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

#ifdef CONFIG_SSDFS_MTD_DEVICE
	fs_info->mtd = sb->s_mtd;
	fs_info->devops = &ssdfs_mtd_devops;
	sb->s_bdi = sb->s_mtd->backing_dev_info;
#elif defined(CONFIG_SSDFS_BLOCK_DEVICE)
	if (bdev_is_zoned(sb->s_bdev)) {
		fs_info->devops = &ssdfs_zns_devops;
		fs_info->is_zns_device = true;
		fs_info->max_open_zones = bdev_max_open_zones(sb->s_bdev);

		fs_info->zone_size = ssdfs_zns_zone_size(sb,
						SSDFS_RESERVED_VBR_SIZE);
		if (fs_info->zone_size >= U64_MAX) {
			SSDFS_ERR("fail to get zone size\n");
			return -ERANGE;
		}

		fs_info->zone_capacity = ssdfs_zns_zone_capacity(sb,
						SSDFS_RESERVED_VBR_SIZE);
		if (fs_info->zone_capacity >= U64_MAX) {
			SSDFS_ERR("fail to get zone capacity\n");
			return -ERANGE;
		} else if (fs_info->zone_capacity > fs_info->zone_size) {
			SSDFS_ERR("invalid zone capacity: "
				  "capacity %llu, size %llu\n",
				  fs_info->zone_capacity,
				  fs_info->zone_size);
			return -ERANGE;
		}
	} else
		fs_info->devops = &ssdfs_bdev_devops;

	sb->s_bdi = bdi_get(sb->s_bdev->bd_disk->bdi);
	atomic_set(&fs_info->pending_bios, 0);
	fs_info->erase_folio = ssdfs_super_alloc_folio(GFP_KERNEL,
							get_order(PAGE_SIZE));
	if (IS_ERR_OR_NULL(fs_info->erase_folio)) {
		err = (fs_info->erase_folio == NULL ?
				-ENOMEM : PTR_ERR(fs_info->erase_folio));
		SSDFS_ERR("unable to allocate memory folio\n");
		goto free_erase_folio;
	}
	memset(folio_address(fs_info->erase_folio), 0xFF, PAGE_SIZE);
#else
	BUILD_BUG();
#endif

	fs_info->sb = sb;
	sb->s_fs_info = fs_info;
	atomic64_set(&fs_info->flush_reqs, 0);
	init_waitqueue_head(&fs_info->pending_wq);
	init_waitqueue_head(&fs_info->finish_user_data_flush_wq);
	atomic_set(&fs_info->global_fs_state, SSDFS_UNKNOWN_GLOBAL_FS_STATE);

	for (i = 0; i < SSDFS_GC_THREAD_TYPE_MAX; i++) {
		init_waitqueue_head(&fs_info->gc_wait_queue[i]);
		atomic_set(&fs_info->gc_should_act[i], 1);
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("parse options started...\n");
#else
	SSDFS_DBG("parse options started...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	err = ssdfs_parse_options(fs_info, data);
	if (err)
		goto free_erase_folio;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("gather superblock info started...\n");
#else
	SSDFS_DBG("gather superblock info started...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	err = ssdfs_gather_superblock_info(fs_info, silent);
	if (err)
		goto free_erase_folio;

	spin_lock(&fs_info->volume_state_lock);
	fs_feature_compat = fs_info->fs_feature_compat;
	spin_unlock(&fs_info->volume_state_lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("create device group started...\n");
#else
	SSDFS_DBG("create device group started...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	err = ssdfs_sysfs_create_device_group(sb);
	if (err)
		goto release_maptbl_cache;

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_magic = SSDFS_SUPER_MAGIC;
	sb->s_op = &ssdfs_super_operations;
	sb->s_export_op = &ssdfs_export_ops;

	sb->s_xattr = ssdfs_xattr_handlers;
	set_posix_acl_flag(sb);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("create snapshots subsystem started...\n");
#else
	SSDFS_DBG("create snapshots subsystem started...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	err = ssdfs_snapshot_subsystem_init(fs_info);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		err = 0;
		goto destroy_sysfs_device_group;
	} else if (err)
		goto destroy_sysfs_device_group;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("create segment tree started...\n");
#else
	SSDFS_DBG("create segment tree started...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	down_write(&fs_info->volume_sem);
	err = ssdfs_segment_tree_create(fs_info);
	up_write(&fs_info->volume_sem);
	if (err)
		goto destroy_snapshot_subsystem;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("create mapping table started...\n");
#else
	SSDFS_DBG("create mapping table started...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (fs_feature_compat & SSDFS_HAS_MAPTBL_COMPAT_FLAG) {
		down_write(&fs_info->volume_sem);
		err = ssdfs_maptbl_create(fs_info);
		up_write(&fs_info->volume_sem);

		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
			err = 0;
			goto destroy_segments_tree;
		} else if (err)
			goto destroy_segments_tree;
	} else {
		err = -EIO;
		SSDFS_WARN("volume hasn't mapping table\n");
		goto destroy_segments_tree;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("create segment bitmap started...\n");
#else
	SSDFS_DBG("create segment bitmap started...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (fs_feature_compat & SSDFS_HAS_SEGBMAP_COMPAT_FLAG) {
		down_write(&fs_info->volume_sem);
		err = ssdfs_segbmap_create(fs_info);
		up_write(&fs_info->volume_sem);

		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
			err = 0;
			goto destroy_maptbl;
		} else if (err)
			goto destroy_maptbl;
	} else {
		err = -EIO;
		SSDFS_WARN("volume hasn't segment bitmap\n");
		goto destroy_maptbl;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("create shared extents tree started...\n");
#else
	SSDFS_DBG("create shared extents tree started...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (fs_info->fs_feature_compat & SSDFS_HAS_SHARED_EXTENTS_COMPAT_FLAG) {
		down_write(&fs_info->volume_sem);
		err = ssdfs_shextree_create(fs_info);
		up_write(&fs_info->volume_sem);
		if (err)
			goto destroy_segbmap;
	} else {
		err = -EIO;
		SSDFS_WARN("volume hasn't shared extents tree\n");
		goto destroy_segbmap;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("create invalidated extents btree started...\n");
#else
	SSDFS_DBG("create invalidated extents btree started...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (fs_feature_compat & SSDFS_HAS_INVALID_EXTENTS_TREE_COMPAT_FLAG) {
		down_write(&fs_info->volume_sem);
		err = ssdfs_invextree_create(fs_info);
		up_write(&fs_info->volume_sem);
		if (err)
			goto destroy_shextree;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("create current segment array started...\n");
#else
	SSDFS_DBG("create current segment array started...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	down_write(&fs_info->volume_sem);
	err = ssdfs_current_segment_array_create(fs_info);
	up_write(&fs_info->volume_sem);
	if (err)
		goto destroy_invext_btree;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("create shared dictionary started...\n");
#else
	SSDFS_DBG("create shared dictionary started...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (fs_feature_compat & SSDFS_HAS_SHARED_DICT_COMPAT_FLAG) {
		down_write(&fs_info->volume_sem);

		err = ssdfs_shared_dict_btree_create(fs_info);
		if (err) {
			up_write(&fs_info->volume_sem);
			goto destroy_current_segment_array;
		}

		err = ssdfs_shared_dict_btree_init(fs_info);
		if (err) {
			up_write(&fs_info->volume_sem);
			goto destroy_shdictree;
		}

		up_write(&fs_info->volume_sem);
	} else {
		err = -EIO;
		SSDFS_WARN("volume hasn't shared dictionary\n");
		goto destroy_current_segment_array;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("create inodes btree started...\n");
#else
	SSDFS_DBG("create inodes btree started...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (fs_feature_compat & SSDFS_HAS_INODES_TREE_COMPAT_FLAG) {
		down_write(&fs_info->volume_sem);
		err = ssdfs_inodes_btree_create(fs_info);
		up_write(&fs_info->volume_sem);
		if (err)
			goto destroy_shdictree;
	} else {
		err = -EIO;
		SSDFS_WARN("volume hasn't inodes btree\n");
		goto destroy_shdictree;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("getting root inode...\n");
#else
	SSDFS_DBG("getting root inode...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	root_i = ssdfs_iget(sb, SSDFS_ROOT_INO);
	if (IS_ERR(root_i)) {
		SSDFS_DBG("getting root inode failed\n");
		err = PTR_ERR(root_i);
		goto destroy_inodes_btree;
	}

	if (!S_ISDIR(root_i->i_mode) || !root_i->i_blocks || !root_i->i_size) {
		err = -ERANGE;
		iput(root_i);
		SSDFS_ERR("corrupted root inode\n");
		goto destroy_inodes_btree;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("d_make_root()\n");
#else
	SSDFS_DBG("d_make_root()\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	sb->s_root = d_make_root(root_i);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto put_root_inode;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("starting GC threads...\n");
#else
	SSDFS_DBG("starting GC threads...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	err = ssdfs_start_gc_thread(fs_info, SSDFS_SEG_USING_GC_THREAD);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		err = 0;
		goto put_root_inode;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to start GC-using-seg thread: "
			  "err %d\n", err);
		goto put_root_inode;
	}

	err = ssdfs_start_gc_thread(fs_info, SSDFS_SEG_USED_GC_THREAD);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		err = 0;
		goto stop_gc_using_seg_thread;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to start GC-used-seg thread: "
			  "err %d\n", err);
		goto stop_gc_using_seg_thread;
	}

	err = ssdfs_start_gc_thread(fs_info, SSDFS_SEG_PRE_DIRTY_GC_THREAD);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		err = 0;
		goto stop_gc_used_seg_thread;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to start GC-pre-dirty-seg thread: "
			  "err %d\n", err);
		goto stop_gc_used_seg_thread;
	}

	err = ssdfs_start_gc_thread(fs_info, SSDFS_SEG_DIRTY_GC_THREAD);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		err = 0;
		goto stop_gc_pre_dirty_seg_thread;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to start GC-dirty-seg thread: "
			  "err %d\n", err);
		goto stop_gc_pre_dirty_seg_thread;
	}

	if (!(sb->s_flags & SB_RDONLY)) {
		folio_batch_init(&payload.maptbl_cache.batch);

		down_write(&fs_info->volume_sem);

		err = ssdfs_prepare_sb_log(sb, &last_sb_log);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare sb log: err %d\n",
				  err);
		}

		err = ssdfs_snapshot_sb_log_payload(sb, &payload);
		if (unlikely(err)) {
			SSDFS_ERR("fail to snapshot sb log's payload: err %d\n",
				  err);
		}

		if (!err) {
			err = ssdfs_commit_super(sb, SSDFS_MOUNTED_FS,
						 &last_sb_log,
						 &payload);
		} else {
			SSDFS_ERR("fail to prepare sb log payload: "
				  "err %d\n", err);
		}

		up_write(&fs_info->volume_sem);

		ssdfs_super_folio_batch_release(&payload.maptbl_cache.batch);

		if (err) {
			SSDFS_NOTICE("fail to commit superblock info: "
				     "remount filesystem in RO mode\n");
			sb->s_flags |= SB_RDONLY;
		}
	}

	atomic_set(&fs_info->global_fs_state, SSDFS_REGULAR_FS_OPERATIONS);

	SSDFS_INFO("%s has been mounted on device %s\n",
		   SSDFS_VERSION, fs_info->devops->device_name(sb));

	return 0;

stop_gc_pre_dirty_seg_thread:
	ssdfs_stop_gc_thread(fs_info, SSDFS_SEG_PRE_DIRTY_GC_THREAD);

stop_gc_used_seg_thread:
	ssdfs_stop_gc_thread(fs_info, SSDFS_SEG_USED_GC_THREAD);

stop_gc_using_seg_thread:
	ssdfs_stop_gc_thread(fs_info, SSDFS_SEG_USING_GC_THREAD);

put_root_inode:
	iput(root_i);

destroy_inodes_btree:
	ssdfs_inodes_btree_destroy(fs_info);

destroy_shdictree:
	ssdfs_shared_dict_btree_destroy(fs_info);

destroy_current_segment_array:
	ssdfs_destroy_all_curent_segments(fs_info);

destroy_invext_btree:
	ssdfs_invextree_destroy(fs_info);

destroy_shextree:
	ssdfs_shextree_destroy(fs_info);

destroy_segbmap:
	ssdfs_segbmap_destroy(fs_info);

destroy_maptbl:
	ssdfs_maptbl_stop_thread(fs_info->maptbl);
	ssdfs_maptbl_destroy(fs_info);

destroy_segments_tree:
	ssdfs_segment_tree_destroy(fs_info);
	ssdfs_current_segment_array_destroy(fs_info);

destroy_snapshot_subsystem:
	ssdfs_snapshot_subsystem_destroy(fs_info);

destroy_sysfs_device_group:
	ssdfs_sysfs_delete_device_group(fs_info);

release_maptbl_cache:
	ssdfs_maptbl_cache_destroy(&fs_info->maptbl_cache);

free_erase_folio:
	if (fs_info->erase_folio)
		ssdfs_super_free_folio(fs_info->erase_folio);

	ssdfs_destruct_sb_info(&fs_info->sbi);
	ssdfs_destruct_sb_info(&fs_info->sbi_backup);

	ssdfs_free_workspaces();

	ssdfs_super_kfree(fs_info);

	rcu_barrier();

	ssdfs_check_memory_folio_locks();
	ssdfs_check_memory_leaks();
	return err;
}

static void ssdfs_put_super(struct super_block *sb)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	struct ssdfs_peb_extent last_sb_log = {0};
	struct ssdfs_sb_log_payload payload;
	u64 fs_feature_compat;
	u16 fs_state;
	bool can_commit_super = true;
	int i;
	int err;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("sb %p\n", sb);
#else
	SSDFS_DBG("sb %p\n", sb);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	atomic_set(&fsi->global_fs_state, SSDFS_METADATA_GOING_FLUSHING);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("SSDFS_METADATA_GOING_FLUSHING\n");
#endif /* CONFIG_SSDFS_DEBUG */

	wake_up_all(&fsi->pending_wq);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("STOP THREADS...\n");
#else
	SSDFS_DBG("STOP THREADS...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	err = ssdfs_stop_gc_thread(fsi, SSDFS_SEG_USING_GC_THREAD);
	if (err) {
		SSDFS_ERR("fail to stop GC using seg thread: "
			  "err %d\n", err);
	}

	err = ssdfs_stop_gc_thread(fsi, SSDFS_SEG_USED_GC_THREAD);
	if (err) {
		SSDFS_ERR("fail to stop GC used seg thread: "
			  "err %d\n", err);
	}

	err = ssdfs_stop_gc_thread(fsi, SSDFS_SEG_PRE_DIRTY_GC_THREAD);
	if (err) {
		SSDFS_ERR("fail to stop GC pre-dirty seg thread: "
			  "err %d\n", err);
	}

	err = ssdfs_stop_gc_thread(fsi, SSDFS_SEG_DIRTY_GC_THREAD);
	if (err) {
		SSDFS_ERR("fail to stop GC dirty seg thread: "
			  "err %d\n", err);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("GC threads have been stoped\n");
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_shared_dict_stop_thread(fsi->shdictree);
	if (err == -EIO) {
		ssdfs_fs_error(fsi->sb,
				__FILE__, __func__, __LINE__,
				"thread I/O issue\n");
	} else if (unlikely(err)) {
		SSDFS_WARN("thread stopping issue: err %d\n",
			   err);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("shared dictionary thread has been stoped\n");
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < SSDFS_INVALIDATION_QUEUE_NUMBER; i++) {
		err = ssdfs_shextree_stop_thread(fsi->shextree, i);
		if (err == -EIO) {
			ssdfs_fs_error(fsi->sb,
					__FILE__, __func__, __LINE__,
					"thread I/O issue\n");
		} else if (unlikely(err)) {
			SSDFS_WARN("thread stopping issue: ID %d, err %d\n",
				   i, err);
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("shared extents threads have been stoped\n");
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_stop_snapshots_btree_thread(fsi);
	if (err == -EIO) {
		ssdfs_fs_error(fsi->sb,
				__FILE__, __func__, __LINE__,
				"thread I/O issue\n");
	} else if (unlikely(err)) {
		SSDFS_WARN("thread stopping issue: err %d\n",
			   err);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("snaphots btree thread has been stoped\n");
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_maptbl_stop_thread(fsi->maptbl);
	if (unlikely(err)) {
		SSDFS_WARN("maptbl thread stopping issue: err %d\n",
			   err);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("mapping table thread has been stoped\n");
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&fsi->volume_state_lock);
	fs_feature_compat = fsi->fs_feature_compat;
	fs_state = fsi->fs_state;
	spin_unlock(&fsi->volume_state_lock);

	folio_batch_init(&payload.maptbl_cache.batch);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("Wait unfinished user data requests...\n");
#endif /* CONFIG_SSDFS_DEBUG */

	if (unfinished_user_data_requests_exist(fsi)) {
		wait_queue_head_t *wq = &fsi->finish_user_data_flush_wq;

		err = wait_event_killable_timeout(*wq,
				!unfinished_user_data_requests_exist(fsi),
				SSDFS_DEFAULT_TIMEOUT);
		if (err < 0)
			WARN_ON(err < 0);
		else
			err = 0;

		if (unfinished_user_data_requests_exist(fsi))
			BUG();
	}

	atomic_set(&fsi->global_fs_state, SSDFS_METADATA_UNDER_FLUSH);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("SSDFS_METADATA_UNDER_FLUSH\n");
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(sb->s_flags & SB_RDONLY)) {
		down_write(&fsi->volume_sem);

		err = ssdfs_prepare_sb_log(sb, &last_sb_log);
		if (unlikely(err)) {
			can_commit_super = false;
			SSDFS_ERR("fail to prepare sb log: err %d\n",
				  err);
		}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("Flush invalidated extents b-tree...\n");
#else
		SSDFS_DBG("Flush invalidated extents b-tree...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		if (fsi->fs_feature_compat &
				SSDFS_HAS_INVALID_EXTENTS_TREE_COMPAT_FLAG) {
			err = ssdfs_invextree_flush(fsi);
			if (err) {
				SSDFS_ERR("fail to flush invalidated extents btree: "
					  "err %d\n", err);
			}
		}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("Flush shared extents b-tree...\n");
#else
		SSDFS_DBG("Flush shared extents b-tree...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		if (fsi->fs_feature_compat &
				SSDFS_HAS_SHARED_EXTENTS_COMPAT_FLAG) {
			err = ssdfs_shextree_flush(fsi);
			if (err) {
				SSDFS_ERR("fail to flush shared extents btree: "
					  "err %d\n", err);
			}
		}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("Flush inodes b-tree...\n");
#else
		SSDFS_DBG("Flush inodes b-tree...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		if (fs_feature_compat & SSDFS_HAS_INODES_TREE_COMPAT_FLAG) {
			err = ssdfs_inodes_btree_flush(fsi->inodes_tree);
			if (err) {
				SSDFS_ERR("fail to flush inodes btree: "
					  "err %d\n", err);
			}
		}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("Flush shared dictionary b-tree...\n");
#else
		SSDFS_DBG("Flush shared dictionary b-tree...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		if (fs_feature_compat & SSDFS_HAS_SHARED_DICT_COMPAT_FLAG) {
			err = ssdfs_shared_dict_btree_flush(fsi->shdictree);
			if (err) {
				SSDFS_ERR("fail to flush shared dictionary: "
					  "err %d\n", err);
			}
		}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("Execute create snapshots...\n");
#else
		SSDFS_DBG("Execute create snapshots...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		err = ssdfs_execute_create_snapshots(fsi);
		if (err) {
			SSDFS_ERR("fail to process the snapshots creation\n");
		}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("Flush snapshots b-tree...\n");
#else
		SSDFS_DBG("Flush snapshots b-tree...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		if (fsi->fs_feature_compat &
				SSDFS_HAS_SNAPSHOTS_TREE_COMPAT_FLAG) {
			err = ssdfs_snapshots_btree_flush(fsi);
			if (err) {
				SSDFS_ERR("fail to flush snapshots btree: "
					  "err %d\n", err);
			}
		}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("Flush segment bitmap...\n");
#else
		SSDFS_DBG("Flush segment bitmap...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		if (fs_feature_compat & SSDFS_HAS_SEGBMAP_COMPAT_FLAG) {
			err = ssdfs_segbmap_flush(fsi->segbmap);
			if (err) {
				SSDFS_ERR("fail to flush segbmap: "
					  "err %d\n", err);
			}
		}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("Flush PEB mapping table...\n");
#else
		SSDFS_DBG("Flush PEB mapping table...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		if (fs_feature_compat & SSDFS_HAS_MAPTBL_COMPAT_FLAG) {
			err = ssdfs_maptbl_flush(fsi->maptbl);
			if (err) {
				SSDFS_ERR("fail to flush maptbl: "
					  "err %d\n", err);
			}

			set_maptbl_going_to_be_destroyed(fsi);
		}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("Commit superblock...\n");
#else
		SSDFS_DBG("Commit superblock...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		if (can_commit_super) {
			err = ssdfs_snapshot_sb_log_payload(sb, &payload);
			if (unlikely(err)) {
				SSDFS_ERR("fail to snapshot log's payload: "
					  "err %d\n", err);
			} else {
				err = ssdfs_commit_super(sb, SSDFS_VALID_FS,
							 &last_sb_log,
							 &payload);
			}
		} else {
			/* prepare error code */
			err = -ERANGE;
		}

		if (err) {
			SSDFS_ERR("fail to commit superblock info: "
				  "err %d\n", err);
		}

		up_write(&fsi->volume_sem);
	} else {
		if (fs_state == SSDFS_ERROR_FS) {
			down_write(&fsi->volume_sem);

			err = ssdfs_prepare_sb_log(sb, &last_sb_log);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare sb log: err %d\n",
					  err);
			}

			err = ssdfs_snapshot_sb_log_payload(sb, &payload);
			if (unlikely(err)) {
				SSDFS_ERR("fail to snapshot log's payload: "
					  "err %d\n", err);
			}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
			SSDFS_ERR("Commit superblock...\n");
#else
			SSDFS_DBG("Commit superblock...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

			if (!err) {
				err = ssdfs_commit_super(sb, SSDFS_ERROR_FS,
							 &last_sb_log,
							 &payload);
			}

			up_write(&fsi->volume_sem);

			if (err) {
				SSDFS_ERR("fail to commit superblock info: "
					  "err %d\n", err);
			}
		}
	}

	atomic_set(&fsi->global_fs_state, SSDFS_UNKNOWN_GLOBAL_FS_STATE);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("SSDFS_UNKNOWN_GLOBAL_FS_STATE\n");
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_super_folio_batch_release(&payload.maptbl_cache.batch);
	fsi->devops->sync(sb);

	/*
	 * Make sure all delayed rcu free inodes are flushed.
	 */
	rcu_barrier();

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("All delayed rcu free inodes has been flushed\n");
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("Starting destroy the metadata structures...\n");
#else
	SSDFS_DBG("Starting destroy the metadata structures...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ssdfs_snapshot_subsystem_destroy(fsi);
	ssdfs_invextree_destroy(fsi);
	ssdfs_shextree_destroy(fsi);
	ssdfs_inodes_btree_destroy(fsi);
	ssdfs_shared_dict_btree_destroy(fsi);
	ssdfs_segbmap_destroy(fsi);
	ssdfs_maptbl_destroy(fsi);
	ssdfs_maptbl_cache_destroy(&fsi->maptbl_cache);
	ssdfs_destroy_all_curent_segments(fsi);
	ssdfs_segment_tree_destroy(fsi);
	ssdfs_current_segment_array_destroy(fsi);
	ssdfs_sysfs_delete_device_group(fsi);

	if (fsi->erase_folio)
		ssdfs_super_free_folio(fsi->erase_folio);

	ssdfs_destruct_sb_info(&fsi->sbi);
	ssdfs_destruct_sb_info(&fsi->sbi_backup);

	ssdfs_free_workspaces();

	ssdfs_super_kfree(fsi);
	sb->s_fs_info = NULL;

	SSDFS_INFO("%s has been unmounted from device %s\n",
		   SSDFS_VERSION, fsi->devops->device_name(sb));

	ssdfs_check_memory_folio_locks();
	ssdfs_check_memory_leaks();

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("All metadata structures have been destroyed...\n");
#else
	SSDFS_DBG("All metadata structures have been destroyed...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */
}

static struct dentry *ssdfs_mount(struct file_system_type *fs_type,
				  int flags, const char *dev_name,
				  void *data)
{
#ifdef CONFIG_SSDFS_MTD_DEVICE
	return mount_mtd(fs_type, flags, dev_name, data, ssdfs_fill_super);
#elif defined(CONFIG_SSDFS_BLOCK_DEVICE)
	return mount_bdev(fs_type, flags, dev_name, data, ssdfs_fill_super);
#else
	BUILD_BUG();
	return NULL;
#endif
}

static void kill_ssdfs_sb(struct super_block *sb)
{
#ifdef CONFIG_SSDFS_MTD_DEVICE
	kill_mtd_super(sb);
#elif defined(CONFIG_SSDFS_BLOCK_DEVICE)
	kill_block_super(sb);
#else
	BUILD_BUG();
#endif
}

static struct file_system_type ssdfs_fs_type = {
	.name		= "ssdfs",
	.owner		= THIS_MODULE,
	.mount		= ssdfs_mount,
	.kill_sb	= kill_ssdfs_sb,
#ifdef CONFIG_SSDFS_BLOCK_DEVICE
	.fs_flags	= FS_REQUIRES_DEV,
#endif
};
MODULE_ALIAS_FS(SSDFS_VERSION);

static void ssdfs_destroy_caches(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();

	if (ssdfs_inode_cachep)
		kmem_cache_destroy(ssdfs_inode_cachep);

	ssdfs_destroy_seg_req_obj_cache();
	ssdfs_destroy_btree_search_obj_cache();
	ssdfs_destroy_free_ino_desc_cache();
	ssdfs_destroy_btree_node_obj_cache();
	ssdfs_destroy_seg_obj_cache();
	ssdfs_destroy_extent_info_cache();
	ssdfs_destroy_peb_mapping_info_cache();
	ssdfs_destroy_blk2off_frag_obj_cache();
	ssdfs_destroy_name_info_cache();
}

static int ssdfs_init_caches(void)
{
	int err;

	ssdfs_zero_seg_obj_cache_ptr();
	ssdfs_zero_seg_req_obj_cache_ptr();
	ssdfs_zero_extent_info_cache_ptr();
	ssdfs_zero_btree_node_obj_cache_ptr();
	ssdfs_zero_btree_search_obj_cache_ptr();
	ssdfs_zero_free_ino_desc_cache_ptr();
	ssdfs_zero_peb_mapping_info_cache_ptr();
	ssdfs_zero_blk2off_frag_obj_cache_ptr();
	ssdfs_zero_name_info_cache_ptr();

	ssdfs_inode_cachep = kmem_cache_create("ssdfs_inode_cache",
					sizeof(struct ssdfs_inode_info), 0,
					SLAB_RECLAIM_ACCOUNT |
					SLAB_MEM_SPREAD |
					SLAB_ACCOUNT,
					ssdfs_init_inode_once);
	if (!ssdfs_inode_cachep) {
		SSDFS_ERR("unable to create inode cache\n");
		return -ENOMEM;
	}

	err = ssdfs_init_seg_obj_cache();
	if (unlikely(err)) {
		SSDFS_ERR("unable to create segment object cache: err %d\n",
			  err);
		goto destroy_caches;
	}

	err = ssdfs_init_seg_req_obj_cache();
	if (unlikely(err)) {
		SSDFS_ERR("unable to create segment request object cache: "
			  "err %d\n",
			  err);
		goto destroy_caches;
	}

	err = ssdfs_init_extent_info_cache();
	if (unlikely(err)) {
		SSDFS_ERR("unable to create extent info object cache: "
			  "err %d\n",
			  err);
		goto destroy_caches;
	}

	err = ssdfs_init_btree_node_obj_cache();
	if (unlikely(err)) {
		SSDFS_ERR("unable to create btree node object cache: err %d\n",
			  err);
		goto destroy_caches;
	}

	err = ssdfs_init_btree_search_obj_cache();
	if (unlikely(err)) {
		SSDFS_ERR("unable to create btree search object cache: "
			  "err %d\n",
			  err);
		goto destroy_caches;
	}

	err = ssdfs_init_free_ino_desc_cache();
	if (unlikely(err)) {
		SSDFS_ERR("unable to create free inode descriptors cache: "
			  "err %d\n",
			  err);
		goto destroy_caches;
	}

	err = ssdfs_init_peb_mapping_info_cache();
	if (unlikely(err)) {
		SSDFS_ERR("unable to create PEB mapping descriptors cache: "
			  "err %d\n",
			  err);
		goto destroy_caches;
	}

	err = ssdfs_init_blk2off_frag_obj_cache();
	if (unlikely(err)) {
		SSDFS_ERR("unable to create blk2off fragments cache: "
			  "err %d\n",
			  err);
		goto destroy_caches;
	}

	err = ssdfs_init_name_info_cache();
	if (unlikely(err)) {
		SSDFS_ERR("unable to create name info cache: "
			  "err %d\n",
			  err);
		goto destroy_caches;
	}

	return 0;

destroy_caches:
	ssdfs_destroy_caches();
	return -ENOMEM;
}

static inline void ssdfs_print_info(void)
{
	SSDFS_INFO("%s loaded\n", SSDFS_VERSION);
}

static int __init ssdfs_init(void)
{
	int err;

	err = ssdfs_init_caches();
	if (err) {
		SSDFS_ERR("failed to initialize caches\n");
		goto failed_init;
	}

	err = ssdfs_compressors_init();
	if (err) {
		SSDFS_ERR("failed to initialize compressors\n");
		goto free_caches;
	}

	err = ssdfs_sysfs_init();
	if (err) {
		SSDFS_ERR("failed to initialize sysfs subsystem\n");
		goto stop_compressors;
	}

	err = register_filesystem(&ssdfs_fs_type);
	if (err) {
		SSDFS_ERR("failed to register filesystem\n");
		goto sysfs_exit;
	}

	ssdfs_print_info();

	return 0;

sysfs_exit:
	ssdfs_sysfs_exit();

stop_compressors:
	ssdfs_compressors_exit();

free_caches:
	ssdfs_destroy_caches();

failed_init:
	return err;
}

static void __exit ssdfs_exit(void)
{
	ssdfs_destroy_caches();
	unregister_filesystem(&ssdfs_fs_type);
	ssdfs_sysfs_exit();
	ssdfs_compressors_exit();
}

module_init(ssdfs_init);
module_exit(ssdfs_exit);

MODULE_DESCRIPTION("SSDFS -- SSD-oriented File System");
MODULE_AUTHOR("HGST, San Jose Research Center, Storage Architecture Group");
MODULE_AUTHOR("Viacheslav Dubeyko <slava@dubeyko.com>");
MODULE_LICENSE("Dual BSD/GPL");
