//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/super.c - module and superblock management.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2019, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
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

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "version.h"
#include "segment_bitmap.h"
#include "page_array.h"
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

#define CREATE_TRACE_POINTS
#include <trace/events/ssdfs.h>

struct ssdfs_payload_content {
	struct pagevec pvec;
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

	ii = kmem_cache_alloc(ssdfs_inode_cachep, GFP_NOFS);
	if (!ii)
		return NULL;

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
	memset(&ii->raw_inode, 0, sizeof(struct ssdfs_inode));

	return &ii->vfs_inode;
}

static void ssdfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);

	if (ii->extents_tree)
		ssdfs_extents_tree_destroy(ii);

	if (ii->dentries_tree)
		ssdfs_dentries_tree_destroy(ii);

	if (ii->xattrs_tree)
		ssdfs_xattrs_tree_destroy(ii);

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

	SSDFS_DBG("sb %p, flags %#x, data %p\n", sb, *flags, data);

	old_sb_flags = sb->s_flags;
	old_mount_opts = fsi->mount_opts;

	pagevec_init(&payload.maptbl_cache.pvec);

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
	pagevec_release(&payload.maptbl_cache.pvec);
	return 0;

restore_opts:
	sb->s_flags = old_sb_flags;
	fsi->mount_opts = old_mount_opts;
	pagevec_release(&payload.maptbl_cache.pvec);
	return err;
}

static int ssdfs_sync_fs(struct super_block *sb, int wait)
{
	struct ssdfs_fs_info *fsi;
	int err = 0;

	fsi = SSDFS_FS_I(sb);

	down_write(&fsi->volume_sem);

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
u32 ssdfs_sb_payload_size(struct pagevec *pvec)
{
	struct ssdfs_maptbl_cache_header *hdr;
	struct page *page;
	void *kaddr;
	u16 fragment_bytes_count;
	u32 bytes_count = 0;
	int i;

	for (i = 0; i < pagevec_count(pvec); i++) {
		page = pvec->pages[i];

		lock_page(page);
		kaddr = kmap_atomic(page);
		hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
		fragment_bytes_count = le16_to_cpu(hdr->bytes_count);
		kunmap_atomic(kaddr);
		unlock_page(page);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("sb %p\n", sb);

	fsi = SSDFS_FS_I(sb);
	payload_size = ssdfs_sb_payload_size(&fsi->maptbl_cache.pvec);
	inline_capacity = PAGE_SIZE - hdr_size;

	if (payload_size > inline_capacity) {
		log_size += PAGE_SIZE;
		log_size += atomic_read(&fsi->maptbl_cache.bytes_count);
		log_size += PAGE_SIZE;
	} else {
		log_size += PAGE_SIZE;
		log_size += PAGE_SIZE;
	}

	log_size = (log_size + fsi->pagesize - 1) >> fsi->log_pagesize;

	return log_size;
}

static int ssdfs_snapshot_sb_log_payload(struct super_block *sb,
					 struct ssdfs_sb_log_payload *payload)
{
	struct ssdfs_fs_info *fsi;
	unsigned pages_count;
	unsigned i;
	struct page *spage, *dpage;
	void *kaddr1, *kaddr2;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !payload);
	BUG_ON(pagevec_count(&payload->maptbl_cache.pvec) != 0);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("sb %p, payload %p\n",
		  sb, payload);

	fsi = SSDFS_FS_I(sb);

	down_read(&fsi->maptbl_cache.lock);

	pages_count = pagevec_count(&fsi->maptbl_cache.pvec);

	for (i = 0; i < pages_count; i++) {
		dpage = ssdfs_add_pagevec_page(&payload->maptbl_cache.pvec);
		if (unlikely(IS_ERR_OR_NULL(dpage))) {
			err = !dpage ? -ENOMEM : PTR_ERR(dpage);
			SSDFS_ERR("fail to add pagevec page: "
				  "index %u, err %d\n",
				  i, err);
			goto finish_maptbl_snapshot;
		}

		spage = fsi->maptbl_cache.pvec.pages[i];
		if (unlikely(!spage)) {
			err = -ERANGE;
			SSDFS_ERR("source page is absent: index %u\n",
				  i);
			goto finish_maptbl_snapshot;
		}

		lock_page(spage);
		lock_page(dpage);
		kaddr1 = kmap_atomic(spage);
		kaddr2 = kmap_atomic(dpage);
		memcpy(kaddr2, kaddr1, PAGE_SIZE);
		kunmap_atomic(kaddr1);
		kunmap_atomic(kaddr2);
		unlock_page(dpage);
		unlock_page(spage);
	}

	payload->maptbl_cache.bytes_count =
		atomic_read(&fsi->maptbl_cache.bytes_count);

finish_maptbl_snapshot:
	up_read(&fsi->maptbl_cache.lock);

	if (unlikely(err))
		pagevec_release(&payload->maptbl_cache.pvec);

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
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !last_sb_log);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("sb %p, last_sb_log %p\n",
		  sb, last_sb_log);
	SSDFS_DBG("last_sb_log->leb_id %llu, last_sb_log->peb_id %llu, "
		  "last_sb_log->page_offset %u, last_sb_log->pages_count %u\n",
		  last_sb_log->leb_id, last_sb_log->peb_id,
		  last_sb_log->page_offset, last_sb_log->pages_count);

	fsi = SSDFS_FS_I(sb);
	offset = fsi->sbi.last_log.page_offset;

	log_size = ssdfs_define_sb_log_size(sb);
	if (log_size > fsi->pages_per_peb) {
		SSDFS_ERR("log_size %u > fsi->pages_per_peb %u\n",
			  log_size, fsi->pages_per_peb);
		return -ERANGE;
	}

	log_size = max_t(u32, log_size, fsi->sbi.last_log.pages_count);

	if (offset > fsi->pages_per_peb || offset > (UINT_MAX - log_size)) {
		SSDFS_ERR("inconsistent metadata state: "
			  "last_sb_log.page_offset %u, "
			  "pages_per_peb %u, log_size %u\n",
			  offset, fsi->pages_per_peb, log_size);
		return -EINVAL;
	}

	for (err = -EINVAL, i = 0; i < SSDFS_SB_SEG_COPY_MAX; i++) {
		cur_peb = fsi->sb_pebs[SSDFS_CUR_SB_SEG][i];
		prev_peb = fsi->sb_pebs[SSDFS_PREV_SB_SEG][i];
		cur_leb = fsi->sb_lebs[SSDFS_CUR_SB_SEG][i];

		if (fsi->sbi.last_log.peb_id == cur_peb) {
			if ((offset + (2 * log_size)) > fsi->pages_per_peb) {
				SSDFS_DBG("sb PEB %llu is full: "
					  "(offset %u + (2 * log_size %u)) > "
					  "pages_per_peb %u\n",
					  cur_peb, offset, log_size,
					  fsi->pages_per_peb);
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
			err = -ERANGE;
			break;
		}
	}

	if (err) {
		SSDFS_ERR("inconsistent metadata state: "
			  "cur_peb %llu, prev_peb %llu, "
			  "last_sb_log.peb_id %llu\n",
			  cur_peb, prev_peb, fsi->sbi.last_log.peb_id);
		return err;
	}

	for (i = 0; i < SSDFS_SB_SEG_COPY_MAX; i++) {
		last_sb_log->leb_id = fsi->sb_lebs[SSDFS_CUR_SB_SEG][i];
		last_sb_log->peb_id = fsi->sb_pebs[SSDFS_CUR_SB_SEG][i];
		err = ssdfs_can_write_sb_log(sb, last_sb_log);
		if (err) {
			SSDFS_ERR("fail to write sb log into PEB %llu\n",
				  last_sb_log->peb_id);
			return err;
		}
	}

	last_sb_log->leb_id = cur_leb;
	last_sb_log->peb_id = cur_peb;

	return 0;
}

static bool ssdfs_sb_seg_exhausted(u64 cur_leb, u64 next_leb,
				   u32 pebs_per_seg)
{
	u64 cur_seg, next_seg;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(cur_leb == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	cur_seg = div_u64(cur_leb, pebs_per_seg);
	next_seg = div_u64(next_leb, pebs_per_seg);

	SSDFS_DBG("cur_seg %llu, next_seg %llu\n",
		  cur_seg, next_seg);

	return cur_seg != next_seg;
}

static u64 ssdfs_reserve_clean_segment(struct super_block *sb,
					int sb_seg_type)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	struct ssdfs_segment_bmap *segbmap = fsi->segbmap;
	struct ssdfs_maptbl_peb_relation pebr;
	u64 reserved_seg;
	u64 start, max;
	struct completion *end;
	int i;
	unsigned long res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(sb_seg_type >= SSDFS_SB_SEG_COPY_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("sb %p, sb_seg_type %#x\n", sb, sb_seg_type);

	switch (sb_seg_type) {
	case SSDFS_MAIN_SB_SEG:
		start = 0;
		max = fsi->nsegs / 2;
		break;

	case SSDFS_COPY_SB_SEG:
		start = fsi->nsegs / 2;
		max = fsi->nsegs;
		break;

	default:
		BUG();
	};

	err = ssdfs_segbmap_reserve_clean_segment(segbmap, start, max,
						  &reserved_seg, &end);
	if (err == -EAGAIN) {
		res = wait_for_completion_timeout(end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("segbmap init failed: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_segbmap_reserve_clean_segment(segbmap,
							  start, max,
							  &reserved_seg,
							  &end);
	}

	if (err == -ENODATA) {
		SSDFS_DBG("unable to reserve segment: type %#x\n",
			  sb_seg_type);
		return U64_MAX;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to reserve segment: type %#x, err %d\n",
			  sb_seg_type, err);
		return U64_MAX;
	}

	for (i = 0; i < fsi->pebs_per_seg; i++) {
		u8 peb_type = SSDFS_MAPTBL_SBSEG_PEB_TYPE;
		u64 leb_id = (reserved_seg * fsi->pebs_per_seg) + i;

		err = ssdfs_maptbl_map_leb2peb(fsi, leb_id, peb_type,
						&pebr, &end);
		if (err == -EAGAIN) {
			res = wait_for_completion_timeout(end,
						SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("maptbl init failed: "
					  "err %d\n", err);
				return err;
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
					  reserved_seg, leb_id, err);
				return U64_MAX;
			} else
				goto finish_reservation;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to map LEB to PEB: "
				  "reserved_seg %llu, leb_id %llu, "
				  "err %d\n",
				  reserved_seg, leb_id, err);
			return U64_MAX;
		}
	}

finish_reservation:
	SSDFS_DBG("reserved_seg %llu\n", reserved_seg);

	return reserved_seg;
}

typedef u64 sb_pebs_array[SSDFS_SB_CHAIN_MAX][SSDFS_SB_SEG_COPY_MAX];

static int ssdfs_move_on_next_sb_seg(struct super_block *sb,
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
	unsigned long res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !sb_lebs || !sb_pebs);

	if (sb_seg_type >= SSDFS_SB_SEG_COPY_MAX) {
		SSDFS_ERR("invalid sb_seg_type %#x\n",
			  sb_seg_type);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("sb %p, sb_seg_type %#x\n", sb, sb_seg_type);

	prev_leb = (*sb_lebs)[SSDFS_PREV_SB_SEG][sb_seg_type];
	cur_leb = (*sb_lebs)[SSDFS_CUR_SB_SEG][sb_seg_type];
	next_leb = cur_leb + 1;
	reserved_leb = (*sb_lebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type];

	prev_peb = (*sb_pebs)[SSDFS_PREV_SB_SEG][sb_seg_type];
	cur_peb = (*sb_pebs)[SSDFS_CUR_SB_SEG][sb_seg_type];
	next_peb = U64_MAX;
	reserved_peb = (*sb_pebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type];

	if (!ssdfs_sb_seg_exhausted(cur_leb, next_leb, fsi->pebs_per_seg)) {
		err = ssdfs_maptbl_convert_leb2peb(fsi, next_leb,
						   peb_type,
						   &pebr, &end);
		if (err == -EAGAIN) {
			res = wait_for_completion_timeout(end,
						SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("maptbl init failed: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_maptbl_convert_leb2peb(fsi, next_leb,
							   peb_type,
							   &pebr, &end);
		}

		if (err == -ENODATA) {
			SSDFS_DBG("LEB %llu doesn't mapped\n", next_leb);
			goto reserve_clean_segment;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to convert LEB %llu to PEB: err %d\n",
				  next_leb, err);
			return err;
		}

		next_peb = pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(next_peb == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		(*sb_lebs)[SSDFS_PREV_SB_SEG][sb_seg_type] = cur_leb;
		(*sb_pebs)[SSDFS_PREV_SB_SEG][sb_seg_type] = cur_peb;

		(*sb_lebs)[SSDFS_CUR_SB_SEG][sb_seg_type] = next_leb;
		(*sb_pebs)[SSDFS_CUR_SB_SEG][sb_seg_type] = next_peb;

		if (prev_leb == U64_MAX)
			goto finish_move_sb_seg;
		else
			goto delete_prev_leb_from_cache;
	} else {
		next_leb = (*sb_lebs)[SSDFS_NEXT_SB_SEG][sb_seg_type];
		next_peb = (*sb_pebs)[SSDFS_NEXT_SB_SEG][sb_seg_type];
	}

reserve_clean_segment:
	reserved_seg = ssdfs_reserve_clean_segment(sb, sb_seg_type);

	if (reserved_seg == U64_MAX) {
		/*
		 * TODO: if we can't to find clean segment then
		 * to live in three reserved ones.
		 */
		/*
		 * TODO: it needs to erase via TRIM command
		 * prev sb segment in background.
		 */

		/* TODO: implement */
		SSDFS_WARN("TODO: implement %s\n", __func__);
		err = -ENOSPC;
		goto finish_move_sb_seg;
	} else {
		new_leb = reserved_seg * fsi->pebs_per_seg;

		err = ssdfs_maptbl_convert_leb2peb(fsi, new_leb,
						   peb_type,
						   &pebr, &end);
		if (err == -EAGAIN) {
			res = wait_for_completion_timeout(end,
						SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("maptbl init failed: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_maptbl_convert_leb2peb(fsi, new_leb,
							   peb_type,
							   &pebr, &end);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to convert LEB %llu to PEB: err %d\n",
				  new_leb, err);
			return err;
		}

		new_peb = pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(new_peb == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	(*sb_lebs)[SSDFS_PREV_SB_SEG][sb_seg_type] = cur_leb;
	(*sb_pebs)[SSDFS_PREV_SB_SEG][sb_seg_type] = cur_peb;

	(*sb_lebs)[SSDFS_CUR_SB_SEG][sb_seg_type] = next_leb;
	(*sb_pebs)[SSDFS_CUR_SB_SEG][sb_seg_type] = next_peb;

	(*sb_lebs)[SSDFS_NEXT_SB_SEG][sb_seg_type] = reserved_leb;
	(*sb_pebs)[SSDFS_NEXT_SB_SEG][sb_seg_type] = reserved_peb;

	(*sb_lebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type] = new_leb;
	(*sb_pebs)[SSDFS_RESERVED_SB_SEG][sb_seg_type] = new_peb;

	SSDFS_DBG("cur_leb %llu, cur_peb %llu, "
		  "next_leb %llu, next_peb %llu, "
		  "reserved_leb %llu, reserved_peb %llu, "
		  "new_leb %llu, new_peb %llu\n",
		  cur_leb, cur_peb,
		  next_leb, next_peb,
		  reserved_leb, reserved_peb,
		  new_leb, new_peb);

	if (prev_leb == U64_MAX)
		goto finish_move_sb_seg;

	prev_seg = div_u64(prev_leb, fsi->pebs_per_seg);
	cur_seg = div_u64(cur_leb, fsi->pebs_per_seg);

	if (prev_seg != cur_seg) {
		err = ssdfs_segbmap_change_state(segbmap, prev_seg,
						 SSDFS_SEG_DIRTY, &end);
		if (err == -EAGAIN) {
			res = wait_for_completion_timeout(end,
						SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
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
			return err;
		}
	}

delete_prev_leb_from_cache:
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(prev_leb == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_maptbl_cache_forget_leb2peb(maptbl_cache, prev_leb,
						SSDFS_PEB_STATE_CONSISTENT);
	if (unlikely(err)) {
		SSDFS_ERR("fail to forget prev_leb %llu, err %d\n",
			  prev_leb, err);
	}

finish_move_sb_seg:
	return err;
}

static int ssdfs_move_on_next_sb_segs_pair(struct super_block *sb)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	sb_pebs_array sb_lebs;
	sb_pebs_array sb_pebs;
	size_t array_size;
	int i;
	int err = 0;

	SSDFS_DBG("sb %p", sb);

	if (!(fsi->fs_feature_compat & SSDFS_HAS_SEGBMAP_COMPAT_FLAG) ||
	    !(fsi->fs_feature_compat & SSDFS_HAS_MAPTBL_COMPAT_FLAG)) {
		SSDFS_ERR("volume hasn't segbmap or maptbl\n");
		return -EIO;
	}

	array_size = sizeof(u64);
	array_size *= SSDFS_SB_CHAIN_MAX;
	array_size *= SSDFS_SB_SEG_COPY_MAX;

	down_read(&fsi->sb_segs_sem);
	memcpy(sb_lebs, fsi->sb_lebs, array_size);
	memcpy(sb_pebs, fsi->sb_pebs, array_size);
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
	memcpy(fsi->sb_lebs, sb_lebs, array_size);
	memcpy(fsi->sb_pebs, sb_pebs, array_size);
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("sb %p, last_sb_log %p\n",
		  sb, last_sb_log);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("desc %p, offset %u, payload %p\n",
		  desc, offset, payload);

	desc->offset = cpu_to_le32(offset);
	desc->size = cpu_to_le32(payload_size);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(payload_size >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	desc->check.bytes = cpu_to_le16((u16)payload_size);
	desc->check.flags = cpu_to_le16(SSDFS_CRC32);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(pagevec_count(&payload->pvec) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < pagevec_count(&payload->pvec); i++) {
		struct page *page = payload->pvec.pages[i];
		struct ssdfs_maptbl_cache_header *hdr;
		u16 bytes_count;
		void *kaddr;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		lock_page(page);
		kaddr = kmap(page);

		hdr = (struct ssdfs_maptbl_cache_header *)kaddr;
		bytes_count = le16_to_cpu(hdr->bytes_count);

		csum = crc32(csum, kaddr, bytes_count);

		kunmap(page);
		unlock_page(page);
	}

	desc->check.csum = cpu_to_le32(csum);
}

static int __ssdfs_commit_sb_log(struct super_block *sb,
				 struct ssdfs_peb_extent *last_sb_log,
				 struct ssdfs_sb_log_payload *payload)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor hdr_desc[SSDFS_SEG_HDR_DESC_MAX];
	size_t desc_size = sizeof(struct ssdfs_metadata_descriptor);
	struct ssdfs_metadata_descriptor *cur_hdr_desc;
	struct page *page;
	struct ssdfs_segment_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	struct ssdfs_log_footer *footer;
	size_t footer_size = sizeof(struct ssdfs_log_footer);
	void *kaddr = NULL;
	loff_t peb_offset, offset;
	unsigned i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !last_sb_log);
	BUG_ON(!SSDFS_FS_I(sb)->devops);
	BUG_ON(!SSDFS_FS_I(sb)->devops->writepage);
	BUG_ON((last_sb_log->page_offset + last_sb_log->pages_count) >
		(ULLONG_MAX >> SSDFS_FS_I(sb)->log_pagesize));
	BUG_ON((last_sb_log->leb_id * SSDFS_FS_I(sb)->pebs_per_seg) >=
		SSDFS_FS_I(sb)->nsegs);
	BUG_ON(last_sb_log->peb_id >
		div_u64(ULLONG_MAX, SSDFS_FS_I(sb)->pages_per_peb));
	BUG_ON((last_sb_log->peb_id * SSDFS_FS_I(sb)->pages_per_peb) >
		(ULLONG_MAX >> SSDFS_FS_I(sb)->log_pagesize));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("sb %p, last_sb_log->leb_id %llu, last_sb_log->peb_id %llu, "
		  "last_sb_log->page_offset %u, last_sb_log->pages_count %u\n",
		  sb, last_sb_log->leb_id, last_sb_log->peb_id,
		  last_sb_log->page_offset, last_sb_log->pages_count);

	fsi = SSDFS_FS_I(sb);
	hdr = SSDFS_SEG_HDR(fsi->sbi.vh_buf);
	footer = SSDFS_LF(fsi->sbi.vs_buf);

	memset(hdr_desc, 0, desc_size * SSDFS_SEG_HDR_DESC_MAX);

	offset = (loff_t)last_sb_log->page_offset << fsi->log_pagesize;
	offset += PAGE_SIZE;

	cur_hdr_desc = &hdr_desc[SSDFS_MAPTBL_CACHE_INDEX];
	ssdfs_prepare_maptbl_cache_descriptor(cur_hdr_desc, (u32)offset,
					     &payload->maptbl_cache,
					     payload->maptbl_cache.bytes_count);

	offset += payload->maptbl_cache.bytes_count;

	cur_hdr_desc = &hdr_desc[SSDFS_LOG_FOOTER_INDEX];
	cur_hdr_desc->offset = cpu_to_le32(offset);
	cur_hdr_desc->size = cpu_to_le32(footer_size);

	memcpy(hdr->desc_array, hdr_desc, desc_size * SSDFS_SEG_HDR_DESC_MAX);

	hdr->peb_migration_id[SSDFS_PREV_MIGRATING_PEB] =
					SSDFS_PEB_UNKNOWN_MIGRATION_ID;
	hdr->peb_migration_id[SSDFS_CUR_MIGRATING_PEB] =
					SSDFS_PEB_UNKNOWN_MIGRATION_ID;

	err = ssdfs_prepare_segment_header_for_commit(fsi,
						     last_sb_log->pages_count,
						     SSDFS_SB_SEG_TYPE,
						     SSDFS_LOG_HAS_FOOTER |
						     SSDFS_LOG_HAS_MAPTBL_CACHE,
						     hdr);
	if (err) {
		SSDFS_ERR("fail to prepare segment header: err %d\n", err);
		return err;
	}

	err = ssdfs_prepare_log_footer_for_commit(fsi, last_sb_log->pages_count,
						  0, footer);
	if (err) {
		SSDFS_ERR("fail to prepare log footer: err %d\n", err);
		return err;
	}

	page = alloc_page(GFP_NOFS | __GFP_ZERO);
	if (unlikely(!page)) {
		SSDFS_ERR("unable to allocate memory page\n");
		return -ENOMEM;
	}

	/* ->writepage() calls put_page() */
	get_page(page);

	/* write segment header */
	lock_page(page);
	kaddr = kmap_atomic(page);
	memcpy(kaddr, fsi->sbi.vh_buf, hdr_size);
	kunmap_atomic(kaddr);
	SetPagePrivate(page);
	SetPageUptodate(page);
	SetPageDirty(page);
	unlock_page(page);

	peb_offset = last_sb_log->peb_id * fsi->pages_per_peb;
	peb_offset <<= fsi->log_pagesize;
	offset = (loff_t)last_sb_log->page_offset << fsi->log_pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(peb_offset > (ULLONG_MAX - (offset + fsi->pagesize)));
#endif /* CONFIG_SSDFS_DEBUG */

	offset += peb_offset;
	err = fsi->devops->writepage(sb, offset, page, 0, hdr_size);
	if (err) {
		SSDFS_ERR("fail to write segment header: "
			  "offset %llu, size %zu\n",
			  (u64)offset, hdr_size);
		goto cleanup_after_failure;
	}

	lock_page(page);
	ClearPageUptodate(page);
	ClearPagePrivate(page);
	unlock_page(page);

	offset += PAGE_SIZE;

	for (i = 0; i < pagevec_count(&payload->maptbl_cache.pvec); i++) {
		struct page *payload_page = payload->maptbl_cache.pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!payload_page);
#endif /* CONFIG_SSDFS_DEBUG */

		/* ->writepage() calls put_page() */
		get_page(payload_page);

		lock_page(payload_page);
		SetPagePrivate(payload_page);
		SetPageUptodate(payload_page);
		SetPageDirty(payload_page);
		unlock_page(payload_page);

		err = fsi->devops->writepage(sb, offset, payload_page,
					     0, PAGE_SIZE);
		if (err) {
			SSDFS_ERR("fail to write maptbl cache page: "
				  "offset %llu, page_index %u, size %zu\n",
				  (u64)offset, i, PAGE_SIZE);
			goto cleanup_after_failure;
		}

		lock_page(payload_page);
		ClearPageUptodate(payload_page);
		ClearPagePrivate(payload_page);
		unlock_page(payload_page);

		offset += PAGE_SIZE;
	}

	/* TODO: write metadata payload */

	/* ->writepage() calls put_page() */
	get_page(page);

	/* write log footer */
	lock_page(page);
	kaddr = kmap_atomic(page);
	memset(kaddr, 0, PAGE_SIZE);
	memcpy(kaddr, fsi->sbi.vs_buf, footer_size);
	kunmap_atomic(kaddr);
	SetPagePrivate(page);
	SetPageUptodate(page);
	SetPageDirty(page);
	unlock_page(page);

	err = fsi->devops->writepage(sb, offset, page, 0, footer_size);
	if (err) {
		SSDFS_ERR("fail to write log footer: "
			  "offset %llu, size %zu\n",
			  (u64)offset, footer_size);
		goto cleanup_after_failure;
	}

	lock_page(page);
	ClearPageUptodate(page);
	ClearPagePrivate(page);
	unlock_page(page);

	ssdfs_free_page(page);
	return 0;

cleanup_after_failure:
	put_page(page);
	ssdfs_free_page(page);

	return err;
}

static int
__ssdfs_commit_sb_log_inline(struct super_block *sb,
			     struct ssdfs_peb_extent *last_sb_log,
			     struct ssdfs_sb_log_payload *payload,
			     u32 payload_size)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor hdr_desc[SSDFS_SEG_HDR_DESC_MAX];
	size_t desc_size = sizeof(struct ssdfs_metadata_descriptor);
	struct ssdfs_metadata_descriptor *cur_hdr_desc;
	struct page *page;
	struct page *payload_page;
	struct ssdfs_segment_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	struct ssdfs_log_footer *footer;
	size_t footer_size = sizeof(struct ssdfs_log_footer);
	void *kaddr1 = NULL, *kaddr2 = NULL;
	loff_t peb_offset, offset;
	u32 inline_capacity;
	void *payload_buf;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !last_sb_log);
	BUG_ON(!SSDFS_FS_I(sb)->devops);
	BUG_ON(!SSDFS_FS_I(sb)->devops->writepage);
	BUG_ON((last_sb_log->page_offset + last_sb_log->pages_count) >
		(ULLONG_MAX >> SSDFS_FS_I(sb)->log_pagesize));
	BUG_ON((last_sb_log->leb_id * SSDFS_FS_I(sb)->pebs_per_seg) >=
		SSDFS_FS_I(sb)->nsegs);
	BUG_ON(last_sb_log->peb_id >
		div_u64(ULLONG_MAX, SSDFS_FS_I(sb)->pages_per_peb));
	BUG_ON((last_sb_log->peb_id * SSDFS_FS_I(sb)->pages_per_peb) >
		(ULLONG_MAX >> SSDFS_FS_I(sb)->log_pagesize));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("sb %p, last_sb_log->leb_id %llu, last_sb_log->peb_id %llu, "
		  "last_sb_log->page_offset %u, last_sb_log->pages_count %u\n",
		  sb, last_sb_log->leb_id, last_sb_log->peb_id,
		  last_sb_log->page_offset, last_sb_log->pages_count);

	fsi = SSDFS_FS_I(sb);
	hdr = SSDFS_SEG_HDR(fsi->sbi.vh_buf);
	footer = SSDFS_LF(fsi->sbi.vs_buf);

	memset(hdr_desc, 0, desc_size * SSDFS_SEG_HDR_DESC_MAX);

	offset = (loff_t)last_sb_log->page_offset << fsi->log_pagesize;
	offset += hdr_size;

	cur_hdr_desc = &hdr_desc[SSDFS_MAPTBL_CACHE_INDEX];
	ssdfs_prepare_maptbl_cache_descriptor(cur_hdr_desc, (u32)offset,
					      &payload->maptbl_cache,
					      payload_size);

	offset += payload_size;

	offset += fsi->pagesize - 1;
	offset = (offset >> fsi->log_pagesize) << fsi->log_pagesize;

	cur_hdr_desc = &hdr_desc[SSDFS_LOG_FOOTER_INDEX];
	cur_hdr_desc->offset = cpu_to_le32(offset);
	cur_hdr_desc->size = cpu_to_le32(footer_size);

	memcpy(hdr->desc_array, hdr_desc, desc_size * SSDFS_SEG_HDR_DESC_MAX);

	hdr->peb_migration_id[SSDFS_PREV_MIGRATING_PEB] =
					SSDFS_PEB_UNKNOWN_MIGRATION_ID;
	hdr->peb_migration_id[SSDFS_CUR_MIGRATING_PEB] =
					SSDFS_PEB_UNKNOWN_MIGRATION_ID;

	err = ssdfs_prepare_segment_header_for_commit(fsi,
						     last_sb_log->pages_count,
						     SSDFS_SB_SEG_TYPE,
						     SSDFS_LOG_HAS_FOOTER |
						     SSDFS_LOG_HAS_MAPTBL_CACHE,
						     hdr);
	if (err) {
		SSDFS_ERR("fail to prepare segment header: err %d\n", err);
		return err;
	}

	err = ssdfs_prepare_log_footer_for_commit(fsi, last_sb_log->pages_count,
						  0, footer);
	if (err) {
		SSDFS_ERR("fail to prepare log footer: err %d\n", err);
		return err;
	}

	if (pagevec_count(&payload->maptbl_cache.pvec) != 1) {
		SSDFS_WARN("payload contains several memory pages\n");
		return -ERANGE;
	}

	inline_capacity = PAGE_SIZE - hdr_size;

	if (payload_size > inline_capacity) {
		SSDFS_ERR("payload_size %u > inline_capacity %u\n",
			  payload_size, inline_capacity);
		return -ERANGE;
	}

	payload_buf = kmalloc(inline_capacity, GFP_KERNEL);
	if (!payload_buf) {
		SSDFS_ERR("fail to allocate payload buffer\n");
		return -ENOMEM;
	}

	page = alloc_page(GFP_NOFS | __GFP_ZERO);
	if (unlikely(!page)) {
		kfree(payload_buf);
		SSDFS_ERR("unable to allocate memory page\n");
		return -ENOMEM;;
	}

	/* ->writepage() calls put_page() */
	get_page(page);

	payload_page = payload->maptbl_cache.pvec.pages[0];
	if (!payload_page) {
		err = -ERANGE;
		SSDFS_ERR("invalid payload page\n");
		goto free_payload_buffer;
	}

	lock_page(payload_page);
	kaddr2 = kmap_atomic(payload_page);
	memcpy(payload_buf, kaddr2, payload_size);
	kunmap_atomic(kaddr2);
	unlock_page(payload_page);

	/* write segment header + payload */
	lock_page(page);
	kaddr1 = kmap_atomic(page);
	memcpy(kaddr1, fsi->sbi.vh_buf, hdr_size);
	memcpy((u8 *)kaddr1 + hdr_size, payload_buf, payload_size);
	kunmap_atomic(kaddr1);
	SetPagePrivate(page);
	SetPageUptodate(page);
	SetPageDirty(page);
	unlock_page(page);

free_payload_buffer:
	kfree(payload_buf);

	if (unlikely(err))
		goto cleanup_after_failure;

	peb_offset = last_sb_log->peb_id * fsi->pages_per_peb;
	peb_offset <<= fsi->log_pagesize;
	offset = (loff_t)last_sb_log->page_offset << fsi->log_pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(peb_offset > (ULLONG_MAX - (offset + fsi->pagesize)));
#endif /* CONFIG_SSDFS_DEBUG */

	offset += peb_offset;
	err = fsi->devops->writepage(sb, offset, page, 0,
				     hdr_size + payload_size);
	if (err) {
		SSDFS_ERR("fail to write segment header: "
			  "offset %llu, size %zu\n",
			  (u64)offset, hdr_size + payload_size);
		goto cleanup_after_failure;
	}

	lock_page(page);
	ClearPageUptodate(page);
	ClearPagePrivate(page);
	unlock_page(page);

	offset += PAGE_SIZE;

	/* ->writepage() calls put_page() */
	get_page(page);

	/* write log footer */
	lock_page(page);
	kaddr1 = kmap_atomic(page);
	memset(kaddr1, 0, PAGE_SIZE);
	memcpy(kaddr1, fsi->sbi.vs_buf, footer_size);
	kunmap_atomic(kaddr1);
	SetPagePrivate(page);
	SetPageUptodate(page);
	SetPageDirty(page);
	unlock_page(page);

	err = fsi->devops->writepage(sb, offset, page, 0, footer_size);
	if (err) {
		SSDFS_ERR("fail to write log footer: "
			  "offset %llu, size %zu\n",
			  (u64)offset, footer_size);
		goto cleanup_after_failure;
	}

	lock_page(page);
	ClearPageUptodate(page);
	ClearPagePrivate(page);
	unlock_page(page);

	ssdfs_free_page(page);
	return 0;

cleanup_after_failure:
	put_page(page);
	ssdfs_free_page(page);

	return err;
}

static int ssdfs_commit_sb_log(struct super_block *sb,
				struct ssdfs_peb_extent *last_sb_log,
				struct ssdfs_sb_log_payload *payload)
{
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	u32 inline_capacity;
	u32 payload_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !last_sb_log || !payload);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("sb %p, last_sb_log->leb_id %llu, last_sb_log->peb_id %llu, "
		  "last_sb_log->page_offset %u, last_sb_log->pages_count %u\n",
		  sb, last_sb_log->leb_id, last_sb_log->peb_id,
		  last_sb_log->page_offset, last_sb_log->pages_count);

	inline_capacity = PAGE_SIZE - hdr_size;
	payload_size = ssdfs_sb_payload_size(&payload->maptbl_cache.pvec);

	if (payload_size > inline_capacity)
		err = __ssdfs_commit_sb_log(sb, last_sb_log, payload);
	else {
		err = __ssdfs_commit_sb_log_inline(sb, last_sb_log,
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
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb || !last_sb_log || !payload);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("sb %p, fs_state %u", sb, fs_state);

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
							 fsi->vs);
	if (unlikely(err)) {
		SSDFS_CRIT("volume state info is inconsistent: err %d\n", err);
		goto finish_commit_super;
	}

	for (i = 0; i < SSDFS_SB_SEG_COPY_MAX; i++) {
		last_sb_log->leb_id = fsi->sb_lebs[SSDFS_CUR_SB_SEG][i];
		last_sb_log->peb_id = fsi->sb_pebs[SSDFS_CUR_SB_SEG][i];
		err = ssdfs_commit_sb_log(sb, last_sb_log, payload);
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
	memcpy(&fsi->sbi.last_log, last_sb_log,
		sizeof(struct ssdfs_peb_extent));

finish_commit_super:
	return err;
}

static int ssdfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct ssdfs_fs_info *fs_info;
	struct ssdfs_peb_extent last_sb_log = {0};
	struct ssdfs_sb_log_payload payload;
	struct inode *root_i;
	u64 fs_feature_compat;
	int err = 0;

	SSDFS_DBG("sb %p, data %p, silent %#x\n", sb, data, silent);

	fs_info = kzalloc(sizeof(*fs_info), GFP_NOFS);
	if (!fs_info)
		return -ENOMEM;

#ifdef CONFIG_SSDFS_MTD_DEVICE
	fs_info->mtd = sb->s_mtd;
	fs_info->devops = &ssdfs_mtd_devops;
	sb->s_bdi = sb->s_mtd->backing_dev_info;
#elif defined(CONFIG_SSDFS_BLOCK_DEVICE)
	fs_info->devops = &ssdfs_bdev_devops;
	sb->s_bdi = bdi_get(sb->s_bdev->bd_bdi);
	atomic_set(&fs_info->pending_bios, 0);
	fs_info->erase_page = alloc_pages(GFP_KERNEL, 0);
	if (!fs_info->erase_page) {
		err = -ENOMEM;
		goto free_erase_page;
	}
	memset(page_address(fs_info->erase_page), 0xFF, PAGE_SIZE);
#else
	BUILD_BUG();
#endif

	fs_info->sb = sb;
	sb->s_fs_info = fs_info;

	SSDFS_DBG("parse options started...\n");

	err = ssdfs_parse_options(fs_info, data);
	if (err)
		goto free_erase_page;

	SSDFS_DBG("gather superblock info started...\n");

	err = ssdfs_gather_superblock_info(fs_info, silent);
	if (err)
		goto free_erase_page;

	spin_lock(&fs_info->volume_state_lock);
	fs_feature_compat = fs_info->fs_feature_compat;
	spin_unlock(&fs_info->volume_state_lock);

	SSDFS_DBG("create device group started...\n");

	err = ssdfs_sysfs_create_device_group(sb);
	if (err)
		goto release_maptbl_cache;

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_magic = SSDFS_SUPER_MAGIC;
	sb->s_op = &ssdfs_super_operations;
	sb->s_export_op = &ssdfs_export_ops;

	sb->s_xattr = ssdfs_xattr_handlers;
	set_posix_acl_flag(sb);

	SSDFS_DBG("create segment tree started...\n");

	down_write(&fs_info->volume_sem);
	err = ssdfs_segment_tree_create(fs_info);
	up_write(&fs_info->volume_sem);
	if (err)
		goto destroy_sysfs_device_group;

	SSDFS_DBG("create mapping table started...\n");

	if (fs_feature_compat & SSDFS_HAS_MAPTBL_COMPAT_FLAG) {
		down_write(&fs_info->volume_sem);
		err = ssdfs_maptbl_create(fs_info);
		up_write(&fs_info->volume_sem);
		if (err)
			goto destroy_segments_tree;
	} else {
		err = -EIO;
		SSDFS_WARN("volume hasn't mapping table\n");
		goto destroy_segments_tree;
	}

	SSDFS_DBG("create segment bitmap started...\n");

	if (fs_feature_compat & SSDFS_HAS_SEGBMAP_COMPAT_FLAG) {
		down_write(&fs_info->volume_sem);
		err = ssdfs_segbmap_create(fs_info);
		up_write(&fs_info->volume_sem);
		if (err)
			goto destroy_maptbl;
	} else {
		err = -EIO;
		SSDFS_WARN("volume hasn't segment bitmap\n");
		goto destroy_maptbl;
	}

	SSDFS_DBG("create current segment array started...\n");

	down_write(&fs_info->volume_sem);
	err = ssdfs_current_segment_array_create(fs_info);
	up_write(&fs_info->volume_sem);
	if (err)
		goto destroy_segbmap;

	SSDFS_DBG("create shared extents tree started...\n");

	down_write(&fs_info->volume_sem);
	err = ssdfs_shextree_create(fs_info);
	up_write(&fs_info->volume_sem);
	if (err)
		goto destroy_current_segment_array;

	SSDFS_DBG("create shared dictionary started...\n");

	if (fs_feature_compat & SSDFS_HAS_SHARED_DICT_COMPAT_FLAG) {
		down_write(&fs_info->volume_sem);

		err = ssdfs_shared_dict_btree_create(fs_info);
		if (err) {
			up_write(&fs_info->volume_sem);
			goto destroy_shextree;
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
		goto destroy_shextree;
	}

	SSDFS_DBG("create inodes btree started...\n");

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

	SSDFS_DBG("getting root inode\n");

	root_i = ssdfs_iget(sb, SSDFS_ROOT_INO);
	if (IS_ERR(root_i)) {
		SSDFS_DBG("getting root inode failed\n");
		err = PTR_ERR(root_i);
		goto destroy_inodes_btree;
	}

	SSDFS_DBG("d_make_root()\n");

	sb->s_root = d_make_root(root_i);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto put_root_inode;
	}

	if (!(sb->s_flags & SB_RDONLY)) {
		pagevec_init(&payload.maptbl_cache.pvec);

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

		pagevec_release(&payload.maptbl_cache.pvec);

		if (err) {
			SSDFS_NOTICE("fail to commit superblock info: "
				     "remount filesystem in RO mode\n");
			sb->s_flags |= SB_RDONLY;
		}
	}

	SSDFS_INFO("%s has been mounted on device %s\n",
		   SSDFS_VERSION, fs_info->devops->device_name(sb));

	return 0;

put_root_inode:
	iput(root_i);

destroy_inodes_btree:
	ssdfs_inodes_btree_destroy(fs_info);

destroy_shdictree:
	ssdfs_shared_dict_btree_destroy(fs_info);

destroy_shextree:
	ssdfs_shextree_destroy(fs_info);

destroy_current_segment_array:
	ssdfs_destroy_all_curent_segments(fs_info);

destroy_segbmap:
	ssdfs_segbmap_destroy(fs_info);

destroy_maptbl:
	ssdfs_maptbl_destroy(fs_info);

destroy_segments_tree:
	ssdfs_segment_tree_destroy(fs_info);
	ssdfs_current_segment_array_destroy(fs_info);

destroy_sysfs_device_group:
	ssdfs_sysfs_delete_device_group(fs_info);

release_maptbl_cache:
	ssdfs_maptbl_cache_destroy(&fs_info->maptbl_cache);

free_erase_page:
	if (fs_info->erase_page)
		ssdfs_free_page(fs_info->erase_page);

	kfree(fs_info);

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
	int err;

	spin_lock(&fsi->volume_state_lock);
	fs_feature_compat = fsi->fs_feature_compat;
	fs_state = fsi->fs_state;
	spin_unlock(&fsi->volume_state_lock);

	pagevec_init(&payload.maptbl_cache.pvec);

	/* TODO: flush shared extents tree */
	ssdfs_shextree_destroy(fsi);

	if (!(sb->s_flags & SB_RDONLY)) {
		down_write(&fsi->volume_sem);

		err = ssdfs_prepare_sb_log(sb, &last_sb_log);
		if (unlikely(err)) {
			can_commit_super = false;
			SSDFS_ERR("fail to prepare sb log: err %d\n",
				  err);
		}

		if (fs_feature_compat & SSDFS_HAS_INODES_TREE_COMPAT_FLAG) {
			err = ssdfs_inodes_btree_flush(fsi->inodes_tree);
			if (err) {
				SSDFS_ERR("fail to flush inodes btree: "
					  "err %d\n", err);
			}
		}

		if (fs_feature_compat & SSDFS_HAS_SHARED_DICT_COMPAT_FLAG) {
			err = ssdfs_shared_dict_btree_flush(fsi->shdictree);
			if (err) {
				SSDFS_ERR("fail to flush shared dictionary: "
					  "err %d\n", err);
			}
		}

		if (fs_feature_compat & SSDFS_HAS_SEGBMAP_COMPAT_FLAG) {
			err = ssdfs_segbmap_flush(fsi->segbmap);
			if (err) {
				SSDFS_ERR("fail to flush segbmap: "
					  "err %d\n", err);
			}
		}

		if (fs_feature_compat & SSDFS_HAS_MAPTBL_COMPAT_FLAG) {
			err = ssdfs_maptbl_flush(fsi->maptbl);
			if (err) {
				SSDFS_ERR("fail to flush maptbl: "
					  "err %d\n", err);
			}
		}

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

	pagevec_release(&payload.maptbl_cache.pvec);
	fsi->devops->sync(sb);
	ssdfs_inodes_btree_destroy(fsi);
	ssdfs_shared_dict_btree_destroy(fsi);
	ssdfs_segbmap_destroy(fsi);
	ssdfs_destroy_all_curent_segments(fsi);
	ssdfs_segment_tree_destroy(fsi);
	ssdfs_current_segment_array_destroy(fsi);
	ssdfs_maptbl_destroy(fsi);
	ssdfs_sysfs_delete_device_group(fsi);

	SSDFS_INFO("%s has been unmounted from device %s\n",
		   SSDFS_VERSION, fsi->devops->device_name(sb));

	if (fsi->erase_page)
		ssdfs_free_page(fsi->erase_page);
	ssdfs_maptbl_cache_destroy(&fsi->maptbl_cache);
	ssdfs_destruct_sb_info(&fsi->sbi);
	ssdfs_destruct_sb_info(&fsi->sbi_backup);
	kfree(fsi);
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
	.name    = "ssdfs",
	.owner   = THIS_MODULE,
	.mount   = ssdfs_mount,
	.kill_sb = kill_ssdfs_sb,
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
}

static int ssdfs_init_caches(void)
{
	int err;

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
MODULE_AUTHOR("Vyacheslav Dubeyko <slava@dubeyko.com>");
MODULE_LICENSE("GPL");
