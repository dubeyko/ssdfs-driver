//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ssdfs_inline.h - inline functions and macros.
 *
 * Copyright (c) 2019-2020 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_INLINE_H
#define _SSDFS_INLINE_H

#define SSDFS_CRIT(fmt, ...) \
	pr_crit("pid %d:%s:%d %s(): " fmt, \
		 current->pid, __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#define SSDFS_ERR(fmt, ...) \
	pr_err("pid %d:%s:%d %s(): " fmt, \
		 current->pid, __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#define SSDFS_WARN(fmt, ...) \
	do { \
		pr_warn("pid %d:%s:%d %s(): " fmt, \
			current->pid, __FILE__, __LINE__, \
			__func__, ##__VA_ARGS__); \
		dump_stack(); \
	} while (0)

#define SSDFS_NOTICE(fmt, ...) \
	pr_notice(fmt, ##__VA_ARGS__)

#define SSDFS_INFO(fmt, ...) \
	pr_info(fmt, ##__VA_ARGS__)

#ifdef CONFIG_SSDFS_DEBUG

#define SSDFS_DBG(fmt, ...) \
	pr_debug("pid %d:%s:%d %s(): " fmt, \
		 current->pid, __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#else /* CONFIG_SSDFS_DEBUG */

#define SSDFS_DBG(fmt, ...) \
	no_printk(KERN_DEBUG fmt, ##__VA_ARGS__)

#endif /* CONFIG_SSDFS_DEBUG */

/*
 * ssdfs_add_pagevec_page() - add page into pagevec
 * @pvec: pagevec
 *
 * This function adds empty page into pagevec.
 *
 * RETURN:
 * [success] - pointer on added page.
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 * %-E2BIG      - pagevec is full.
 */
static inline
struct page *ssdfs_add_pagevec_page(struct pagevec *pvec)
{
	struct page *page;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("pagevec count %d\n", pagevec_count(pvec));

	if (pagevec_space(pvec) == 0) {
		SSDFS_ERR("pagevec hasn't space\n");
		return ERR_PTR(-E2BIG);
	}

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (unlikely(!page)) {
		SSDFS_ERR("unable to allocate memory page\n");
		return ERR_PTR(-ENOMEM);
	}

	get_page(page);

	pagevec_add(pvec, page);
	return page;
}

static inline
void ssdfs_free_page(struct page *page)
{
	if (!page)
		return;

	if (page_ref_count(page) <= 0) {
		SSDFS_WARN("page %px, count %d\n",
			  page, page_ref_count(page));
	}

	__free_pages(page, 0);
}

static inline
__le32 ssdfs_crc32_le(void *data, size_t len)
{
	return cpu_to_le32(crc32(~0, data, len));
}

static inline
int ssdfs_calculate_csum(struct ssdfs_metadata_check *check,
			  void *buf, size_t buf_size)
{
	u16 bytes;
	u16 flags;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!check || !buf);
#endif /* CONFIG_SSDFS_DEBUG */

	bytes = le16_to_cpu(check->bytes);
	flags = le16_to_cpu(check->flags);

	if (bytes > buf_size) {
		SSDFS_ERR("corrupted size %d of checked data\n", bytes);
		return -EINVAL;
	}

	if (flags & SSDFS_CRC32) {
		check->csum = 0;
		check->csum = ssdfs_crc32_le(buf, bytes);
	} else {
		SSDFS_ERR("unknown flags set %#x\n", flags);
		return -EINVAL;
	}

	return 0;
}

static inline
bool is_csum_valid(struct ssdfs_metadata_check *check,
		   void *buf, size_t buf_size)
{
	__le32 old_csum;
	__le32 calc_csum;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!check);
#endif /* CONFIG_SSDFS_DEBUG */

	old_csum = check->csum;

	err = ssdfs_calculate_csum(check, buf, buf_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to calculate checksum\n");
		return false;
	}

	calc_csum = check->csum;
	check->csum = old_csum;

	if (old_csum != calc_csum) {
		SSDFS_ERR("old_csum %#x != calc_csum %#x\n",
			  __le32_to_cpu(old_csum),
			  __le32_to_cpu(calc_csum));
		return false;
	}

	return true;
}

static inline
bool is_ssdfs_magic_valid(struct ssdfs_signature *magic)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!magic);
#endif /* CONFIG_SSDFS_DEBUG */

	if (le32_to_cpu(magic->common) != SSDFS_SUPER_MAGIC)
		return false;
	if (magic->version.major > SSDFS_MAJOR_REVISION ||
	    magic->version.minor > SSDFS_MINOR_REVISION)
		return false;

	return true;
}

#define SSDFS_SEG_HDR(ptr) \
	((struct ssdfs_segment_header *)(ptr))
#define SSDFS_LF(ptr) \
	((struct ssdfs_log_footer *)(ptr))
#define SSDFS_VH(ptr) \
	((struct ssdfs_volume_header *)(ptr))
#define SSDFS_VS(ptr) \
	((struct ssdfs_volume_state *)(ptr))
#define SSDFS_PLH(ptr) \
	((struct ssdfs_partial_log_header *)(ptr))

/*
 * Flags for mount options.
 */
#define SSDFS_MOUNT_COMPR_MODE_NONE		(1 << 0)
#define SSDFS_MOUNT_COMPR_MODE_ZLIB		(1 << 1)
#define SSDFS_MOUNT_COMPR_MODE_LZO		(1 << 2)
#define SSDFS_MOUNT_ERRORS_CONT			(1 << 3)
#define SSDFS_MOUNT_ERRORS_RO			(1 << 4)
#define SSDFS_MOUNT_ERRORS_PANIC		(1 << 5)
#define SSDFS_MOUNT_IGNORE_FS_STATE		(1 << 6)

#define ssdfs_clear_opt(o, opt)		((o) &= ~SSDFS_MOUNT_##opt)
#define ssdfs_set_opt(o, opt)		((o) |= SSDFS_MOUNT_##opt)
#define ssdfs_test_opt(o, opt)		((o) & SSDFS_MOUNT_##opt)

#define SSDFS_LOG_FOOTER_OFF(seg_hdr)({ \
	u32 offset; \
	int index; \
	struct ssdfs_metadata_descriptor *desc; \
	index = SSDFS_LOG_FOOTER_INDEX; \
	desc = &SSDFS_SEG_HDR(seg_hdr)->desc_array[index]; \
	offset = le32_to_cpu(desc->offset); \
	offset; \
})

#define SSDFS_LOG_PAGES(seg_hdr) \
	(le16_to_cpu(SSDFS_SEG_HDR(seg_hdr)->log_pages))
#define SSDFS_SEG_TYPE(seg_hdr) \
	(le16_to_cpu(SSDFS_SEG_HDR(seg_hdr)->seg_type))

#define SSDFS_MAIN_SB_PEB(vh, type) \
	(le64_to_cpu(SSDFS_VH(vh)->sb_pebs[type][SSDFS_MAIN_SB_SEG].peb_id))
#define SSDFS_COPY_SB_PEB(vh, type) \
	(le64_to_cpu(SSDFS_VH(vh)->sb_pebs[type][SSDFS_COPY_SB_SEG].peb_id))
#define SSDFS_MAIN_SB_LEB(vh, type) \
	(le64_to_cpu(SSDFS_VH(vh)->sb_pebs[type][SSDFS_MAIN_SB_SEG].leb_id))
#define SSDFS_COPY_SB_LEB(vh, type) \
	(le64_to_cpu(SSDFS_VH(vh)->sb_pebs[type][SSDFS_COPY_SB_SEG].leb_id))

#define SSDFS_SEG_CNO(seg_hdr) \
	(le64_to_cpu(SSDFS_SEG_HDR(seg_hdr)->cno))

static inline
u64 ssdfs_current_timestamp(void)
{
	struct timespec64 cur_time;

	ktime_get_coarse_real_ts64(&cur_time);

	return (u64)timespec64_to_ns(&cur_time);
}

static inline
void ssdfs_init_boot_vs_mount_timediff(struct ssdfs_fs_info *fsi)
{
	struct timespec64 uptime;

	ktime_get_boottime_ts64(&uptime);
	fsi->boot_vs_mount_timediff = timespec64_to_ns(&uptime);
}

static inline
u64 ssdfs_current_cno(struct super_block *sb)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	struct timespec64 uptime;
	u64 boot_vs_mount_timediff;
	u64 fs_mount_cno;

	spin_lock(&fsi->volume_state_lock);
	boot_vs_mount_timediff = fsi->boot_vs_mount_timediff;
	fs_mount_cno = fsi->fs_mount_cno;
	spin_unlock(&fsi->volume_state_lock);

	ktime_get_boottime_ts64(&uptime);
	return fs_mount_cno +
		timespec64_to_ns(&uptime) -
		boot_vs_mount_timediff;
}

#define SSDFS_MAPTBL_CACHE_HDR(ptr) \
	((struct ssdfs_maptbl_cache_header *)(ptr))

#define SSDFS_SEG_HDR_MAGIC(vh) \
	(le16_to_cpu(SSDFS_VH(vh)->magic.key))
#define SSDFS_SEG_TIME(seg_hdr) \
	(le64_to_cpu(SSDFS_SEG_HDR(seg_hdr)->timestamp))

#define SSDFS_VH_CNO(vh) \
	(le64_to_cpu(SSDFS_VH(vh)->create_cno))
#define SSDFS_VH_TIME(vh) \
	(le64_to_cpu(SSDFS_VH(vh)->create_timestamp)

#define SSDFS_VS_CNO(vs) \
	(le64_to_cpu(SSDFS_VS(vs)->cno))
#define SSDFS_VS_TIME(vs) \
	(le64_to_cpu(SSDFS_VS(vs)->timestamp)

#define SSDFS_POFFTH(ptr) \
	((struct ssdfs_phys_offset_table_header *)(ptr))
#define SSDFS_PHYSOFFD(ptr) \
	((struct ssdfs_phys_offset_descriptor *)(ptr))

static inline
pgoff_t ssdfs_phys_page_to_mem_page(struct ssdfs_fs_info *fsi,
				    pgoff_t index)
{
	if (fsi->log_pagesize == PAGE_SHIFT)
		return index;
	else if (fsi->log_pagesize > PAGE_SHIFT)
		return index << (fsi->log_pagesize - PAGE_SHIFT);
	else
		return index >> (PAGE_SHIFT - fsi->log_pagesize);
}

static inline
pgoff_t ssdfs_mem_page_to_phys_page(struct ssdfs_fs_info *fsi,
				    pgoff_t index)
{
	if (fsi->log_pagesize == PAGE_SHIFT)
		return index;
	else if (fsi->log_pagesize > PAGE_SHIFT)
		return index >> (fsi->log_pagesize - PAGE_SHIFT);
	else
		return index << (PAGE_SHIFT - fsi->log_pagesize);
}

#define SSDFS_MEMPAGE2BYTES(index) \
	((pgoff_t)index << PAGE_SHIFT)
#define SSDFS_BYTES2MEMPAGE(offset) \
	((pgoff_t)offset >> PAGE_SHIFT)

#define SSDFS_BLKBMP_HDR(ptr) \
	((struct ssdfs_block_bitmap_header *)(ptr))
#define SSDFS_SBMP_FRAG_HDR(ptr) \
	((struct ssdfs_segbmap_fragment_header *)(ptr))
#define SSDFS_BTN(ptr) \
	((struct ssdfs_btree_node *)(ptr))

static inline
bool need_add_block(struct page *page)
{
	return PageChecked(page);
}

static inline
void set_page_new(struct page *page)
{
	SetPageChecked(page);
}

static inline
void clear_page_new(struct page *page)
{
	ClearPageChecked(page);
}

static inline
bool can_be_merged_into_extent(struct page *page1, struct page *page2)
{
	ino_t ino1 = page1->mapping->host->i_ino;
	ino_t ino2 = page2->mapping->host->i_ino;
	pgoff_t index1 = page_index(page1);
	pgoff_t index2 = page_index(page2);
	pgoff_t diff_index;
	bool has_identical_type;
	bool has_identical_ino;

	has_identical_type = (PageChecked(page1) && PageChecked(page2)) ||
				(!PageChecked(page1) && !PageChecked(page2));
	has_identical_ino = ino1 == ino2;

	if (index1 >= index2)
		diff_index = index1 - index2;
	else
		diff_index = index2 - index1;

	return has_identical_type && has_identical_ino && (diff_index == 1);
}

#define SSDFS_FSI(ptr) \
	((struct ssdfs_fs_info *)(ptr))
#define SSDFS_BLKT(ptr) \
	((struct ssdfs_area_block_table *)(ptr))
#define SSDFS_FRAGD(ptr) \
	((struct ssdfs_fragment_desc *)(ptr))
#define SSDFS_BLKD(ptr) \
	((struct ssdfs_block_descriptor *)(ptr))
#define SSDFS_BLKSTOFF(ptr) \
	((struct ssdfs_blk_state_offset *)(ptr))
#define SSDFS_STNODE_HDR(ptr) \
	((struct ssdfs_segment_tree_node_header *)(ptr))

#define SSDFS_SEG2PEB(fsi, seg) \
	((u64)seg << (SSDFS_FSI(fsi)->log_segsize - \
			SSDFS_FSI(fsi)->log_erasesize))
#define SSDFS_PEB2SEG(fsi, peb) \
	((u64)peb >> (SSDFS_FSI(fsi)->log_segsize - \
			SSDFS_FSI(fsi)->log_erasesize))

#endif /* _SSDFS_INLINE_H */
