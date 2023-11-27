// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ssdfs_inline.h - inline functions and macros.
 *
 * Copyright (c) 2019-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_INLINE_H
#define _SSDFS_INLINE_H

#include <linux/slab.h>
#include <linux/swap.h>

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

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
extern atomic64_t ssdfs_allocated_folios;
extern atomic64_t ssdfs_memory_leaks;

extern atomic64_t ssdfs_locked_folios;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

static inline
void ssdfs_memory_leaks_increment(void *kaddr)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_inc(&ssdfs_memory_leaks);

	SSDFS_DBG("memory %p, allocation count %lld\n",
		  kaddr,
		  atomic64_read(&ssdfs_memory_leaks));
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static inline
void ssdfs_memory_leaks_decrement(void *kaddr)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_dec(&ssdfs_memory_leaks);

	SSDFS_DBG("memory %p, allocation count %lld\n",
		  kaddr,
		  atomic64_read(&ssdfs_memory_leaks));
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static inline
void *ssdfs_kmalloc(size_t size, gfp_t flags)
{
	void *kaddr = kmalloc(size, flags);

	if (kaddr)
		ssdfs_memory_leaks_increment(kaddr);

	return kaddr;
}

static inline
void *ssdfs_kzalloc(size_t size, gfp_t flags)
{
	void *kaddr = kzalloc(size, flags);

	if (kaddr)
		ssdfs_memory_leaks_increment(kaddr);

	return kaddr;
}

static inline
void *ssdfs_kvzalloc(size_t size, gfp_t flags)
{
	void *kaddr = kvzalloc(size, flags);

	if (kaddr)
		ssdfs_memory_leaks_increment(kaddr);

	return kaddr;
}

static inline
void *ssdfs_kcalloc(size_t n, size_t size, gfp_t flags)
{
	void *kaddr = kcalloc(n, size, flags);

	if (kaddr)
		ssdfs_memory_leaks_increment(kaddr);

	return kaddr;
}

static inline
void ssdfs_kfree(void *kaddr)
{
	if (kaddr) {
		ssdfs_memory_leaks_decrement(kaddr);
		kfree(kaddr);
	}
}

static inline
void ssdfs_kvfree(void *kaddr)
{
	if (kaddr) {
		ssdfs_memory_leaks_decrement(kaddr);
		kvfree(kaddr);
	}
}

static inline
void ssdfs_folio_get(struct folio *folio)
{
	folio_get(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d, flags %#lx\n",
		  folio, folio_ref_count(folio), folio->flags);
#endif /* CONFIG_SSDFS_DEBUG */
}

static inline
void ssdfs_folio_put(struct folio *folio)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));

	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));

	if (folio_ref_count(folio) < 1) {
		SSDFS_WARN("folio %p, count %d\n",
			   folio, folio_ref_count(folio));
	}
#endif /* CONFIG_SSDFS_DEBUG */

	folio_put(folio);
}

static inline
void ssdfs_folio_lock(struct folio *folio)
{
	folio_lock(folio);

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_locked_folios) < 0) {
		SSDFS_WARN("ssdfs_locked_folios %lld\n",
			   atomic64_read(&ssdfs_locked_folios));
	}

	atomic64_inc(&ssdfs_locked_folios);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static inline
void ssdfs_account_locked_folio(struct folio *folio)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (!folio)
		return;

	if (!folio_test_locked(folio)) {
		SSDFS_WARN("folio %p, folio_index %llu\n",
			   folio, (u64)folio_index(folio));
	}

	if (atomic64_read(&ssdfs_locked_folios) < 0) {
		SSDFS_WARN("ssdfs_locked_folios %lld\n",
			   atomic64_read(&ssdfs_locked_folios));
	}

	atomic64_inc(&ssdfs_locked_folios);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static inline
void ssdfs_folio_unlock(struct folio *folio)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (!folio_test_locked(folio)) {
		SSDFS_WARN("folio %p, folio_index %llu\n",
			   folio, (u64)folio_index(folio));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

	folio_unlock(folio);

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_dec(&ssdfs_locked_folios);

	if (atomic64_read(&ssdfs_locked_folios) < 0) {
		SSDFS_WARN("ssdfs_locked_folios %lld\n",
			   atomic64_read(&ssdfs_locked_folios));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static inline
struct folio *ssdfs_folio_alloc(gfp_t gfp_mask, unsigned int order)
{
	struct folio *folio;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("mask %#x, order %u\n",
		  gfp_mask, order);

	if (order > get_order(SSDFS_128KB)) {
		SSDFS_WARN("invalid order %u\n",
			   order);
		return ERR_PTR(-ERANGE);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	folio = folio_alloc(gfp_mask, order);
	if (unlikely(!folio)) {
		SSDFS_WARN("unable to allocate folio\n");
		return ERR_PTR(-ENOMEM);
	}

	ssdfs_folio_get(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d, "
		  "flags %#lx, folio_index %lu\n",
		  folio, folio_ref_count(folio),
		  folio->flags, folio_index(folio));
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_inc(&ssdfs_allocated_folios);

	SSDFS_DBG("folio %p, allocated_folios %lld\n",
		  folio, atomic64_read(&ssdfs_allocated_folios));
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

	return folio;
}

static inline
void ssdfs_folio_account(struct folio *folio)
{
	return;
}

static inline
void ssdfs_folio_forget(struct folio *folio)
{
	return;
}

/*
 * ssdfs_add_batch_folio() - add folio into batch
 * @batch: folio batch
 *
 * This function adds folio into batch.
 *
 * RETURN:
 * [success] - pointer on added folio.
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 * %-E2BIG      - batch is full.
 */
static inline
struct folio *ssdfs_add_batch_folio(struct folio_batch *batch,
				    unsigned int order)
{
	struct folio *folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!batch);
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio_batch_space(batch) == 0) {
		SSDFS_ERR("batch hasn't space\n");
		return ERR_PTR(-E2BIG);
	}

	folio = ssdfs_folio_alloc(GFP_KERNEL | __GFP_ZERO, order);
	if (IS_ERR_OR_NULL(folio)) {
		err = (folio == NULL ? -ENOMEM : PTR_ERR(folio));
		SSDFS_ERR("unable to allocate folio\n");
		return ERR_PTR(err);
	}

	folio_batch_add(batch, folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("batch %p, batch count %u\n",
		  batch, folio_batch_count(batch));
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	return folio;
}

static inline
void ssdfs_folio_free(struct folio *folio)
{
	if (!folio)
		return;

#ifdef CONFIG_SSDFS_DEBUG
	if (folio_test_locked(folio)) {
		SSDFS_WARN("folio %p is still locked\n",
			   folio);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	/* descrease reference counter */
	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d, "
		  "flags %#lx, folio_index %lu\n",
		  folio, folio_ref_count(folio),
		  folio->flags, folio_index(folio));

	if (folio_ref_count(folio) <= 0 ||
	    folio_ref_count(folio) > 2) {
		SSDFS_WARN("folio %p, count %d\n",
			   folio, folio_ref_count(folio));
	}
#endif /* CONFIG_SSDFS_DEBUG */

	/* free folio */
	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_dec(&ssdfs_allocated_folios);

	SSDFS_DBG("allocated_folios %lld\n",
		  atomic64_read(&ssdfs_allocated_folios));
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static inline
void ssdfs_folio_batch_release(struct folio_batch *batch)
{
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("batch %p\n", batch);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!batch)
		return;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("batch count %u\n", folio_batch_count(batch));
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < folio_batch_count(batch); i++) {
		struct folio *folio = batch->folios[i];

		if (!folio)
			continue;

		ssdfs_folio_free(folio);

		batch->folios[i] = NULL;
	}

	folio_batch_reinit(batch);
}

#define SSDFS_MEMORY_LEAKS_CHECKER_FNS(name)				\
static inline								\
void ssdfs_##name##_cache_leaks_increment(void *kaddr)			\
{									\
	atomic64_inc(&ssdfs_##name##_cache_leaks);			\
	SSDFS_DBG("memory %p, allocation count %lld\n",			\
		  kaddr,						\
		  atomic64_read(&ssdfs_##name##_cache_leaks));		\
	ssdfs_memory_leaks_increment(kaddr);				\
}									\
static inline								\
void ssdfs_##name##_cache_leaks_decrement(void *kaddr)			\
{									\
	atomic64_dec(&ssdfs_##name##_cache_leaks);			\
	SSDFS_DBG("memory %p, allocation count %lld\n",			\
		  kaddr,						\
		  atomic64_read(&ssdfs_##name##_cache_leaks));		\
	ssdfs_memory_leaks_decrement(kaddr);				\
}									\
static inline								\
void *ssdfs_##name##_kmalloc(size_t size, gfp_t flags)			\
{									\
	void *kaddr = ssdfs_kmalloc(size, flags);			\
	if (kaddr) {							\
		atomic64_inc(&ssdfs_##name##_memory_leaks);		\
		SSDFS_DBG("memory %p, allocation count %lld\n",		\
			  kaddr,					\
			  atomic64_read(&ssdfs_##name##_memory_leaks));	\
	}								\
	return kaddr;							\
}									\
static inline								\
void *ssdfs_##name##_kzalloc(size_t size, gfp_t flags)			\
{									\
	void *kaddr = ssdfs_kzalloc(size, flags);			\
	if (kaddr) {							\
		atomic64_inc(&ssdfs_##name##_memory_leaks);		\
		SSDFS_DBG("memory %p, allocation count %lld\n",		\
			  kaddr,					\
			  atomic64_read(&ssdfs_##name##_memory_leaks));	\
	}								\
	return kaddr;							\
}									\
static inline								\
void *ssdfs_##name##_kvzalloc(size_t size, gfp_t flags)			\
{									\
	void *kaddr = ssdfs_kvzalloc(size, flags);			\
	if (kaddr) {							\
		atomic64_inc(&ssdfs_##name##_memory_leaks);		\
		SSDFS_DBG("memory %p, allocation count %lld\n",		\
			  kaddr,					\
			  atomic64_read(&ssdfs_##name##_memory_leaks));	\
	}								\
	return kaddr;							\
}									\
static inline								\
void *ssdfs_##name##_kcalloc(size_t n, size_t size, gfp_t flags)	\
{									\
	void *kaddr = ssdfs_kcalloc(n, size, flags);			\
	if (kaddr) {							\
		atomic64_inc(&ssdfs_##name##_memory_leaks);		\
		SSDFS_DBG("memory %p, allocation count %lld\n",		\
			  kaddr,					\
			  atomic64_read(&ssdfs_##name##_memory_leaks));	\
	}								\
	return kaddr;							\
}									\
static inline								\
void ssdfs_##name##_kfree(void *kaddr)					\
{									\
	if (kaddr) {							\
		atomic64_dec(&ssdfs_##name##_memory_leaks);		\
		SSDFS_DBG("memory %p, allocation count %lld\n",		\
			  kaddr,					\
			  atomic64_read(&ssdfs_##name##_memory_leaks));	\
	}								\
	ssdfs_kfree(kaddr);						\
}									\
static inline								\
void ssdfs_##name##_kvfree(void *kaddr)					\
{									\
	if (kaddr) {							\
		atomic64_dec(&ssdfs_##name##_memory_leaks);		\
		SSDFS_DBG("memory %p, allocation count %lld\n",		\
			  kaddr,					\
			  atomic64_read(&ssdfs_##name##_memory_leaks));	\
	}								\
	ssdfs_kvfree(kaddr);						\
}									\
static inline								\
struct folio *ssdfs_##name##_alloc_folio(gfp_t gfp_mask,		\
					 unsigned int order)		\
{									\
	struct folio *folio;						\
	folio = ssdfs_folio_alloc(gfp_mask, order);			\
	if (!IS_ERR_OR_NULL(folio)) {					\
		atomic64_inc(&ssdfs_##name##_folio_leaks);		\
		SSDFS_DBG("folio %p, allocated_folios %lld\n",		\
			  folio,					\
			  atomic64_read(&ssdfs_##name##_folio_leaks));	\
	}								\
	return folio;							\
}									\
static inline								\
void ssdfs_##name##_account_folio(struct folio *folio)			\
{									\
	if (folio) {							\
		atomic64_inc(&ssdfs_##name##_folio_leaks);		\
		SSDFS_DBG("folio %p, allocated_folios %lld\n",		\
			  folio,					\
			  atomic64_read(&ssdfs_##name##_folio_leaks));	\
	}								\
}									\
static inline								\
void ssdfs_##name##_forget_folio(struct folio *folio)			\
{									\
	if (folio) {							\
		atomic64_dec(&ssdfs_##name##_folio_leaks);		\
		SSDFS_DBG("folio %p, allocated_folios %lld\n",		\
			  folio,					\
			  atomic64_read(&ssdfs_##name##_folio_leaks));	\
	}								\
}									\
static inline								\
struct folio *ssdfs_##name##_add_batch_folio(struct folio_batch *batch,	\
					     unsigned int order)	\
{									\
	struct folio *folio;						\
	folio = ssdfs_add_batch_folio(batch, order);			\
	if (!IS_ERR_OR_NULL(folio)) {					\
		atomic64_inc(&ssdfs_##name##_folio_leaks);		\
		SSDFS_DBG("folio %p, allocated_folios %lld\n",		\
			  folio,					\
			  atomic64_read(&ssdfs_##name##_folio_leaks));	\
	}								\
	return folio;							\
}									\
static inline								\
void ssdfs_##name##_free_folio(struct folio *folio)			\
{									\
	if (folio) {							\
		atomic64_dec(&ssdfs_##name##_folio_leaks);		\
		SSDFS_DBG("folio %p, allocated_folios %lld\n",		\
			  folio,					\
			  atomic64_read(&ssdfs_##name##_folio_leaks));	\
	}								\
	ssdfs_folio_free(folio);					\
}									\
static inline								\
void ssdfs_##name##_folio_batch_release(struct folio_batch *batch)	\
{									\
	int i;								\
	if (batch) {							\
		for (i = 0; i < folio_batch_count(batch); i++) {	\
			struct folio *folio = batch->folios[i];		\
			if (!folio)					\
				continue;				\
			atomic64_dec(&ssdfs_##name##_folio_leaks);	\
			SSDFS_DBG("folio %p, allocated_folios %lld\n",	\
			    folio,					\
			    atomic64_read(&ssdfs_##name##_folio_leaks));\
		}							\
	}								\
	ssdfs_folio_batch_release(batch);				\
}									\

#define SSDFS_MEMORY_ALLOCATOR_FNS(name)				\
static inline								\
void ssdfs_##name##_cache_leaks_increment(void *kaddr)			\
{									\
	ssdfs_memory_leaks_increment(kaddr);				\
}									\
static inline								\
void ssdfs_##name##_cache_leaks_decrement(void *kaddr)			\
{									\
	ssdfs_memory_leaks_decrement(kaddr);				\
}									\
static inline								\
void *ssdfs_##name##_kmalloc(size_t size, gfp_t flags)			\
{									\
	return ssdfs_kmalloc(size, flags);				\
}									\
static inline								\
void *ssdfs_##name##_kzalloc(size_t size, gfp_t flags)			\
{									\
	return ssdfs_kzalloc(size, flags);				\
}									\
static inline								\
void *ssdfs_##name##_kvzalloc(size_t size, gfp_t flags)			\
{									\
	return ssdfs_kvzalloc(size, flags);				\
}									\
static inline								\
void *ssdfs_##name##_kcalloc(size_t n, size_t size, gfp_t flags)	\
{									\
	return ssdfs_kcalloc(n, size, flags);				\
}									\
static inline								\
void ssdfs_##name##_kfree(void *kaddr)					\
{									\
	ssdfs_kfree(kaddr);						\
}									\
static inline								\
void ssdfs_##name##_kvfree(void *kaddr)					\
{									\
	ssdfs_kvfree(kaddr);						\
}									\
static inline								\
struct folio *ssdfs_##name##_alloc_folio(gfp_t gfp_mask,		\
					 unsigned int order)		\
{									\
	return ssdfs_folio_alloc(gfp_mask, order);			\
}									\
static inline								\
void ssdfs_##name##_account_folio(struct folio *folio)			\
{									\
	ssdfs_folio_account(folio);					\
}									\
static inline								\
void ssdfs_##name##_forget_folio(struct folio *folio)			\
{									\
	ssdfs_folio_forget(folio);					\
}									\
static inline								\
struct folio *ssdfs_##name##_add_batch_folio(struct folio_batch *batch,	\
					     unsigned int order)	\
{									\
	return ssdfs_add_batch_folio(batch, order);			\
}									\
static inline								\
void ssdfs_##name##_free_folio(struct folio *folio)			\
{									\
	ssdfs_folio_free(folio);					\
}									\
static inline								\
void ssdfs_##name##_folio_batch_release(struct folio_batch *batch)	\
{									\
	ssdfs_folio_batch_release(batch);				\
}									\

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
		SSDFS_WARN("unknown flags set %#x\n", flags);

#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */

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
	    magic->version.minor > SSDFS_MINOR_REVISION) {
		SSDFS_INFO("Volume has unsupported %u.%u version. "
			   "Driver expects %u.%u version.\n",
			   magic->version.major,
			   magic->version.minor,
			   SSDFS_MAJOR_REVISION,
			   SSDFS_MINOR_REVISION);
		return false;
	}

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

/*
 * struct ssdfs_offset2folio - folio descriptor for offset
 * @block_size: logical block size in bytes
 * @offset: offset in bytes
 * @folio_index: folio index
 * @folio_offset: folio offset in bytes
 * @page_in_folio: page index in folio
 * @page_offset: page offset from folio's beginning in bytes
 * @offset_inside_page: offset inside of page in bytes
 */
struct ssdfs_offset2folio {
	u32 block_size;
	u64 offset;
	u32 folio_index;
	u64 folio_offset;
	u32 page_in_folio;
	u32 page_offset;
	u32 offset_inside_page;
};

/*
 * struct ssdfs_smart_folio - smart memory folio
 * @ptr: memory folio pointer
 * @desc: offset to folio descriptor
 */
struct ssdfs_smart_folio {
	struct folio *ptr;
	struct ssdfs_offset2folio desc;
};

/*
 * IS_SSDFS_OFF2FOLIO_VALID() - check offset to folio descriptor
 */
static inline
bool IS_SSDFS_OFF2FOLIO_VALID(struct ssdfs_offset2folio *desc)
{
	u64 calculated;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (desc->block_size) {
	case SSDFS_4KB:
	case SSDFS_8KB:
	case SSDFS_16KB:
	case SSDFS_32KB:
	case SSDFS_64KB:
	case SSDFS_128KB:
		/* expected block size */
		break;

	default:
		SSDFS_ERR("unexpected logical block size %u\n",
			  desc->block_size);
		return false;
	}

	calculated = (u64)desc->folio_index * desc->block_size;
	if (calculated != desc->folio_offset) {
		SSDFS_ERR("invalid folio index: "
			  "folio_index %u, block_size %u, "
			  "folio_offset %llu\n",
			  desc->folio_index,
			  desc->block_size,
			  desc->folio_offset);
		return false;
	}

	calculated = (u64)desc->page_in_folio << PAGE_SHIFT;
	if (calculated != desc->page_offset) {
		SSDFS_ERR("invalid page in folio index: "
			  "page_index %u, page_offset %u\n",
			  desc->page_in_folio,
			  desc->page_offset);
		return false;
	}

	calculated = desc->folio_offset;
	calculated += desc->page_offset;
	calculated += desc->offset_inside_page;
	if (calculated != desc->offset) {
		SSDFS_ERR("invalid offset: "
			  "offset %llu, folio_offset %llu, "
			  "page_offset %u, offset_inside_page %u\n",
			  desc->offset,
			  desc->folio_offset,
			  desc->page_offset,
			  desc->offset_inside_page);
		return false;
	}

	return true;
}

/*
 * SSDFS_OFF2FOLIO() - convert offset to folio
 * @block_size: size of block in bytes
 * @offset: offset in bytes
 * @desc: offset to folio descriptor [out]
 */
static inline
int SSDFS_OFF2FOLIO(u32 block_size, u64 offset,
		    struct ssdfs_offset2folio *desc)
{
	u64 index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
	BUG_ON(offset >= U64_MAX);

	switch (block_size) {
	case SSDFS_4KB:
	case SSDFS_8KB:
	case SSDFS_16KB:
	case SSDFS_32KB:
	case SSDFS_64KB:
	case SSDFS_128KB:
		/* expected block size */
		break;

	default:
		SSDFS_ERR("unexpected logical block size %u\n",
			  block_size);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	desc->block_size = block_size;
	desc->offset = offset;

	desc->folio_index = div_u64(desc->offset, desc->block_size);
	desc->folio_offset = (u64)desc->folio_index * desc->block_size;

	index = (desc->offset - desc->folio_offset) >> PAGE_SHIFT;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(index >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	desc->page_in_folio = (u32)index;

	index <<= PAGE_SHIFT;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(index >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	desc->page_offset = (u32)index;

	desc->offset_inside_page = offset % PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("block_size %u, offset %llu, "
		  "folio_index %u, folio_offset %llu, "
		  "page_in_folio %u, page_offset %u, "
		  "offset_inside_page %u\n",
		  desc->block_size, desc->offset,
		  desc->folio_index, desc->folio_offset,
		  desc->page_in_folio, desc->page_offset,
		  desc->offset_inside_page);

	if (!IS_SSDFS_OFF2FOLIO_VALID(desc)) {
		SSDFS_ERR("invalid descriptor\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

#define SSDFS_BLKBMP_HDR(ptr) \
	((struct ssdfs_block_bitmap_header *)(ptr))
#define SSDFS_SBMP_FRAG_HDR(ptr) \
	((struct ssdfs_segbmap_fragment_header *)(ptr))
#define SSDFS_BTN(ptr) \
	((struct ssdfs_btree_node *)(ptr))

static inline
bool can_be_merged_into_extent(struct folio *folio1, struct folio *folio2)
{
	ino_t ino1 = folio1->mapping->host->i_ino;
	ino_t ino2 = folio2->mapping->host->i_ino;
	pgoff_t index1 = folio_index(folio1);
	pgoff_t index2 = folio_index(folio2);
	pgoff_t diff_index;
	bool has_identical_type;
	bool has_identical_ino;

	has_identical_type = (folio_test_checked(folio1) &&
					folio_test_checked(folio2)) ||
				(!folio_test_checked(folio1) &&
					!folio_test_checked(folio2));
	has_identical_ino = ino1 == ino2;

	if (index1 >= index2)
		diff_index = index1 - index2;
	else
		diff_index = index2 - index1;

	return has_identical_type && has_identical_ino && (diff_index == 1);
}

static inline
bool need_add_block(struct folio *folio)
{
	return folio_test_checked(folio);
}

static inline
bool is_diff_folio(struct folio *folio)
{
	return folio_test_checked(folio);
}

static inline
void set_folio_new(struct folio *folio)
{
	folio_set_checked(folio);
}

static inline
void clear_folio_new(struct folio *folio)
{
	folio_clear_checked(folio);
}

static
inline void ssdfs_set_folio_private(struct folio *folio,
				    unsigned long private)
{
	folio_change_private(folio, (void *)private);
	folio_set_private(folio);
}

static
inline void ssdfs_clear_folio_private(struct folio *folio,
				      unsigned long private)
{
	folio_change_private(folio, (void *)private);
	folio_clear_private(folio);
}

static inline
int ssdfs_memcpy(void *dst, u32 dst_off, u32 dst_size,
		 const void *src, u32 src_off, u32 src_size,
		 u32 copy_size)
{
#ifdef CONFIG_SSDFS_DEBUG
	if ((src_off + copy_size) > src_size) {
		SSDFS_WARN("fail to copy: "
			   "src_off %u, copy_size %u, src_size %u\n",
			   src_off, copy_size, src_size);
		return -ERANGE;
	}

	if ((dst_off + copy_size) > dst_size) {
		SSDFS_WARN("fail to copy: "
			   "dst_off %u, copy_size %u, dst_size %u\n",
			   dst_off, copy_size, dst_size);
		return -ERANGE;
	}

	SSDFS_DBG("dst %p, dst_off %u, dst_size %u, "
		  "src %p, src_off %u, src_size %u, "
		  "copy_size %u\n",
		  dst, dst_off, dst_size,
		  src, src_off, src_size,
		  copy_size);
#endif /* CONFIG_SSDFS_DEBUG */

	memcpy((u8 *)dst + dst_off, (u8 *)src + src_off, copy_size);
	return 0;
}

static inline
int ssdfs_iter_copy(void *dst_kaddr, u32 dst_offset,
		    void *src_kaddr, u32 src_offset,
		    u32 copy_size, u32 *copied_bytes)
{
	u32 src_offset_in_page;
	u32 dst_offset_in_page;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!copied_bytes);
	BUG_ON(copy_size == 0);

	SSDFS_DBG("src_kaddr %p, src_offset %u, "
		  "dst_kaddr %p, dst_offset %u, "
		  "copy_size %u\n",
		  src_kaddr, src_offset,
		  dst_kaddr, dst_offset,
		  copy_size);
#endif /* CONFIG_SSDFS_DEBUG */

	src_offset_in_page = src_offset % PAGE_SIZE;
	*copied_bytes = PAGE_SIZE - src_offset_in_page;

	dst_offset_in_page = dst_offset % PAGE_SIZE;
	*copied_bytes = min_t(u32, *copied_bytes,
				   PAGE_SIZE - dst_offset_in_page);

	*copied_bytes = min_t(u32, *copied_bytes, copy_size);

	err = ssdfs_memcpy(dst_kaddr, dst_offset_in_page, PAGE_SIZE,
			   src_kaddr, src_offset_in_page, PAGE_SIZE,
			   *copied_bytes);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: "
			  "src_kaddr %p, src_offset_in_page %u, "
			  "dst_kaddr %p, dst_offset_in_page %u, "
			  "copied_bytes %u, err %d\n",
			  src_kaddr, src_offset_in_page,
			  dst_kaddr, dst_offset_in_page,
			  *copied_bytes, err);
		return err;
	}

	return 0;
}

static inline
int ssdfs_iter_copy_from_folio(void *dst_kaddr, u32 dst_offset, u32 dst_size,
				void *src_kaddr, u32 src_offset,
				u32 copy_size, u32 *copied_bytes)
{
	u32 src_offset_in_page;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!copied_bytes);
	BUG_ON(copy_size == 0);

	SSDFS_DBG("src_kaddr %p, src_offset %u, "
		  "dst_kaddr %p, dst_offset %u, dst_size %u, "
		  "copy_size %u\n",
		  src_kaddr, src_offset,
		  dst_kaddr, dst_offset, dst_size,
		  copy_size);
#endif /* CONFIG_SSDFS_DEBUG */

	src_offset_in_page = src_offset % PAGE_SIZE;
	*copied_bytes = PAGE_SIZE - src_offset_in_page;
	*copied_bytes = min_t(u32, *copied_bytes, copy_size);

	err = ssdfs_memcpy(dst_kaddr, dst_offset, dst_size,
			   src_kaddr, src_offset_in_page, PAGE_SIZE,
			   *copied_bytes);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: "
			  "src_kaddr %p, src_offset_in_page %u, "
			  "dst_kaddr %p, dst_offset %u, "
			  "copied_bytes %u, err %d\n",
			  src_kaddr, src_offset_in_page,
			  dst_kaddr, dst_offset,
			  *copied_bytes, err);
		return err;
	}

	return 0;
}

static inline
int ssdfs_iter_copy_to_folio(void *dst_kaddr, u32 dst_offset,
			     void *src_kaddr, u32 src_offset, u32 src_size,
			     u32 copy_size, u32 *copied_bytes)
{
	u32 dst_offset_in_page;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!copied_bytes);
	BUG_ON(copy_size == 0);

	SSDFS_DBG("src_kaddr %p, src_offset %u, "
		  "dst_kaddr %p, dst_offset %u, "
		  "copy_size %u\n",
		  src_kaddr, src_offset,
		  dst_kaddr, dst_offset,
		  copy_size);
#endif /* CONFIG_SSDFS_DEBUG */

	dst_offset_in_page = dst_offset % PAGE_SIZE;
	*copied_bytes = PAGE_SIZE - dst_offset_in_page;
	*copied_bytes = min_t(u32, *copied_bytes, copy_size);

	err = ssdfs_memcpy(dst_kaddr, dst_offset_in_page, PAGE_SIZE,
			   src_kaddr, src_offset, src_size,
			   *copied_bytes);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: "
			  "src_kaddr %p, src_offset %u, src_size %u, "
			  "dst_kaddr %p, dst_offset_in_page %u, "
			  "copied_bytes %u, err %d\n",
			  src_kaddr, src_offset, src_size,
			  dst_kaddr, dst_offset_in_page,
			  *copied_bytes, err);
		return err;
	}

	return 0;
}

static inline
int __ssdfs_memcpy_folio(struct folio *dst_folio, u32 dst_off, u32 dst_size,
			 struct folio *src_folio, u32 src_off, u32 src_size,
			 u32 copy_size)
{
	void *src_kaddr;
	void *dst_kaddr;
	u32 src_page, dst_page;
	u32 copied_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!dst_folio || !src_folio);

	switch (dst_size) {
	case SSDFS_4KB:
	case SSDFS_8KB:
	case SSDFS_16KB:
	case SSDFS_32KB:
	case SSDFS_64KB:
	case SSDFS_128KB:
		/* expected block size */
		break;

	default:
		SSDFS_ERR("unexpected dst_size %u\n",
			  dst_size);
		return -EINVAL;
	}

	switch (src_size) {
	case SSDFS_4KB:
	case SSDFS_8KB:
	case SSDFS_16KB:
	case SSDFS_32KB:
	case SSDFS_64KB:
	case SSDFS_128KB:
		/* expected block size */
		break;

	default:
		SSDFS_ERR("unexpected src_size %u\n",
			  src_size);
		return -EINVAL;
	}

	if (dst_size > folio_size(dst_folio) ||
	    copy_size > folio_size(dst_folio)) {
		SSDFS_ERR("fail to copy: "
			  "dst_size %u, copy_size %u, folio_size %zu\n",
			  dst_size, copy_size, folio_size(dst_folio));
		return -ERANGE;
	}

	if (src_size > folio_size(src_folio) ||
	    copy_size > folio_size(src_folio)) {
		SSDFS_ERR("fail to copy: "
			  "src_size %u, copy_size %u, folio_size %zu\n",
			  src_size, copy_size, folio_size(src_folio));
		return -ERANGE;
	}

	if ((src_off + copy_size) > src_size) {
		SSDFS_ERR("fail to copy: "
			  "src_off %u, copy_size %u, src_size %u\n",
			  src_off, copy_size, src_size);
		return -ERANGE;
	}

	if ((dst_off + copy_size) > dst_size) {
		SSDFS_ERR("fail to copy: "
			  "dst_off %u, copy_size %u, dst_size %u\n",
			  dst_off, copy_size, dst_size);
		return -ERANGE;
	}

	SSDFS_DBG("dst_folio %p, dst_off %u, dst_size %u, "
		  "src_folio %p, src_off %u, src_size %u, "
		  "copy_size %u\n",
		  dst_folio, dst_off, dst_size,
		  src_folio, src_off, src_size,
		  copy_size);
#endif /* CONFIG_SSDFS_DEBUG */

	if (copy_size == 0) {
		SSDFS_ERR("copy_size == 0\n");
		return -ERANGE;
	}

	while (copied_bytes < copy_size) {
		u32 src_iter_offset;
		u32 dst_iter_offset;
		u32 iter_bytes;

		src_iter_offset = src_off + copied_bytes;
		src_page = src_iter_offset >> PAGE_SHIFT;

		dst_iter_offset = dst_off + copied_bytes;
		dst_page = dst_iter_offset >> PAGE_SHIFT;

		src_kaddr = kmap_local_folio(src_folio, src_page * PAGE_SIZE);
		dst_kaddr = kmap_local_folio(dst_folio, dst_page * PAGE_SIZE);
		err = ssdfs_iter_copy(dst_kaddr, dst_iter_offset,
				      src_kaddr, src_iter_offset,
				      copy_size - copied_bytes,
				      &iter_bytes);
		kunmap_local(dst_kaddr);
		kunmap_local(src_kaddr);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy folio: "
				  "src_page %u, src_iter_offset %u, "
				  "dst_page %u, dst_iter_offset %u, "
				  "iter_bytes %u, err %d\n",
				  src_page, src_iter_offset,
				  dst_page, dst_iter_offset,
				  iter_bytes, err);
			return err;
		}

		copied_bytes += iter_bytes;
	}

	if (copied_bytes != copy_size) {
		SSDFS_ERR("copied_bytes %u != copy_size %u\n",
			  copied_bytes, copy_size);
		return -ERANGE;
	}

	flush_dcache_folio(dst_folio);

	return 0;
}

static inline
int ssdfs_memcpy_folio(struct ssdfs_smart_folio *dst_folio,
			struct ssdfs_smart_folio *src_folio,
			u32 copy_size)
{
	u32 dst_off;
	u32 src_off;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!dst_folio || !src_folio);
#endif /* CONFIG_SSDFS_DEBUG */

	dst_off = dst_folio->desc.page_offset +
			dst_folio->desc.offset_inside_page;
	src_off = src_folio->desc.page_offset +
			src_folio->desc.offset_inside_page;

	return __ssdfs_memcpy_folio(dst_folio->ptr,
				    dst_off, dst_folio->desc.block_size,
				    src_folio->ptr,
				    src_off, src_folio->desc.block_size,
				    copy_size);
}

static inline
int __ssdfs_memcpy_from_folio(void *dst, u32 dst_off, u32 dst_size,
			      struct folio *folio, u32 src_off, u32 src_size,
			      u32 copy_size)
{
	void *src_kaddr;
	u32 src_page;
	u32 copied_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	switch (src_size) {
	case SSDFS_4KB:
	case SSDFS_8KB:
	case SSDFS_16KB:
	case SSDFS_32KB:
	case SSDFS_64KB:
	case SSDFS_128KB:
		/* expected block size */
		break;

	default:
		SSDFS_ERR("unexpected src_size %u\n",
			  src_size);
		return -EINVAL;
	}

	if (src_size > folio_size(folio) ||
	    copy_size > folio_size(folio)) {
		SSDFS_ERR("fail to copy: "
			  "src_size %u, copy_size %u, folio_size %zu\n",
			  src_size, copy_size, folio_size(folio));
		return -ERANGE;
	}

	if ((src_off + copy_size) > src_size) {
		SSDFS_ERR("fail to copy: "
			  "src_off %u, copy_size %u, src_size %u\n",
			  src_off, copy_size, src_size);
		return -ERANGE;
	}

	if ((dst_off + copy_size) > dst_size) {
		SSDFS_ERR("fail to copy: "
			  "dst_off %u, copy_size %u, dst_size %u\n",
			  dst_off, copy_size, dst_size);
		return -ERANGE;
	}

	SSDFS_DBG("dst %p, dst_off %u, dst_size %u, "
		  "folio %p, src_off %u, src_size %u, "
		  "copy_size %u\n",
		  dst, dst_off, dst_size,
		  folio, src_off, src_size,
		  copy_size);
#endif /* CONFIG_SSDFS_DEBUG */

	if (copy_size == 0) {
		SSDFS_ERR("copy_size == 0\n");
		return -ERANGE;
	}

	while (copied_bytes < copy_size) {
		u32 src_iter_offset;
		u32 dst_iter_offset;
		u32 iter_bytes;

		src_iter_offset = src_off + copied_bytes;
		src_page = src_iter_offset >> PAGE_SHIFT;

		dst_iter_offset = dst_off + copied_bytes;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("src_off %u, src_iter_offset %u, src_page %u, "
			  "dst_off %u, dst_iter_offset %u\n",
			  src_off, src_iter_offset, src_page,
			  dst_off, dst_iter_offset);
#endif /* CONFIG_SSDFS_DEBUG */

		src_kaddr = kmap_local_folio(folio, src_page * PAGE_SIZE);
		err = ssdfs_iter_copy_from_folio(dst, dst_iter_offset, dst_size,
						 src_kaddr, src_iter_offset,
						 copy_size - copied_bytes,
						 &iter_bytes);
		kunmap_local(src_kaddr);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy folio: "
				  "src_page %u, src_iter_offset %u, "
				  "dst_iter_offset %u, "
				  "iter_bytes %u, err %d\n",
				  src_page, src_iter_offset,
				  dst_iter_offset,
				  iter_bytes, err);
			return err;
		}

		copied_bytes += iter_bytes;
	}

	if (copied_bytes != copy_size) {
		SSDFS_ERR("copied_bytes %u != copy_size %u\n",
			  copied_bytes, copy_size);
		return -ERANGE;
	}

	return 0;
}

static inline
int ssdfs_memcpy_from_folio(void *dst, u32 dst_off, u32 dst_size,
			    struct ssdfs_smart_folio *src_folio,
			    u32 copy_size)
{
	u32 src_off;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!dst || !src_folio);
#endif /* CONFIG_SSDFS_DEBUG */

	src_off = src_folio->desc.page_offset +
			src_folio->desc.offset_inside_page;

	return __ssdfs_memcpy_from_folio(dst, dst_off, dst_size,
					 src_folio->ptr,
					 src_off, folio_size(src_folio->ptr),
					 copy_size);
}

static inline
int ssdfs_memcpy_from_batch(u32 pagesize,
			    void *dst, u32 dst_off, u32 dst_size,
			    struct folio_batch *batch, u32 src_off,
			    u32 copy_size)
{
	struct ssdfs_smart_folio folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!dst || !batch);

	SSDFS_DBG("dst_off %u, dst_size %u, "
		  "src_off %u, copy_size %u\n",
		  dst_off, dst_size,
		  src_off, copy_size);
#endif /* CONFIG_SSDFS_DEBUG */

	err = SSDFS_OFF2FOLIO(pagesize, src_off, &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert offset into folio: "
			  "src_off %u, err %d\n",
			  src_off, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio.desc.folio_index >= folio_batch_count(batch)) {
		SSDFS_ERR("invalid folio_index: "
			  "index %d, batch_size %u\n",
			  folio.desc.folio_index,
			  folio_batch_count(batch));
		return -ERANGE;
	}

	folio.ptr = batch->folios[folio.desc.folio_index];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_folio_lock(folio.ptr);
	err = ssdfs_memcpy_from_folio(dst, dst_off, dst_size,
				      &folio, copy_size);
	ssdfs_folio_unlock(folio.ptr);

	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		return err;
	}

	return 0;
}

static inline
int __ssdfs_memcpy_to_folio(struct folio *folio, u32 dst_off, u32 dst_size,
			    void *src, u32 src_off, u32 src_size,
			    u32 copy_size)
{
	void *dst_kaddr;
	u32 dst_page;
	u32 copied_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	switch (dst_size) {
	case SSDFS_4KB:
	case SSDFS_8KB:
	case SSDFS_16KB:
	case SSDFS_32KB:
	case SSDFS_64KB:
	case SSDFS_128KB:
		/* expected block size */
		break;

	default:
		SSDFS_ERR("unexpected dst_size %u\n",
			  dst_size);
		return -EINVAL;
	}

	if (dst_size > folio_size(folio) ||
	    copy_size > folio_size(folio)) {
		SSDFS_ERR("fail to copy: "
			  "dst_size %u, copy_size %u, folio_size %zu\n",
			  dst_size, copy_size, folio_size(folio));
		return -ERANGE;
	}

	if ((src_off + copy_size) > src_size) {
		SSDFS_ERR("fail to copy: "
			  "src_off %u, copy_size %u, src_size %u\n",
			  src_off, copy_size, src_size);
		return -ERANGE;
	}

	if ((dst_off + copy_size) > dst_size) {
		SSDFS_ERR("fail to copy: "
			  "dst_off %u, copy_size %u, dst_size %u\n",
			  dst_off, copy_size, dst_size);
		return -ERANGE;
	}

	SSDFS_DBG("folio %p, dst_off %u, dst_size %u, "
		  "src %p, src_off %u, src_size %u, "
		  "copy_size %u\n",
		  folio, dst_off, dst_size,
		  src, src_off, src_size,
		  copy_size);
#endif /* CONFIG_SSDFS_DEBUG */

	if (copy_size == 0) {
		SSDFS_ERR("copy_size == 0\n");
		return -ERANGE;
	}

	while (copied_bytes < copy_size) {
		u32 src_iter_offset;
		u32 dst_iter_offset;
		u32 iter_bytes;

		src_iter_offset = src_off + copied_bytes;

		dst_iter_offset = dst_off + copied_bytes;
		dst_page = dst_iter_offset >> PAGE_SHIFT;

		dst_kaddr = kmap_local_folio(folio, dst_page * PAGE_SIZE);
		err = ssdfs_iter_copy_to_folio(dst_kaddr, dst_iter_offset,
						src, src_iter_offset, src_size,
						copy_size - copied_bytes,
						&iter_bytes);
		kunmap_local(dst_kaddr);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy folio: "
				  "src_iter_offset %u, "
				  "dst_page %u, dst_iter_offset %u, "
				  "iter_bytes %u, err %d\n",
				  src_iter_offset,
				  dst_page, dst_iter_offset,
				  iter_bytes, err);
			return err;
		}

		copied_bytes += iter_bytes;
	}

	if (copied_bytes != copy_size) {
		SSDFS_ERR("copied_bytes %u != copy_size %u\n",
			  copied_bytes, copy_size);
		return -ERANGE;
	}

	flush_dcache_folio(folio);

	return 0;
}

static inline
int ssdfs_memcpy_to_folio(struct ssdfs_smart_folio *dst_folio,
			  void *src, u32 src_off, u32 src_size,
			  u32 copy_size)
{
	u32 dst_off;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!dst_folio);
#endif /* CONFIG_SSDFS_DEBUG */

	dst_off = dst_folio->desc.page_offset +
			dst_folio->desc.offset_inside_page;

	return __ssdfs_memcpy_to_folio(dst_folio->ptr,
					dst_off, dst_folio->desc.block_size,
					src, src_off, src_size,
					copy_size);
}

static inline
int ssdfs_memcpy_to_batch(u32 pagesize,
			  struct folio_batch *batch, u32 dst_off,
			  void *src, u32 src_off, u32 src_size,
			  u32 copy_size)
{
	struct ssdfs_smart_folio folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!batch || !src);

	SSDFS_DBG("dst_off %u, src_off %u, "
		  "src_size %u, copy_size %u\n",
		  dst_off, src_off, src_size, copy_size);
#endif /* CONFIG_SSDFS_DEBUG */

	err = SSDFS_OFF2FOLIO(pagesize, dst_off, &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert offset into folio: "
			  "dst_off %u, err %d\n",
			  dst_off, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio.desc.folio_index >= folio_batch_count(batch)) {
		SSDFS_ERR("invalid folio_index: "
			  "index %d, batch_size %u\n",
			  folio.desc.folio_index,
			  folio_batch_count(batch));
		return -ERANGE;
	}

	folio.ptr = batch->folios[folio.desc.folio_index];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_folio_lock(folio.ptr);
	err = ssdfs_memcpy_to_folio(&folio,
				    src, src_off, src_size,
				    copy_size);
	ssdfs_folio_unlock(folio.ptr);

	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		return err;
	}

	return 0;
}

static inline
int ssdfs_memmove(void *dst, u32 dst_off, u32 dst_size,
		  const void *src, u32 src_off, u32 src_size,
		  u32 move_size)
{
#ifdef CONFIG_SSDFS_DEBUG
	if ((src_off + move_size) > src_size) {
		SSDFS_ERR("fail to move: "
			  "src_off %u, move_size %u, src_size %u\n",
			  src_off, move_size, src_size);
		return -ERANGE;
	}

	if ((dst_off + move_size) > dst_size) {
		SSDFS_ERR("fail to move: "
			  "dst_off %u, move_size %u, dst_size %u\n",
			  dst_off, move_size, dst_size);
		return -ERANGE;
	}

	SSDFS_DBG("dst %p, dst_off %u, dst_size %u, "
		  "src %p, src_off %u, src_size %u, "
		  "move_size %u\n",
		  dst, dst_off, dst_size,
		  src, src_off, src_size,
		  move_size);
#endif /* CONFIG_SSDFS_DEBUG */

	memmove((u8 *)dst + dst_off, (u8 *)src + src_off, move_size);
	return 0;
}

static inline
int ssdfs_memmove_folio(struct ssdfs_smart_folio *dst_folio,
			struct ssdfs_smart_folio *src_folio,
			u32 move_size)
{
	void *kaddr;
	u64 src_offset, dst_offset;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!dst_folio || !src_folio);
#endif /* CONFIG_SSDFS_DEBUG */

	if (src_folio->desc.folio_index == dst_folio->desc.folio_index &&
	    src_folio->desc.page_in_folio == dst_folio->desc.page_in_folio) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!src_folio->ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		src_offset = src_folio->desc.offset_inside_page;
		dst_offset = dst_folio->desc.offset_inside_page;

		kaddr = kmap_local_folio(src_folio->ptr,
					 src_folio->desc.page_offset);
		err = ssdfs_memmove(kaddr, dst_offset, PAGE_SIZE,
				    kaddr, src_offset, PAGE_SIZE,
				    move_size);
		flush_dcache_folio(src_folio->ptr);
		kunmap_local(kaddr);
	} else {
		err = ssdfs_memcpy_folio(dst_folio, src_folio, move_size);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to move: err %d\n", err);
		return err;
	}

	return 0;
}

static inline
int __ssdfs_memmove_folio(struct folio *dst_ptr, u32 dst_off, u32 dst_size,
			  struct folio *src_ptr, u32 src_off, u32 src_size,
			  u32 move_size)
{
	struct ssdfs_smart_folio src_folio, dst_folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!dst_ptr || !src_ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	err = SSDFS_OFF2FOLIO(folio_size(src_ptr), src_off, &src_folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert offset into folio: "
			  "offset %u, err %d\n",
			  src_off, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&src_folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	src_folio.ptr = src_ptr;

	err = SSDFS_OFF2FOLIO(folio_size(dst_ptr), dst_off, &dst_folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert offset into folio: "
			  "offset %u, err %d\n",
			  dst_off, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&dst_folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	dst_folio.ptr = dst_ptr;

	return ssdfs_memcpy_folio(&dst_folio, &src_folio, move_size);
}

static inline
int __ssdfs_memset_folio(struct folio *folio, u32 dst_off, u32 dst_size,
			 int value, u32 set_size)
{
	void *dst_kaddr;
	u32 dst_page;
	u32 processed_bytes = 0;

#ifdef CONFIG_SSDFS_DEBUG
	switch (dst_size) {
	case SSDFS_4KB:
	case SSDFS_8KB:
	case SSDFS_16KB:
	case SSDFS_32KB:
	case SSDFS_64KB:
	case SSDFS_128KB:
		/* expected block size */
		break;

	default:
		SSDFS_ERR("unexpected dst_size %u\n",
			  dst_size);
		return -EINVAL;
	}

	if (dst_size > folio_size(folio) ||
	    set_size > folio_size(folio)) {
		SSDFS_ERR("fail to copy: "
			  "dst_size %u, set_size %u, folio_size %zu\n",
			  dst_size, set_size, folio_size(folio));
		return -ERANGE;
	}

	if ((dst_off + set_size) > dst_size) {
		SSDFS_WARN("fail to memset: "
			   "dst_off %u, set_size %u, dst_size %u\n",
			   dst_off, set_size, dst_size);
		return -ERANGE;
	}

	SSDFS_DBG("folio %p, dst_off %u, dst_size %u, "
		  "value %#x, set_size %u\n",
		  folio, dst_off, dst_size,
		  value, set_size);
#endif /* CONFIG_SSDFS_DEBUG */

	if (set_size == 0) {
		SSDFS_ERR("set_size == 0\n");
		return -ERANGE;
	}

	while (processed_bytes < set_size) {
		u32 dst_iter_offset;
		u32 iter_bytes;

		dst_iter_offset = dst_off + processed_bytes;
		dst_page = dst_iter_offset >> PAGE_SHIFT;
		dst_iter_offset = dst_iter_offset % PAGE_SIZE;

		iter_bytes = min_t(u32, PAGE_SIZE - dst_iter_offset,
				   set_size - processed_bytes);

		dst_kaddr = kmap_local_folio(folio, dst_page * PAGE_SIZE);
		memset((u8 *)dst_kaddr + dst_iter_offset,
			value, iter_bytes);
		kunmap_local(dst_kaddr);

		processed_bytes += iter_bytes;
	}

	if (processed_bytes != set_size) {
		SSDFS_ERR("processed_bytes %u != set_size %u\n",
			  processed_bytes, set_size);
		return -ERANGE;
	}

	flush_dcache_folio(folio);

	return 0;
}

static inline
int ssdfs_memset_folio(struct ssdfs_smart_folio *dst_folio,
			int value, u32 set_size)
{
	u32 dst_off;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!dst_folio);
#endif /* CONFIG_SSDFS_DEBUG */

	dst_off = dst_folio->desc.page_offset +
			dst_folio->desc.offset_inside_page;

	return __ssdfs_memset_folio(dst_folio->ptr,
				    dst_off, dst_folio->desc.block_size,
				    value, set_size);
}

static inline
int __ssdfs_memzero_folio(struct folio *folio, u32 dst_off, u32 dst_size,
			  u32 set_size)
{
	return __ssdfs_memset_folio(folio, dst_off, dst_size,
				    0, set_size);
}

static inline
int ssdfs_memzero_folio(struct ssdfs_smart_folio *dst_folio,
			u32 set_size)
{
	u32 dst_off;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!dst_folio);
#endif /* CONFIG_SSDFS_DEBUG */

	dst_off = dst_folio->desc.page_offset +
				dst_folio->desc.offset_inside_page;

	return __ssdfs_memzero_folio(dst_folio->ptr,
				     dst_off, dst_folio->desc.block_size,
				     set_size);
}

static inline
bool is_ssdfs_file_inline(struct ssdfs_inode_info *ii)
{
	return atomic_read(&ii->private_flags) & SSDFS_INODE_HAS_INLINE_FILE;
}

static inline
size_t ssdfs_inode_inline_file_capacity(struct inode *inode)
{
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	size_t raw_inode_size;
	size_t metadata_len;

	raw_inode_size = ii->raw_inode_size;
	metadata_len = offsetof(struct ssdfs_inode, internal);

	if (raw_inode_size <= metadata_len) {
		SSDFS_ERR("corrupted raw inode: "
			  "raw_inode_size %zu, metadata_len %zu\n",
			  raw_inode_size, metadata_len);
		return 0;
	}

	return raw_inode_size - metadata_len;
}

/*
 * __ssdfs_generate_name_hash() - generate a name's hash
 * @name: pointer on the name's string
 * @len: length of the name
 * @inline_name_max_len: max length of inline name
 */
static inline
u64 __ssdfs_generate_name_hash(const char *name, size_t len,
				size_t inline_name_max_len)
{
	u32 hash32_lo, hash32_hi;
	size_t copy_len;
	u64 name_hash;
	u32 diff = 0;
	u8 symbol1, symbol2;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!name);

	SSDFS_DBG("name %s, len %zu, inline_name_max_len %zu\n",
		  name, len, inline_name_max_len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (len == 0) {
		SSDFS_ERR("invalid len %zu\n", len);
		return U64_MAX;
	}

	copy_len = min_t(size_t, len, inline_name_max_len);
	hash32_lo = full_name_hash(NULL, name, copy_len);

	if (len <= inline_name_max_len) {
		hash32_hi = len;

		for (i = 1; i < len; i++) {
			symbol1 = (u8)name[i - 1];
			symbol2 = (u8)name[i];
			diff = 0;

			if (symbol1 > symbol2)
				diff = symbol1 - symbol2;
			else
				diff = symbol2 - symbol1;

			hash32_hi += diff * symbol1;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("hash32_hi %x, symbol1 %x, "
				  "symbol2 %x, index %d, diff %u\n",
				  hash32_hi, symbol1, symbol2,
				  i, diff);
#endif /* CONFIG_SSDFS_DEBUG */
		}
	} else {
		hash32_hi = full_name_hash(NULL,
					   name + inline_name_max_len,
					   len - copy_len);
	}

	name_hash = SSDFS_NAME_HASH(hash32_lo, hash32_hi);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("name %s, len %zu, name_hash %llx\n",
		  name, len, name_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	return name_hash;
}

#define SSDFS_LOG_FOOTER_OFF(seg_hdr)({ \
	u32 offset; \
	int index; \
	struct ssdfs_metadata_descriptor *desc; \
	index = SSDFS_LOG_FOOTER_INDEX; \
	desc = &SSDFS_SEG_HDR(seg_hdr)->desc_array[index]; \
	offset = le32_to_cpu(desc->offset); \
	offset; \
})

#define SSDFS_WAITED_TOO_LONG_MSECS		(1000)

static inline
void ssdfs_check_jiffies_left_till_timeout(unsigned long value)
{
#ifdef CONFIG_SSDFS_DEBUG
	unsigned int msecs;

	msecs = jiffies_to_msecs(SSDFS_DEFAULT_TIMEOUT - value);
	if (msecs >= SSDFS_WAITED_TOO_LONG_MSECS)
		SSDFS_WARN("function waited %u msecs\n", msecs);
#endif /* CONFIG_SSDFS_DEBUG */
}

#define SSDFS_WAIT_COMPLETION(end)({ \
	unsigned long res; \
	int err = 0; \
	res = wait_for_completion_timeout(end, SSDFS_DEFAULT_TIMEOUT); \
	if (res == 0) { \
		err = -ERANGE; \
	} else { \
		ssdfs_check_jiffies_left_till_timeout(res); \
	} \
	err; \
})

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
#define SSDFS_SNRU_HDR(ptr) \
	((struct ssdfs_snapshot_rules_header *)(ptr))
#define SSDFS_SNRU_INFO(ptr) \
	((struct ssdfs_snapshot_rule_info *)(ptr))

#define SSDFS_LEB2SEG(fsi, leb) \
	((u64)ssdfs_get_seg_id_for_leb_id(fsi, leb))

#endif /* _SSDFS_INLINE_H */
