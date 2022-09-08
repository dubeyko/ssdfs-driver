//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/compression.c - compression logic implementation.
 *
 * Copyright (c) 2019-2022 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/rwsem.h>
#include <linux/zlib.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "compression.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_compr_page_leaks;
atomic64_t ssdfs_compr_memory_leaks;
atomic64_t ssdfs_compr_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_compr_cache_leaks_increment(void *kaddr)
 * void ssdfs_compr_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_compr_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_compr_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_compr_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_compr_kfree(void *kaddr)
 * struct page *ssdfs_compr_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_compr_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_compr_free_page(struct page *page)
 * void ssdfs_compr_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(compr)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(compr)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_compr_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_compr_page_leaks, 0);
	atomic64_set(&ssdfs_compr_memory_leaks, 0);
	atomic64_set(&ssdfs_compr_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_compr_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_compr_page_leaks) != 0) {
		SSDFS_ERR("COMPRESSION: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_compr_page_leaks));
	}

	if (atomic64_read(&ssdfs_compr_memory_leaks) != 0) {
		SSDFS_ERR("COMPRESSION: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_compr_memory_leaks));
	}

	if (atomic64_read(&ssdfs_compr_cache_leaks) != 0) {
		SSDFS_ERR("COMPRESSION: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_compr_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

struct ssdfs_compressor *ssdfs_compressors[SSDFS_COMPR_TYPES_CNT];

static struct list_head compr_idle_workspace[SSDFS_COMPR_TYPES_CNT];
static spinlock_t compr_workspace_lock[SSDFS_COMPR_TYPES_CNT];
static int compr_num_workspace[SSDFS_COMPR_TYPES_CNT];
static atomic_t compr_alloc_workspace[SSDFS_COMPR_TYPES_CNT];
static wait_queue_head_t compr_workspace_wait[SSDFS_COMPR_TYPES_CNT];

static inline bool unable_compress(int type)
{
	if (!ssdfs_compressors[type])
		return true;
	else if (!ssdfs_compressors[type]->compr_ops)
		return true;
	else if (!ssdfs_compressors[type]->compr_ops->compress)
		return true;
	return false;
}

static inline bool unable_decompress(int type)
{
	if (!ssdfs_compressors[type])
		return true;
	else if (!ssdfs_compressors[type]->compr_ops)
		return true;
	else if (!ssdfs_compressors[type]->compr_ops->decompress)
		return true;
	return false;
}

static int ssdfs_none_compress(struct list_head *ws_ptr,
				unsigned char *data_in,
				unsigned char *cdata_out,
				size_t *srclen, size_t *destlen)
{
	int err;

	SSDFS_DBG("data_in %p, cdata_out %p, srclen %p, destlen %p\n",
		  data_in, cdata_out, srclen, destlen);

	if (*srclen > *destlen) {
		SSDFS_ERR("src_len %zu > dest_len %zu\n",
			  *srclen, *destlen);
		return -E2BIG;
	}

	err = ssdfs_memcpy(cdata_out, 0, PAGE_SIZE,
			   data_in, 0, PAGE_SIZE,
			   *srclen);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		return err;
	}

	*destlen = *srclen;
	return 0;
}

static int ssdfs_none_decompress(struct list_head *ws_ptr,
				 unsigned char *cdata_in,
				 unsigned char *data_out,
				 size_t srclen, size_t destlen)
{
	/* TODO: implement ssdfs_none_decompress() */
	SSDFS_WARN("TODO: implement %s\n", __func__);
	return -EOPNOTSUPP;
}

static const struct ssdfs_compress_ops ssdfs_compr_none_ops = {
	.compress = ssdfs_none_compress,
	.decompress = ssdfs_none_decompress,
};

static struct ssdfs_compressor ssdfs_none_compr = {
	.type = SSDFS_COMPR_NONE,
	.compr_ops = &ssdfs_compr_none_ops,
	.name = "none",
};

static inline bool unknown_compression(int type)
{
	return type < SSDFS_COMPR_NONE || type >= SSDFS_COMPR_TYPES_CNT;
}

int ssdfs_register_compressor(struct ssdfs_compressor *compr)
{
	SSDFS_INFO("register %s compressor\n", compr->name);
	ssdfs_compressors[compr->type] = compr;
	return 0;
}

int ssdfs_unregister_compressor(struct ssdfs_compressor *compr)
{
	SSDFS_INFO("unregister %s compressor\n", compr->name);
	ssdfs_compressors[compr->type] = NULL;
	return 0;
}

int ssdfs_compressors_init(void)
{
	int i;
	int err;

	SSDFS_DBG("init compressors subsystem\n");

	for (i = 0; i < SSDFS_COMPR_TYPES_CNT; i++) {
		INIT_LIST_HEAD(&compr_idle_workspace[i]);
		spin_lock_init(&compr_workspace_lock[i]);
		atomic_set(&compr_alloc_workspace[i], 0);
		init_waitqueue_head(&compr_workspace_wait[i]);
	}

	err = ssdfs_zlib_init();
	if (err)
		goto out;

	err = ssdfs_lzo_init();
	if (err)
		goto zlib_exit;

	err = ssdfs_register_compressor(&ssdfs_none_compr);
	if (err)
		goto lzo_exit;

	return 0;

lzo_exit:
	ssdfs_lzo_exit();

zlib_exit:
	ssdfs_zlib_exit();

out:
	return err;
}

void ssdfs_free_workspaces(void)
{
	struct list_head *workspace;
	const struct ssdfs_compress_ops *ops;
	int i;

	SSDFS_DBG("destruct auxiliary workspaces\n");

	for (i = 0; i < SSDFS_COMPR_TYPES_CNT; i++) {
		if (!ssdfs_compressors[i])
			continue;

		ops = ssdfs_compressors[i]->compr_ops;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!ops);
#endif /* CONFIG_SSDFS_DEBUG */

		while (!list_empty(&compr_idle_workspace[i])) {
			workspace = compr_idle_workspace[i].next;
			list_del(workspace);
			if (ops->free_workspace)
				ops->free_workspace(workspace);
			atomic_dec(&compr_alloc_workspace[i]);
		}
	}
}

void ssdfs_compressors_exit(void)
{
	SSDFS_DBG("deinitialize compressors subsystem\n");

	ssdfs_free_workspaces();
	ssdfs_unregister_compressor(&ssdfs_none_compr);
	ssdfs_zlib_exit();
	ssdfs_lzo_exit();
}

/*
 * Find an available workspace or allocate a new one.
 * ERR_PTR is returned in the case of error.
 */
static struct list_head *ssdfs_find_workspace(int type)
{
	struct list_head *workspace;
	int cpus;
	struct list_head *idle_workspace;
	spinlock_t *workspace_lock;
	atomic_t *alloc_workspace;
	wait_queue_head_t *workspace_wait;
	int *num_workspace;
	const struct ssdfs_compress_ops *ops;

	SSDFS_DBG("type %d\n", type);

#ifdef CONFIG_SSDFS_DEBUG
	if (unknown_compression(type)) {
		SSDFS_ERR("unknown compression type %d\n", type);
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

	ops = ssdfs_compressors[type]->compr_ops;

	if (!ops->alloc_workspace)
		return ERR_PTR(-EOPNOTSUPP);

	cpus = num_online_cpus();
	idle_workspace = &compr_idle_workspace[type];
	workspace_lock = &compr_workspace_lock[type];
	alloc_workspace = &compr_alloc_workspace[type];
	workspace_wait = &compr_workspace_wait[type];
	num_workspace = &compr_num_workspace[type];

again:
	spin_lock(workspace_lock);

	if (!list_empty(idle_workspace)) {
		workspace = idle_workspace->next;
		list_del(workspace);
		(*num_workspace)--;
		spin_unlock(workspace_lock);
		return workspace;
	}

	if (atomic_read(alloc_workspace) > cpus) {
		DEFINE_WAIT(wait);

		spin_unlock(workspace_lock);
		prepare_to_wait(workspace_wait, &wait, TASK_UNINTERRUPTIBLE);
		if (atomic_read(alloc_workspace) > cpus && !*num_workspace)
			schedule();
		finish_wait(workspace_wait, &wait);
		goto again;
	}
	atomic_inc(alloc_workspace);
	spin_unlock(workspace_lock);

	workspace = ops->alloc_workspace();
	if (IS_ERR(workspace)) {
		atomic_dec(alloc_workspace);
		wake_up(workspace_wait);
	}

	return workspace;
}

static void ssdfs_free_workspace(int type, struct list_head *workspace)
{
	struct list_head *idle_workspace;
	spinlock_t *workspace_lock;
	atomic_t *alloc_workspace;
	wait_queue_head_t *workspace_wait;
	int *num_workspace;
	const struct ssdfs_compress_ops *ops;

	SSDFS_DBG("type %d, workspace %p\n", type, workspace);

#ifdef CONFIG_SSDFS_DEBUG
	if (unknown_compression(type)) {
		SSDFS_ERR("unknown compression type %d\n", type);
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

	ops = ssdfs_compressors[type]->compr_ops;

	if (!ops->free_workspace)
		return;

	idle_workspace = &compr_idle_workspace[type];
	workspace_lock = &compr_workspace_lock[type];
	alloc_workspace = &compr_alloc_workspace[type];
	workspace_wait = &compr_workspace_wait[type];
	num_workspace = &compr_num_workspace[type];

	spin_lock(workspace_lock);
	if (*num_workspace < num_online_cpus()) {
		list_add_tail(workspace, idle_workspace);
		(*num_workspace)++;
		spin_unlock(workspace_lock);
		goto wake;
	}
	spin_unlock(workspace_lock);

	ops->free_workspace(workspace);
	atomic_dec(alloc_workspace);
wake:
	smp_mb();
	if (waitqueue_active(workspace_wait))
		wake_up(workspace_wait);
}

#define SSDFS_DICT_SIZE			256
#define SSDFS_MIN_MAX_DIFF_THRESHOLD	150

bool ssdfs_can_compress_data(struct page *page,
			     unsigned data_size)
{
	unsigned *counts;
	unsigned found_symbols = 0;
	unsigned min, max;
	u8 *kaddr;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(data_size == 0 || data_size > PAGE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_ZLIB
	if (CONFIG_SSDFS_ZLIB_COMR_LEVEL == Z_NO_COMPRESSION)
		return false;
#endif /* CONFIG_SSDFS_DEBUG */

	counts = ssdfs_compr_kzalloc(sizeof(unsigned) * SSDFS_DICT_SIZE,
				     GFP_KERNEL);
	if (!counts) {
		SSDFS_WARN("fail to alloc array\n");
		return true;
	}

	min = SSDFS_DICT_SIZE;
	max = 0;

	kaddr = (u8 *)kmap_local_page(page);
	for (i = 0; i < data_size; i++) {
		u8 *value = kaddr + i;
		counts[*value]++;
		if (counts[*value] == 1)
			found_symbols++;
		if (counts[*value] < min)
			min = counts[*value];
		if (counts[*value] > max)
			max = counts[*value];
	}
	kunmap_local(kaddr);

	ssdfs_compr_kfree(counts);

	SSDFS_DBG("data_size %u, found_symbols %u, min %u, max %u\n",
		  data_size, found_symbols, min, max);

	return (max - min) >= SSDFS_MIN_MAX_DIFF_THRESHOLD;
}

int __ssdfs_compress(int type,
		     unsigned char *data_in, unsigned char *cdata_out,
		     size_t *srclen, size_t *destlen)
{
	const struct ssdfs_compress_ops *ops;
	struct list_head *workspace = NULL;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("type %d, data_in %p, cdata_out %p, "
		  "srclen %zu, destlen %zu\n",
		  type, data_in, cdata_out, *srclen, *destlen);

	if (unknown_compression(type)) {
		SSDFS_ERR("unknown compression type %d\n", type);
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (unable_compress(type)) {
		SSDFS_ERR("unsupported compression type %d\n", type);
		err = -EOPNOTSUPP;
		goto failed_compress;
	}

	workspace = ssdfs_find_workspace(type);
	if (PTR_ERR(workspace) == -EOPNOTSUPP &&
	    ssdfs_compressors[type]->type == SSDFS_COMPR_NONE) {
		/*
		 * None compressor case.
		 * Simply call compress() operation.
		 */
	} else if (IS_ERR(workspace)) {
		err = -ENOMEM;
		goto failed_compress;
	}

	ops = ssdfs_compressors[type]->compr_ops;
	err = ops->compress(workspace, data_in, cdata_out, srclen, destlen);

	ssdfs_free_workspace(type, workspace);
	if (err == -E2BIG) {
		SSDFS_DBG("%s compressor is unable to compress data %p "
			  "of size %zu\n",
			  ssdfs_compressors[type]->name,
			  data_in, *srclen);
		goto failed_compress;
	} else if (unlikely(err)) {
		SSDFS_ERR("%s compressor fails to compress data %p "
			  "of size %zu because of err %d\n",
			  ssdfs_compressors[type]->name,
			  data_in, *srclen, err);
		goto failed_compress;
	}

	return 0;

failed_compress:
	return err;
}

int ssdfs_qat_compress(int type,
			unsigned char *data_in, unsigned char *cdata_out,
			size_t *srclen, size_t *destlen)
{
	int err = 0;
#ifdef CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION
	struct scatterlist input, output;
	struct crypto_acomp *acomp;
	struct crypto_wait wait;
	struct acomp_req *req;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("type %d, data_in %p, cdata_out %p, "
		  "srclen %zu, destlen %zu\n",
		  type, data_in, cdata_out, *srclen, *destlen);

	if (unknown_compression(type)) {
		SSDFS_ERR("unknown compression type %d\n", type);
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (*srclen < SSDFS_COMPR_ACCELERATOR_THRESHOLD) {
		SSDFS_DBG("srclen %zu is small for QAT compression\n",
			  *srclen);

		return __ssdfs_compress(type, data_in, data_out, srclen, dstlen);
	}

	switch (type) {
	case SSDFS_COMPR_NONE:
	case SSDFS_COMPR_LZO:
		SSDFS_DBG("QAT device doesn't support compression type %#x\n",
			  type);
		return __ssdfs_compress(type, data_in, data_out, srclen, dstlen);

	default:
		/* continue logic */
		break;
	}

	acomp = crypto_alloc_acomp("qat_deflate", 0, 0);
	if (IS_ERR_OR_NULL(acomp)) {
		SSDFS_DBG("unable to allocate QAT compression object: "
			  "err %d\n", err);

		return __ssdfs_compress(type, data_in, data_out, srclen, dstlen);
	}

	req = acomp_request_alloc(acomp);
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate compression request: "
			  "err %d\n", err);
		goto free_acomp;
	}

	sg_init_one(&input, data_in, *srclen);
	sg_init_one(&output, data_out, *dstlen);

	acomp_request_set_params(req, &input, &output, *srclen, *dstlen);

	crypto_init_wait(&wait);

	acomp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   crypto_req_done, &wait);

	err = crypto_wait_req(crypto_acomp_compress(req), &wait);
	if (unlikely(err)) {
		SSDFS_ERR("fail to make QAT-based compression: "
			  "err %d\n", err);
		goto free_acomp_requst;
	}

	*destlen = req->dlen;

free_acomp_requst:
	acomp_request_free(req);

free_acomp:
	crypto_free_acomp(acomp);
#else
	err = -EOPNOTSUPP;
#endif /* CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION */

	return err;
}

int ssdfs_compress(int type,
		   unsigned char *data_in, unsigned char *cdata_out,
		   size_t *srclen, size_t *destlen)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("type %d, data_in %p, cdata_out %p, "
		  "srclen %zu, destlen %zu\n",
		  type, data_in, cdata_out, *srclen, *destlen);

	if (unknown_compression(type)) {
		SSDFS_ERR("unknown compression type %d\n", type);
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION
	err = ssdfs_qat_compress(type, data_in, cdata_out, srclen, destlen);
#else
	err = __ssdfs_compress(type, data_in, cdata_out, srclen, destlen);
#endif /* CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION */

	return err;
}

int ssdfs_qat_compress_page(int type,
			    struct page *data_in, struct page *cdata_out,
			    size_t *srclen, size_t *destlen)
{
	int err = 0;
#ifdef CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION
	struct scatterlist input, output;
	struct crypto_acomp *acomp;
	struct crypto_wait wait;
	struct acomp_req *req;
	unsigned char *kaddr_in;
	unsigned char *kaddr_out;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("type %d, data_in %p, cdata_out %p, "
		  "srclen %zu, destlen %zu\n",
		  type, data_in, cdata_out, *srclen, *destlen);

	if (unknown_compression(type)) {
		SSDFS_ERR("unknown compression type %d\n", type);
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (*srclen < SSDFS_COMPR_ACCELERATOR_THRESHOLD) {
		SSDFS_DBG("srclen %zu is small for QAT compression\n",
			  *srclen);

		kaddr_in = kmap_local_page(data_in);
		kaddr_out = kmap_local_page(data_out);
		err = __ssdfs_compress(type, kaddr_in, kaddr_out,
					srclen, dstlen);
		flush_dcache_page(kaddr_out);
		kunmap_local(kaddr_out);
		kunmap_local(kaddr_in);

		return err;
	}

	switch (type) {
	case SSDFS_COMPR_NONE:
	case SSDFS_COMPR_LZO:
		SSDFS_DBG("QAT device doesn't support compression type %#x\n",
			  type);

		kaddr_in = kmap_local_page(data_in);
		kaddr_out = kmap_local_page(data_out);
		err = __ssdfs_compress(type, kaddr_in, kaddr_out,
					srclen, dstlen);
		flush_dcache_page(kaddr_out);
		kunmap_local(kaddr_out);
		kunmap_local(kaddr_in);
		return err;

	default:
		/* continue logic */
		break;
	}

	acomp = crypto_alloc_acomp("qat_deflate", 0, 0);
	if (IS_ERR_OR_NULL(acomp)) {
		SSDFS_DBG("unable to allocate QAT compression object: "
			  "err %d\n", err);

		kaddr_in = kmap_local_page(data_in);
		kaddr_out = kmap_local_page(data_out);
		err = __ssdfs_compress(type, kaddr_in, kaddr_out,
					srclen, dstlen);
		flush_dcache_page(kaddr_out);
		kunmap_local(kaddr_out);
		kunmap_local(kaddr_in);

		return err;
	}

	req = acomp_request_alloc(acomp);
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate compression request: "
			  "err %d\n", err);
		goto free_acomp;
	}

	sg_init_table(&input, 1);
	sg_set_page(&input, data_in, *srclen, 0);

	sg_init_table(&output, 1);
	sg_set_page(&output, data_out, *dstlen, 0);

	acomp_request_set_params(req, &input, &output, *srclen, *dstlen);

	crypto_init_wait(&wait);

	acomp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   crypto_req_done, &wait);

	err = crypto_wait_req(crypto_acomp_compress(req), &wait);
	if (unlikely(err)) {
		SSDFS_ERR("fail to make QAT-based compression: "
			  "err %d\n", err);
		goto free_acomp_requst;
	}

	*destlen = req->dlen;

free_acomp_requst:
	acomp_request_free(req);

free_acomp:
	crypto_free_acomp(acomp);
#else
	err = -EOPNOTSUPP;
#endif /* CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION */

	return err;
}

int ssdfs_compress_page(int type,
			struct page *data_in, struct page *cdata_out,
			size_t *srclen, size_t *destlen)
{
	unsigned char *kaddr_in;
	unsigned char *kaddr_out;
#ifdef CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION
	struct scatterlist input, output;
	struct crypto_acomp *acomp;
	struct crypto_wait wait;
	struct acomp_req *req;
#endif /* CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("type %d, data_in %p, cdata_out %p, "
		  "srclen %zu, destlen %zu\n",
		  type, data_in, cdata_out, *srclen, *destlen);

	if (unknown_compression(type)) {
		SSDFS_ERR("unknown compression type %d\n", type);
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION
	err = ssdfs_qat_compress_page(type, data_in, cdata_out,
				      srclen, destlen);
#else
	kaddr_in = kmap_local_page(data_in);
	kaddr_out = kmap_local_page(cdata_out);
	err = __ssdfs_compress(type, kaddr_in, kaddr_out, srclen, destlen);
	flush_dcache_page(cdata_out);
	kunmap_local(kaddr_out);
	kunmap_local(kaddr_in);
#endif /* CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION */

	return err;
}

int __ssdfs_decompress(int type,
			unsigned char *cdata_in, unsigned char *data_out,
			size_t srclen, size_t destlen)
{
	const struct ssdfs_compress_ops *ops;
	struct list_head *workspace;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("type %d, cdata_in %p, data_out %p, "
		  "srclen %zu, destlen %zu\n",
		  type, cdata_in, data_out, srclen, destlen);

	if (unknown_compression(type)) {
		SSDFS_ERR("unknown compression type %d\n", type);
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (unable_decompress(type)) {
		SSDFS_ERR("unsupported compression type %d\n", type);
		err = -EOPNOTSUPP;
		goto failed_decompress;
	}

	workspace = ssdfs_find_workspace(type);
	if (PTR_ERR(workspace) == -EOPNOTSUPP &&
	    ssdfs_compressors[type]->type == SSDFS_COMPR_NONE) {
		/*
		 * None compressor case.
		 * Simply call decompress() operation.
		 */
	} else if (IS_ERR(workspace)) {
		err = -ENOMEM;
		goto failed_decompress;
	}

	ops = ssdfs_compressors[type]->compr_ops;
	err = ops->decompress(workspace, cdata_in, data_out, srclen, destlen);

	ssdfs_free_workspace(type, workspace);
	if (unlikely(err)) {
		SSDFS_ERR("%s compresor fails to decompress data %p "
			  "of size %zu because of err %d\n",
			  ssdfs_compressors[type]->name,
			  cdata_in, srclen, err);
		goto failed_decompress;
	}

	return 0;

failed_decompress:
	return err;
}

int ssdfs_qat_decompress(int type,
			 unsigned char *cdata_in, unsigned char *data_out,
			 size_t srclen, size_t destlen)
{
	int err = 0;
#ifdef CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION
	struct scatterlist input, output;
	struct crypto_acomp *acomp;
	struct crypto_wait wait;
	struct acomp_req *req;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("type %d, data_in %p, cdata_out %p, "
		  "srclen %zu, destlen %zu\n",
		  type, data_in, cdata_out, srclen, destlen);

	if (unknown_compression(type)) {
		SSDFS_ERR("unknown compression type %d\n", type);
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

	switch (type) {
	case SSDFS_COMPR_NONE:
	case SSDFS_COMPR_LZO:
		SSDFS_DBG("QAT device doesn't support compression type %#x\n",
			  type);
		return __ssdfs_decompress(type, data_in, data_out, srclen, dstlen);

	default:
		/* continue logic */
		break;
	}

	acomp = crypto_alloc_acomp("qat_deflate", 0, 0);
	if (IS_ERR_OR_NULL(acomp)) {
		SSDFS_DBG("unable to allocate QAT compression object: "
			  "err %d\n", err);

		return __ssdfs_decompress(type, data_in, data_out, srclen, dstlen);
	}

	req = acomp_request_alloc(acomp);
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate compression request: "
			  "err %d\n", err);
		goto free_acomp;
	}

	sg_init_one(&input, data_in, srclen);
	sg_init_one(&output, data_out, dstlen);

	acomp_request_set_params(req, &input, &output, srclen, dstlen);

	crypto_init_wait(&wait);

	acomp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   crypto_req_done, &wait);

	err = crypto_wait_req(crypto_acomp_decompress(req), &wait);
	if (unlikely(err)) {
		SSDFS_ERR("fail to make QAT-based decompression: "
			  "err %d\n", err);
		goto free_acomp_requst;
	}

free_acomp_requst:
	acomp_request_free(req);

free_acomp:
	crypto_free_acomp(acomp);
#else
	err = -EOPNOTSUPP;
#endif /* CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION */

	return err;
}

int ssdfs_decompress(int type,
		     unsigned char *cdata_in, unsigned char *data_out,
		     size_t srclen, size_t destlen)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("type %d, cdata_in %p, data_out %p, "
		  "srclen %zu, destlen %zu\n",
		  type, cdata_in, data_out, srclen, destlen);

	if (unknown_compression(type)) {
		SSDFS_ERR("unknown compression type %d\n", type);
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION
	err = ssdfs_qat_decompress(type, cdata_in, data_out, srclen, destlen);
#else
	err = __ssdfs_decompress(type, cdata_in, data_out, srclen, destlen);
#endif /* CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION */

	return err;
}

int ssdfs_qat_decompress_page(int type,
			      struct page *data_in, struct page *cdata_out,
			      size_t srclen, size_t destlen)
{
	int err = 0;
#ifdef CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION
	struct scatterlist input, output;
	struct crypto_acomp *acomp;
	struct crypto_wait wait;
	struct acomp_req *req;
	unsigned char *kaddr_in;
	unsigned char *kaddr_out;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("type %d, data_in %p, cdata_out %p, "
		  "srclen %zu, destlen %zu\n",
		  type, data_in, cdata_out, srclen, destlen);

	if (unknown_compression(type)) {
		SSDFS_ERR("unknown compression type %d\n", type);
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

	switch (type) {
	case SSDFS_COMPR_NONE:
	case SSDFS_COMPR_LZO:
		SSDFS_DBG("QAT device doesn't support compression type %#x\n",
			  type);

		kaddr_in = kmap_local_page(data_in);
		kaddr_out = kmap_local_page(data_out);
		err = __ssdfs_decompress(type, kaddr_in, kaddr_out,
					 srclen, dstlen);
		flush_dcache_page(kaddr_out);
		kunmap_local(kaddr_out);
		kunmap_local(kaddr_in);
		return err;

	default:
		/* continue logic */
		break;
	}

	acomp = crypto_alloc_acomp("qat_inflate", 0, 0);
	if (IS_ERR_OR_NULL(acomp)) {
		SSDFS_DBG("unable to allocate QAT compression object: "
			  "err %d\n", err);

		kaddr_in = kmap_local_page(data_in);
		kaddr_out = kmap_local_page(data_out);
		err = __ssdfs_decompress(type, kaddr_in, kaddr_out,
					 srclen, dstlen);
		flush_dcache_page(kaddr_out);
		kunmap_local(kaddr_out);
		kunmap_local(kaddr_in);

		return err;
	}

	req = acomp_request_alloc(acomp);
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate compression request: "
			  "err %d\n", err);
		goto free_acomp;
	}

	sg_init_table(&input, 1);
	sg_set_page(&input, data_in, srclen, 0);

	sg_init_table(&output, 1);
	sg_set_page(&output, data_out, dstlen, 0);

	acomp_request_set_params(req, &input, &output, srclen, dstlen);

	crypto_init_wait(&wait);

	acomp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   crypto_req_done, &wait);

	err = crypto_wait_req(crypto_acomp_decompress(req), &wait);
	if (unlikely(err)) {
		SSDFS_ERR("fail to make QAT-based compression: "
			  "err %d\n", err);
		goto free_acomp_requst;
	}

free_acomp_requst:
	acomp_request_free(req);

free_acomp:
	crypto_free_acomp(acomp);
#else
	err = -EOPNOTSUPP;
#endif /* CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION */

	return err;
}

int ssdfs_decompress_page(int type,
			  struct page *cdata_in, struct page *data_out,
			  size_t srclen, size_t destlen)
{
	unsigned char *kaddr_in;
	unsigned char *kaddr_out;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("type %d, cdata_in %p, data_out %p, "
		  "srclen %zu, destlen %zu\n",
		  type, cdata_in, data_out, srclen, destlen);

	if (unknown_compression(type)) {
		SSDFS_ERR("unknown compression type %d\n", type);
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION
	err = ssdfs_qat_decompress_page(type, data_in, cdata_out,
					srclen, destlen);
#else
	kaddr_in = kmap_local_page(cdata_in);
	kaddr_out = kmap_local_page(data_out);
	err = __ssdfs_decompress(type, kaddr_in, kaddr_out, srclen, destlen);
	flush_dcache_page(data_out);
	kunmap_local(kaddr_out);
	kunmap_local(kaddr_in);
#endif /* CONFIG_SSDFS_QAT_COMPRESSION_ACCELERATION */

	return err;
}
