/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/compr_lz4.c - LZ4 compression support.
 *
 * Copyright (c) 2026 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/lz4.h>
#include <linux/pagevec.h>

#include <kunit/visibility.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "compression.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_lz4_folio_leaks;
atomic64_t ssdfs_lz4_memory_leaks;
atomic64_t ssdfs_lz4_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_lz4_cache_leaks_increment(void *kaddr)
 * void ssdfs_lz4_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_lz4_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_lz4_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_lz4_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_lz4_kfree(void *kaddr)
 * struct folio *ssdfs_lz4_alloc_folio(gfp_t gfp_mask,
 *                                     unsigned int order)
 * struct folio *ssdfs_lz4_add_batch_folio(struct folio_batch *batch,
 *                                         unsigned int order)
 * void ssdfs_lz4_free_folio(struct folio *folio)
 * void ssdfs_lz4_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(lz4)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(lz4)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_lz4_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_lz4_folio_leaks, 0);
	atomic64_set(&ssdfs_lz4_memory_leaks, 0);
	atomic64_set(&ssdfs_lz4_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_lz4_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_lz4_folio_leaks) != 0) {
		SSDFS_ERR("LZ4: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_lz4_folio_leaks));
	}

	if (atomic64_read(&ssdfs_lz4_memory_leaks) != 0) {
		SSDFS_ERR("LZ4: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_lz4_memory_leaks));
	}

	if (atomic64_read(&ssdfs_lz4_cache_leaks) != 0) {
		SSDFS_ERR("LZ4: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_lz4_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static int ssdfs_lz4_compress(struct list_head *ws_ptr,
				unsigned char *data_in,
				unsigned char *cdata_out,
				size_t *srclen, size_t *destlen);

static int ssdfs_lz4_decompress(struct list_head *ws_ptr,
				 unsigned char *cdata_in,
				 unsigned char *data_out,
				 size_t srclen, size_t destlen);

static struct list_head *ssdfs_lz4_alloc_workspace(void);
static void ssdfs_lz4_free_workspace(struct list_head *ptr);

static const struct ssdfs_compress_ops ssdfs_lz4_compress_ops = {
	.alloc_workspace = ssdfs_lz4_alloc_workspace,
	.free_workspace = ssdfs_lz4_free_workspace,
	.compress = ssdfs_lz4_compress,
	.decompress = ssdfs_lz4_decompress,
};

static struct ssdfs_compressor lz4_compr = {
	.type = SSDFS_COMPR_LZ4,
	.compr_ops = &ssdfs_lz4_compress_ops,
	.name = "lz4",
};

struct ssdfs_lz4_workspace {
	void *mem;	/* working memory for compression */
	void *cbuf;	/* where compressed data goes */
	struct list_head list;
};

static void ssdfs_lz4_free_workspace(struct list_head *ptr)
{
	struct ssdfs_lz4_workspace *workspace;

	workspace = list_entry(ptr, struct ssdfs_lz4_workspace, list);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("workspace %p\n", workspace);
#endif /* CONFIG_SSDFS_DEBUG */

	vfree(workspace->cbuf);
	vfree(workspace->mem);
	ssdfs_lz4_kfree(workspace);
}

static struct list_head *ssdfs_lz4_alloc_workspace(void)
{
	struct ssdfs_lz4_workspace *workspace;
	unsigned int nofs_flags;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("try to allocate workspace\n");
#endif /* CONFIG_SSDFS_DEBUG */

	workspace = ssdfs_lz4_kzalloc(sizeof(*workspace), GFP_KERNEL);
	if (unlikely(!workspace))
		goto failed_alloc_workspaces;

	nofs_flags = memalloc_nofs_save();
	workspace->mem = vmalloc(LZ4_MEM_COMPRESS);
	workspace->cbuf = vmalloc(LZ4_COMPRESSBOUND(PAGE_SIZE));
	memalloc_nofs_restore(nofs_flags);

	if (!workspace->mem || !workspace->cbuf)
		goto failed_alloc_workspaces;

	INIT_LIST_HEAD(&workspace->list);

	return &workspace->list;

failed_alloc_workspaces:
	SSDFS_ERR("unable to allocate memory for workspace\n");
	ssdfs_lz4_free_workspace(&workspace->list);
	return ERR_PTR(-ENOMEM);
}

int ssdfs_lz4_init(void)
{
	return ssdfs_register_compressor(&lz4_compr);
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_lz4_init);

void ssdfs_lz4_exit(void)
{
	ssdfs_unregister_compressor(&lz4_compr);
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_lz4_exit);

static int ssdfs_lz4_compress(struct list_head *ws,
				unsigned char *data_in,
				unsigned char *cdata_out,
				size_t *srclen, size_t *destlen)
{
	struct ssdfs_lz4_workspace *workspace;
	int compress_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ws_ptr %p, data_in %p, cdata_out %p, "
		  "srclen ptr %p, destlen ptr %p\n",
		  ws, data_in, cdata_out, srclen, destlen);

	BUG_ON(!ws || !data_in || !cdata_out || !srclen || !destlen);
#endif /* CONFIG_SSDFS_DEBUG */

	workspace = list_entry(ws, struct ssdfs_lz4_workspace, list);

	compress_size = LZ4_compress_default((const char *)data_in,
					     (char *)workspace->cbuf,
					     (int)*srclen,
					     LZ4_COMPRESSBOUND(PAGE_SIZE),
					     workspace->mem);
	if (compress_size == 0) {
		SSDFS_ERR("LZ4 compression failed: "
			  "srclen %zu, destlen %zu\n",
			  *srclen, *destlen);
		err = -EINVAL;
		goto failed_compress;
	}

	if ((size_t)compress_size > *destlen) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to compress: compress_size %d, "
			  "destlen %zu\n",
			  compress_size, *destlen);
#endif /* CONFIG_SSDFS_DEBUG */
		err = -E2BIG;
		goto failed_compress;
	}

	ssdfs_memcpy(cdata_out, 0, *destlen,
		     workspace->cbuf, 0, LZ4_COMPRESSBOUND(PAGE_SIZE),
		     (size_t)compress_size);
	*destlen = (size_t)compress_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("compress has succeded: srclen %zu, destlen %zu\n",
		    *srclen, *destlen);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;

failed_compress:
	return err;
}

static int ssdfs_lz4_decompress(struct list_head *ws,
				 unsigned char *cdata_in,
				 unsigned char *data_out,
				 size_t srclen, size_t destlen)
{
	int ret;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ws_ptr %p, cdata_in %p, data_out %p, "
		  "srclen %zu, destlen %zu\n",
		  ws, cdata_in, data_out, srclen, destlen);

	BUG_ON(!ws || !cdata_in || !data_out);
#endif /* CONFIG_SSDFS_DEBUG */

	ret = LZ4_decompress_safe((const char *)cdata_in,
				  (char *)data_out,
				  (int)srclen,
				  (int)destlen);

	if (ret < 0) {
		SSDFS_ERR("decompression failed: LZ4 err %d, "
			  "srclen %zu, destlen %zu\n",
			  ret, srclen, destlen);
		return -EINVAL;
	}

	if ((size_t)ret != destlen) {
		SSDFS_ERR("decompression size mismatch: "
			  "got %d bytes, expected %zu\n",
			  ret, destlen);
		return -EINVAL;
	}

	return 0;
}
