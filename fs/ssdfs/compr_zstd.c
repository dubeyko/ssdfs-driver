/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/compr_zstd.c - ZSTD compression support.
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
#include <linux/zstd.h>
#include <linux/pagevec.h>

#include <kunit/visibility.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "compression.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_zstd_folio_leaks;
atomic64_t ssdfs_zstd_memory_leaks;
atomic64_t ssdfs_zstd_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_zstd_cache_leaks_increment(void *kaddr)
 * void ssdfs_zstd_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_zstd_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_zstd_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_zstd_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_zstd_kfree(void *kaddr)
 * struct folio *ssdfs_zstd_alloc_folio(gfp_t gfp_mask,
 *                                      unsigned int order)
 * struct folio *ssdfs_zstd_add_batch_folio(struct folio_batch *batch,
 *                                          unsigned int order)
 * void ssdfs_zstd_free_folio(struct folio *folio)
 * void ssdfs_zstd_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(zstd)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(zstd)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_zstd_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_zstd_folio_leaks, 0);
	atomic64_set(&ssdfs_zstd_memory_leaks, 0);
	atomic64_set(&ssdfs_zstd_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_zstd_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_zstd_folio_leaks) != 0) {
		SSDFS_ERR("ZSTD: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_zstd_folio_leaks));
	}

	if (atomic64_read(&ssdfs_zstd_memory_leaks) != 0) {
		SSDFS_ERR("ZSTD: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_zstd_memory_leaks));
	}

	if (atomic64_read(&ssdfs_zstd_cache_leaks) != 0) {
		SSDFS_ERR("ZSTD: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_zstd_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static int ssdfs_zstd_compress(struct list_head *ws_ptr,
				unsigned char *data_in,
				unsigned char *cdata_out,
				size_t *srclen, size_t *destlen);

static int ssdfs_zstd_decompress(struct list_head *ws_ptr,
				  unsigned char *cdata_in,
				  unsigned char *data_out,
				  size_t srclen, size_t destlen);

static struct list_head *ssdfs_zstd_alloc_workspace(void);
static void ssdfs_zstd_free_workspace(struct list_head *ptr);

static const struct ssdfs_compress_ops ssdfs_zstd_compress_ops = {
	.alloc_workspace = ssdfs_zstd_alloc_workspace,
	.free_workspace = ssdfs_zstd_free_workspace,
	.compress = ssdfs_zstd_compress,
	.decompress = ssdfs_zstd_decompress,
};

static struct ssdfs_compressor zstd_compr = {
	.type = SSDFS_COMPR_ZSTD,
	.compr_ops = &ssdfs_zstd_compress_ops,
	.name = "zstd",
};

struct ssdfs_zstd_workspace {
	void *mem;	  /* workspace memory for cctx/dctx */
	size_t mem_size;  /* size of workspace memory */
	void *cbuf;	  /* where compressed data goes */
	struct list_head list;
};

static void ssdfs_zstd_free_workspace(struct list_head *ptr)
{
	struct ssdfs_zstd_workspace *workspace;

	workspace = list_entry(ptr, struct ssdfs_zstd_workspace, list);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("workspace %p\n", workspace);
#endif /* CONFIG_SSDFS_DEBUG */

	vfree(workspace->cbuf);
	vfree(workspace->mem);
	ssdfs_zstd_kfree(workspace);
}

static struct list_head *ssdfs_zstd_alloc_workspace(void)
{
	struct ssdfs_zstd_workspace *workspace;
	zstd_parameters params;
	size_t cctx_size;
	size_t dctx_size;
	unsigned int nofs_flags;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("try to allocate workspace\n");
#endif /* CONFIG_SSDFS_DEBUG */

	workspace = ssdfs_zstd_kzalloc(sizeof(*workspace), GFP_KERNEL);
	if (unlikely(!workspace))
		goto failed_alloc_workspaces;

	params = zstd_get_params(CONFIG_SSDFS_ZSTD_COMPR_LEVEL, PAGE_SIZE);
	cctx_size = zstd_cctx_workspace_bound(&params.cParams);
	dctx_size = zstd_dctx_workspace_bound();
	workspace->mem_size = max(cctx_size, dctx_size);

	nofs_flags = memalloc_nofs_save();
	workspace->mem = vmalloc(workspace->mem_size);
	workspace->cbuf = vmalloc(zstd_compress_bound(PAGE_SIZE));
	memalloc_nofs_restore(nofs_flags);

	if (!workspace->mem || !workspace->cbuf)
		goto failed_alloc_workspaces;

	INIT_LIST_HEAD(&workspace->list);

	return &workspace->list;

failed_alloc_workspaces:
	SSDFS_ERR("unable to allocate memory for workspace\n");
	ssdfs_zstd_free_workspace(&workspace->list);
	return ERR_PTR(-ENOMEM);
}

int ssdfs_zstd_init(void)
{
	return ssdfs_register_compressor(&zstd_compr);
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_zstd_init);

void ssdfs_zstd_exit(void)
{
	ssdfs_unregister_compressor(&zstd_compr);
}
EXPORT_SYMBOL_IF_KUNIT(ssdfs_zstd_exit);

static int ssdfs_zstd_compress(struct list_head *ws,
				unsigned char *data_in,
				unsigned char *cdata_out,
				size_t *srclen, size_t *destlen)
{
	struct ssdfs_zstd_workspace *workspace;
	zstd_parameters params;
	zstd_cctx *cctx;
	size_t compress_size;
	size_t cbuf_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ws_ptr %p, data_in %p, cdata_out %p, "
		  "srclen ptr %p, destlen ptr %p\n",
		  ws, data_in, cdata_out, srclen, destlen);

	BUG_ON(!ws || !data_in || !cdata_out || !srclen || !destlen);
#endif /* CONFIG_SSDFS_DEBUG */

	workspace = list_entry(ws, struct ssdfs_zstd_workspace, list);

	params = zstd_get_params(CONFIG_SSDFS_ZSTD_COMPR_LEVEL, *srclen);

	cctx = zstd_init_cctx(workspace->mem, workspace->mem_size);
	if (unlikely(!cctx)) {
		SSDFS_ERR("failed to initialize ZSTD compression context\n");
		err = -EINVAL;
		goto failed_compress;
	}

	cbuf_size = zstd_compress_bound(PAGE_SIZE);
	compress_size = zstd_compress_cctx(cctx, workspace->cbuf, cbuf_size,
					   data_in, *srclen, &params);
	if (zstd_is_error(compress_size)) {
		SSDFS_ERR("ZSTD compression failed: %s, "
			  "srclen %zu, destlen %zu\n",
			  zstd_get_error_name(compress_size),
			  *srclen, *destlen);
		err = -EINVAL;
		goto failed_compress;
	}

	if (compress_size > *destlen) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to compress: compress_size %zu, "
			  "destlen %zu\n",
			  compress_size, *destlen);
#endif /* CONFIG_SSDFS_DEBUG */
		err = -E2BIG;
		goto failed_compress;
	}

	ssdfs_memcpy(cdata_out, 0, *destlen,
		     workspace->cbuf, 0, cbuf_size,
		     compress_size);
	*destlen = compress_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("compress has succeded: srclen %zu, destlen %zu\n",
		    *srclen, *destlen);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;

failed_compress:
	return err;
}

static int ssdfs_zstd_decompress(struct list_head *ws,
				  unsigned char *cdata_in,
				  unsigned char *data_out,
				  size_t srclen, size_t destlen)
{
	struct ssdfs_zstd_workspace *workspace;
	zstd_dctx *dctx;
	size_t result;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ws_ptr %p, cdata_in %p, data_out %p, "
		  "srclen %zu, destlen %zu\n",
		  ws, cdata_in, data_out, srclen, destlen);

	BUG_ON(!ws || !cdata_in || !data_out);
#endif /* CONFIG_SSDFS_DEBUG */

	workspace = list_entry(ws, struct ssdfs_zstd_workspace, list);

	dctx = zstd_init_dctx(workspace->mem, workspace->mem_size);
	if (unlikely(!dctx)) {
		SSDFS_ERR("failed to initialize ZSTD decompression context\n");
		return -EINVAL;
	}

	result = zstd_decompress_dctx(dctx, data_out, destlen,
				      cdata_in, srclen);
	if (zstd_is_error(result)) {
		SSDFS_ERR("decompression failed: %s, "
			  "srclen %zu, destlen %zu\n",
			  zstd_get_error_name(result), srclen, destlen);
		return -EINVAL;
	}

	if (result != destlen) {
		SSDFS_ERR("decompression size mismatch: "
			  "expected %zu, got %zu\n",
			  destlen, result);
		return -EINVAL;
	}

	return 0;
}
