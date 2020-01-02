//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/compr_lzo.c - LZO compression support.
 *
 * Copyright (c) 2014-2020 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2020, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/lzo.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "compression.h"

static int ssdfs_lzo_compress(struct list_head *ws_ptr,
				unsigned char *data_in,
				unsigned char *cdata_out,
				size_t *srclen, size_t *destlen);

static int ssdfs_lzo_decompress(struct list_head *ws_ptr,
				 unsigned char *cdata_in,
				 unsigned char *data_out,
				 size_t srclen, size_t destlen);

static struct list_head *ssdfs_lzo_alloc_workspace(void);
static void ssdfs_lzo_free_workspace(struct list_head *ptr);

static const struct ssdfs_compress_ops ssdfs_lzo_compress_ops = {
	.alloc_workspace = ssdfs_lzo_alloc_workspace,
	.free_workspace = ssdfs_lzo_free_workspace,
	.compress = ssdfs_lzo_compress,
	.decompress = ssdfs_lzo_decompress,
};

static struct ssdfs_compressor lzo_compr = {
	.type = SSDFS_COMPR_LZO,
	.compr_ops = &ssdfs_lzo_compress_ops,
	.name = "lzo",
};

struct ssdfs_lzo_workspace {
	void *mem;
	void *cbuf;	/* where compressed data goes */
	struct list_head list;
};

static void ssdfs_lzo_free_workspace(struct list_head *ptr)
{
	struct ssdfs_lzo_workspace *workspace;

	workspace = list_entry(ptr, struct ssdfs_lzo_workspace, list);

	SSDFS_DBG("workspace %p\n", workspace);

	vfree(workspace->cbuf);
	vfree(workspace->mem);
	kfree(workspace);
}

static struct list_head *ssdfs_lzo_alloc_workspace(void)
{
	struct ssdfs_lzo_workspace *workspace;

	SSDFS_DBG("try to allocate workspace\n");

	workspace = kzalloc(sizeof(*workspace), GFP_NOFS);
	if (unlikely(!workspace))
		goto failed_alloc_workspaces;

	workspace->mem = vmalloc(LZO1X_MEM_COMPRESS);
	workspace->cbuf = vmalloc(lzo1x_worst_compress(PAGE_SIZE));
	if (!workspace->mem || !workspace->cbuf)
		goto failed_alloc_workspaces;

	INIT_LIST_HEAD(&workspace->list);

	return &workspace->list;

failed_alloc_workspaces:
	SSDFS_ERR("unable to allocate memory for workspace\n");
	ssdfs_lzo_free_workspace(&workspace->list);
	return ERR_PTR(-ENOMEM);
}

int ssdfs_lzo_init(void)
{
	return ssdfs_register_compressor(&lzo_compr);
}

void ssdfs_lzo_exit(void)
{
	ssdfs_unregister_compressor(&lzo_compr);
}

static int ssdfs_lzo_compress(struct list_head *ws,
				unsigned char *data_in,
				unsigned char *cdata_out,
				size_t *srclen, size_t *destlen)
{
	struct ssdfs_lzo_workspace *workspace;
	size_t compress_size;
	int err = 0;

	SSDFS_DBG("ws_ptr %p, data_in %p, cdata_out %p, "
		  "srclen ptr %p, destlen ptr %p\n",
		  ws, data_in, cdata_out, srclen, destlen);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ws || !data_in || !cdata_out || !srclen || !destlen);
#endif /* CONFIG_SSDFS_DEBUG */

	workspace = list_entry(ws, struct ssdfs_lzo_workspace, list);

	err = lzo1x_1_compress(data_in, *srclen, workspace->cbuf,
				&compress_size, workspace->mem);
	if (err != LZO_E_OK) {
		SSDFS_ERR("LZO compression failed: internal err %d, "
			  "srclen %zu, destlen %zu\n",
			  err, *srclen, *destlen);
		err = -EINVAL;
		goto failed_compress;
	}

	if (compress_size > *destlen) {
		SSDFS_DBG("unable to compress: compress_size %zu, "
			  "destlen %zu\n",
			  compress_size, *destlen);
		err = -E2BIG;
		goto failed_compress;
	}

	memcpy(cdata_out, workspace->cbuf, compress_size);
	*destlen = compress_size;

	SSDFS_DBG("compress has succeded: srclen %zu, destlen %zu\n",
		    *srclen, *destlen);

	return 0;

failed_compress:
	return err;
}

static int ssdfs_lzo_decompress(struct list_head *ws,
				 unsigned char *cdata_in,
				 unsigned char *data_out,
				 size_t srclen, size_t destlen)
{
	size_t dl = destlen;
	int err;

	SSDFS_DBG("ws_ptr %p, cdata_in %p, data_out %p, "
		  "srclen %zu, destlen %zu\n",
		  ws, cdata_in, data_out, srclen, destlen);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ws || !cdata_in || !data_out);
#endif /* CONFIG_SSDFS_DEBUG */

	err = lzo1x_decompress_safe(cdata_in, srclen, data_out, &dl);

	if (err != LZO_E_OK || dl != destlen) {
		SSDFS_ERR("decompression failed: LZO compressor err %d, "
			  "srclen %zu, destlen %zu\n",
			  err, srclen, destlen);
		return -EINVAL;
	}

	return 0;
}
