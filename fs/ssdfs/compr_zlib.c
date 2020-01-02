//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/compr_zlib.c - ZLIB compression support.
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
#include <linux/zlib.h>
#include <linux/zutil.h>
#include <linux/vmalloc.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "compression.h"

#define COMPR_LEVEL CONFIG_SSDFS_ZLIB_COMR_LEVEL

static int ssdfs_zlib_compress(struct list_head *ws_ptr,
				unsigned char *data_in,
				unsigned char *cdata_out,
				size_t *srclen, size_t *destlen);

static int ssdfs_zlib_decompress(struct list_head *ws_ptr,
				 unsigned char *cdata_in,
				 unsigned char *data_out,
				 size_t srclen, size_t destlen);

static struct list_head *ssdfs_zlib_alloc_workspace(void);
static void ssdfs_zlib_free_workspace(struct list_head *ptr);

static const struct ssdfs_compress_ops ssdfs_zlib_compress_ops = {
	.alloc_workspace = ssdfs_zlib_alloc_workspace,
	.free_workspace = ssdfs_zlib_free_workspace,
	.compress = ssdfs_zlib_compress,
	.decompress = ssdfs_zlib_decompress,
};

static struct ssdfs_compressor zlib_compr = {
	.type = SSDFS_COMPR_ZLIB,
	.compr_ops = &ssdfs_zlib_compress_ops,
	.name = "zlib",
};

struct ssdfs_zlib_workspace {
	z_stream inflate_stream;
	z_stream deflate_stream;
	struct list_head list;
};

static void ssdfs_zlib_free_workspace(struct list_head *ptr)
{
	struct ssdfs_zlib_workspace *workspace;

	workspace = list_entry(ptr, struct ssdfs_zlib_workspace, list);

	SSDFS_DBG("workspace %p\n", workspace);

	vfree(workspace->deflate_stream.workspace);
	vfree(workspace->inflate_stream.workspace);
	kfree(workspace);
}

static struct list_head *ssdfs_zlib_alloc_workspace(void)
{
	struct ssdfs_zlib_workspace *workspace;
	int deflate_size, inflate_size;

	SSDFS_DBG("try to allocate workspace\n");

	workspace = kzalloc(sizeof(*workspace), GFP_NOFS);
	if (unlikely(!workspace)) {
		SSDFS_ERR("unable to allocate memory for workspace\n");
		return ERR_PTR(-ENOMEM);
	}

	deflate_size = zlib_deflate_workspacesize(MAX_WBITS, MAX_MEM_LEVEL);
	workspace->deflate_stream.workspace = vmalloc(deflate_size);
	if (unlikely(!workspace->deflate_stream.workspace)) {
		SSDFS_ERR("unable to allocate memory for deflate stream\n");
		goto failed_alloc_workspaces;
	}

	SSDFS_DBG("deflate stream size %d\n", deflate_size);

	inflate_size = zlib_inflate_workspacesize();
	workspace->inflate_stream.workspace = vmalloc(inflate_size);
	if (unlikely(!workspace->inflate_stream.workspace)) {
		SSDFS_ERR("unable to allocate memory for inflate stream\n");
		goto failed_alloc_workspaces;
	}

	SSDFS_DBG("inflate stream size %d\n", inflate_size);

	INIT_LIST_HEAD(&workspace->list);

	return &workspace->list;

failed_alloc_workspaces:
	ssdfs_zlib_free_workspace(&workspace->list);
	return ERR_PTR(-ENOMEM);
}

int ssdfs_zlib_init(void)
{
	return ssdfs_register_compressor(&zlib_compr);
}

void ssdfs_zlib_exit(void)
{
	ssdfs_unregister_compressor(&zlib_compr);
}

static int ssdfs_zlib_compress(struct list_head *ws,
				unsigned char *data_in,
				unsigned char *cdata_out,
				size_t *srclen, size_t *destlen)
{
	struct ssdfs_zlib_workspace *workspace;
	z_stream *stream;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ws || !data_in || !cdata_out || !srclen || !destlen);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ws_ptr %p, data_in %p, cdata_out %p, "
		  "srclen %zu, destlen %zu\n",
		  ws, data_in, cdata_out, *srclen, *destlen);

	workspace = list_entry(ws, struct ssdfs_zlib_workspace, list);
	stream = &workspace->deflate_stream;

	if (Z_OK != zlib_deflateInit(stream, COMPR_LEVEL)) {
		SSDFS_ERR("zlib_deflateInit() failed\n");
		err = -EINVAL;
		goto failed_compress;
	}

	stream->next_in = data_in;
	stream->avail_in = *srclen;
	stream->total_in = 0;

	stream->next_out = cdata_out;
	stream->avail_out = *destlen;
	stream->total_out = 0;

	SSDFS_DBG("calling deflate with: "
		  "stream->avail_in %lu, stream->total_in %lu, "
		  "stream->avail_out %lu, stream->total_out %lu\n",
		  (unsigned long)stream->avail_in,
		  (unsigned long)stream->total_in,
		  (unsigned long)stream->avail_out,
		  (unsigned long)stream->total_out);

	err = zlib_deflate(stream, Z_FINISH);

	SSDFS_DBG("deflate returned with: "
		  "stream->avail_in %lu, stream->total_in %lu, "
		  "stream->avail_out %lu, stream->total_out %lu\n",
		  (unsigned long)stream->avail_in,
		  (unsigned long)stream->total_in,
		  (unsigned long)stream->avail_out,
		  (unsigned long)stream->total_out);

	if (err != Z_STREAM_END) {
		if (err == Z_OK) {
			err = -E2BIG;
			SSDFS_DBG("unable to compress: "
				  "total_in %zu, total_out %zu\n",
				  stream->total_in, stream->total_out);
		} else {
			SSDFS_ERR("ZLIB compression failed: "
				  "internal err %d\n",
				  err);
		}
		goto failed_compress;
	}

	err = zlib_deflateEnd(stream);
	if (err != Z_OK) {
		SSDFS_ERR("ZLIB compression failed with internal err %d\n",
			  err);
		goto failed_compress;
	}

	if (stream->total_out >= stream->total_in) {
		SSDFS_DBG("unable to compress: total_in %zu, total_out %zu\n",
			  stream->total_in, stream->total_out);
		err = -E2BIG;
		goto failed_compress;
	}

	*destlen = stream->total_out;
	*srclen = stream->total_in;

	SSDFS_DBG("compress has succeded: srclen %zu, destlen %zu\n",
		    *srclen, *destlen);

failed_compress:
	return err;
}

static int ssdfs_zlib_decompress(struct list_head *ws,
				 unsigned char *cdata_in,
				 unsigned char *data_out,
				 size_t srclen, size_t destlen)
{
	struct ssdfs_zlib_workspace *workspace;
	int wbits = MAX_WBITS;
	int ret = Z_OK;

	SSDFS_DBG("ws_ptr %p, cdata_in %p, data_out %p, "
		  "srclen %zu, destlen %zu\n",
		  ws, cdata_in, data_out, srclen, destlen);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ws || !cdata_in || !data_out);
#endif /* CONFIG_SSDFS_DEBUG */

	workspace = list_entry(ws, struct ssdfs_zlib_workspace, list);

	workspace->inflate_stream.next_in = cdata_in;
	workspace->inflate_stream.avail_in = srclen;
	workspace->inflate_stream.total_in = 0;

	workspace->inflate_stream.next_out = data_out;
	workspace->inflate_stream.avail_out = destlen;
	workspace->inflate_stream.total_out = 0;

	/*
	 * If it's deflate, and it's got no preset dictionary, then
	 * we can tell zlib to skip the adler32 check.
	 */
	if (srclen > 2 && !(cdata_in[1] & PRESET_DICT) &&
	    ((cdata_in[0] & 0x0f) == Z_DEFLATED) &&
	    !(((cdata_in[0] << 8) + cdata_in[1]) % 31)) {

		wbits = -((cdata_in[0] >> 4) + 8);
		workspace->inflate_stream.next_in += 2;
		workspace->inflate_stream.avail_in -= 2;
	}

	if (Z_OK != zlib_inflateInit2(&workspace->inflate_stream, wbits)) {
		SSDFS_ERR("zlib_inflateInit2() failed\n");
		return -EINVAL;
	}

	do {
		ret = zlib_inflate(&workspace->inflate_stream, Z_FINISH);
	} while (ret == Z_OK);

	if (ret != Z_STREAM_END)
		SSDFS_NOTICE("inflate returned %d\n", ret);

	zlib_inflateEnd(&workspace->inflate_stream);

	SSDFS_DBG("decompression has succeded: total_in %zu, total_out %zu\n",
		  workspace->inflate_stream.total_in,
		  workspace->inflate_stream.total_out);

	return 0;
}
