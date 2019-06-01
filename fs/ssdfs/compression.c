//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 *  SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/compression.c - compression logic implementation.
 *
 * Copyright (c) 2019 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include "ssdfs.h"
#include "compression.h"

struct ssdfs_compressor *ssdfs_compressors[SSDFS_COMPR_TYPES_CNT];

static struct list_head compr_idle_workspace[SSDFS_COMPR_TYPES_CNT];
static spinlock_t compr_workspace_lock[SSDFS_COMPR_TYPES_CNT];
static int compr_num_workspace[SSDFS_COMPR_TYPES_CNT];
static atomic_t compr_alloc_workspace[SSDFS_COMPR_TYPES_CNT];
static wait_queue_head_t compr_workspace_wait[SSDFS_COMPR_TYPES_CNT];

static int ssdfs_none_compress(struct list_head *ws_ptr,
				unsigned char *data_in,
				unsigned char *cdata_out,
				u64 *srclen,
				u64 *destlen);

static int ssdfs_none_decompress(struct list_head *ws_ptr,
				 unsigned char *cdata_in,
				 unsigned char *data_out,
				 u64 srclen,
				 u64 destlen);

static const struct ssdfs_compress_ops ssdfs_compr_none_ops = {
	.compress = sdfs_none_compress,
	.decompress = ssdfs_none_decompress,
};

static struct ssdfs_compressor ssdfs_none_compr = {
	.type = SSDFS_COMPR_NONE,
	.compr_ops = &ssdfs_compr_none_ops,
	.name = "none",
};

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

int __init ssdfs_compressors_init(void)
{
	int err;

	SSDFS_DBG("init compressors subsystem\n");

	for (int i = 0; i < SSDFS_COMPR_TYPES_CNT; i++) {
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

	err = ssdfs_register_compressor(&none_compr);
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

static void free_workspaces(void)
{
	struct list_head *workspace;
	const struct ssdfs_compress_ops *ops;

	SSDFS_DBG("destruct auxiliary workspaces\n");

	for (int i = 0; i < SSDFS_COMPR_TYPES_CNT; i++) {
		ops = ssdfs_compressors[i]->compr_ops;
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

	ssdfs_unregister_compressor(&none_compr);
	ssdfs_zlib_exit();
	ssdfs_lzo_exit();
	free_workspaces();
}
