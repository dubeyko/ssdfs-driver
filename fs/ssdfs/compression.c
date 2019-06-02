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

#define SSDFS_CHECK_COMPRESSOR_OP(name) \
static inline bool unable_##name(int type) \
{ \
	if (!ssdfs_compressors[type]) \
		return true; \
	else if (!ssdfs_compressors[type]->compr_ops) \
		return true; \
	else if (!ssdfs_compressors[type]->compr_ops->##name) \
		return true; \
	return false; \
}

SSDFS_CHECK_COMPRESSOR_OP(compress);
SSDFS_CHECK_COMPRESSOR_OP(decompress);

static int ssdfs_none_compress(struct list_head *ws_ptr,
				unsigned char *data_in,
				unsigned char *cdata_out,
				u64 *srclen,
				u64 *destlen)
{
	/* TODO: implement ssdfs_none_compress() */
	SSDFS_WARN("TODO: implement %s\n", __func__);
	return -EOPNOTSUPP;
}

static int ssdfs_none_decompress(struct list_head *ws_ptr,
				 unsigned char *cdata_in,
				 unsigned char *data_out,
				 u64 srclen,
				 u64 destlen)
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
	return (type < SSDFS_COMPR_NONE || type >= SSDFS_COMPR_TYPES_CNT);
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

int __init ssdfs_compressors_init(void)
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

static void ssdfs_free_workspaces(void)
{
	struct list_head *workspace;
	const struct ssdfs_compress_ops *ops;
	int i;

	SSDFS_DBG("destruct auxiliary workspaces\n");

	for (i = 0; i < SSDFS_COMPR_TYPES_CNT; i++) {
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

	ssdfs_unregister_compressor(&ssdfs_none_compr);
	ssdfs_zlib_exit();
	ssdfs_lzo_exit();
	ssdfs_free_workspaces();
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

#ifdef SSDFS_DEBUG
	if (unknown_compression(type)) {
		SSDFS_ERR("unknown compression type %d\n", type);
		BUG();
	}
#endif /* SSDFS_DEBUG */

	if (!ops->alloc_workspace)
		return ERR_PTR(-EOPNOTSUPP);

	cpus = num_online_cpus();
	idle_workspace = &compr_idle_workspace[type];
	workspace_lock = &compr_workspace_lock[type];
	alloc_workspace = &compr_alloc_workspace[type];
	workspace_wait = &compr_workspace_wait[type];
	num_workspace = &compr_num_workspace[type];
	ops = ssdfs_compressors[type]->compr_ops;

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

#ifdef SSDFS_DEBUG
	if (unknown_compression(type)) {
		SSDFS_ERR("unknown compression type %d\n", type);
		BUG();
	}
#endif /* SSDFS_DEBUG */

	if (!ops->free_workspace)
		return;

	idle_workspace = &compr_idle_workspace[type];
	workspace_lock = &compr_workspace_lock[type];
	alloc_workspace = &compr_alloc_workspace[type];
	workspace_wait = &compr_workspace_wait[type];
	num_workspace = &compr_num_workspace[type];
	ops = ssdfs_compressors[type]->compr_ops;

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

int ssdfs_compress(int type, unsigned char *data_in, unsigned char *cdata_out,
		    u64 *srclen, u64 *destlen)
{
	struct ssdfs_compress_ops *ops;
	struct list_head *workspace;
	int err;

	SSDFS_DBG("type %d, data_in %p, cdata_out %p, srclen %p, destlen %p\n",
		  type, data_in, cdata_out, srclen, destlen);

#ifdef SSDFS_DEBUG
	if (unknown_compression(type)) {
		SSDFS_ERR("unknown compression type %d\n", type);
		BUG();
	}
#endif /* SSDFS_DEBUG */

	if (unable_compress(type)) {
		SSDFS_ERR("%s compressor is unable to compress\n",
			  ssdfs_compressors[type]->name);
		err = -EOPNOTSUPP;
		goto failed_compress;
	}

	workspace = find_workspace(type);
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

	free_workspace(type, workspace);
	if (unlikely(err)) {
		SSDFS_ERR("%s compresor fails to compress data %p of size %llu because of err %d\n",
			  ssdfs_compressors[type]->name,
			  data_in, srclen, err);
		goto failed_compress;
	}

	return 0;

failed_compress:
	return err;
}

int ssdfs_decompress(int type, unsigned char *cdata_in, unsigned char *data_out,
			u64 srclen, u64 destlen)
{
	struct ssdfs_compress_ops *ops;
	struct list_head *workspace;
	int err;

	SSDFS_DBG("type %d, cdata_in %p, data_out %p, srclen %llu, destlen %llu\n",
		  type, cdata_in, data_out, srclen, destlen);

#ifdef SSDFS_DEBUG
	if (unknown_compression(type)) {
		SSDFS_ERR("unknown compression type %d\n", type);
		BUG();
	}
#endif /* SSDFS_DEBUG */

	if (unable_decompress(type)) {
		SSDFS_ERR("%s compressor is unable to decompress\n",
			  ssdfs_compressors[type]->name);
		err = -EOPNOTSUPP;
		goto failed_decompress;
	}

	workspace = find_workspace(type);
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

	free_workspace(type, workspace);
	if (unlikely(err)) {
		SSDFS_ERR("%s compresor fails to decompress data %p of size %llu because of err %d\n",
			  ssdfs_compressors[type]->name,
			  cdata_in, srclen, err);
		goto failed_decompress;
	}

	return 0;

failed_decompress:
	return err;
}
