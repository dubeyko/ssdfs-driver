/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/options.c - mount options parsing.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2025 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 *
 * (C) Copyright 2014-2019, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot
 *                  Zvonimir Bandic
 */

#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/parser.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/pagevec.h>
#include <linux/fs_parser.h>
#include <linux/fs_context.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "segment_bitmap.h"

/*
 * SSDFS mount options.
 *
 * Opt_err: behavior if fs error is detected
 * Opt_compr: change default compressor
 * Opt_ignore_fs_state: ignore on-disk file system state during mount
 */
enum {
	Opt_err,
	Opt_compr,
	Opt_ignore_fs_state,
};

static const struct constant_table ssdfs_param_err[] = {
	{"panic",	SSDFS_MOUNT_ERRORS_PANIC},
	{"remount-ro",	SSDFS_MOUNT_ERRORS_RO},
	{"continue",	SSDFS_MOUNT_ERRORS_CONT},
	{}
};

static const struct constant_table ssdfs_param_compr[] = {
	{"none",	SSDFS_MOUNT_COMPR_MODE_NONE},
#ifdef CONFIG_SSDFS_ZLIB
	{"zlib",	SSDFS_MOUNT_COMPR_MODE_ZLIB},
#endif
#ifdef CONFIG_SSDFS_LZO
	{"lzo",		SSDFS_MOUNT_COMPR_MODE_LZO},
#endif
	{}
};

static const struct constant_table ssdfs_param_fs_state[] = {
	{"ignore",	SSDFS_MOUNT_IGNORE_FS_STATE},
	{}
};

static const struct fs_parameter_spec ssdfs_fs_parameters[] = {
	fsparam_enum	("errors", Opt_err, ssdfs_param_err),
	fsparam_enum	("compr", Opt_compr, ssdfs_param_compr),
	fsparam_enum	("fs_state", Opt_ignore_fs_state, ssdfs_param_fs_state),
	{}
};

int ssdfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct ssdfs_mount_context *ctx = fc->fs_private;
	struct fs_parse_result result;
	int opt;

	opt = fs_parse(fc, ssdfs_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_err:
		ssdfs_clear_opt(ctx->s_mount_opts, ERRORS_PANIC);
		ssdfs_clear_opt(ctx->s_mount_opts, ERRORS_RO);
		ssdfs_clear_opt(ctx->s_mount_opts, ERRORS_CONT);
		ctx->s_mount_opts |= result.uint_32;
		break;

	case Opt_compr:
		ssdfs_clear_opt(ctx->s_mount_opts, COMPR_MODE_NONE);
		ssdfs_clear_opt(ctx->s_mount_opts, COMPR_MODE_ZLIB);
		ssdfs_clear_opt(ctx->s_mount_opts, COMPR_MODE_LZO);
		ctx->s_mount_opts |= result.uint_32;
		break;

	case Opt_ignore_fs_state:
		ctx->s_mount_opts |= result.uint_32;
		break;

	default:
		SSDFS_ERR("unrecognized mount option\n");
		return -EINVAL;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("DONE: parse options\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

void ssdfs_initialize_fs_errors_option(struct ssdfs_fs_info *fsi)
{
	if (fsi->fs_errors == SSDFS_ERRORS_PANIC)
		ssdfs_set_opt(fsi->mount_opts, ERRORS_PANIC);
	else if (fsi->fs_errors == SSDFS_ERRORS_RO)
		ssdfs_set_opt(fsi->mount_opts, ERRORS_RO);
	else if (fsi->fs_errors == SSDFS_ERRORS_CONTINUE)
		ssdfs_set_opt(fsi->mount_opts, ERRORS_CONT);
	else {
		u16 def_behaviour = SSDFS_ERRORS_DEFAULT;

		switch (def_behaviour) {
		case SSDFS_ERRORS_PANIC:
			ssdfs_set_opt(fsi->mount_opts, ERRORS_PANIC);
			break;

		case SSDFS_ERRORS_RO:
			ssdfs_set_opt(fsi->mount_opts, ERRORS_RO);
			break;
		}
	}
}

int ssdfs_show_options(struct seq_file *seq, struct dentry *root)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(root->d_sb);
	char *compress_type;

	if (ssdfs_test_opt(fsi->mount_opts, COMPR_MODE_ZLIB)) {
		compress_type = "zlib";
		seq_printf(seq, ",compress=%s", compress_type);
	} else if (ssdfs_test_opt(fsi->mount_opts, COMPR_MODE_LZO)) {
		compress_type = "lzo";
		seq_printf(seq, ",compress=%s", compress_type);
	}

	if (ssdfs_test_opt(fsi->mount_opts, ERRORS_PANIC))
		seq_puts(seq, ",errors=panic");
	else if (ssdfs_test_opt(fsi->mount_opts, ERRORS_RO))
		seq_puts(seq, ",errors=remount-ro");
	else if (ssdfs_test_opt(fsi->mount_opts, ERRORS_CONT))
		seq_puts(seq, ",errors=continue");

	if (ssdfs_test_opt(fsi->mount_opts, IGNORE_FS_STATE))
		seq_puts(seq, ",fs_state=ignore");

	return 0;
}
