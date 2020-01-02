//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/options.c - mount options parsing.
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

#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/parser.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "segment_bitmap.h"

/*
 * SSDFS mount options.
 *
 * Opt_compr: change default compressor
 * Opt_fs_err_panic: panic if fs error is detected
 * Opt_fs_err_ro: remount in RO state if fs error is detected
 * Opt_fs_err_cont: continue execution if fs error is detected
 * Opt_ignore_fs_state: ignore on-disk file system state during mount
 * Opt_err: just end of array marker
 */
enum {
	Opt_compr,
	Opt_fs_err_panic,
	Opt_fs_err_ro,
	Opt_fs_err_cont,
	Opt_ignore_fs_state,
	Opt_err,
};

static const match_table_t tokens = {
	{Opt_compr, "compr=%s"},
	{Opt_fs_err_panic, "errors=panic"},
	{Opt_fs_err_ro, "errors=remount-ro"},
	{Opt_fs_err_cont, "errors=continue"},
	{Opt_ignore_fs_state, "fs_state=ignore"},
	{Opt_err, NULL},
};

int ssdfs_parse_options(struct ssdfs_fs_info *fs_info, char *data)
{
	substring_t args[MAX_OPT_ARGS];
	char *p, *name;

	if (!data)
		return 0;

	while ((p = strsep(&data, ","))) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_compr:
			name = match_strdup(&args[0]);

			if (!name)
				return -ENOMEM;
			if (!strcmp(name, "none"))
				ssdfs_set_opt(fs_info->mount_opts,
						COMPR_MODE_NONE);
#ifdef CONFIG_SSDFS_ZLIB
			else if (!strcmp(name, "zlib"))
				ssdfs_set_opt(fs_info->mount_opts,
						COMPR_MODE_ZLIB);
#endif
#ifdef CONFIG_SSDFS_LZO
			else if (!strcmp(name, "lzo"))
				ssdfs_set_opt(fs_info->mount_opts,
						COMPR_MODE_LZO);
#endif
			else {
				SSDFS_ERR("unknown compressor %s\n", name);
				kfree(name);
				return -EINVAL;
			}
			kfree(name);
			break;

		case Opt_fs_err_panic:
			/* Clear possible default initialization */
			ssdfs_clear_opt(fs_info->mount_opts, ERRORS_RO);
			ssdfs_clear_opt(fs_info->mount_opts, ERRORS_CONT);
			ssdfs_set_opt(fs_info->mount_opts, ERRORS_PANIC);
			break;

		case Opt_fs_err_ro:
			/* Clear possible default initialization */
			ssdfs_clear_opt(fs_info->mount_opts, ERRORS_PANIC);
			ssdfs_clear_opt(fs_info->mount_opts, ERRORS_CONT);
			ssdfs_set_opt(fs_info->mount_opts, ERRORS_RO);
			break;

		case Opt_fs_err_cont:
			/* Clear possible default initialization */
			ssdfs_clear_opt(fs_info->mount_opts, ERRORS_PANIC);
			ssdfs_clear_opt(fs_info->mount_opts, ERRORS_RO);
			ssdfs_set_opt(fs_info->mount_opts, ERRORS_CONT);
			break;

		case Opt_ignore_fs_state:
			ssdfs_set_opt(fs_info->mount_opts, IGNORE_FS_STATE);
			break;

		default:
			SSDFS_ERR("unrecognized mount option '%s'\n", p);
			return -EINVAL;
		}
	}

	SSDFS_DBG("DONE: parse options\n");

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
