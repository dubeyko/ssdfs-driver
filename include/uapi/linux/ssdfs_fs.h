//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * include/uapi/linux/ssdfs_fs.h - SSDFS common declarations.
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

#ifndef _UAPI_LINUX_SSDFS_H
#define _UAPI_LINUX_SSDFS_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* SSDFS magic signatures */
#define SSDFS_SUPER_MAGIC			0x53734466	/* SsDf */
#define SSDFS_SEGMENT_HDR_MAGIC			0x5348		/* SH */
#define SSDFS_LOG_FOOTER_MAGIC			0x4C46		/* LF */
#define SSDFS_PARTIAL_LOG_HDR_MAGIC		0x5048		/* PH */
#define SSDFS_BLK_BMAP_MAGIC			0x424D		/* BM */
#define SSDFS_FRAGMENT_DESC_MAGIC		0x66		/* f */
#define SSDFS_CHAIN_HDR_MAGIC			0x63		/* c */
#define SSDFS_PHYS_OFF_TABLE_MAGIC		0x504F5448	/* POTH */
#define SSDFS_BLK2OFF_TABLE_HDR_MAGIC		0x5474		/* Tt */
#define SSDFS_SEGBMAP_HDR_MAGIC			0x534D		/* SM */
#define SSDFS_INODE_MAGIC			0x6469		/* di */
#define SSDFS_PEB_TABLE_MAGIC			0x5074		/* Pt */
#define SSDFS_LEB_TABLE_MAGIC			0x4C74		/* Lt */
#define SSDFS_MAPTBL_CACHE_MAGIC		0x4D63		/* Mc */
#define SSDFS_MAPTBL_CACHE_PEB_STATE_MAGIC	0x4D635053	/* McPS */
#define SSDFS_INODES_BTREE_MAGIC		0x496E4274	/* InBt */
#define SSDFS_INODES_BNODE_MAGIC		0x494E		/* IN */
#define SSDFS_DENTRIES_BTREE_MAGIC		0x44654274	/* DeBt */
#define SSDFS_DENTRIES_BNODE_MAGIC		0x444E		/* DN */
#define SSDFS_EXTENTS_BTREE_MAGIC		0x45784274	/* ExBt */
#define SSDFS_SHARED_EXTENTS_BTREE_MAGIC	0x53454274	/* SEBt */
#define SSDFS_EXTENTS_BNODE_MAGIC		0x454E		/* EN */
#define SSDFS_XATTR_BTREE_MAGIC			0x45414274	/* EABt */
#define SSDFS_SHARED_XATTR_BTREE_MAGIC		0x53454174	/* SEAt */
#define SSDFS_XATTR_BNODE_MAGIC			0x414E		/* AN */
#define SSDFS_SHARED_DICT_BTREE_MAGIC		0x53446963	/* SDic */
#define SSDFS_DICTIONARY_BNODE_MAGIC		0x534E		/* SN */

/* SSDFS revision */
#define SSDFS_MAJOR_REVISION		1
#define SSDFS_MINOR_REVISION		2

/* SSDFS constants */
#define SSDFS_MAX_NAME_LEN		255
#define SSDFS_UUID_SIZE			16
#define SSDFS_VOLUME_LABEL_MAX		16

#define SSDFS_RESERVED_VBR_SIZE		1024 /* Volume Boot Record size*/
#define SSDFS_DEFAULT_SEG_SIZE		8388608

/*
 * File system states
 */
#define SSDFS_MOUNTED_FS		0x0000  /* Mounted FS state */
#define SSDFS_VALID_FS			0x0001  /* Unmounted cleanly */
#define SSDFS_ERROR_FS			0x0002  /* Errors detected */
#define SSDFS_RESIZE_FS			0x0004	/* Resize required */
#define SSDFS_LAST_KNOWN_FS_STATE	SSDFS_RESIZE_FS

/*
 * Behaviour when detecting errors
 */
#define SSDFS_ERRORS_CONTINUE		1	/* Continue execution */
#define SSDFS_ERRORS_RO			2	/* Remount fs read-only */
#define SSDFS_ERRORS_PANIC		3	/* Panic */
#define SSDFS_ERRORS_DEFAULT		SSDFS_ERRORS_CONTINUE
#define SSDFS_LAST_KNOWN_FS_ERROR	SSDFS_ERRORS_PANIC

/* Reserved inode id */
#define SSDFS_SHARED_DICT_BTREE_INO		8
#define SSDFS_INODES_BTREE_INO			9
#define SSDFS_SHARED_EXTENTS_BTREE_INO		10
#define SSDFS_SHARED_XATTR_BTREE_INO		11
#define SSDFS_MAPTBL_INO			12
#define SSDFS_SEG_TREE_INO			13
#define SSDFS_SEG_BMAP_INO			14
#define SSDFS_PEB_CACHE_INO			15
#define SSDFS_ROOT_INO				16

#define SSDFS_LINK_MAX		INT_MAX

#define SSDFS_CUR_SEG_DEFAULT_ID	3
#define SSDFS_LOG_PAGES_DEFAULT		32
#define SSDFS_CREATE_THREADS_DEFAULT	1

#endif /* _UAPI_LINUX_SSDFS_H */
