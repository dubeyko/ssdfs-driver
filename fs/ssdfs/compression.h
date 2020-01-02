//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/compression.h - compression/decompression support declarations.
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

#ifndef _SSDFS_COMPRESSION_H
#define _SSDFS_COMPRESSION_H

/*
 * SSDFS compression algorithms.
 *
 * SSDFS_COMPR_NONE: no compression
 * SSDFS_COMPR_ZLIB: ZLIB compression
 * SSDFS_COMPR_LZO: LZO compression
 * SSDFS_COMPR_TYPES_CNT: count of supported compression types
 */
enum {
	SSDFS_COMPR_NONE,
	SSDFS_COMPR_ZLIB,
	SSDFS_COMPR_LZO,
	SSDFS_COMPR_TYPES_CNT,
};

/*
 * struct ssdfs_compress_ops - compressor operations
 * @alloc_workspace - prepare workspace for (de)compression
 * @free_workspace - free workspace after (de)compression
 * @compress - compression method
 * @decompress - decompression method
 */
struct ssdfs_compress_ops {
	struct list_head * (*alloc_workspace)(void);
	void (*free_workspace)(struct list_head *workspace);
	int (*compress)(struct list_head *ws_ptr,
			unsigned char *data_in,
			unsigned char *cdata_out,
			size_t *srclen,
			size_t *destlen);
	int (*decompress)(struct list_head *ws_ptr,
			unsigned char *cdata_in,
			unsigned char *data_out,
			size_t srclen,
			size_t destlen);
};

/*
 * struct ssdfs_compressor - compressor type.
 * @type: compressor type
 * @name: compressor name
 * @compr_ops: compressor operations
 */
struct ssdfs_compressor {
	int type;
	const char *name;
	const struct ssdfs_compress_ops *compr_ops;
};

/* Available SSDFS compressors */
extern struct ssdfs_compressor *ssdfs_compressors[SSDFS_COMPR_TYPES_CNT];

/* compression.c */
int ssdfs_register_compressor(struct ssdfs_compressor *);
int ssdfs_unregister_compressor(struct ssdfs_compressor *);
bool ssdfs_can_compress_data(struct page *page, unsigned data_size);
int ssdfs_compress(int type, unsigned char *data_in, unsigned char *cdata_out,
		    size_t *srclen, size_t *destlen);
int ssdfs_decompress(int type, unsigned char *cdata_in, unsigned char *data_out,
			size_t srclen, size_t destlen);

#ifdef CONFIG_SSDFS_ZLIB
/* compr_zlib.c */
int ssdfs_zlib_init(void);
void ssdfs_zlib_exit(void);
#else
static inline int ssdfs_zlib_init(void) { return 0; }
static inline void ssdfs_zlib_exit(void) { return; }
#endif /* CONFIG_SSDFS_ZLIB */

#ifdef CONFIG_SSDFS_LZO
/* compr_lzo.c */
int ssdfs_lzo_init(void);
void ssdfs_lzo_exit(void);
#else
static inline int ssdfs_lzo_init(void) { return 0; }
static inline void ssdfs_lzo_exit(void) { return; }
#endif /* CONFIG_SSDFS_LZO */

#endif /* _SSDFS_COMPRESSION_H */
