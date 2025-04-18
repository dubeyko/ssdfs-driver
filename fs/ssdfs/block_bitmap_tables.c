/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/block_bitmap_tables.c - declaration of block bitmap's search tables.
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

#include <linux/kernel.h>

/*
 * Table for determination presence of free block
 * state in provided byte. Checking byte is used
 * as index in array.
 */
const bool detect_free_blk[U8_MAX + 1] = {
/* 00 - 0x00 */	true, true, true, true,
/* 01 - 0x04 */	true, true, true, true,
/* 02 - 0x08 */	true, true, true, true,
/* 03 - 0x0C */	true, true, true, true,
/* 04 - 0x10 */	true, true, true, true,
/* 05 - 0x14 */	true, true, true, true,
/* 06 - 0x18 */	true, true, true, true,
/* 07 - 0x1C */	true, true, true, true,
/* 08 - 0x20 */	true, true, true, true,
/* 09 - 0x24 */	true, true, true, true,
/* 10 - 0x28 */	true, true, true, true,
/* 11 - 0x2C */	true, true, true, true,
/* 12 - 0x30 */	true, true, true, true,
/* 13 - 0x34 */	true, true, true, true,
/* 14 - 0x38 */	true, true, true, true,
/* 15 - 0x3C */	true, true, true, true,
/* 16 - 0x40 */	true, true, true, true,
/* 17 - 0x44 */	true, true, true, true,
/* 18 - 0x48 */	true, true, true, true,
/* 19 - 0x4C */	true, true, true, true,
/* 20 - 0x50 */	true, true, true, true,
/* 21 - 0x54 */	true, false, false, false,
/* 22 - 0x58 */	true, false, false, false,
/* 23 - 0x5C */	true, false, false, false,
/* 24 - 0x60 */	true, true, true, true,
/* 25 - 0x64 */	true, false, false, false,
/* 26 - 0x68 */	true, false, false, false,
/* 27 - 0x6C */	true, false, false, false,
/* 28 - 0x70 */	true, true, true, true,
/* 29 - 0x74 */	true, false, false, false,
/* 30 - 0x78 */	true, false, false, false,
/* 31 - 0x7C */	true, false, false, false,
/* 32 - 0x80 */	true, true, true, true,
/* 33 - 0x84 */	true, true, true, true,
/* 34 - 0x88 */	true, true, true, true,
/* 35 - 0x8C */	true, true, true, true,
/* 36 - 0x90 */	true, true, true, true,
/* 37 - 0x94 */	true, false, false, false,
/* 38 - 0x98 */	true, false, false, false,
/* 39 - 0x9C */	true, false, false, false,
/* 40 - 0xA0 */	true, true, true, true,
/* 41 - 0xA4 */	true, false, false, false,
/* 42 - 0xA8 */	true, false, false, false,
/* 43 - 0xAC */	true, false, false, false,
/* 44 - 0xB0 */	true, true, true, true,
/* 45 - 0xB4 */	true, false, false, false,
/* 46 - 0xB8 */	true, false, false, false,
/* 47 - 0xBC */	true, false, false, false,
/* 48 - 0xC0 */	true, true, true, true,
/* 49 - 0xC4 */	true, true, true, true,
/* 50 - 0xC8 */	true, true, true, true,
/* 51 - 0xCC */	true, true, true, true,
/* 52 - 0xD0 */	true, true, true, true,
/* 53 - 0xD4 */	true, false, false, false,
/* 54 - 0xD8 */	true, false, false, false,
/* 55 - 0xDC */	true, false, false, false,
/* 56 - 0xE0 */	true, true, true, true,
/* 57 - 0xE4 */	true, false, false, false,
/* 58 - 0xE8 */	true, false, false, false,
/* 59 - 0xEC */	true, false, false, false,
/* 60 - 0xF0 */	true, true, true, true,
/* 61 - 0xF4 */	true, false, false, false,
/* 62 - 0xF8 */	true, false, false, false,
/* 63 - 0xFC */	true, false, false, false
};

/*
 * Table for determination presence of pre-allocated
 * block state in provided byte. Checking byte is used
 * as index in array.
 */
const bool detect_pre_allocated_blk[U8_MAX + 1] = {
/* 00 - 0x00 */	false, true, false, false,
/* 01 - 0x04 */	true, true, true, true,
/* 02 - 0x08 */	false, true, false, false,
/* 03 - 0x0C */	false, true, false, false,
/* 04 - 0x10 */	true, true, true, true,
/* 05 - 0x14 */	true, true, true, true,
/* 06 - 0x18 */	true, true, true, true,
/* 07 - 0x1C */	true, true, true, true,
/* 08 - 0x20 */	false, true, false, false,
/* 09 - 0x24 */	true, true, true, true,
/* 10 - 0x28 */	false, true, false, false,
/* 11 - 0x2C */	false, true, false, false,
/* 12 - 0x30 */	false, true, false, false,
/* 13 - 0x34 */	true, true, true, true,
/* 14 - 0x38 */	false, true, false, false,
/* 15 - 0x3C */	false, true, false, false,
/* 16 - 0x40 */	true, true, true, true,
/* 17 - 0x44 */	true, true, true, true,
/* 18 - 0x48 */	true, true, true, true,
/* 19 - 0x4C */	true, true, true, true,
/* 20 - 0x50 */	true, true, true, true,
/* 21 - 0x54 */	true, true, true, true,
/* 22 - 0x58 */	true, true, true, true,
/* 23 - 0x5C */	true, true, true, true,
/* 24 - 0x60 */	true, true, true, true,
/* 25 - 0x64 */	true, true, true, true,
/* 26 - 0x68 */	true, true, true, true,
/* 27 - 0x6C */	true, true, true, true,
/* 28 - 0x70 */	true, true, true, true,
/* 29 - 0x74 */	true, true, true, true,
/* 30 - 0x78 */	true, true, true, true,
/* 31 - 0x7C */	true, true, true, true,
/* 32 - 0x80 */	false, true, false, false,
/* 33 - 0x84 */	true, true, true, true,
/* 34 - 0x88 */	false, true, false, false,
/* 35 - 0x8C */	false, true, false, false,
/* 36 - 0x90 */	true, true, true, true,
/* 37 - 0x94 */	true, true, true, true,
/* 38 - 0x98 */	true, true, true, true,
/* 39 - 0x9C */	true, true, true, true,
/* 40 - 0xA0 */	false, true, false, false,
/* 41 - 0xA4 */	true, true, true, true,
/* 42 - 0xA8 */	false, true, false, false,
/* 43 - 0xAC */	false, true, false, false,
/* 44 - 0xB0 */	false, true, false, false,
/* 45 - 0xB4 */	true, true, true, true,
/* 46 - 0xB8 */	false, true, false, false,
/* 47 - 0xBC */	false, true, false, false,
/* 48 - 0xC0 */	false, true, false, false,
/* 49 - 0xC4 */	true, true, true, true,
/* 50 - 0xC8 */	false, true, false, false,
/* 51 - 0xCC */	false, true, false, false,
/* 52 - 0xD0 */	true, true, true, true,
/* 53 - 0xD4 */	true, true, true, true,
/* 54 - 0xD8 */	true, true, true, true,
/* 55 - 0xDC */	true, true, true, true,
/* 56 - 0xE0 */	false, true, false, false,
/* 57 - 0xE4 */	true, true, true, true,
/* 58 - 0xE8 */	false, true, false, false,
/* 59 - 0xEC */	false, true, false, false,
/* 60 - 0xF0 */	false, true, false, false,
/* 61 - 0xF4 */	true, true, true, true,
/* 62 - 0xF8 */	false, true, false, false,
/* 63 - 0xFC */	false, true, false, false
};

/*
 * Table for determination presence of valid block
 * state in provided byte. Checking byte is used
 * as index in array.
 */
const bool detect_valid_blk[U8_MAX + 1] = {
/* 00 - 0x00 */	false, false, false, true,
/* 01 - 0x04 */	false, false, false, true,
/* 02 - 0x08 */	false, false, false, true,
/* 03 - 0x0C */	true, true, true, true,
/* 04 - 0x10 */	false, false, false, true,
/* 05 - 0x14 */	false, false, false, true,
/* 06 - 0x18 */	false, false, false, true,
/* 07 - 0x1C */	true, true, true, true,
/* 08 - 0x20 */	false, false, false, true,
/* 09 - 0x24 */	false, false, false, true,
/* 10 - 0x28 */	false, false, false, true,
/* 11 - 0x2C */	true, true, true, true,
/* 12 - 0x30 */	true, true, true, true,
/* 13 - 0x34 */	true, true, true, true,
/* 14 - 0x38 */	true, true, true, true,
/* 15 - 0x3C */	true, true, true, true,
/* 16 - 0x40 */	false, false, false, true,
/* 17 - 0x44 */	false, false, false, true,
/* 18 - 0x48 */	false, false, false, true,
/* 19 - 0x4C */	true, true, true, true,
/* 20 - 0x50 */	false, false, false, true,
/* 21 - 0x54 */	false, false, false, true,
/* 22 - 0x58 */	false, false, false, true,
/* 23 - 0x5C */	true, true, true, true,
/* 24 - 0x60 */	false, false, false, true,
/* 25 - 0x64 */	false, false, false, true,
/* 26 - 0x68 */	false, false, false, true,
/* 27 - 0x6C */	true, true, true, true,
/* 28 - 0x70 */	true, true, true, true,
/* 29 - 0x74 */	true, true, true, true,
/* 30 - 0x78 */	true, true, true, true,
/* 31 - 0x7C */	true, true, true, true,
/* 32 - 0x80 */	false, false, false, true,
/* 33 - 0x84 */	false, false, false, true,
/* 34 - 0x88 */	false, false, false, true,
/* 35 - 0x8C */	true, true, true, true,
/* 36 - 0x90 */	false, false, false, true,
/* 37 - 0x94 */	false, false, false, true,
/* 38 - 0x98 */	false, false, false, true,
/* 39 - 0x9C */	true, true, true, true,
/* 40 - 0xA0 */	false, false, false, true,
/* 41 - 0xA4 */	false, false, false, true,
/* 42 - 0xA8 */	false, false, false, true,
/* 43 - 0xAC */	true, true, true, true,
/* 44 - 0xB0 */	true, true, true, true,
/* 45 - 0xB4 */	true, true, true, true,
/* 46 - 0xB8 */	true, true, true, true,
/* 47 - 0xBC */	true, true, true, true,
/* 48 - 0xC0 */	true, true, true, true,
/* 49 - 0xC4 */	true, true, true, true,
/* 50 - 0xC8 */	true, true, true, true,
/* 51 - 0xCC */	true, true, true, true,
/* 52 - 0xD0 */	true, true, true, true,
/* 53 - 0xD4 */	true, true, true, true,
/* 54 - 0xD8 */	true, true, true, true,
/* 55 - 0xDC */	true, true, true, true,
/* 56 - 0xE0 */	true, true, true, true,
/* 57 - 0xE4 */	true, true, true, true,
/* 58 - 0xE8 */	true, true, true, true,
/* 59 - 0xEC */	true, true, true, true,
/* 60 - 0xF0 */	true, true, true, true,
/* 61 - 0xF4 */	true, true, true, true,
/* 62 - 0xF8 */	true, true, true, true,
/* 63 - 0xFC */	true, true, true, true
};

/*
 * Table for determination presence of invalid block
 * state in provided byte. Checking byte is used
 * as index in array.
 */
const bool detect_invalid_blk[U8_MAX + 1] = {
/* 00 - 0x00 */	false, false, true, false,
/* 01 - 0x04 */	false, false, true, false,
/* 02 - 0x08 */	true, true, true, true,
/* 03 - 0x0C */	false, false, true, false,
/* 04 - 0x10 */	false, false, true, false,
/* 05 - 0x14 */	false, false, true, false,
/* 06 - 0x18 */	true, true, true, true,
/* 07 - 0x1C */	false, false, true, false,
/* 08 - 0x20 */	true, true, true, true,
/* 09 - 0x24 */	true, true, true, true,
/* 10 - 0x28 */	true, true, true, true,
/* 11 - 0x2C */	true, true, true, true,
/* 12 - 0x30 */	false, false, true, false,
/* 13 - 0x34 */	false, false, true, false,
/* 14 - 0x38 */	true, true, true, true,
/* 15 - 0x3C */	false, false, true, false,
/* 16 - 0x40 */	false, false, true, false,
/* 17 - 0x44 */	false, false, true, false,
/* 18 - 0x48 */	true, true, true, true,
/* 19 - 0x4C */	false, false, true, false,
/* 20 - 0x50 */	false, false, true, false,
/* 21 - 0x54 */	false, false, true, false,
/* 22 - 0x58 */	true, true, true, true,
/* 23 - 0x5C */	false, false, true, false,
/* 24 - 0x60 */	true, true, true, true,
/* 25 - 0x64 */	true, true, true, true,
/* 26 - 0x68 */	true, true, true, true,
/* 27 - 0x6C */	true, true, true, true,
/* 28 - 0x70 */	false, false, true, false,
/* 29 - 0x74 */	false, false, true, false,
/* 30 - 0x78 */	true, true, true, true,
/* 31 - 0x7C */	false, false, true, false,
/* 32 - 0x80 */	true, true, true, true,
/* 33 - 0x84 */	true, true, true, true,
/* 34 - 0x88 */	true, true, true, true,
/* 35 - 0x8C */	true, true, true, true,
/* 36 - 0x90 */	true, true, true, true,
/* 37 - 0x94 */	true, true, true, true,
/* 38 - 0x98 */	true, true, true, true,
/* 39 - 0x9C */	true, true, true, true,
/* 40 - 0xA0 */	true, true, true, true,
/* 41 - 0xA4 */	true, true, true, true,
/* 42 - 0xA8 */	true, true, true, true,
/* 43 - 0xAC */	true, true, true, true,
/* 44 - 0xB0 */	true, true, true, true,
/* 45 - 0xB4 */	true, true, true, true,
/* 46 - 0xB8 */	true, true, true, true,
/* 47 - 0xBC */	true, true, true, true,
/* 48 - 0xC0 */	false, false, true, false,
/* 49 - 0xC4 */	false, false, true, false,
/* 50 - 0xC8 */	true, true, true, true,
/* 51 - 0xCC */	false, false, true, false,
/* 52 - 0xD0 */	false, false, true, false,
/* 53 - 0xD4 */	false, false, true, false,
/* 54 - 0xD8 */	true, true, true, true,
/* 55 - 0xDC */	false, false, true, false,
/* 56 - 0xE0 */	true, true, true, true,
/* 57 - 0xE4 */	true, true, true, true,
/* 58 - 0xE8 */	true, true, true, true,
/* 59 - 0xEC */	true, true, true, true,
/* 60 - 0xF0 */	false, false, true, false,
/* 61 - 0xF4 */	false, false, true, false,
/* 62 - 0xF8 */	true, true, true, true,
/* 63 - 0xFC */	false, false, true, false
};
