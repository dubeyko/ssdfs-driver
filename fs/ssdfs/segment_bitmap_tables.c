/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/segment_bitmap_tables.c - declaration of segbmap's search tables.
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
 * Table for determination presence of clean segment
 * state in provided byte. Checking byte is used
 * as index in array.
 */
const bool detect_clean_seg[U8_MAX + 1] = {
/* 00 - 0x00 */	true, true, true, true,
/* 01 - 0x04 */	true, true, true, true,
/* 02 - 0x08 */	true, true, true, true,
/* 03 - 0x0C */	true, true, true, true,
/* 04 - 0x10 */	true, false, false, false,
/* 05 - 0x14 */	false, false, false, false,
/* 06 - 0x18 */	false, false, false, false,
/* 07 - 0x1C */	false, false, false, false,
/* 08 - 0x20 */	true, false, false, false,
/* 09 - 0x24 */	false, false, false, false,
/* 10 - 0x28 */	false, false, false, false,
/* 11 - 0x2C */	false, false, false, false,
/* 12 - 0x30 */	true, false, false, false,
/* 13 - 0x34 */	false, false, false, false,
/* 14 - 0x38 */	false, false, false, false,
/* 15 - 0x3C */	false, false, false, false,
/* 16 - 0x40 */	true, false, false, false,
/* 17 - 0x44 */	false, false, false, false,
/* 18 - 0x48 */	false, false, false, false,
/* 19 - 0x4C */	false, false, false, false,
/* 20 - 0x50 */	true, false, false, false,
/* 21 - 0x54 */	false, false, false, false,
/* 22 - 0x58 */	false, false, false, false,
/* 23 - 0x5C */	false, false, false, false,
/* 24 - 0x60 */	true, false, false, false,
/* 25 - 0x64 */	false, false, false, false,
/* 26 - 0x68 */	false, false, false, false,
/* 27 - 0x6C */	false, false, false, false,
/* 28 - 0x70 */	true, false, false, false,
/* 29 - 0x74 */	false, false, false, false,
/* 30 - 0x78 */	false, false, false, false,
/* 31 - 0x7C */	false, false, false, false,
/* 32 - 0x80 */	true, false, false, false,
/* 33 - 0x84 */	false, false, false, false,
/* 34 - 0x88 */	false, false, false, false,
/* 35 - 0x8C */	false, false, false, false,
/* 36 - 0x90 */	true, false, false, false,
/* 37 - 0x94 */	false, false, false, false,
/* 38 - 0x98 */	false, false, false, false,
/* 39 - 0x9C */	false, false, false, false,
/* 40 - 0xA0 */	true, false, false, false,
/* 41 - 0xA4 */	false, false, false, false,
/* 42 - 0xA8 */	false, false, false, false,
/* 43 - 0xAC */	false, false, false, false,
/* 44 - 0xB0 */	true, false, false, false,
/* 45 - 0xB4 */	false, false, false, false,
/* 46 - 0xB8 */	false, false, false, false,
/* 47 - 0xBC */	false, false, false, false,
/* 48 - 0xC0 */	true, false, false, false,
/* 49 - 0xC4 */	false, false, false, false,
/* 50 - 0xC8 */	false, false, false, false,
/* 51 - 0xCC */	false, false, false, false,
/* 52 - 0xD0 */	true, false, false, false,
/* 53 - 0xD4 */	false, false, false, false,
/* 54 - 0xD8 */	false, false, false, false,
/* 55 - 0xDC */	false, false, false, false,
/* 56 - 0xE0 */	true, false, false, false,
/* 57 - 0xE4 */	false, false, false, false,
/* 58 - 0xE8 */	false, false, false, false,
/* 59 - 0xEC */	false, false, false, false,
/* 60 - 0xF0 */	true, false, false, false,
/* 61 - 0xF4 */	false, false, false, false,
/* 62 - 0xF8 */	false, false, false, false,
/* 63 - 0xFC */	false, false, false, false
};

/*
 * Table for determination presence of data using segment
 * state in provided byte. Checking byte is used
 * as index in array.
 */
const bool detect_data_using_seg[U8_MAX + 1] = {
/* 00 - 0x00 */	false, true, false, false,
/* 01 - 0x04 */	false, false, false, false,
/* 02 - 0x08 */	false, false, false, false,
/* 03 - 0x0C */	false, false, false, false,
/* 04 - 0x10 */	true, true, true, true,
/* 05 - 0x14 */	true, true, true, true,
/* 06 - 0x18 */	true, true, true, true,
/* 07 - 0x1C */	true, true, true, true,
/* 08 - 0x20 */	false, true, false, false,
/* 09 - 0x24 */	false, false, false, false,
/* 10 - 0x28 */	false, false, false, false,
/* 11 - 0x2C */	false, false, false, false,
/* 12 - 0x30 */	false, true, false, false,
/* 13 - 0x34 */	false, false, false, false,
/* 14 - 0x38 */	false, false, false, false,
/* 15 - 0x3C */	false, false, false, false,
/* 16 - 0x40 */	false, true, false, false,
/* 17 - 0x44 */	false, false, false, false,
/* 18 - 0x48 */	false, false, false, false,
/* 19 - 0x4C */	false, false, false, false,
/* 20 - 0x50 */	false, true, false, false,
/* 21 - 0x54 */	false, false, false, false,
/* 22 - 0x58 */	false, false, false, false,
/* 23 - 0x5C */	false, false, false, false,
/* 24 - 0x60 */	false, true, false, false,
/* 25 - 0x64 */	false, false, false, false,
/* 26 - 0x68 */	false, false, false, false,
/* 27 - 0x6C */	false, false, false, false,
/* 28 - 0x70 */	false, true, false, false,
/* 29 - 0x74 */	false, false, false, false,
/* 30 - 0x78 */	false, false, false, false,
/* 31 - 0x7C */	false, false, false, false,
/* 32 - 0x80 */	false, true, false, false,
/* 33 - 0x84 */	false, false, false, false,
/* 34 - 0x88 */	false, false, false, false,
/* 35 - 0x8C */	false, false, false, false,
/* 36 - 0x90 */	false, true, false, false,
/* 37 - 0x94 */	false, false, false, false,
/* 38 - 0x98 */	false, false, false, false,
/* 39 - 0x9C */	false, false, false, false,
/* 40 - 0xA0 */	false, true, false, false,
/* 41 - 0xA4 */	false, false, false, false,
/* 42 - 0xA8 */	false, false, false, false,
/* 43 - 0xAC */	false, false, false, false,
/* 44 - 0xB0 */	false, true, false, false,
/* 45 - 0xB4 */	false, false, false, false,
/* 46 - 0xB8 */	false, false, false, false,
/* 47 - 0xBC */	false, false, false, false,
/* 48 - 0xC0 */	false, true, false, false,
/* 49 - 0xC4 */	false, false, false, false,
/* 50 - 0xC8 */	false, false, false, false,
/* 51 - 0xCC */	false, false, false, false,
/* 52 - 0xD0 */	false, true, false, false,
/* 53 - 0xD4 */	false, false, false, false,
/* 54 - 0xD8 */	false, false, false, false,
/* 55 - 0xDC */	false, false, false, false,
/* 56 - 0xE0 */	false, true, false, false,
/* 57 - 0xE4 */	false, false, false, false,
/* 58 - 0xE8 */	false, false, false, false,
/* 59 - 0xEC */	false, false, false, false,
/* 60 - 0xF0 */	false, true, false, false,
/* 61 - 0xF4 */	false, false, false, false,
/* 62 - 0xF8 */	false, false, false, false,
/* 63 - 0xFC */	false, false, false, false
};

/*
 * Table for determination presence of leaf node segment
 * state in provided byte. Checking byte is used
 * as index in array.
 */
const bool detect_lnode_using_seg[U8_MAX + 1] = {
/* 00 - 0x00 */	false, false, true, false,
/* 01 - 0x04 */	false, false, false, false,
/* 02 - 0x08 */	false, false, false, false,
/* 03 - 0x0C */	false, false, false, false,
/* 04 - 0x10 */	false, false, true, false,
/* 05 - 0x14 */	false, false, false, false,
/* 06 - 0x18 */	false, false, false, false,
/* 07 - 0x1C */	false, false, false, false,
/* 08 - 0x20 */	true, true, true, true,
/* 09 - 0x24 */	true, true, true, true,
/* 10 - 0x28 */	true, true, true, true,
/* 11 - 0x2C */	true, true, true, true,
/* 12 - 0x30 */	false, false, true, false,
/* 13 - 0x34 */	false, false, false, false,
/* 14 - 0x38 */	false, false, false, false,
/* 15 - 0x3C */	false, false, false, false,
/* 16 - 0x40 */	false, false, true, false,
/* 17 - 0x44 */	false, false, false, false,
/* 18 - 0x48 */	false, false, false, false,
/* 19 - 0x4C */	false, false, false, false,
/* 20 - 0x50 */	false, false, true, false,
/* 21 - 0x54 */	false, false, false, false,
/* 22 - 0x58 */	false, false, false, false,
/* 23 - 0x5C */	false, false, false, false,
/* 24 - 0x60 */	false, false, true, false,
/* 25 - 0x64 */	false, false, false, false,
/* 26 - 0x68 */	false, false, false, false,
/* 27 - 0x6C */	false, false, false, false,
/* 28 - 0x70 */	false, false, true, false,
/* 29 - 0x74 */	false, false, false, false,
/* 30 - 0x78 */	false, false, false, false,
/* 31 - 0x7C */	false, false, false, false,
/* 32 - 0x80 */	false, false, true, false,
/* 33 - 0x84 */	false, false, false, false,
/* 34 - 0x88 */	false, false, false, false,
/* 35 - 0x8C */	false, false, false, false,
/* 36 - 0x90 */	false, false, true, false,
/* 37 - 0x94 */	false, false, false, false,
/* 38 - 0x98 */	false, false, false, false,
/* 39 - 0x9C */	false, false, false, false,
/* 40 - 0xA0 */	false, false, true, false,
/* 41 - 0xA4 */	false, false, false, false,
/* 42 - 0xA8 */	false, false, false, false,
/* 43 - 0xAC */	false, false, false, false,
/* 44 - 0xB0 */	false, false, true, false,
/* 45 - 0xB4 */	false, false, false, false,
/* 46 - 0xB8 */	false, false, false, false,
/* 47 - 0xBC */	false, false, false, false,
/* 48 - 0xC0 */	false, false, true, false,
/* 49 - 0xC4 */	false, false, false, false,
/* 50 - 0xC8 */	false, false, false, false,
/* 51 - 0xCC */	false, false, false, false,
/* 52 - 0xD0 */	false, false, true, false,
/* 53 - 0xD4 */	false, false, false, false,
/* 54 - 0xD8 */	false, false, false, false,
/* 55 - 0xDC */	false, false, false, false,
/* 56 - 0xE0 */	false, false, true, false,
/* 57 - 0xE4 */	false, false, false, false,
/* 58 - 0xE8 */	false, false, false, false,
/* 59 - 0xEC */	false, false, false, false,
/* 60 - 0xF0 */	false, false, true, false,
/* 61 - 0xF4 */	false, false, false, false,
/* 62 - 0xF8 */	false, false, false, false,
/* 63 - 0xFC */	false, false, false, false
};

/*
 * Table for determination presence of hybrid node segment
 * state in provided byte. Checking byte is used
 * as index in array.
 */
const bool detect_hnode_using_seg[U8_MAX + 1] = {
/* 00 - 0x00 */	false, false, false, false,
/* 01 - 0x04 */	false, true, false, false,
/* 02 - 0x08 */	false, false, false, false,
/* 03 - 0x0C */	false, false, false, false,
/* 04 - 0x10 */	false, false, false, false,
/* 05 - 0x14 */	false, true, false, false,
/* 06 - 0x18 */	false, false, false, false,
/* 07 - 0x1C */	false, false, false, false,
/* 08 - 0x20 */	false, false, false, false,
/* 09 - 0x24 */	false, true, false, false,
/* 10 - 0x28 */	false, false, false, false,
/* 11 - 0x2C */	false, false, false, false,
/* 12 - 0x30 */	false, false, false, false,
/* 13 - 0x34 */	false, true, false, false,
/* 14 - 0x38 */	false, false, false, false,
/* 15 - 0x3C */	false, false, false, false,
/* 16 - 0x40 */	false, false, false, false,
/* 17 - 0x44 */	false, true, false, false,
/* 18 - 0x48 */	false, false, false, false,
/* 19 - 0x4C */	false, false, false, false,
/* 20 - 0x50 */	true, true, true, true,
/* 21 - 0x54 */	true, true, true, true,
/* 22 - 0x58 */	true, true, true, true,
/* 23 - 0x5C */	true, true, true, true,
/* 24 - 0x60 */	false, false, false, false,
/* 25 - 0x64 */	false, true, false, false,
/* 26 - 0x68 */	false, false, false, false,
/* 27 - 0x6C */	false, false, false, false,
/* 28 - 0x70 */	false, false, false, false,
/* 29 - 0x74 */	false, true, false, false,
/* 30 - 0x78 */	false, false, false, false,
/* 31 - 0x7C */	false, false, false, false,
/* 32 - 0x80 */	false, false, false, false,
/* 33 - 0x84 */	false, true, false, false,
/* 34 - 0x88 */	false, false, false, false,
/* 35 - 0x8C */	false, false, false, false,
/* 36 - 0x90 */	false, false, false, false,
/* 37 - 0x94 */	false, true, false, false,
/* 38 - 0x98 */	false, false, false, false,
/* 39 - 0x9C */	false, false, false, false,
/* 40 - 0xA0 */	false, false, false, false,
/* 41 - 0xA4 */	false, true, false, false,
/* 42 - 0xA8 */	false, false, false, false,
/* 43 - 0xAC */	false, false, false, false,
/* 44 - 0xB0 */	false, false, false, false,
/* 45 - 0xB4 */	false, true, false, false,
/* 46 - 0xB8 */	false, false, false, false,
/* 47 - 0xBC */	false, false, false, false,
/* 48 - 0xC0 */	false, false, false, false,
/* 49 - 0xC4 */	false, true, false, false,
/* 50 - 0xC8 */	false, false, false, false,
/* 51 - 0xCC */	false, false, false, false,
/* 52 - 0xD0 */	false, false, false, false,
/* 53 - 0xD4 */	false, true, false, false,
/* 54 - 0xD8 */	false, false, false, false,
/* 55 - 0xDC */	false, false, false, false,
/* 56 - 0xE0 */	false, false, false, false,
/* 57 - 0xE4 */	false, true, false, false,
/* 58 - 0xE8 */	false, false, false, false,
/* 59 - 0xEC */	false, false, false, false,
/* 60 - 0xF0 */	false, false, false, false,
/* 61 - 0xF4 */	false, true, false, false,
/* 62 - 0xF8 */	false, false, false, false,
/* 63 - 0xFC */	false, false, false, false
};

/*
 * Table for determination presence of index node segment
 * state in provided byte. Checking byte is used
 * as index in array.
 */
const bool detect_idxnode_using_seg[U8_MAX + 1] = {
/* 00 - 0x00 */	false, false, false, true,
/* 01 - 0x04 */	false, false, false, false,
/* 02 - 0x08 */	false, false, false, false,
/* 03 - 0x0C */	false, false, false, false,
/* 04 - 0x10 */	false, false, false, true,
/* 05 - 0x14 */	false, false, false, false,
/* 06 - 0x18 */	false, false, false, false,
/* 07 - 0x1C */	false, false, false, false,
/* 08 - 0x20 */	false, false, false, true,
/* 09 - 0x24 */	false, false, false, false,
/* 10 - 0x28 */	false, false, false, false,
/* 11 - 0x2C */	false, false, false, false,
/* 12 - 0x30 */	true, true, true, true,
/* 13 - 0x34 */	true, true, true, true,
/* 14 - 0x38 */	true, true, true, true,
/* 15 - 0x3C */	true, true, true, true,
/* 16 - 0x40 */	false, false, false, true,
/* 17 - 0x44 */	false, false, false, false,
/* 18 - 0x48 */	false, false, false, false,
/* 19 - 0x4C */	false, false, false, false,
/* 20 - 0x50 */	false, false, false, true,
/* 21 - 0x54 */	false, false, false, false,
/* 22 - 0x58 */	false, false, false, false,
/* 23 - 0x5C */	false, false, false, false,
/* 24 - 0x60 */	false, false, false, true,
/* 25 - 0x64 */	false, false, false, false,
/* 26 - 0x68 */	false, false, false, false,
/* 27 - 0x6C */	false, false, false, false,
/* 28 - 0x70 */	false, false, false, true,
/* 29 - 0x74 */	false, false, false, false,
/* 30 - 0x78 */	false, false, false, false,
/* 31 - 0x7C */	false, false, false, false,
/* 32 - 0x80 */	false, false, false, true,
/* 33 - 0x84 */	false, false, false, false,
/* 34 - 0x88 */	false, false, false, false,
/* 35 - 0x8C */	false, false, false, false,
/* 36 - 0x90 */	false, false, false, true,
/* 37 - 0x94 */	false, false, false, false,
/* 38 - 0x98 */	false, false, false, false,
/* 39 - 0x9C */	false, false, false, false,
/* 40 - 0xA0 */	false, false, false, true,
/* 41 - 0xA4 */	false, false, false, false,
/* 42 - 0xA8 */	false, false, false, false,
/* 43 - 0xAC */	false, false, false, false,
/* 44 - 0xB0 */	false, false, false, true,
/* 45 - 0xB4 */	false, false, false, false,
/* 46 - 0xB8 */	false, false, false, false,
/* 47 - 0xBC */	false, false, false, false,
/* 48 - 0xC0 */	false, false, false, true,
/* 49 - 0xC4 */	false, false, false, false,
/* 50 - 0xC8 */	false, false, false, false,
/* 51 - 0xCC */	false, false, false, false,
/* 52 - 0xD0 */	false, false, false, true,
/* 53 - 0xD4 */	false, false, false, false,
/* 54 - 0xD8 */	false, false, false, false,
/* 55 - 0xDC */	false, false, false, false,
/* 56 - 0xE0 */	false, false, false, true,
/* 57 - 0xE4 */	false, false, false, false,
/* 58 - 0xE8 */	false, false, false, false,
/* 59 - 0xEC */	false, false, false, false,
/* 60 - 0xF0 */	false, false, false, true,
/* 61 - 0xF4 */	false, false, false, false,
/* 62 - 0xF8 */	false, false, false, false,
/* 63 - 0xFC */	false, false, false, false
};

/*
 * Table for determination presence of used segment
 * state in provided byte. Checking byte is used
 * as index in array.
 */
const bool detect_used_seg[U8_MAX + 1] = {
/* 00 - 0x00 */	false, false, false, false,
/* 01 - 0x04 */	false, false, false, true,
/* 02 - 0x08 */	false, false, false, false,
/* 03 - 0x0C */	false, false, false, false,
/* 04 - 0x10 */	false, false, false, false,
/* 05 - 0x14 */	false, false, false, true,
/* 06 - 0x18 */	false, false, false, false,
/* 07 - 0x1C */	false, false, false, false,
/* 08 - 0x20 */	false, false, false, false,
/* 09 - 0x24 */	false, false, false, true,
/* 10 - 0x28 */	false, false, false, false,
/* 11 - 0x2C */	false, false, false, false,
/* 12 - 0x30 */	false, false, false, false,
/* 13 - 0x34 */	false, false, false, true,
/* 14 - 0x38 */	false, false, false, false,
/* 15 - 0x3C */	false, false, false, false,
/* 16 - 0x40 */	false, false, false, false,
/* 17 - 0x44 */	false, false, false, true,
/* 18 - 0x48 */	false, false, false, false,
/* 19 - 0x4C */	false, false, false, false,
/* 20 - 0x50 */	false, false, false, false,
/* 21 - 0x54 */	false, false, false, true,
/* 22 - 0x58 */	false, false, false, false,
/* 23 - 0x5C */	false, false, false, false,
/* 24 - 0x60 */	false, false, false, false,
/* 25 - 0x64 */	false, false, false, true,
/* 26 - 0x68 */	false, false, false, false,
/* 27 - 0x6C */	false, false, false, false,
/* 28 - 0x70 */	true, true, true, true,
/* 29 - 0x74 */	true, true, true, true,
/* 30 - 0x78 */	true, true, true, true,
/* 31 - 0x7C */	true, true, true, true,
/* 32 - 0x80 */	false, false, false, false,
/* 33 - 0x84 */	false, false, false, true,
/* 34 - 0x88 */	false, false, false, false,
/* 35 - 0x8C */	false, false, false, false,
/* 36 - 0x90 */	false, false, false, false,
/* 37 - 0x94 */	false, false, false, true,
/* 38 - 0x98 */	false, false, false, false,
/* 39 - 0x9C */	false, false, false, false,
/* 40 - 0xA0 */	false, false, false, false,
/* 41 - 0xA4 */	false, false, false, true,
/* 42 - 0xA8 */	false, false, false, false,
/* 43 - 0xAC */	false, false, false, false,
/* 44 - 0xB0 */	false, false, false, false,
/* 45 - 0xB4 */	false, false, false, true,
/* 46 - 0xB8 */	false, false, false, false,
/* 47 - 0xBC */	false, false, false, false,
/* 48 - 0xC0 */	false, false, false, false,
/* 49 - 0xC4 */	false, false, false, true,
/* 50 - 0xC8 */	false, false, false, false,
/* 51 - 0xCC */	false, false, false, false,
/* 52 - 0xD0 */	false, false, false, false,
/* 53 - 0xD4 */	false, false, false, true,
/* 54 - 0xD8 */	false, false, false, false,
/* 55 - 0xDC */	false, false, false, false,
/* 56 - 0xE0 */	false, false, false, false,
/* 57 - 0xE4 */	false, false, false, true,
/* 58 - 0xE8 */	false, false, false, false,
/* 59 - 0xEC */	false, false, false, false,
/* 60 - 0xF0 */	false, false, false, false,
/* 61 - 0xF4 */	false, false, false, true,
/* 62 - 0xF8 */	false, false, false, false,
/* 63 - 0xFC */	false, false, false, false
};

/*
 * Table for determination presence of pre-dirty segment
 * state in provided byte. Checking byte is used
 * as index in array.
 */
const bool detect_pre_dirty_seg[U8_MAX + 1] = {
/* 00 - 0x00 */	false, false, false, false,
/* 01 - 0x04 */	false, false, true, false,
/* 02 - 0x08 */	false, false, false, false,
/* 03 - 0x0C */	false, false, false, false,
/* 04 - 0x10 */	false, false, false, false,
/* 05 - 0x14 */	false, false, true, false,
/* 06 - 0x18 */	false, false, false, false,
/* 07 - 0x1C */	false, false, false, false,
/* 08 - 0x20 */	false, false, false, false,
/* 09 - 0x24 */	false, false, true, false,
/* 10 - 0x28 */	false, false, false, false,
/* 11 - 0x2C */	false, false, false, false,
/* 12 - 0x30 */	false, false, false, false,
/* 13 - 0x34 */	false, false, true, false,
/* 14 - 0x38 */	false, false, false, false,
/* 15 - 0x3C */	false, false, false, false,
/* 16 - 0x40 */	false, false, false, false,
/* 17 - 0x44 */	false, false, true, false,
/* 18 - 0x48 */	false, false, false, false,
/* 19 - 0x4C */	false, false, false, false,
/* 20 - 0x50 */	false, false, false, false,
/* 21 - 0x54 */	false, false, true, false,
/* 22 - 0x58 */	false, false, false, false,
/* 23 - 0x5C */	false, false, false, false,
/* 24 - 0x60 */	true, true, true, true,
/* 25 - 0x64 */	true, true, true, true,
/* 26 - 0x68 */	true, true, true, true,
/* 27 - 0x6C */	true, true, true, true,
/* 28 - 0x70 */	false, false, false, false,
/* 29 - 0x74 */	false, false, true, false,
/* 30 - 0x78 */	false, false, false, false,
/* 31 - 0x7C */	false, false, false, false,
/* 32 - 0x80 */	false, false, false, false,
/* 33 - 0x84 */	false, false, true, false,
/* 34 - 0x88 */	false, false, false, false,
/* 35 - 0x8C */	false, false, false, false,
/* 36 - 0x90 */	false, false, false, false,
/* 37 - 0x94 */	false, false, true, false,
/* 38 - 0x98 */	false, false, false, false,
/* 39 - 0x9C */	false, false, false, false,
/* 40 - 0xA0 */	false, false, false, false,
/* 41 - 0xA4 */	false, false, true, false,
/* 42 - 0xA8 */	false, false, false, false,
/* 43 - 0xAC */	false, false, false, false,
/* 44 - 0xB0 */	false, false, false, false,
/* 45 - 0xB4 */	false, false, true, false,
/* 46 - 0xB8 */	false, false, false, false,
/* 47 - 0xBC */	false, false, false, false,
/* 48 - 0xC0 */	false, false, false, false,
/* 49 - 0xC4 */	false, false, true, false,
/* 50 - 0xC8 */	false, false, false, false,
/* 51 - 0xCC */	false, false, false, false,
/* 52 - 0xD0 */	false, false, false, false,
/* 53 - 0xD4 */	false, false, true, false,
/* 54 - 0xD8 */	false, false, false, false,
/* 55 - 0xDC */	false, false, false, false,
/* 56 - 0xE0 */	false, false, false, false,
/* 57 - 0xE4 */	false, false, true, false,
/* 58 - 0xE8 */	false, false, false, false,
/* 59 - 0xEC */	false, false, false, false,
/* 60 - 0xF0 */	false, false, false, false,
/* 61 - 0xF4 */	false, false, true, false,
/* 62 - 0xF8 */	false, false, false, false,
/* 63 - 0xFC */	false, false, false, false
};

/*
 * Table for determination presence of dirty segment
 * state in provided byte. Checking byte is used
 * as index in array.
 */
const bool detect_dirty_seg[U8_MAX + 1] = {
/* 00 - 0x00 */	false, false, false, false,
/* 01 - 0x04 */	true, false, false, false,
/* 02 - 0x08 */	false, false, false, false,
/* 03 - 0x0C */	false, false, false, false,
/* 04 - 0x10 */	false, false, false, false,
/* 05 - 0x14 */	true, false, false, false,
/* 06 - 0x18 */	false, false, false, false,
/* 07 - 0x1C */	false, false, false, false,
/* 08 - 0x20 */	false, false, false, false,
/* 09 - 0x24 */	true, false, false, false,
/* 10 - 0x28 */	false, false, false, false,
/* 11 - 0x2C */	false, false, false, false,
/* 12 - 0x30 */	false, false, false, false,
/* 13 - 0x34 */	true, false, false, false,
/* 14 - 0x38 */	false, false, false, false,
/* 15 - 0x3C */	false, false, false, false,
/* 16 - 0x40 */	true, true, true, true,
/* 17 - 0x44 */	true, true, true, true,
/* 18 - 0x48 */	true, true, true, true,
/* 19 - 0x4C */	true, true, true, true,
/* 20 - 0x50 */	false, false, false, false,
/* 21 - 0x54 */	true, false, false, false,
/* 22 - 0x58 */	false, false, false, false,
/* 23 - 0x5C */	false, false, false, false,
/* 24 - 0x60 */	false, false, false, false,
/* 25 - 0x64 */	true, false, false, false,
/* 26 - 0x68 */	false, false, false, false,
/* 27 - 0x6C */	false, false, false, false,
/* 28 - 0x70 */	false, false, false, false,
/* 29 - 0x74 */	true, false, false, false,
/* 30 - 0x78 */	false, false, false, false,
/* 31 - 0x7C */	false, false, false, false,
/* 32 - 0x80 */	false, false, false, false,
/* 33 - 0x84 */	true, false, false, false,
/* 34 - 0x88 */	false, false, false, false,
/* 35 - 0x8C */	false, false, false, false,
/* 36 - 0x90 */	false, false, false, false,
/* 37 - 0x94 */	true, false, false, false,
/* 38 - 0x98 */	false, false, false, false,
/* 39 - 0x9C */	false, false, false, false,
/* 40 - 0xA0 */	false, false, false, false,
/* 41 - 0xA4 */	true, false, false, false,
/* 42 - 0xA8 */	false, false, false, false,
/* 43 - 0xAC */	false, false, false, false,
/* 44 - 0xB0 */	false, false, false, false,
/* 45 - 0xB4 */	true, false, false, false,
/* 46 - 0xB8 */	false, false, false, false,
/* 47 - 0xBC */	false, false, false, false,
/* 48 - 0xC0 */	false, false, false, false,
/* 49 - 0xC4 */	true, false, false, false,
/* 50 - 0xC8 */	false, false, false, false,
/* 51 - 0xCC */	false, false, false, false,
/* 52 - 0xD0 */	false, false, false, false,
/* 53 - 0xD4 */	true, false, false, false,
/* 54 - 0xD8 */	false, false, false, false,
/* 55 - 0xDC */	false, false, false, false,
/* 56 - 0xE0 */	false, false, false, false,
/* 57 - 0xE4 */	true, false, false, false,
/* 58 - 0xE8 */	false, false, false, false,
/* 59 - 0xEC */	false, false, false, false,
/* 60 - 0xF0 */	false, false, false, false,
/* 61 - 0xF4 */	true, false, false, false,
/* 62 - 0xF8 */	false, false, false, false,
/* 63 - 0xFC */	false, false, false, false
};

/*
 * Table for determination presence of bad segment
 * state in provided byte. Checking byte is used
 * as index in array.
 */
const bool detect_bad_seg[U8_MAX + 1] = {
/* 00 - 0x00 */	false, false, false, false,
/* 01 - 0x04 */	false, false, false, false,
/* 02 - 0x08 */	true, false, false, false,
/* 03 - 0x0C */	false, false, false, false,
/* 04 - 0x10 */	false, false, false, false,
/* 05 - 0x14 */	false, false, false, false,
/* 06 - 0x18 */	true, false, false, false,
/* 07 - 0x1C */	false, false, false, false,
/* 08 - 0x20 */	false, false, false, false,
/* 09 - 0x24 */	false, false, false, false,
/* 10 - 0x28 */	true, false, false, false,
/* 11 - 0x2C */	false, false, false, false,
/* 12 - 0x30 */	false, false, false, false,
/* 13 - 0x34 */	false, false, false, false,
/* 14 - 0x38 */	true, false, false, false,
/* 15 - 0x3C */	false, false, false, false,
/* 16 - 0x40 */	false, false, false, false,
/* 17 - 0x44 */	false, false, false, false,
/* 18 - 0x48 */	true, false, false, false,
/* 19 - 0x4C */	false, false, false, false,
/* 20 - 0x50 */	false, false, false, false,
/* 21 - 0x54 */	false, false, false, false,
/* 22 - 0x58 */	true, false, false, false,
/* 23 - 0x5C */	false, false, false, false,
/* 24 - 0x60 */	false, false, false, false,
/* 25 - 0x64 */	false, false, false, false,
/* 26 - 0x68 */	true, false, false, false,
/* 27 - 0x6C */	false, false, false, false,
/* 28 - 0x70 */	false, false, false, false,
/* 29 - 0x74 */	false, false, false, false,
/* 30 - 0x78 */	true, false, false, false,
/* 31 - 0x7C */	false, false, false, false,
/* 32 - 0x80 */	true, true, true, true,
/* 33 - 0x84 */	true, true, true, true,
/* 34 - 0x88 */	true, true, true, true,
/* 35 - 0x8C */	true, true, true, true,
/* 36 - 0x90 */	false, false, false, false,
/* 37 - 0x94 */	false, false, false, false,
/* 38 - 0x98 */	true, false, false, false,
/* 39 - 0x9C */	false, false, false, false,
/* 40 - 0xA0 */	false, false, false, false,
/* 41 - 0xA4 */	false, false, false, false,
/* 42 - 0xA8 */	true, false, false, false,
/* 43 - 0xAC */	false, false, false, false,
/* 44 - 0xB0 */	false, false, false, false,
/* 45 - 0xB4 */	false, false, false, false,
/* 46 - 0xB8 */	true, false, false, false,
/* 47 - 0xBC */	false, false, false, false,
/* 48 - 0xC0 */	false, false, false, false,
/* 49 - 0xC4 */	false, false, false, false,
/* 50 - 0xC8 */	true, false, false, false,
/* 51 - 0xCC */	false, false, false, false,
/* 52 - 0xD0 */	false, false, false, false,
/* 53 - 0xD4 */	false, false, false, false,
/* 54 - 0xD8 */	true, false, false, false,
/* 55 - 0xDC */	false, false, false, false,
/* 56 - 0xE0 */	false, false, false, false,
/* 57 - 0xE4 */	false, false, false, false,
/* 58 - 0xE8 */	true, false, false, false,
/* 59 - 0xEC */	false, false, false, false,
/* 60 - 0xF0 */	false, false, false, false,
/* 61 - 0xF4 */	false, false, false, false,
/* 62 - 0xF8 */	true, false, false, false,
/* 63 - 0xFC */	false, false, false, false
};

/*
 * Table for determination presence of clean or using segment
 * state in provided byte. Checking byte is used
 * as index in array.
 */
const bool detect_clean_using_mask[U8_MAX + 1] = {
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
/* 17 - 0x44 */	false, true, false, false,
/* 18 - 0x48 */	false, false, false, false,
/* 19 - 0x4C */	false, false, false, false,
/* 20 - 0x50 */	true, true, true, true,
/* 21 - 0x54 */	true, true, true, true,
/* 22 - 0x58 */	true, true, true, true,
/* 23 - 0x5C */	true, true, true, true,
/* 24 - 0x60 */	true, true, true, true,
/* 25 - 0x64 */	false, true, false, false,
/* 26 - 0x68 */	false, false, false, false,
/* 27 - 0x6C */	false, false, false, false,
/* 28 - 0x70 */	true, true, true, true,
/* 29 - 0x74 */	false, true, false, false,
/* 30 - 0x78 */	false, false, false, false,
/* 31 - 0x7C */	false, false, false, false,
/* 32 - 0x80 */	true, true, true, true,
/* 33 - 0x84 */	false, true, false, false,
/* 34 - 0x88 */	false, false, false, false,
/* 35 - 0x8C */	false, false, false, false,
/* 36 - 0x90 */	true, true, true, true,
/* 37 - 0x94 */	false, true, false, false,
/* 38 - 0x98 */	false, false, false, false,
/* 39 - 0x9C */	false, false, false, false,
/* 40 - 0xA0 */	true, true, true, true,
/* 41 - 0xA4 */	false, true, false, false,
/* 42 - 0xA8 */	false, false, false, false,
/* 43 - 0xAC */	false, false, false, false,
/* 44 - 0xB0 */	true, true, true, true,
/* 45 - 0xB4 */	false, true, false, false,
/* 46 - 0xB8 */	false, false, false, false,
/* 47 - 0xBC */	false, false, false, false,
/* 48 - 0xC0 */	true, true, true, true,
/* 49 - 0xC4 */	false, true, false, false,
/* 50 - 0xC8 */	false, false, false, false,
/* 51 - 0xCC */	false, false, false, false,
/* 52 - 0xD0 */	true, true, true, true,
/* 53 - 0xD4 */	false, true, false, false,
/* 54 - 0xD8 */	false, false, false, false,
/* 55 - 0xDC */	false, false, false, false,
/* 56 - 0xE0 */	true, true, true, true,
/* 57 - 0xE4 */	false, true, false, false,
/* 58 - 0xE8 */	false, false, false, false,
/* 59 - 0xEC */	false, false, false, false,
/* 60 - 0xF0 */	true, true, true, true,
/* 61 - 0xF4 */	false, true, false, false,
/* 62 - 0xF8 */	false, false, false, false,
/* 63 - 0xFC */	false, false, false, false
};

/*
 * Table for determination presence of used, pre-dirty or
 * dirty segment state in provided byte.
 * Checking byte is used as index in array.
 */
const bool detect_used_dirty_mask[U8_MAX + 1] = {
/* 00 - 0x00 */	false, false, false, false,
/* 01 - 0x04 */	true, false, true, true,
/* 02 - 0x08 */	false, false, false, false,
/* 03 - 0x0C */	false, false, false, false,
/* 04 - 0x10 */	false, false, false, false,
/* 05 - 0x14 */	true, false, true, true,
/* 06 - 0x18 */	false, false, false, false,
/* 07 - 0x1C */	false, false, false, false,
/* 08 - 0x20 */	false, false, false, false,
/* 09 - 0x24 */	true, false, true, true,
/* 10 - 0x28 */	false, false, false, false,
/* 11 - 0x2C */	false, false, false, false,
/* 12 - 0x30 */	false, false, false, false,
/* 13 - 0x34 */	true, false, true, true,
/* 14 - 0x38 */	false, false, false, false,
/* 15 - 0x3C */	false, false, false, false,
/* 16 - 0x40 */	true, true, true, true,
/* 17 - 0x44 */	true, true, true, true,
/* 18 - 0x48 */	true, true, true, true,
/* 19 - 0x4C */	true, true, true, true,
/* 20 - 0x50 */	false, false, false, false,
/* 21 - 0x54 */	true, false, true, true,
/* 22 - 0x58 */	false, false, false, false,
/* 23 - 0x5C */	false, false, false, false,
/* 24 - 0x60 */	true, true, true, true,
/* 25 - 0x64 */	true, true, true, true,
/* 26 - 0x68 */	true, true, true, true,
/* 27 - 0x6C */	true, true, true, true,
/* 28 - 0x70 */	true, true, true, true,
/* 29 - 0x74 */	true, true, true, true,
/* 30 - 0x78 */	true, true, true, true,
/* 31 - 0x7C */	true, true, true, true,
/* 32 - 0x80 */	false, false, false, false,
/* 33 - 0x84 */	true, false, true, true,
/* 34 - 0x88 */	false, false, false, false,
/* 35 - 0x8C */	false, false, false, false,
/* 36 - 0x90 */	false, false, false, false,
/* 37 - 0x94 */	true, false, true, true,
/* 38 - 0x98 */	false, false, false, false,
/* 39 - 0x9C */	false, false, false, false,
/* 40 - 0xA0 */	false, false, false, false,
/* 41 - 0xA4 */	true, false, true, true,
/* 42 - 0xA8 */	false, false, false, false,
/* 43 - 0xAC */	false, false, false, false,
/* 44 - 0xB0 */	false, false, false, false,
/* 45 - 0xB4 */	true, false, true, true,
/* 46 - 0xB8 */	false, false, false, false,
/* 47 - 0xBC */	false, false, false, false,
/* 48 - 0xC0 */	false, false, false, false,
/* 49 - 0xC4 */	true, false, true, true,
/* 50 - 0xC8 */	false, false, false, false,
/* 51 - 0xCC */	false, false, false, false,
/* 52 - 0xD0 */	false, false, false, false,
/* 53 - 0xD4 */	true, false, true, true,
/* 54 - 0xD8 */	false, false, false, false,
/* 55 - 0xDC */	false, false, false, false,
/* 56 - 0xE0 */	false, false, false, false,
/* 57 - 0xE4 */	true, false, true, true,
/* 58 - 0xE8 */	false, false, false, false,
/* 59 - 0xEC */	false, false, false, false,
/* 60 - 0xF0 */	false, false, false, false,
/* 61 - 0xF4 */	true, false, true, true,
/* 62 - 0xF8 */	false, false, false, false,
/* 63 - 0xFC */	false, false, false, false
};
