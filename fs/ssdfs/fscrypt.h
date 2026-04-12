/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/fscrypt.h - fscrypt (FS-level encryption) support declarations.
 *
 * Copyright (c) 2026 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_FSCRYPT_H
#define _SSDFS_FSCRYPT_H

#include <linux/fscrypt.h>

#ifdef CONFIG_SSDFS_FS_ENCRYPTION

extern const struct fscrypt_operations ssdfs_cryptops;

#endif /* CONFIG_SSDFS_FS_ENCRYPTION */

#endif /* _SSDFS_FSCRYPT_H */
