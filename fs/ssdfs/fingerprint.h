/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/fingerprint.h - fingerprint's declarations.
 *
 * Copyright (c) 2023-2026 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_FINGERPRINT_H
#define _SSDFS_FINGERPRINT_H

#include <crypto/hash_info.h>
#include <crypto/ghash.h>
#include <crypto/polyval.h>

/*
 * struct ssdfs_fingerprint - fingerprint object
 * @buf: fingerprint buffer
 * @len: fingerprint length
 * @type: fingerprint type
 */
struct ssdfs_fingerprint {
	u8 buf[SSDFS_FINGERPRINT_LENGTH_MAX];
	u8 len;
	u8 type;
};

/* Fingerprint types */
enum {
	SSDFS_UNKNOWN_FINGERPRINT_TYPE = 0,
	SSDFS_MD5_FINGERPRINT,
	SSDFS_SHA1_FINGERPRINT,
	SSDFS_SHA224_FINGERPRINT,
	SSDFS_SHA256_FINGERPRINT,
	SSDFS_GHASH_FINGERPRINT,
	SSDFS_POLYVAL_FINGERPRINT,
	SSDFS_FINGERPRINT_TYPE_MAX
};

/* Fingerprint algorithm names */
#define SSDFS_MD5_HASH_FUNCTION_NAME		("md5")
#define SSDFS_SHA1_HASH_FUNCTION_NAME		("sha1")
#define SSDFS_SHA224_HASH_FUNCTION_NAME		("sha224")
#define SSDFS_SHA256_HASH_FUNCTION_NAME		("sha256")
#define SSDFS_GHASH_HASH_FUNCTION_NAME		("ghash")
#define SSDFS_POLYVAL_HASH_FUNCTION_NAME	("polyval")

/*
 * struct ssdfs_fingerprint_range - range of fingerprints
 * @start: starting fingerprint
 * @end: ending fingerprint
 */
struct ssdfs_fingerprint_range {
	struct ssdfs_fingerprint start;
	struct ssdfs_fingerprint end;
};

/*
 * Inline methods
 */

/*
 * SSDFS_DEFAULT_FINGERPRINT_TYPE() - default fingerprint type
 */
static inline
int SSDFS_DEFAULT_FINGERPRINT_TYPE(void)
{
#ifdef CONFIG_SSDFS_MD5_FINGEPRINT_TYPE
	return SSDFS_MD5_FINGERPRINT;
#elif defined(CONFIG_SSDFS_SHA1_FINGEPRINT_TYPE)
	return SSDFS_SHA1_FINGERPRINT;
#elif defined(CONFIG_SSDFS_SHA224_FINGEPRINT_TYPE)
	return SSDFS_SHA224_FINGERPRINT;
#elif defined(CONFIG_SSDFS_SHA256_FINGEPRINT_TYPE)
	return SSDFS_SHA256_FINGERPRINT;
#elif defined(CONFIG_SSDFS_GHASH_FINGEPRINT_TYPE)
	return SSDFS_GHASH_FINGERPRINT;
#elif defined(CONFIG_SSDFS_POLYVAL_FINGEPRINT_TYPE)
	return SSDFS_POLYVAL_FINGERPRINT;
#else
	return SSDFS_UNKNOWN_FINGERPRINT_TYPE;
#endif
}

/*
 * SSDFS_FINGERPRINT_TYPE2NAME() - convert fingerprint type into name
 */
static inline
const char *SSDFS_FINGERPRINT_TYPE2NAME(int type)
{
	switch (type) {
	case SSDFS_MD5_FINGERPRINT:
		return SSDFS_MD5_HASH_FUNCTION_NAME;
	case SSDFS_SHA1_FINGERPRINT:
		return SSDFS_SHA1_HASH_FUNCTION_NAME;
	case SSDFS_SHA224_FINGERPRINT:
		return SSDFS_SHA224_HASH_FUNCTION_NAME;
	case SSDFS_SHA256_FINGERPRINT:
		return SSDFS_SHA256_HASH_FUNCTION_NAME;
	case SSDFS_GHASH_FINGERPRINT:
		return SSDFS_GHASH_HASH_FUNCTION_NAME;
	case SSDFS_POLYVAL_FINGERPRINT:
		return SSDFS_POLYVAL_HASH_FUNCTION_NAME;
	default:
		/* SHA1 is used by default */
		break;
	}

	return SSDFS_SHA1_HASH_FUNCTION_NAME;
}

/*
 * SSDFS_DEFAULT_FINGERPRINT_NAME() - default fingerprint algorithm name
 */
static inline
const char *SSDFS_DEFAULT_FINGERPRINT_NAME(void)
{
#ifdef CONFIG_SSDFS_MD5_FINGEPRINT_TYPE
	return SSDFS_FINGERPRINT_TYPE2NAME(SSDFS_MD5_FINGERPRINT);
#elif defined(CONFIG_SSDFS_SHA1_FINGEPRINT_TYPE)
	return SSDFS_FINGERPRINT_TYPE2NAME(SSDFS_SHA1_FINGERPRINT);
#elif defined(CONFIG_SSDFS_SHA224_FINGEPRINT_TYPE)
	return SSDFS_FINGERPRINT_TYPE2NAME(SSDFS_SHA224_FINGERPRINT);
#elif defined(CONFIG_SSDFS_SHA256_FINGEPRINT_TYPE)
	return SSDFS_FINGERPRINT_TYPE2NAME(SSDFS_SHA256_FINGERPRINT);
#elif defined(CONFIG_SSDFS_GHASH_FINGEPRINT_TYPE)
	return SSDFS_FINGERPRINT_TYPE2NAME(SSDFS_GHASH_FINGERPRINT);
#elif defined(CONFIG_SSDFS_POLYVAL_FINGEPRINT_TYPE)
	return SSDFS_FINGERPRINT_TYPE2NAME(SSDFS_POLYVAL_FINGERPRINT);
#else
	return SSDFS_FINGERPRINT_TYPE2NAME(SSDFS_UNKNOWN_FINGERPRINT_TYPE);
#endif
}

/*
 * SSDFS_FINGEPRINT_TYPE2LENGTH() - convert fingerprint type into digest size
 */
static inline
u32 SSDFS_FINGEPRINT_TYPE2LENGTH(int type)
{
	switch (type) {
	case SSDFS_MD5_FINGERPRINT:
		return MD5_DIGEST_SIZE;
	case SSDFS_SHA1_FINGERPRINT:
		return SHA1_DIGEST_SIZE;
	case SSDFS_SHA224_FINGERPRINT:
		return SHA224_DIGEST_SIZE;
	case SSDFS_SHA256_FINGERPRINT:
		return SHA256_DIGEST_SIZE;
	case SSDFS_GHASH_FINGERPRINT:
		return GHASH_DIGEST_SIZE;
	case SSDFS_POLYVAL_FINGERPRINT:
		return POLYVAL_DIGEST_SIZE;
	default:
		SSDFS_WARN("unknown fingerprint type %#x\n",
			   type);
		break;
	}

	return U32_MAX;
}

/*
 * SSDFS_DEFAULT_FINGERPRINT_LENGTH() - default fingerprint digest size
 */
static inline
u32 SSDFS_DEFAULT_FINGERPRINT_LENGTH(void)
{
#ifdef CONFIG_SSDFS_MD5_FINGEPRINT_TYPE
	return SSDFS_FINGEPRINT_TYPE2LENGTH(SSDFS_MD5_FINGERPRINT);
#elif defined(CONFIG_SSDFS_SHA1_FINGEPRINT_TYPE)
	return SSDFS_FINGEPRINT_TYPE2LENGTH(SSDFS_SHA1_FINGERPRINT);
#elif defined(CONFIG_SSDFS_SHA224_FINGEPRINT_TYPE)
	return SSDFS_FINGEPRINT_TYPE2LENGTH(SSDFS_SHA224_FINGERPRINT);
#elif defined(CONFIG_SSDFS_SHA256_FINGEPRINT_TYPE)
	return SSDFS_FINGEPRINT_TYPE2LENGTH(SSDFS_SHA256_FINGERPRINT);
#elif defined(CONFIG_SSDFS_GHASH_FINGEPRINT_TYPE)
	return SSDFS_FINGEPRINT_TYPE2LENGTH(SSDFS_GHASH_FINGERPRINT);
#elif defined(CONFIG_SSDFS_POLYVAL_FINGEPRINT_TYPE)
	return SSDFS_FINGEPRINT_TYPE2LENGTH(SSDFS_POLYVAL_FINGERPRINT);
#else
	return SSDFS_FINGEPRINT_TYPE2LENGTH(SSDFS_UNKNOWN_FINGERPRINT_TYPE);
#endif
}

/*
 * IS_FINGERPRINT_VALID() - check that fingerprint is valid
 */
static inline
bool IS_FINGERPRINT_VALID(struct ssdfs_fingerprint *hash)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hash);
#endif /* CONFIG_SSDFS_DEBUG */

	if (hash->type <= SSDFS_UNKNOWN_FINGERPRINT_TYPE ||
	    hash->type >= SSDFS_FINGERPRINT_TYPE_MAX)
		return false;

	if (hash->len == 0 || hash->len > SSDFS_FINGERPRINT_LENGTH_MAX)
		return false;

	return true;
}

/*
 * IS_FINGERPRINTS_COMPARABLE() - check that fingerprints can be compared
 */
static inline
bool IS_FINGERPRINTS_COMPARABLE(struct ssdfs_fingerprint *hash1,
				struct ssdfs_fingerprint *hash2)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hash1 || !hash2);
	BUG_ON(!IS_FINGERPRINT_VALID(hash1));
	BUG_ON(!IS_FINGERPRINT_VALID(hash2));
#endif /* CONFIG_SSDFS_DEBUG */

	if (hash1->type == hash2->type && hash1->len == hash2->len)
		return true;

	return false;
}

/*
 * ssdfs_compare_fingerprints() - compare fingerprints
 * @hash1: first fingerprint
 * @hash2: second fingerprint
 *
 * This function tries to compare two fingerprints.
 *
 * RETURN:
 * [-1]   - hash1 is lesser that hash2
 * [ 0]   - hash1 is equal to hash2
 * [+1]   - hash1 is bigger that hash2
 */
static inline
int ssdfs_compare_fingerprints(struct ssdfs_fingerprint *hash1,
				struct ssdfs_fingerprint *hash2)
{
	size_t len;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hash1 || !hash2);
	BUG_ON(!IS_FINGERPRINT_VALID(hash1));
	BUG_ON(!IS_FINGERPRINT_VALID(hash2));
	BUG_ON(!IS_FINGERPRINTS_COMPARABLE(hash1, hash2));
#endif /* CONFIG_SSDFS_DEBUG */

	len = min_t(u8, hash1->len, hash2->len);

	return memcmp(hash1->buf, hash2->buf, len);
}

#endif /* _SSDFS_FINGERPRINT_H */
