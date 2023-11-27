// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/xattr.c - extended attributes support implementation.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2023 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include <linux/rwsem.h>
#include <linux/pagevec.h>
#include <linux/sched/signal.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "folio_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "xattr_tree.h"
#include "shared_dictionary.h"
#include "dentries_tree.h"
#include "xattr.h"

const struct xattr_handler *ssdfs_xattr_handlers[] = {
	&ssdfs_xattr_user_handler,
	&ssdfs_xattr_trusted_handler,
#ifdef CONFIG_SSDFS_SECURITY
	&ssdfs_xattr_security_handler,
#endif
	NULL
};

static
int ssdfs_xattrs_tree_get_start_hash(struct ssdfs_xattrs_btree_info *tree,
				     u64 *start_hash)
{
	struct ssdfs_btree_index *index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !start_hash);

	SSDFS_DBG("tree %p, start_hash %p\n",
		  tree, start_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	*start_hash = U64_MAX;

	switch (atomic_read(&tree->state)) {
	case SSDFS_XATTR_BTREE_CREATED:
	case SSDFS_XATTR_BTREE_INITIALIZED:
	case SSDFS_XATTR_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid xattrs tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	down_read(&tree->lock);

	if (!tree->root) {
		err = -ERANGE;
		SSDFS_ERR("root node pointer is NULL\n");
		goto finish_get_start_hash;
	}

	index = &tree->root->indexes[SSDFS_ROOT_NODE_LEFT_LEAF_NODE];
	*start_hash = le64_to_cpu(index->hash);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_hash %llx\n", *start_hash);
#endif /* CONFIG_SSDFS_DEBUG */

finish_get_start_hash:
	up_read(&tree->lock);

	return err;
}

static
int ssdfs_xattrs_tree_get_next_hash(struct ssdfs_xattrs_btree_info *tree,
				    struct ssdfs_btree_search *search,
				    u64 *next_hash)
{
	u64 old_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search || !next_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	old_hash = le64_to_cpu(search->node.found_index.index.hash);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("search %p, next_hash %p, old (node %u, hash %llx)\n",
		  search, next_hash, search->node.id, old_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_XATTR:
	case SSDFS_INLINE_XATTR_ARRAY:
		SSDFS_DBG("inline xattrs array is unsupported\n");
		return -ENOENT;

	case SSDFS_PRIVATE_XATTR_BTREE:
		/* expected tree type */
		break;

	default:
		SSDFS_ERR("invalid tree type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	down_read(&tree->lock);
	err = ssdfs_btree_get_next_hash(tree->generic_tree, search, next_hash);
	up_read(&tree->lock);

	return err;
}

static
int ssdfs_xattrs_tree_node_hash_range(struct ssdfs_xattrs_btree_info *tree,
					struct ssdfs_btree_search *search,
					u64 *start_hash, u64 *end_hash,
					u16 *items_count)
{
	struct ssdfs_xattr_entry *cur_xattr;
	u16 inline_count;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !start_hash || !end_hash || !items_count);

	SSDFS_DBG("search %p, start_hash %p, "
		  "end_hash %p, items_count %p\n",
		  tree, start_hash, end_hash, items_count);
#endif /* CONFIG_SSDFS_DEBUG */

	*start_hash = *end_hash = U64_MAX;
	*items_count = 0;

	switch (atomic_read(&tree->state)) {
	case SSDFS_XATTR_BTREE_CREATED:
	case SSDFS_XATTR_BTREE_INITIALIZED:
	case SSDFS_XATTR_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid xattrs tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_XATTR:
	case SSDFS_INLINE_XATTR_ARRAY:
		down_read(&tree->lock);

		if (!tree->inline_xattrs) {
			err = -ERANGE;
			SSDFS_ERR("inline tree's pointer is empty\n");
			goto finish_process_inline_tree;
		}

		inline_count = tree->inline_count;

		if (inline_count >= U16_MAX) {
			err = -ERANGE;
			SSDFS_ERR("unexpected xattrs count %u\n",
				  inline_count);
			goto finish_process_inline_tree;
		}

		*items_count = inline_count;

		if (*items_count == 0)
			goto finish_process_inline_tree;

		cur_xattr = &tree->inline_xattrs[0];
		*start_hash = le64_to_cpu(cur_xattr->name_hash);

		if (inline_count > tree->inline_capacity) {
			err = -ERANGE;
			SSDFS_ERR("xattrs_count %u > max_value %u\n",
				  inline_count,
				  tree->inline_capacity);
			goto finish_process_inline_tree;
		}

		cur_xattr = &tree->inline_xattrs[inline_count - 1];
		*end_hash = le64_to_cpu(cur_xattr->name_hash);

finish_process_inline_tree:
		up_read(&tree->lock);
		break;

	case SSDFS_PRIVATE_XATTR_BTREE:
		err = ssdfs_btree_node_get_hash_range(search,
						      start_hash,
						      end_hash,
						      items_count);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get hash range: err %d\n",
				  err);
			goto finish_extract_hash_range;
		}
		break;

	default:
		SSDFS_ERR("invalid tree type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

finish_extract_hash_range:
	return err;
}

static
int ssdfs_xattrs_tree_check_search_result(struct ssdfs_btree_search *search)
{
	size_t xattr_size = sizeof(struct ssdfs_xattr_entry);
	u16 items_count;
	size_t buf_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		/* expected state */
		break;

	default:
		SSDFS_ERR("unexpected result's state %#x\n",
			  search->result.state);
		return  -ERANGE;
	}

	switch (search->result.buf_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		if (!search->result.buf) {
			SSDFS_ERR("buffer pointer is NULL\n");
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("unexpected buffer's state\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.items_in_buffer >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	items_count = (u16)search->result.items_in_buffer;

	if (items_count == 0) {
		SSDFS_ERR("items_in_buffer %u\n",
			  items_count);
		return -ENOENT;
	} else if (items_count != search->result.count) {
		SSDFS_ERR("items_count %u != search->result.count %u\n",
			  items_count, search->result.count);
		return -ERANGE;
	}

	buf_size = xattr_size * items_count;

	if (buf_size != search->result.buf_size) {
		SSDFS_ERR("buf_size %zu != search->result.buf_size %zu\n",
			  buf_size,
			  search->result.buf_size);
		return -ERANGE;
	}

	return 0;
}

static
bool is_invalid_xattr(struct ssdfs_xattr_entry *xattr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!xattr);
#endif /* CONFIG_SSDFS_DEBUG */

	if (le64_to_cpu(xattr->name_hash) >= U64_MAX) {
		SSDFS_ERR("invalid hash_code\n");
		return true;
	}

	if (xattr->name_len > SSDFS_MAX_NAME_LEN) {
		SSDFS_ERR("invalid name_len %u\n",
			  xattr->name_len);
		return true;
	}

	if (xattr->name_type <= SSDFS_XATTR_NAME_UNKNOWN_TYPE ||
	    xattr->name_type >= SSDFS_XATTR_NAME_TYPE_MAX) {
		SSDFS_ERR("invalid name_type %#x\n",
			  xattr->name_type);
		return true;
	}

	if (xattr->name_flags & ~SSDFS_XATTR_NAME_FLAGS_MASK) {
		SSDFS_ERR("invalid set of flags %#x\n",
			  xattr->name_flags);
		return true;
	}

	if (xattr->blob_type <= SSDFS_XATTR_BLOB_UNKNOWN_TYPE ||
	    xattr->blob_type >= SSDFS_XATTR_BLOB_TYPE_MAX) {
		SSDFS_ERR("invalid blob_type %#x\n",
			  xattr->blob_type);
		return true;
	}

	if (xattr->blob_flags & ~SSDFS_XATTR_BLOB_FLAGS_MASK) {
		SSDFS_ERR("invalid set of flags %#x\n",
			  xattr->blob_flags);
		return true;
	}

	return false;
}

static
ssize_t ssdfs_copy_name2buffer(struct ssdfs_shared_dict_btree_info *dict,
				struct ssdfs_xattr_entry *xattr,
				struct ssdfs_btree_search *search,
				ssize_t offset,
				char *buffer, size_t size)
{
	u64 hash;
	size_t prefix_len, name_len;
	ssize_t copied = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!xattr || !buffer);

	SSDFS_DBG("xattr %p, offset %zd, "
		  "buffer %p, size %zu\n",
		  xattr, offset, buffer, size);
#endif /* CONFIG_SSDFS_DEBUG */

	hash = le64_to_cpu(xattr->name_hash);

	if ((copied + xattr->name_len) >= size) {
		SSDFS_ERR("copied %zd, name_len %u, size %zu\n",
			  copied, xattr->name_len, size);
		return -ERANGE;
	}

	if (xattr->name_flags & SSDFS_XATTR_HAS_EXTERNAL_STRING) {
		err = ssdfs_shared_dict_get_name(dict, hash,
						 &search->name);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the name: "
				  "hash %llx, err %d\n",
				  hash, err);
			return err;
		}

		switch (xattr->name_type) {
		case SSDFS_XATTR_REGULAR_NAME:
			/* do nothing here */
			break;

		case SSDFS_XATTR_USER_REGULAR_NAME:
			prefix_len =
				strlen(SSDFS_NS_PREFIX[SSDFS_USER_NS_INDEX]);
			err = ssdfs_memcpy(buffer, offset, size,
				     SSDFS_NS_PREFIX[SSDFS_USER_NS_INDEX],
				     0, prefix_len,
				     prefix_len);
			BUG_ON(unlikely(err != 0));
			offset += prefix_len;
			copied += prefix_len;
			break;

		case SSDFS_XATTR_TRUSTED_REGULAR_NAME:
			prefix_len =
				strlen(SSDFS_NS_PREFIX[SSDFS_TRUSTED_NS_INDEX]);
			err = ssdfs_memcpy(buffer, offset, size,
				     SSDFS_NS_PREFIX[SSDFS_TRUSTED_NS_INDEX],
				     0, prefix_len,
				     prefix_len);
			BUG_ON(unlikely(err != 0));
			offset += prefix_len;
			copied += prefix_len;
			break;

		case SSDFS_XATTR_SYSTEM_REGULAR_NAME:
			prefix_len =
				strlen(SSDFS_NS_PREFIX[SSDFS_SYSTEM_NS_INDEX]);
			err = ssdfs_memcpy(buffer, offset, size,
				     SSDFS_NS_PREFIX[SSDFS_SYSTEM_NS_INDEX],
				     0, prefix_len,
				     prefix_len);
			BUG_ON(unlikely(err != 0));
			offset += prefix_len;
			copied += prefix_len;
			break;

		case SSDFS_XATTR_SECURITY_REGULAR_NAME:
			prefix_len =
			    strlen(SSDFS_NS_PREFIX[SSDFS_SECURITY_NS_INDEX]);
			err = ssdfs_memcpy(buffer, offset, size,
				     SSDFS_NS_PREFIX[SSDFS_SECURITY_NS_INDEX],
				     0, prefix_len,
				     prefix_len);
			BUG_ON(unlikely(err != 0));
			offset += prefix_len;
			copied += prefix_len;
			break;

		default:
			SSDFS_ERR("unexpected name type %#x\n",
				  xattr->name_type);
			return -EIO;
		}

		err = ssdfs_memcpy(buffer, offset, size,
				   search->name.str, 0, SSDFS_MAX_NAME_LEN,
				   search->name.len);
		BUG_ON(unlikely(err != 0));

		offset += search->name.len;
		copied += search->name.len;

		if (offset >= size) {
			SSDFS_ERR("invalid offset: "
				  "offset %zd, size %zu\n",
				  offset, size);
			return -ERANGE;
		}

		memset(buffer + offset, 0, size - offset);
	} else {
		switch (xattr->name_type) {
		case SSDFS_XATTR_INLINE_NAME:
			/* do nothing here */
			break;

		case SSDFS_XATTR_USER_INLINE_NAME:
			prefix_len =
				strlen(SSDFS_NS_PREFIX[SSDFS_USER_NS_INDEX]);
			err = ssdfs_memcpy(buffer, offset, size,
				     SSDFS_NS_PREFIX[SSDFS_USER_NS_INDEX],
				     0, prefix_len,
				     prefix_len);
			BUG_ON(unlikely(err != 0));
			offset += prefix_len;
			copied += prefix_len;
			break;

		case SSDFS_XATTR_TRUSTED_INLINE_NAME:
			prefix_len =
				strlen(SSDFS_NS_PREFIX[SSDFS_TRUSTED_NS_INDEX]);
			err = ssdfs_memcpy(buffer, offset, size,
				     SSDFS_NS_PREFIX[SSDFS_TRUSTED_NS_INDEX],
				     0, prefix_len,
				     prefix_len);
			BUG_ON(unlikely(err != 0));
			offset += prefix_len;
			copied += prefix_len;
			break;

		case SSDFS_XATTR_SYSTEM_INLINE_NAME:
			prefix_len =
				strlen(SSDFS_NS_PREFIX[SSDFS_SYSTEM_NS_INDEX]);
			err = ssdfs_memcpy(buffer, offset, size,
				     SSDFS_NS_PREFIX[SSDFS_SYSTEM_NS_INDEX],
				     0, prefix_len,
				     prefix_len);
			BUG_ON(unlikely(err != 0));
			offset += prefix_len;
			copied += prefix_len;
			break;

		case SSDFS_XATTR_SECURITY_INLINE_NAME:
			prefix_len =
			    strlen(SSDFS_NS_PREFIX[SSDFS_SECURITY_NS_INDEX]);
			err = ssdfs_memcpy(buffer, offset, size,
				     SSDFS_NS_PREFIX[SSDFS_SECURITY_NS_INDEX],
				     0, prefix_len,
				     prefix_len);
			offset += prefix_len;
			copied += prefix_len;
			break;

		default:
			SSDFS_ERR("unexpected name type %#x\n",
				  xattr->name_type);
			return -EIO;
		}

		name_len = xattr->name_len;

		err = ssdfs_memcpy(buffer, offset, size,
				   xattr->inline_string,
				   0, SSDFS_XATTR_INLINE_NAME_MAX_LEN,
				   name_len);
		BUG_ON(unlikely(err != 0));

		offset += name_len;
		copied += name_len;

		if (offset >= size) {
			SSDFS_ERR("invalid offset: "
				  "offset %zd, size %zu\n",
				  offset, size);
			return -ERANGE;
		}

		memset(buffer + offset, 0, size - offset);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("XATTR NAME DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     buffer, size);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return copied;
}

static inline
size_t ssdfs_calculate_name_length(struct ssdfs_xattr_entry *xattr)
{
	size_t prefix_len = 0;
	size_t name_len = 0;

	switch (xattr->name_type) {
	case SSDFS_XATTR_INLINE_NAME:
	case SSDFS_XATTR_REGULAR_NAME:
		/* do nothing here */
		break;

	case SSDFS_XATTR_USER_INLINE_NAME:
	case SSDFS_XATTR_USER_REGULAR_NAME:
		prefix_len = strlen(SSDFS_NS_PREFIX[SSDFS_USER_NS_INDEX]);
		break;

	case SSDFS_XATTR_TRUSTED_INLINE_NAME:
	case SSDFS_XATTR_TRUSTED_REGULAR_NAME:
		prefix_len = strlen(SSDFS_NS_PREFIX[SSDFS_TRUSTED_NS_INDEX]);
		break;

	case SSDFS_XATTR_SYSTEM_INLINE_NAME:
	case SSDFS_XATTR_SYSTEM_REGULAR_NAME:
		prefix_len = strlen(SSDFS_NS_PREFIX[SSDFS_SYSTEM_NS_INDEX]);
		break;

	case SSDFS_XATTR_SECURITY_INLINE_NAME:
	case SSDFS_XATTR_SECURITY_REGULAR_NAME:
		prefix_len = strlen(SSDFS_NS_PREFIX[SSDFS_SECURITY_NS_INDEX]);
		break;

	default:
		/* do nothing */
		break;
	}

	name_len = prefix_len + xattr->name_len;

	return name_len;
}

inline
ssize_t ssdfs_listxattr_inline_tree(struct inode *inode,
				    struct ssdfs_btree_search *search,
				    char *buffer, size_t size)
{
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_shared_dict_btree_info *dict;
	struct ssdfs_xattr_entry *xattr;
	size_t xattr_size = sizeof(struct ssdfs_xattr_entry);
	u16 items_count;
	ssize_t res, copied = 0;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, buffer %p, size %zu\n",
		  inode->i_ino, buffer, size);
#endif /* CONFIG_SSDFS_DEBUG */

	dict = fsi->shdictree;
	if (!dict) {
		SSDFS_ERR("shared dictionary is absent\n");
		return -ERANGE;
	}

	down_read(&ii->lock);

	if (!ii->xattrs_tree) {
		err = -ERANGE;
		SSDFS_ERR("unexpected xattrs tree absence\n");
		goto finish_tree_processing;
	}

	err = ssdfs_xattrs_tree_extract_range(ii->xattrs_tree,
					      0,
					      SSDFS_DEFAULT_INLINE_XATTR_COUNT,
					      search);
	if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to extract inline xattr: "
			  "ino %lu\n",
			  inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_tree_processing;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to extract inline xattr: "
			  "ino %lu, err %d\n",
			  inode->i_ino, err);
		goto finish_tree_processing;
	}

finish_tree_processing:
	up_read(&ii->lock);

	if (err == -ENOENT) {
		err = 0;
		goto clean_up;
	} else if (unlikely(err))
		goto clean_up;

	err = ssdfs_xattrs_tree_check_search_result(search);
	if (unlikely(err)) {
		SSDFS_ERR("corrupted search result: "
			  "err %d\n", err);
		goto clean_up;
	}

	items_count = search->result.count;

	for (i = 0; i < items_count; i++) {
		xattr = (struct ssdfs_xattr_entry *)(search->result.buf +
							(i * xattr_size));

		if (is_invalid_xattr(xattr)) {
			err = -EIO;
			SSDFS_ERR("found corrupted xattr\n");
			goto clean_up;
		}

		if (buffer) {
			res = ssdfs_copy_name2buffer(dict, xattr,
						     search, copied,
						     buffer, size);
			if (res < 0) {
				err = res;
				SSDFS_ERR("failed to copy name: "
					  "err %d\n", err);
				goto clean_up;
			} else
				copied += res + 1;
		} else
			copied += ssdfs_calculate_name_length(xattr) + 1;
	}

clean_up:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("copied %zd\n", copied);
#endif /* CONFIG_SSDFS_DEBUG */

	return err < 0 ? err : copied;
}

inline
ssize_t ssdfs_listxattr_generic_tree(struct inode *inode,
				     struct ssdfs_btree_search *search,
				     char *buffer, size_t size)
{
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_shared_dict_btree_info *dict;
	struct ssdfs_xattr_entry *xattr;
	size_t xattr_size = sizeof(struct ssdfs_xattr_entry);
	u64 start_hash, end_hash;
	u16 items_count;
	ssize_t res, copied = 0;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, buffer %p, size %zu\n",
		  inode->i_ino, buffer, size);
#endif /* CONFIG_SSDFS_DEBUG */

	dict = fsi->shdictree;
	if (!dict) {
		SSDFS_ERR("shared dictionary is absent\n");
		return -ERANGE;
	}

	down_read(&ii->lock);

	if (!ii->xattrs_tree) {
		err = -ERANGE;
		SSDFS_ERR("unexpected xattrs tree absence\n");
		goto finish_get_start_hash;
	}

	err = ssdfs_xattrs_tree_get_start_hash(ii->xattrs_tree,
						&start_hash);
	if (err == -ENOENT)
		goto finish_get_start_hash;
	else if (unlikely(err)) {
		SSDFS_ERR("fail to get start root hash: err %d\n", err);
		goto finish_get_start_hash;
	} else if (start_hash >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid hash value\n");
		goto finish_get_start_hash;
	}

finish_get_start_hash:
	up_read(&ii->lock);

	if (err == -ENOENT) {
		err = 0;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to extract start hash: "
			  "ino %lu\n",
			  inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */
		goto clean_up;
	} else if (unlikely(err))
		goto clean_up;

	do {
		ssdfs_btree_search_init(search);

		/* allow ssdfs_listxattr_generic_tree() to be interrupted */
		if (fatal_signal_pending(current)) {
			err = -ERESTARTSYS;
			goto clean_up;
		}
		cond_resched();

		down_read(&ii->lock);

		err = ssdfs_xattrs_tree_find_leaf_node(ii->xattrs_tree,
							start_hash,
							search);
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find a leaf node: "
				  "hash %llx, err %d\n",
				  start_hash, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_tree_processing;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find a leaf node: "
				  "hash %llx, err %d\n",
				  start_hash, err);
			goto finish_tree_processing;
		}

		err = ssdfs_xattrs_tree_node_hash_range(ii->xattrs_tree,
							search,
							&start_hash,
							&end_hash,
							&items_count);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get node's hash range: "
				  "err %d\n", err);
			goto finish_tree_processing;
		}

		if (items_count == 0) {
			err = -ENOENT;
			SSDFS_DBG("empty leaf node\n");
			goto finish_tree_processing;
		}

		if (start_hash > end_hash) {
			err = -ENOENT;
			goto finish_tree_processing;
		}

		err = ssdfs_xattrs_tree_extract_range(ii->xattrs_tree,
							0, items_count,
							search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the range: "
				  "items_count %u, err %d\n",
				  items_count, err);
			goto finish_tree_processing;
		}

finish_tree_processing:
		up_read(&ii->lock);

		if (err == -ENOENT) {
			err = 0;
			goto clean_up;
		} else if (unlikely(err))
			goto clean_up;

		err = ssdfs_xattrs_tree_check_search_result(search);
		if (unlikely(err)) {
			SSDFS_ERR("corrupted search result: "
				  "err %d\n", err);
			goto clean_up;
		}

		items_count = search->result.count;

		for (i = 0; i < items_count; i++) {
			u64 hash;

			xattr =
			    (struct ssdfs_xattr_entry *)(search->result.buf +
							(i * xattr_size));
			hash = le64_to_cpu(xattr->name_hash);

			if (is_invalid_xattr(xattr)) {
				err = -EIO;
				SSDFS_ERR("found corrupted xattr\n");
				goto clean_up;
			}

			if (buffer) {
				res = ssdfs_copy_name2buffer(dict, xattr,
							     search, copied,
							     buffer, size);
				if (res < 0) {
					err = res;
					SSDFS_ERR("failed to copy name: "
						  "err %d\n", err);
					goto clean_up;
				} else
					copied += res + 1;
			} else {
				copied +=
					ssdfs_calculate_name_length(xattr) + 1;
			}

			start_hash = hash;
		}

		if (start_hash != end_hash) {
			err = -ERANGE;
			SSDFS_ERR("cur_hash %llx != end_hash %llx\n",
				  start_hash, end_hash);
			goto clean_up;
		}

		start_hash = end_hash + 1;

		down_read(&ii->lock);
		err = ssdfs_xattrs_tree_get_next_hash(ii->xattrs_tree,
						      search,
						      &start_hash);
		up_read(&ii->lock);

		ssdfs_btree_search_forget_parent_node(search);
		ssdfs_btree_search_forget_child_node(search);

		if (err == -ENOENT) {
			err = 0;
			SSDFS_DBG("no more xattrs in the tree\n");
			goto clean_up;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get next hash: err %d\n",
				  err);
			goto clean_up;
		}
	} while (start_hash < U64_MAX);

clean_up:
	return err < 0 ? err : copied;
}

/*
 * Copy a list of attribute names into the buffer
 * provided, or compute the buffer size required.
 * Buffer is NULL to compute the size of the buffer required.
 *
 * Returns a negative error number on failure, or the number of bytes
 * used / required on success.
 */
ssize_t ssdfs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct inode *inode = d_inode(dentry);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	struct ssdfs_btree_search *search;
	int private_flags;
	ssize_t copied = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, buffer %p, size %zu\n",
		  inode->i_ino, buffer, size);
#endif /* CONFIG_SSDFS_DEBUG */

	private_flags = atomic_read(&ii->private_flags);

	switch (private_flags) {
	case SSDFS_INODE_HAS_INLINE_XATTR:
	case SSDFS_INODE_HAS_XATTR_BTREE:
		/* xattrs tree exists */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("xattrs tree is absent: "
			  "ino %lu\n",
			  inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	if (!ii->xattrs_tree) {
		err = -ERANGE;
		SSDFS_ERR("unexpected xattrs tree absence\n");
		goto clean_up;
	}

	switch (atomic_read(&ii->xattrs_tree->type)) {
	case SSDFS_INLINE_XATTR:
	case SSDFS_INLINE_XATTR_ARRAY:
		ssdfs_btree_search_init(search);
		copied = ssdfs_listxattr_inline_tree(inode, search,
						     buffer, size);
		if (unlikely(copied < 0)) {
			err = copied;
			SSDFS_ERR("fail to extract the inline range: "
				  "err %d\n", err);
			goto clean_up;
		}
		break;

	case SSDFS_PRIVATE_XATTR_BTREE:
		copied = ssdfs_listxattr_generic_tree(inode, search,
						      buffer, size);
		if (unlikely(copied < 0)) {
			err = copied;
			SSDFS_ERR("fail to extract the range: "
				  "err %d\n", err);
			goto clean_up;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid xattrs tree type %#x\n",
			  atomic_read(&ii->xattrs_tree->type));
		goto clean_up;
	}

clean_up:
	ssdfs_btree_search_free(search);

	return err < 0 ? err : copied;
}

/*
 * Read external blob
 */
static
int ssdfs_xattr_read_external_blob(struct ssdfs_fs_info *fsi,
				   struct inode *inode,
				   struct ssdfs_xattr_entry *xattr,
				   void *value, size_t size)
{
	struct ssdfs_segment_request *req;
	struct ssdfs_peb_container *pebc;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_offset_position pos;
	struct ssdfs_segment_info *si;
	u16 blob_size;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	u32 batch_size;
	u64 logical_offset;
	u32 data_bytes;
	u32 copied_bytes = 0;
	struct completion *end;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !inode || !xattr || !value);
#endif /* CONFIG_SSDFS_DEBUG */

	seg_id = le64_to_cpu(xattr->blob.descriptor.extent.seg_id);
	logical_blk = le32_to_cpu(xattr->blob.descriptor.extent.logical_blk);
	len = le32_to_cpu(xattr->blob.descriptor.extent.len);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, logical_blk %u, len %u\n",
		  seg_id, logical_blk, len);

	BUG_ON(seg_id == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	si = ssdfs_grab_segment(fsi, SSDFS_USER_DATA_SEG_TYPE,
				seg_id, U64_MAX);
	if (unlikely(IS_ERR_OR_NULL(si))) {
		err = !si ? -ENOMEM : PTR_ERR(si);
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
		} else {
			SSDFS_ERR("fail to grab segment object: "
				  "seg %llu, err %d\n",
				  seg_id, err);
		}
		goto fail_get_segment;
	}

	blob_size = le16_to_cpu(xattr->blob_len);

	if (blob_size > size) {
		err = -EINVAL;
		SSDFS_ERR("invalid request: blob_size %u > size %zu\n",
			  blob_size, size);
		goto fail_get_segment;
	}

	batch_size = blob_size >> fsi->log_pagesize;

	if (batch_size == 0)
		batch_size = 1;

	if (batch_size > PAGEVEC_SIZE) {
		err = -ERANGE;
		SSDFS_WARN("invalid memory pages count: "
			   "blob_size %u, batch_size %u\n",
			   blob_size, batch_size);
		goto finish_prepare_request;
	}

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		goto finish_prepare_request;
	}

	ssdfs_request_init(req, fsi->pagesize);
	ssdfs_get_request(req);

	logical_offset = 0;
	data_bytes = blob_size;
	ssdfs_request_prepare_logical_extent(inode->i_ino,
					     (u64)logical_offset,
					     (u32)data_bytes,
					     0, 0, req);

	for (i = 0; i < batch_size; i++) {
		err = ssdfs_request_add_allocated_folio_locked(req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add folio into request: "
				  "err %d\n",
				  err);
			goto fail_read_blob;
		}
	}

	ssdfs_request_define_segment(seg_id, req);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(logical_blk >= U16_MAX);
	BUG_ON(len >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	ssdfs_request_define_volume_extent((u16)logical_blk, (u16)len, req);

	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    SSDFS_READ_PAGES_READAHEAD,
					    SSDFS_REQ_SYNC,
					    req);

	table = si->blk2off_table;

	err = ssdfs_blk2off_table_get_offset_position(table, logical_blk, &pos);
	if (err == -EAGAIN) {
		end = &table->full_init_end;

		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("blk2off init failed: "
				  "seg_id %llu, logical_blk %u, "
				  "len %u, err %d\n",
				  seg_id, logical_blk, len, err);
			goto fail_read_blob;
		}

		err = ssdfs_blk2off_table_get_offset_position(table,
							      logical_blk,
							      &pos);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to convert: "
			  "seg_id %llu, logical_blk %u, len %u, err %d\n",
			  seg_id, logical_blk, len, err);
		goto fail_read_blob;
	}

	pebc = &si->peb_array[pos.peb_index];

	err = ssdfs_peb_readahead_pages(pebc, req, &end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("PEB init failed: "
				  "err %d\n", err);
			goto fail_read_blob;
		}

		err = ssdfs_peb_readahead_pages(pebc, req, &end);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to read page: err %d\n",
			  err);
		goto fail_read_blob;
	}

	for (i = 0; i < req->result.processed_blks; i++)
		ssdfs_peb_mark_request_block_uptodate(pebc, req, i);

#ifdef CONFIG_SSDFS_DEBUG
	for (i = 0; i < folio_batch_count(&req->result.batch); i++) {
		void *kaddr;
		struct folio *folio = req->result.batch.folios[i];
		u32 processed_bytes = 0;
		u32 page_index = 0;

		do {
			kaddr = kmap_local_folio(folio, processed_bytes);
			SSDFS_DBG("PAGE DUMP: folio_index %d, "
				  "page_index %u\n",
				  i, page_index);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr,
					     PAGE_SIZE);
			SSDFS_DBG("\n");
			kunmap_local(kaddr);

			processed_bytes += PAGE_SIZE;
			page_index++;
		} while (processed_bytes < folio_size(folio));

		WARN_ON(!folio_test_locked(folio));
	}
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < folio_batch_count(&req->result.batch); i++) {
		u32 cur_len;

		if (copied_bytes >= blob_size)
			break;

		cur_len = min_t(u32, (u32)fsi->pagesize,
				blob_size - copied_bytes);

		err = __ssdfs_memcpy_from_folio(value,
						copied_bytes, size,
						req->result.batch.folios[i],
						0, fsi->pagesize,
						cur_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: "
				  "copied_bytes %u, cur_len %u\n",
				  copied_bytes, cur_len);
			goto fail_read_blob;
		}

		copied_bytes += cur_len;
	}

	ssdfs_request_unlock_and_remove_folios(req);

	ssdfs_put_request(req);
	ssdfs_request_free(req);

	ssdfs_segment_put_object(si);

	return 0;

fail_read_blob:
	ssdfs_request_unlock_and_remove_folios(req);
	ssdfs_put_request(req);
	ssdfs_request_free(req);

finish_prepare_request:
	ssdfs_segment_put_object(si);

fail_get_segment:
	return err;
}

/*
 * Copy an extended attribute into the buffer
 * provided, or compute the buffer size required.
 * Buffer is NULL to compute the size of the buffer required.
 *
 * Returns a negative error number on failure, or the number of bytes
 * used / required on success.
 */
ssize_t __ssdfs_getxattr(struct inode *inode, int name_index, const char *name,
			 void *value, size_t size)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	struct ssdfs_btree_search *search;
	struct ssdfs_xattr_entry *xattr;
	size_t name_len;
	u16 blob_len;
	u8 blob_type;
	u8 blob_flags;
	int private_flags;
	ssize_t err = 0;

	if (name == NULL) {
		SSDFS_ERR("name pointer is NULL\n");
		return -EINVAL;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("name_index %d, name %s, value %p, size %zu\n",
		  name_index, name, value, size);
#endif /* CONFIG_SSDFS_DEBUG */

	name_len = strlen(name);
	if (name_len > SSDFS_MAX_NAME_LEN)
		return -ERANGE;

	private_flags = atomic_read(&ii->private_flags);

	switch (private_flags) {
	case SSDFS_INODE_HAS_INLINE_XATTR:
	case SSDFS_INODE_HAS_XATTR_BTREE:
		down_read(&ii->lock);

		if (!ii->xattrs_tree) {
			err = -ERANGE;
			SSDFS_WARN("xattrs tree is absent!!!\n");
			goto finish_search_xattr;
		}

		search = ssdfs_btree_search_alloc();
		if (!search) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate btree search object\n");
			goto finish_search_xattr;
		}

		ssdfs_btree_search_init(search);

		err = ssdfs_xattrs_tree_find(ii->xattrs_tree,
					     name, name_len,
					     search);

		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("inode %lu hasn't xattr %s\n",
				  (unsigned long)inode->i_ino,
				  name);
#endif /* CONFIG_SSDFS_DEBUG */
			goto xattr_is_not_available;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find the xattr: "
				  "inode %lu, name %s\n",
				  (unsigned long)inode->i_ino,
				  name);
			goto xattr_is_not_available;
		}

		if (search->result.state != SSDFS_BTREE_SEARCH_VALID_ITEM) {
			err = -ERANGE;
			SSDFS_ERR("invalid result's state %#x\n",
				  search->result.state);
			goto xattr_is_not_available;
		}

		switch (search->result.buf_state) {
		case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
		case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
			/* expected state */
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid buffer state %#x\n",
				  search->result.buf_state);
			goto xattr_is_not_available;
		}

		if (!search->result.buf) {
			err = -ERANGE;
			SSDFS_ERR("buffer is absent\n");
			goto xattr_is_not_available;
		}

		if (search->result.buf_size == 0) {
			err = -ERANGE;
			SSDFS_ERR("result.buf_size %zu\n",
				  search->result.buf_size);
			goto xattr_is_not_available;
		}

		xattr = (struct ssdfs_xattr_entry *)(search->result.buf);

		blob_len = le16_to_cpu(xattr->blob_len);
		blob_type = xattr->blob_type;
		blob_flags = xattr->blob_flags;

		switch (blob_type) {
		case SSDFS_XATTR_INLINE_BLOB:
			if (blob_len > SSDFS_XATTR_INLINE_BLOB_MAX_LEN) {
				err = -ERANGE;
				SSDFS_ERR("invalid blob_len %u\n",
					  blob_len);
				goto xattr_is_not_available;
			}
			break;

		case SSDFS_XATTR_REGULAR_BLOB:
			if (!(blob_flags & SSDFS_XATTR_HAS_EXTERNAL_BLOB)) {
				err = -ERANGE;
				SSDFS_ERR("invalid set of flags %#x\n",
					  blob_flags);
				goto xattr_is_not_available;
			}

			if (blob_len > SSDFS_XATTR_EXTERNAL_BLOB_MAX_LEN) {
				err = -ERANGE;
				SSDFS_ERR("invalid blob_len %u\n",
					  blob_len);
				goto xattr_is_not_available;
			}
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("unexpected blob type %#x\n",
				  blob_type);
			goto xattr_is_not_available;
		}

		if (value) {
			switch (blob_type) {
			case SSDFS_XATTR_INLINE_BLOB:
				/* return value of attribute */
				err = ssdfs_memcpy(value, 0, size,
					     xattr->blob.inline_value.bytes,
					     0, SSDFS_XATTR_INLINE_BLOB_MAX_LEN,
					     blob_len);
				if (unlikely(err)) {
					SSDFS_ERR("fail to copy inline blob: "
						  "err %zd\n", err);
					goto xattr_is_not_available;
				}
				break;

			case SSDFS_XATTR_REGULAR_BLOB:
				err = ssdfs_xattr_read_external_blob(fsi,
								     inode,
								     xattr,
								     value,
								     size);
				if (err == -EINTR) {
					/*
					 * Ignore this error.
					 */
					goto xattr_is_not_available;
				} else if (unlikely(err)) {
					SSDFS_ERR("fail to read external blob: "
						  "err %zd\n", err);
					goto xattr_is_not_available;
				}
				break;

			default:
				BUG();
			}

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("BLOB DUMP:\n");
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     value, size);
			SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */
		}

		err = blob_len;

xattr_is_not_available:
		ssdfs_btree_search_free(search);

finish_search_xattr:
		up_read(&ii->lock);
		break;

	default:
		err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("xattrs tree is absent: "
			  "ino %lu\n",
			  (unsigned long)inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */
		break;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished: err %zd\n", err);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * Create, replace or remove an extended attribute for this inode.  Value
 * is NULL to remove an existing extended attribute, and non-NULL to
 * either replace an existing extended attribute, or create a new extended
 * attribute. The flags XATTR_REPLACE and XATTR_CREATE
 * specify that an extended attribute must exist and must not exist
 * previous to the call, respectively.
 *
 * Returns 0, or a negative error number on failure.
 */
int __ssdfs_setxattr(struct inode *inode, int name_index, const char *name,
			const void *value, size_t size, int flags)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	struct ssdfs_btree_search *search;
	size_t name_len;
	int private_flags;
	u64 name_hash;
	int err = 0;

	if (name == NULL) {
		SSDFS_ERR("name pointer is NULL\n");
		return -EINVAL;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("name_index %d, name %s, value %p, "
		  "size %zu, flags %#x\n",
		  name_index, name, value, size, flags);
#endif /* CONFIG_SSDFS_DEBUG */

	if (value == NULL)
		size = 0;

	name_len = strlen(name);
	if (name_len > SSDFS_MAX_NAME_LEN)
		return -ERANGE;

	private_flags = atomic_read(&ii->private_flags);

	switch (private_flags) {
	case SSDFS_INODE_HAS_INLINE_XATTR:
	case SSDFS_INODE_HAS_XATTR_BTREE:
		down_read(&ii->lock);

		if (!ii->xattrs_tree) {
			err = -ERANGE;
			SSDFS_WARN("xattrs tree is absent!!!\n");
			goto finish_setxattr;
		}
		break;

	default:
		down_write(&ii->lock);

		if (ii->xattrs_tree) {
			err = -ERANGE;
			SSDFS_WARN("xattrs tree exists unexpectedly!!!\n");
			goto finish_create_xattrs_tree;
		} else {
			err = ssdfs_xattrs_tree_create(fsi, ii);
			if (unlikely(err)) {
				SSDFS_ERR("fail to create the xattrs tree: "
					  "ino %lu, err %d\n",
					  inode->i_ino, err);
				goto finish_create_xattrs_tree;
			}

			atomic_or(SSDFS_INODE_HAS_INLINE_XATTR,
				  &ii->private_flags);
		}

finish_create_xattrs_tree:
		downgrade_write(&ii->lock);

		if (unlikely(err))
			goto finish_setxattr;
		break;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto finish_setxattr;
	}

	ssdfs_btree_search_init(search);

	name_hash = __ssdfs_generate_name_hash(name, name_len,
					       SSDFS_XATTR_INLINE_NAME_MAX_LEN);
	if (name_hash >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid name hash\n");
		goto clean_up;
	}

	if (value == NULL) {
		/* remove value */
		err = ssdfs_xattrs_tree_delete(ii->xattrs_tree,
						name_hash,
						name, name_len,
						search);
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to remove xattr: "
				  "ino %lu, name %s, err %d\n",
				  inode->i_ino, name, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto clean_up;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to remove xattr: "
				  "ino %lu, name %s, err %d\n",
				  inode->i_ino, name, err);
			goto clean_up;
		}
	} else if (flags & XATTR_CREATE) {
		err = ssdfs_xattrs_tree_add(ii->xattrs_tree,
					    name_index,
					    name, name_len,
					    value, size,
					    ii,
					    search);
		if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to create xattr: "
				  "ino %lu, name %s, err %d\n",
				  inode->i_ino, name, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto clean_up;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to create xattr: "
				  "ino %lu, name %s, err %d\n",
				  inode->i_ino, name, err);
			goto clean_up;
		}
	} else if (flags & XATTR_REPLACE) {
		err = ssdfs_xattrs_tree_change(ii->xattrs_tree,
						name_index,
						name_hash,
						name, name_len,
						value, size,
						search);
		if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to replace xattr: "
				  "ino %lu, name %s, err %d\n",
				  inode->i_ino, name, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto clean_up;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to replace xattr: "
				  "ino %lu, name %s, err %d\n",
				  inode->i_ino, name, err);
			goto clean_up;
		}
	} else {
		err = ssdfs_xattrs_tree_delete(ii->xattrs_tree,
						name_hash,
						name, name_len,
						search);
		if (err == -ENODATA) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("no requested xattr in the tree: "
				  "ino %lu, name %s\n",
				  inode->i_ino, name);
#endif /* CONFIG_SSDFS_DEBUG */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to remove xattr: "
				  "ino %lu, name %s, err %d\n",
				  inode->i_ino, name, err);
			goto clean_up;
		}

		ssdfs_btree_search_init(search);

		err = ssdfs_xattrs_tree_add(ii->xattrs_tree,
					    name_index,
					    name, name_len,
					    value, size,
					    ii,
					    search);
		if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to create xattr: "
				  "ino %lu, name %s, err %d\n",
				  inode->i_ino, name, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto clean_up;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to create xattr: "
				  "ino %lu, name %s, err %d\n",
				  inode->i_ino, name, err);
			goto clean_up;
		}
	}

	inode_set_ctime_to_ts(inode, current_time(inode));
	mark_inode_dirty(inode);

clean_up:
	ssdfs_btree_search_free(search);

finish_setxattr:
	up_read(&ii->lock);

	return err;
}
