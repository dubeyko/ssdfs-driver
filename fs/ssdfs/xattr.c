//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/xattr.c - extended attributes support implementation.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2019, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
 */

#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, start_hash %p\n",
		  tree, start_hash);

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

finish_get_start_hash:
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("search %p, start_hash %p, "
		  "end_hash %p, items_count %p\n",
		  tree, start_hash, end_hash, items_count);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("xattr %p, offset %zd, "
		  "buffer %p, size %zu\n",
		  xattr, offset, buffer, size);

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
			memcpy((u8 *)buffer + offset,
				SSDFS_NS_PREFIX[SSDFS_USER_NS_INDEX],
				prefix_len);
			offset += prefix_len;
			copied += prefix_len;
			break;

		case SSDFS_XATTR_TRUSTED_REGULAR_NAME:
			prefix_len =
				strlen(SSDFS_NS_PREFIX[SSDFS_TRUSTED_NS_INDEX]);
			memcpy((u8 *)buffer + offset,
				SSDFS_NS_PREFIX[SSDFS_TRUSTED_NS_INDEX],
				prefix_len);
			offset += prefix_len;
			copied += prefix_len;
			break;

		case SSDFS_XATTR_SYSTEM_REGULAR_NAME:
			prefix_len =
				strlen(SSDFS_NS_PREFIX[SSDFS_SYSTEM_NS_INDEX]);
			memcpy((u8 *)buffer + offset,
				SSDFS_NS_PREFIX[SSDFS_SYSTEM_NS_INDEX],
				prefix_len);
			offset += prefix_len;
			copied += prefix_len;
			break;

		case SSDFS_XATTR_SECURITY_REGULAR_NAME:
			prefix_len =
			    strlen(SSDFS_NS_PREFIX[SSDFS_SECURITY_NS_INDEX]);
			memcpy((u8 *)buffer + offset,
				SSDFS_NS_PREFIX[SSDFS_SECURITY_NS_INDEX],
				prefix_len);
			offset += prefix_len;
			copied += prefix_len;
			break;

		default:
			SSDFS_ERR("unexpected name type %#x\n",
				  xattr->name_type);
			return -EIO;
		}

		memcpy((u8 *)buffer + offset,
			search->name.str,
			search->name.len);

		offset += search->name.len;
		copied += search->name.len;
	} else {
		switch (xattr->name_type) {
		case SSDFS_XATTR_INLINE_NAME:
			/* do nothing here */
			break;

		case SSDFS_XATTR_USER_INLINE_NAME:
			prefix_len =
				strlen(SSDFS_NS_PREFIX[SSDFS_USER_NS_INDEX]);
			memcpy((u8 *)buffer + offset,
				SSDFS_NS_PREFIX[SSDFS_USER_NS_INDEX],
				prefix_len);
			offset += prefix_len;
			copied += prefix_len;
			break;

		case SSDFS_XATTR_TRUSTED_INLINE_NAME:
			prefix_len =
				strlen(SSDFS_NS_PREFIX[SSDFS_TRUSTED_NS_INDEX]);
			memcpy((u8 *)buffer + offset,
				SSDFS_NS_PREFIX[SSDFS_TRUSTED_NS_INDEX],
				prefix_len);
			offset += prefix_len;
			copied += prefix_len;
			break;

		case SSDFS_XATTR_SYSTEM_INLINE_NAME:
			prefix_len =
				strlen(SSDFS_NS_PREFIX[SSDFS_SYSTEM_NS_INDEX]);
			memcpy((u8 *)buffer + offset,
				SSDFS_NS_PREFIX[SSDFS_SYSTEM_NS_INDEX],
				prefix_len);
			offset += prefix_len;
			copied += prefix_len;
			break;

		case SSDFS_XATTR_SECURITY_INLINE_NAME:
			prefix_len =
			    strlen(SSDFS_NS_PREFIX[SSDFS_SECURITY_NS_INDEX]);
			memcpy((u8 *)buffer + offset,
				SSDFS_NS_PREFIX[SSDFS_SECURITY_NS_INDEX],
				prefix_len);
			offset += prefix_len;
			copied += prefix_len;
			break;

		default:
			SSDFS_ERR("unexpected name type %#x\n",
				  xattr->name_type);
			return -EIO;
		}

		if (copied >= xattr->name_len) {
			SSDFS_ERR("copied %zd >= name_len %u\n",
				  copied, xattr->name_len);
			return -EIO;
		}

		name_len = xattr->name_len - copied;

		memcpy((u8 *)buffer + offset,
			xattr->inline_string,
			name_len);

		offset += name_len;
		copied += name_len;
	}

	if (copied != xattr->name_len) {
		SSDFS_ERR("copied %zd != name_len %u\n",
			  copied, xattr->name_len);
		return -ERANGE;
	}

	return copied;
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
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_shared_dict_btree_info *dict;
	struct ssdfs_btree_search *search;
	struct ssdfs_xattr_entry *xattr;
	size_t xattr_size = sizeof(struct ssdfs_xattr_entry);
	int private_flags;
	u64 start_hash, end_hash, hash;
	u64 cur_hash = 0;
	u16 items_count;
	ssize_t res, copied = 0;
	int i;
	int err = 0;

	SSDFS_DBG("ino %lu, buffer %p, size %zu\n",
		  inode->i_ino, buffer, size);

	dict = fsi->shdictree;
	if (!dict) {
		SSDFS_ERR("shared dictionary is absent\n");
		return -ERANGE;
	}

	private_flags = atomic_read(&ii->private_flags);

	switch (private_flags) {
	case SSDFS_INODE_HAS_INLINE_XATTR:
	case SSDFS_INODE_HAS_XATTR_BTREE:
		/* xattrs tree exists */
		break;

	default:
		SSDFS_DBG("xattrs tree is absent: "
			  "ino %lu\n",
			  inode->i_ino);
		return 0;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);

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
		SSDFS_DBG("unable to extract start hash: "
			  "ino %lu\n",
			  inode->i_ino);
		goto clean_up;
	} else if (unlikely(err))
		goto clean_up;

	do {
		down_read(&ii->lock);

		err = ssdfs_xattrs_tree_find_leaf_node(ii->xattrs_tree,
							cur_hash,
							search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find a leaf node: "
				  "hash %llx, err %d\n",
				  cur_hash, err);
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

		if (cur_hash >= end_hash) {
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
			xattr =
			    (struct ssdfs_xattr_entry *)(search->result.buf +
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
				copied += xattr->name_len + 1;

			cur_hash = hash + 1;
		}

		if (cur_hash <= end_hash) {
			err = -ERANGE;
			SSDFS_ERR("cur_hash %llx <= end_hash %llx\n",
				  cur_hash, end_hash);
			goto clean_up;
		}
	} while (cur_hash < U64_MAX);

clean_up:
	ssdfs_btree_search_free(search);

	return err < 0 ? err : copied;
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
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	struct ssdfs_btree_search *search;
	size_t name_len;
	int private_flags;
	int err = 0;

	if (name == NULL) {
		SSDFS_ERR("name pointer is NULL\n");
		return -EINVAL;
	}

	SSDFS_DBG("name_index %d, name %s, value %p, size %zu\n",
		  name_index, name, value, size);

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
			SSDFS_DBG("inode %lu hasn't xattr %s\n",
				  (unsigned long)inode->i_ino,
				  name);
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

		if (value) {
			err = -ERANGE;

			if (search->result.buf_size > size)
				goto xattr_is_not_available;

			/* return value of attribute */
			memcpy(value, search->result.buf,
				search->result.buf_size);
		}

		err = search->result.buf_size;

xattr_is_not_available:
		ssdfs_btree_search_free(search);

finish_search_xattr:
		up_read(&ii->lock);
		break;

	default:
		err = -ENODATA;
		SSDFS_DBG("xattrs tree is absent: "
			  "ino %lu\n",
			  (unsigned long)inode->i_ino);
		break;
	}

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

	SSDFS_DBG("name_index %d, name %s, value %p, size %zu\n",
		  name_index, name, value, size);

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

	name_hash = __ssdfs_generate_name_hash(name, name_len);
	if (name_hash >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid name hash\n");
		goto clean_up;
	}

	if (value == NULL) {
		/* remove value */
		err = ssdfs_xattrs_tree_delete(ii->xattrs_tree,
						name_hash, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to remove xattr: "
				  "ino %lu, name %s, err %d\n",
				  inode->i_ino, name, err);
			goto clean_up;
		}
	} else if (flags & XATTR_CREATE) {
		err = ssdfs_xattrs_tree_add(ii->xattrs_tree,
					    name, name_len,
					    value, size,
					    ii,
					    search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create xattr: "
				  "ino %lu, name %s, err %d\n",
				  inode->i_ino, name, err);
			goto clean_up;
		}
	} else if (flags & XATTR_REPLACE) {
		err = ssdfs_xattrs_tree_change(ii->xattrs_tree,
						name_hash,
						name, name_len,
						value, size,
						search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to replace xattr: "
				  "ino %lu, name %s, err %d\n",
				  inode->i_ino, name, err);
			goto clean_up;
		}
	} else
		BUG();

	inode->i_ctime = current_time(inode);
	mark_inode_dirty(inode);

clean_up:
	ssdfs_btree_search_free(search);

finish_setxattr:
	up_read(&ii->lock);

	return err;
}
