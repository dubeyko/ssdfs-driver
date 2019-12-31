//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/xattr_tree.c - extended attributes btree implementation.
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
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "request_queue.h"
#include "segment_bitmap.h"
#include "page_array.h"
#include "segment.h"
#include "extents_queue.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "shared_dictionary.h"
#include "shared_extents_tree.h"
#include "segment_tree.h"
#include "xattr_tree.h"

/******************************************************************************
 *                     XATTR TREE OBJECT FUNCTIONALITY                        *
 ******************************************************************************/

/*
 * ssdfs_calculate_inline_capacity() - caclulate xattrs' inline capacity
 * @fsi: pointer on shared file system object
 */
static
u16 ssdfs_calculate_inline_capacity(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_inodes_btree *inodes_btree;
	size_t raw_size;
	size_t inode_size = sizeof(struct ssdfs_inode);
	size_t private_area_size = sizeof(struct ssdfs_inode_private_area);
	u16 inline_capacity = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	inodes_btree = &fsi->vs->inodes_btree;
	raw_size = le16_to_cpu(inodes_btree->desc.item_size);

	if (raw_size < inode_size || raw_size % inode_size) {
		SSDFS_ERR("invalid inode size: "
			  "raw_size %zu, default_size %zu\n",
			  raw_size, inode_size);
		return U16_MAX;
	}

	raw_size -= inode_size;
	inline_capacity += 1;

	if (raw_size > 0) {
		/*
		 * One private area contains inline xattr in area2 only.
		 */
		inline_capacity += (raw_size / private_area_size) / 2;
	}

	return inline_capacity;
}

/*
 * ssdfs_xattrs_tree_create() - create xattrs tree of a new inode
 * @fsi: pointer on shared file system object
 * @ii: pointer on in-core SSDFS inode
 *
 * This method tries to create xattrs btree for a new inode.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 */
int ssdfs_xattrs_tree_create(struct ssdfs_fs_info *fsi,
			     struct ssdfs_inode_info *ii)
{
	struct ssdfs_xattrs_btree_info *ptr;
	size_t xattr_size = sizeof(struct ssdfs_xattr_entry);
	u16 inline_capacity = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !ii);
	BUG_ON(!rwsem_is_locked(&ii->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ii %p, ino %lu\n",
		  ii, ii->vfs_inode.i_ino);

	ptr = kzalloc(sizeof(struct ssdfs_xattrs_btree_info),
			GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate xattrs tree\n");
		return -ENOMEM;
	}

	atomic_set(&ptr->state, SSDFS_XATTR_BTREE_UNKNOWN_STATE);
	init_rwsem(&ptr->lock);
	ptr->generic_tree = NULL;

	inline_capacity = ssdfs_calculate_inline_capacity(fsi);
	if (inline_capacity >= U16_MAX) {
		SSDFS_ERR("invalid inline_capacity %u\n",
			  inline_capacity);
		return -ERANGE;
	}

	ptr->inline_capacity = (u16)inline_capacity;
	ptr->inline_count = 0;

	if (ptr->inline_capacity > 1) {
		atomic_set(&ptr->type, SSDFS_INLINE_XATTR);
		memset(&ptr->buffer.xattr, 0, xattr_size);
		ptr->inline_xattrs = &ptr->buffer.xattr;
	} else {
		atomic_set(&ptr->type, SSDFS_INLINE_XATTR_ARRAY);

		ptr->inline_xattrs =
			kzalloc(xattr_size * ptr->inline_capacity, GFP_KERNEL);
		if (!ptr->inline_xattrs) {
			SSDFS_ERR("fail to allocate memory: "
				  "size %zu\n",
				  xattr_size * ptr->inline_capacity);
			return -ENOMEM;
		}
	}

	memset(&ptr->root_buffer, 0xFF,
		sizeof(struct ssdfs_btree_inline_root_node));
	ptr->root = NULL;
	memcpy(&ptr->desc, &fsi->segs_tree->xattr_btree,
		sizeof(struct ssdfs_xattr_btree_descriptor));
	ptr->owner = ii;
	ptr->fsi = fsi;

	atomic_set(&ptr->state, SSDFS_XATTR_BTREE_CREATED);

	ssdfs_debug_xattrs_btree_object(ptr);

	ii->xattrs_tree = ptr;

	return 0;
}

/*
 * ssdfs_xattrs_tree_destroy() - destroy xattrs tree
 * @ii: pointer on in-core SSDFS inode
 */
void ssdfs_xattrs_tree_destroy(struct ssdfs_inode_info *ii)
{
	struct ssdfs_xattrs_btree_info *tree;
	size_t xattr_size = sizeof(struct ssdfs_xattr_entry);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ii);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ii %p, ino %lu\n",
		  ii, ii->vfs_inode.i_ino);

	tree = SSDFS_XATTREE(ii);

	if (!tree) {
		SSDFS_DBG("xattrs tree is absent: ino %lu\n",
			  ii->vfs_inode.i_ino);
		return;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_XATTR_BTREE_CREATED:
	case SSDFS_XATTR_BTREE_INITIALIZED:
		/* expected state*/
		break;

	case SSDFS_XATTR_BTREE_CORRUPTED:
		SSDFS_WARN("xattrs tree is corrupted: "
			   "ino %lu\n",
			   ii->vfs_inode.i_ino);
		break;

	case SSDFS_XATTR_BTREE_DIRTY:
		SSDFS_WARN("xattrs tree is dirty: "
			   "ino %lu\n",
			   ii->vfs_inode.i_ino);
		break;

	default:
		SSDFS_WARN("invalid state of xattrs tree: "
			   "ino %lu, state %#x\n",
			   ii->vfs_inode.i_ino,
			   atomic_read(&tree->state));
		return;
	}

	if (rwsem_is_locked(&tree->lock)) {
		/* inform about possible trouble */
		SSDFS_WARN("tree is locked under destruction\n");
	}

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_XATTR:
		if (!tree->inline_xattrs) {
			SSDFS_WARN("empty inline_xattrs pointer\n");
			memset(&tree->buffer.xattr, 0, xattr_size);
		} else
			memset(tree->inline_xattrs, 0, xattr_size);
		tree->inline_xattrs = NULL;
		break;

	case SSDFS_INLINE_XATTR_ARRAY:
		if (!tree->inline_xattrs) {
			/* pointer is NULL */
			SSDFS_WARN("empty inline_xattrs pointer\n");
		} else {
			kfree(tree->inline_xattrs);
			tree->inline_xattrs = NULL;
		}
		break;

	case SSDFS_PRIVATE_XATTR_BTREE:
		if (!tree->generic_tree) {
			SSDFS_WARN("empty generic_tree pointer\n");
			ssdfs_btree_destroy(&tree->buffer.tree);
		} else {
			/* destroy tree via pointer */
			ssdfs_btree_destroy(tree->generic_tree);
		}
		tree->generic_tree = NULL;
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid xattrs btree state %#x\n",
			   atomic_read(&tree->state));
#endif /* CONFIG_SSDFS_DEBUG */
		break;
	}

	memset(&tree->root_buffer, 0xFF,
		sizeof(struct ssdfs_btree_inline_root_node));
	tree->root = NULL;

	tree->owner = NULL;
	tree->fsi = NULL;

	atomic_set(&tree->type, SSDFS_XATTR_BTREE_UNKNOWN_TYPE);
	atomic_set(&tree->state, SSDFS_XATTR_BTREE_UNKNOWN_STATE);

	kfree(ii->xattrs_tree);
	ii->xattrs_tree = NULL;
}

/*
 * ssdfs_xattrs_tree_init() - init xattrs tree for existing inode
 * @fsi: pointer on shared file system object
 * @ii: pointer on in-core SSDFS inode
 *
 * This method tries to create the xattrs tree and to initialize
 * the root node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 * %-EIO        - corrupted raw on-disk inode.
 */
int ssdfs_xattrs_tree_init(struct ssdfs_fs_info *fsi,
			   struct ssdfs_inode_info *ii)
{
	struct ssdfs_inode raw_inode;
	struct ssdfs_btree_node *node;
	struct ssdfs_xattrs_btree_info *tree;
	struct ssdfs_btree_inline_root_node *root_node;
	size_t xattr_size = sizeof(struct ssdfs_xattr_entry);
	u16 flags;
	u64 hash;
	u8 index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !ii);
	BUG_ON(!rwsem_is_locked(&ii->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, ii %p, ino %lu\n",
		  fsi, ii, ii->vfs_inode.i_ino);

	tree = SSDFS_XATTREE(ii);
	if (!tree) {
		SSDFS_DBG("xattrs tree is absent: ino %lu\n",
			  ii->vfs_inode.i_ino);
		return -ERANGE;
	}

	memcpy(&raw_inode, &ii->raw_inode, sizeof(struct ssdfs_inode));

	flags = le16_to_cpu(raw_inode.private_flags);

	switch (atomic_read(&tree->state)) {
	case SSDFS_XATTR_BTREE_CREATED:
		/* expected tree state */
		break;

	default:
		SSDFS_WARN("unexpected state of tree %#x\n",
			   atomic_read(&tree->state));
		return -ERANGE;
	}

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_XATTR:
	case SSDFS_INLINE_XATTR_ARRAY:
		/* expected tree type */
		break;

	case SSDFS_PRIVATE_XATTR_BTREE:
		SSDFS_WARN("unexpected type of tree %#x\n",
			   atomic_read(&tree->type));
		return -ERANGE;

	default:
		SSDFS_WARN("invalid type of tree %#x\n",
			   atomic_read(&tree->type));
		return -ERANGE;
	}

	down_write(&tree->lock);

	if (flags & SSDFS_INODE_HAS_XATTR_BTREE) {
		if (tree->generic_tree) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_XATTR_BTREE_CORRUPTED);
			SSDFS_WARN("generic tree exists\n");
			goto finish_tree_init;
		}

		tree->generic_tree = &tree->buffer.tree;
		tree->inline_xattrs = NULL;

		err = ssdfs_btree_create(fsi,
					 ii->vfs_inode.i_ino,
					 &ssdfs_xattrs_btree_desc_ops,
					 &ssdfs_xattrs_btree_ops,
					 tree->generic_tree);
		if (unlikely(err)) {
			atomic_set(&tree->state,
				   SSDFS_XATTR_BTREE_CORRUPTED);
			SSDFS_ERR("fail to create xattrs tree: err %d\n",
				  err);
			goto finish_tree_init;
		}

		err = ssdfs_btree_radix_tree_find(tree->generic_tree,
						  SSDFS_BTREE_ROOT_NODE_ID,
						  &node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get the root node: err %d\n",
				  err);
			goto fail_create_generic_tree;
		} else if (unlikely(!node)) {
			err = -ERANGE;
			SSDFS_WARN("empty node pointer\n");
			goto fail_create_generic_tree;
		}

		root_node = &raw_inode.internal[0].area2.xattr_root;
		err = ssdfs_btree_create_root_node(node, root_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init the root node: err %d\n",
				  err);
			goto fail_create_generic_tree;
		}

		tree->root = &tree->root_buffer;
		memcpy(tree->root, root_node,
			sizeof(struct ssdfs_btree_inline_root_node));

		atomic_set(&tree->type, SSDFS_PRIVATE_XATTR_BTREE);
		atomic_set(&tree->state, SSDFS_XATTR_BTREE_INITIALIZED);

fail_create_generic_tree:
		if (unlikely(err)) {
			atomic_set(&tree->state,
				   SSDFS_XATTR_BTREE_CORRUPTED);
			ssdfs_btree_destroy(tree->generic_tree);
			tree->generic_tree = NULL;
			goto finish_tree_init;
		}
	} else if (flags & SSDFS_INODE_HAS_INLINE_XATTR) {
		u16 capacity = tree->inline_capacity;

		if (!tree->inline_xattrs) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_XATTR_BTREE_CORRUPTED);
			SSDFS_WARN("undefined inline xattrs pointer\n");
			goto finish_tree_init;
		} else if (capacity == 0 || capacity >= U16_MAX) {
			err = -ERANGE;
			SSDFS_ERR("invalid inline capacity %u\n",
				  capacity);
			goto finish_tree_init;
		} else if (capacity == SSDFS_DEFAULT_INLINE_XATTR_COUNT) {
			memcpy(tree->inline_xattrs,
				&raw_inode.internal[0].area2.inline_xattr,
				xattr_size);
			atomic_set(&tree->type, SSDFS_INLINE_XATTR);

			hash = le64_to_cpu(tree->inline_xattrs[0].name_hash);
			index = tree->inline_xattrs[0].inline_index;

			if (hash >= U64_MAX)
				tree->inline_count = 0;
			else if (index == 0)
				tree->inline_count = 1;
			else {
				err = -EIO;
				SSDFS_ERR("invalid inline index %u\n",
					  index);
				goto finish_tree_init;
			}
		} else {
			/* TODO: implement support */
			BUG();
		}

		atomic_set(&tree->state, SSDFS_XATTR_BTREE_INITIALIZED);
	} else {
		err = -EIO;
		SSDFS_ERR("xattrs tree doesn't exist in the raw inode: "
			  "ino %lu\n",
			  ii->vfs_inode.i_ino);
		goto finish_tree_init;
	}

finish_tree_init:
	up_write(&tree->lock);

	return err;
}

/*
 * ssdfs_xattrs_tree_flush() - save modified xattrs tree
 * @fsi: pointer on shared file system object
 * @ii: pointer on in-core SSDFS inode
 *
 * This method tries to flush inode's xattrs btree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_xattrs_tree_flush(struct ssdfs_fs_info *fsi,
			    struct ssdfs_inode_info *ii)
{
	struct ssdfs_xattrs_btree_info *tree;
	size_t xattr_size = sizeof(struct ssdfs_xattr_entry);
	int flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !ii);
	BUG_ON(!rwsem_is_locked(&ii->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, ii %p, ino %lu\n",
		  fsi, ii, ii->vfs_inode.i_ino);

	tree = SSDFS_XATTREE(ii);
	if (!tree) {
		SSDFS_DBG("xattrs tree is absent: ino %lu\n",
			  ii->vfs_inode.i_ino);
		return -ERANGE;
	}

	flags = atomic_read(&ii->private_flags);

	switch (atomic_read(&tree->state)) {
	case SSDFS_XATTR_BTREE_DIRTY:
		/* need to flush */
		break;

	case SSDFS_XATTR_BTREE_CREATED:
	case SSDFS_XATTR_BTREE_INITIALIZED:
		/* do nothing */
		return 0;

	case SSDFS_XATTR_BTREE_CORRUPTED:
		SSDFS_DBG("xattrs btree corrupted: ino %lu\n",
			  ii->vfs_inode.i_ino);
		return -EOPNOTSUPP;

	default:
		SSDFS_WARN("unexpected state of tree %#x\n",
			   atomic_read(&tree->state));
		return -ERANGE;
	}

	down_write(&tree->lock);

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_XATTR:
		if (!tree->inline_xattrs) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_XATTR_BTREE_CORRUPTED);
			SSDFS_WARN("undefined inline xattrs pointer\n");
			goto finish_xattrs_tree_flush;
		}

		memcpy(&ii->raw_inode.internal[0].area2.inline_xattr,
			tree->inline_xattrs,
			xattr_size);
		atomic_or(SSDFS_INODE_HAS_INLINE_XATTR,
			  &ii->private_flags);
		break;

	case SSDFS_INLINE_XATTR_ARRAY:
		/* TODO: implement support */
		BUG();
		break;

	case SSDFS_PRIVATE_XATTR_BTREE:
		if (!tree->generic_tree) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_XATTR_BTREE_CORRUPTED);
			SSDFS_WARN("undefined generic tree pointer\n");
			goto finish_xattrs_tree_flush;
		}

		err = ssdfs_btree_flush(tree->generic_tree);
		if (unlikely(err)) {
			SSDFS_ERR("fail to flush xattrs btree: "
				  "ino %lu, err %d\n",
				  ii->vfs_inode.i_ino, err);
			goto finish_xattrs_tree_flush;
		}

		if (!tree->root) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_XATTR_BTREE_CORRUPTED);
			SSDFS_WARN("undefined root node pointer\n");
			goto finish_xattrs_tree_flush;
		}

		memcpy(&ii->raw_inode.internal[0].area2.xattr_root,
			tree->root,
			sizeof(struct ssdfs_btree_inline_root_node));

		atomic_or(SSDFS_INODE_HAS_XATTR_BTREE,
			  &ii->private_flags);
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid type of tree %#x\n",
			   atomic_read(&tree->type));
		goto finish_xattrs_tree_flush;
	}

	atomic_set(&tree->state, SSDFS_XATTR_BTREE_INITIALIZED);

finish_xattrs_tree_flush:
	up_write(&tree->lock);

	return err;
}

/******************************************************************************
 *                       XATTR TREE OBJECT FUNCTIONALITY                      *
 ******************************************************************************/

/*
 * need_initialize_xattrs_btree_search() - check necessity to init the search
 * @name_hash: name hash
 * @search: search object
 */
static inline
bool need_initialize_xattrs_btree_search(u64 name_hash,
					 struct ssdfs_btree_search *search)
{
	return need_initialize_btree_search(search) ||
		search->request.start.hash != name_hash;
}

/*
 * ssdfs_generate_name_hash() - generate a name's hash
 * @name: pointer on the name's string
 * @len: length of the name
 */
static
u64 ssdfs_generate_name_hash(const char *name, size_t len)
{
	u32 hash32_lo, hash32_hi;
	size_t copy_len;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!name);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("name %s, len %zu\n",
		  name, len);

	if (len == 0) {
		SSDFS_ERR("invalid len %zu\n", len);
		return U64_MAX;
	}

	copy_len = min_t(size_t, len, (size_t)SSDFS_XATTR_INLINE_NAME_MAX_LEN);
	hash32_lo = full_name_hash(NULL, name, copy_len);

	if (len <= SSDFS_XATTR_INLINE_NAME_MAX_LEN)
		hash32_hi = 0;
	else {
		hash32_hi = full_name_hash(NULL,
					name + SSDFS_XATTR_INLINE_NAME_MAX_LEN,
					len - copy_len);
	}

	return SSDFS_NAME_HASH(hash32_lo, hash32_hi);
}

/*
 * ssdfs_check_xattr_for_request() - check extended attribute
 * @fsi:  pointer on shared file system object
 * @xattr: pointer on xattr object
 * @search: search object
 *
 * This method tries to check @xattr for the @search request.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EAGAIN     - continue the search.
 * %-ENODATA    - possible place was found.
 */
static
int ssdfs_check_xattr_for_request(struct ssdfs_fs_info *fsi,
				  struct ssdfs_xattr_entry *xattr,
				  struct ssdfs_btree_search *search)
{
	struct ssdfs_shared_dict_btree_info *dict;
	u32 req_flags;
	u64 start_hash;
	const char *req_name;
	size_t req_name_len;
	u64 hash_code;
	u8 flags;
	u16 name_len;
	int err = 0, res = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !xattr || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, xattr %p, search %p\n",
		  fsi, xattr, search);

	dict = fsi->shdictree;
	if (!dict) {
		SSDFS_ERR("shared dictionary is absent\n");
		return -ERANGE;
	}

	req_flags = search->request.flags;
	start_hash = search->request.start.hash;
	req_name = search->request.start.name;
	req_name_len = search->request.start.name_len;

	hash_code = le64_to_cpu(xattr->name_hash);
	flags = xattr->name_flags;
	name_len = le16_to_cpu(xattr->name_len);

	if (start_hash < hash_code) {
		err = -ENODATA;
		search->result.err = -ENODATA;
		search->result.state =
			SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
		goto finish_check_xattr;
	} else if (start_hash > hash_code) {
		/* continue the search */
		err = -EAGAIN;
		goto finish_check_xattr;
	} else {
		/* start_hash == hash_code */

		if (req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME) {
			int res;

			if (!req_name) {
				SSDFS_ERR("empty name pointer\n");
				return -ERANGE;
			}

			name_len = min_t(u16, name_len,
					 SSDFS_XATTR_INLINE_NAME_MAX_LEN);
			res = strncmp(req_name, xattr->inline_string,
					name_len);
			if (res < 0) {
				/* hash collision case */
				err = -ENODATA;
				search->result.err = -ENODATA;
				search->result.state =
					SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
				goto finish_check_xattr;
			} else if (res == 0) {
				search->result.state =
					SSDFS_BTREE_SEARCH_VALID_ITEM;
				goto extract_full_name;
			} else {
				/* hash collision case */
				/* continue the search */
				err = -EAGAIN;
				goto finish_check_xattr;
			}
		}

extract_full_name:
		if (flags & SSDFS_XATTR_HAS_EXTERNAL_STRING) {
			err = ssdfs_shared_dict_get_name(dict, start_hash,
							 &search->name);
			if (unlikely(err)) {
				SSDFS_ERR("fail to extract the name: "
					  "hash %llx, err %d\n",
					  start_hash, err);
				goto finish_check_xattr;
			}
		} else
			goto finish_check_xattr;

		if (req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME) {
			name_len = le16_to_cpu(xattr->name_len);

			res = strncmp(req_name, search->name.str,
					name_len);
			if (res < 0) {
				/* hash collision case */
				err = -ENODATA;
				search->result.err = -ENODATA;
				search->result.state =
					SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
				goto finish_check_xattr;
			} else if (res == 0) {
				search->result.state =
					SSDFS_BTREE_SEARCH_VALID_ITEM;
				goto finish_check_xattr;
			} else {
				/* hash collision case */
				/* continue the search */
				err = -EAGAIN;
				goto finish_check_xattr;
			}
		}
	}

finish_check_xattr:
	return err;
}

/*
 * ssdfs_xattrs_tree_find_inline_xattr() - find inline xattr
 * @tree: btree object
 * @search: search object
 *
 * This method tries to find an inline xattr.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - possible place was found.
 */
static
int ssdfs_xattrs_tree_find_inline_xattr(struct ssdfs_xattrs_btree_info *tree,
					struct ssdfs_btree_search *search)
{
	u32 req_flags;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_XATTR:
	case SSDFS_INLINE_XATTR_ARRAY:
		/* expected type */
		break;

	default:
		SSDFS_ERR("invalid tree type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	if (tree->inline_capacity == 0) {
		SSDFS_ERR("invalid inline_capacity %u\n",
			  tree->inline_capacity);
		return -ERANGE;
	}

	if (tree->inline_count > tree->inline_capacity) {
		SSDFS_ERR("inline_count %u > inline_capacity %u\n",
			  tree->inline_count,
			  tree->inline_capacity);
	}

	if (!tree->inline_xattrs) {
		SSDFS_ERR("inline xattrs haven't been initialized\n");
		return -ERANGE;
	}

	req_flags = search->request.flags;

	for (i = 0; i < tree->inline_count; i++) {
		struct ssdfs_xattr_entry *xattr;
		u64 hash_code;
		u8 name_type;
		u8 name_flags;
		u16 name_len;
		u8 blob_type;
		u8 blob_flags;

		search->result.state = SSDFS_BTREE_SEARCH_UNKNOWN_RESULT;

		xattr = &tree->inline_xattrs[i];
		hash_code = le64_to_cpu(xattr->name_hash);
		name_type = xattr->name_type;
		name_flags = xattr->name_flags;
		name_len = le16_to_cpu(xattr->name_len);
		blob_type = xattr->blob_type;
		blob_flags = xattr->blob_flags;

		if (name_type <= SSDFS_XATTR_NAME_UNKNOWN_TYPE ||
		    name_type >= SSDFS_XATTR_NAME_TYPE_MAX) {
			SSDFS_ERR("corrupted xattr: "
				  "hash_code %llu, "
				  "name_type %#x, name_flags %#x, "
				  "blob_type %#x, blob_flags %#x\n",
				  hash_code, name_type, name_flags,
				  blob_type, blob_flags);
			atomic_set(&tree->state,
				   SSDFS_XATTR_BTREE_CORRUPTED);
			return -ERANGE;
		}

		if (blob_type <= SSDFS_XATTR_BLOB_UNKNOWN_TYPE ||
		    blob_type >= SSDFS_XATTR_BLOB_TYPE_MAX) {
			SSDFS_ERR("corrupted xattr: "
				  "hash_code %llu, "
				  "name_type %#x, name_flags %#x, "
				  "blob_type %#x, blob_flags %#x\n",
				  hash_code, name_type, name_flags,
				  blob_type, blob_flags);
			atomic_set(&tree->state,
				   SSDFS_XATTR_BTREE_CORRUPTED);
			return -ERANGE;
		}

		if (name_flags & ~SSDFS_XATTR_NAME_FLAGS_MASK) {
			SSDFS_ERR("corrupted xattr: "
				  "hash_code %llu, "
				  "name_type %#x, name_flags %#x, "
				  "blob_type %#x, blob_flags %#x\n",
				  hash_code, name_type, name_flags,
				  blob_type, blob_flags);
			atomic_set(&tree->state,
				   SSDFS_XATTR_BTREE_CORRUPTED);
			return -ERANGE;
		}

		if (blob_flags & ~SSDFS_XATTR_BLOB_FLAGS_MASK) {
			SSDFS_ERR("corrupted xattr: "
				  "hash_code %llu, "
				  "name_type %#x, name_flags %#x, "
				  "blob_type %#x, blob_flags %#x\n",
				  hash_code, name_type, name_flags,
				  blob_type, blob_flags);
			atomic_set(&tree->state,
				   SSDFS_XATTR_BTREE_CORRUPTED);
			return -ERANGE;
		}

		if (hash_code >= U64_MAX) {
			SSDFS_ERR("corrupted xattr: "
				  "hash_code %llu, "
				  "name_type %#x, name_flags %#x, "
				  "blob_type %#x, blob_flags %#x\n",
				  hash_code, name_type, name_flags,
				  blob_type, blob_flags);
			atomic_set(&tree->state,
				   SSDFS_XATTR_BTREE_CORRUPTED);
			return -ERANGE;
		}

		if (!(req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE)) {
			SSDFS_ERR("invalid request: hash is absent\n");
			return -ERANGE;
		}

		memcpy(&search->raw.xattr.header, xattr,
			sizeof(struct ssdfs_xattr_entry));

		search->result.err = 0;
		search->result.start_index = (u16)i;
		search->result.count = 1;
		search->result.search_cno = ssdfs_current_cno(tree->fsi->sb);
		search->result.buf_state = SSDFS_BTREE_SEARCH_INLINE_BUFFER;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */
		search->result.buf = &search->raw.xattr;
		search->result.buf_size = sizeof(struct ssdfs_xattr_entry);
		search->result.items_in_buffer = 1;

		err = ssdfs_check_xattr_for_request(tree->fsi, xattr, search);
		if (err == -ENODATA)
			goto finish_search_inline_xattr;
		else if (err == -EAGAIN)
			continue;
		else if (unlikely(err)) {
			SSDFS_ERR("fail to check xattr: err %d\n", err);
			goto finish_search_inline_xattr;
		} else {
			search->result.state =
				SSDFS_BTREE_SEARCH_VALID_ITEM;
			goto finish_search_inline_xattr;
		}
	}

	err = -ENODATA;
	search->result.err = -ENODATA;
	search->result.state = SSDFS_BTREE_SEARCH_OUT_OF_RANGE;

finish_search_inline_xattr:
	return err;
}

/*
 * __ssdfs_xattrs_tree_find() - find an xattr in the tree
 * @tree: xattrs tree
 * @name: name string
 * @len: length of the string
 * @search: search object
 *
 * This method tries to find an xattr for the requested @name_hash.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - item hasn't been found
 */
int __ssdfs_xattrs_tree_find(struct ssdfs_xattrs_btree_info *tree,
				struct ssdfs_btree_search *search)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

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
		err = ssdfs_xattrs_tree_find_inline_xattr(tree, search);
		up_read(&tree->lock);

		if (err == -ENODATA) {
			SSDFS_ERR("unable to find the inline xattr: "
				  "err %d\n",
				  err);
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find the inline xattr: "
				  "err %d\n",
				  err);
		}
		break;

	case SSDFS_PRIVATE_XATTR_BTREE:
		down_read(&tree->lock);
		err = ssdfs_btree_find_item(tree->generic_tree, search);
		up_read(&tree->lock);

		if (err == -ENODATA) {
			SSDFS_DBG("unable to find the xattr: "
				  "err %d\n",
				  err);
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find the xattr: "
				  "err %d\n",
				  err);
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid xattrs tree type %#x\n",
			  atomic_read(&tree->type));
		break;
	}

	return err;
}

/*
 * ssdfs_xattrs_tree_find() - find an xattr in the tree
 * @tree: xattrs tree
 * @name: name string
 * @len: length of the string
 * @search: search object
 *
 * This method tries to find an xattr for the requested @name_hash.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - item hasn't been found
 */
int ssdfs_xattrs_tree_find(struct ssdfs_xattrs_btree_info *tree,
			   const char *name, size_t len,
			   struct ssdfs_btree_search *search)
{
	u64 name_hash;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !name || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, name %s, len %zu, search %p\n",
		  tree, name, len, search);

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	name_hash = ssdfs_generate_name_hash(name, len);
	if (name_hash == U64_MAX) {
		SSDFS_ERR("fail to generate name hash\n");
		return -ERANGE;
	}

	if (need_initialize_xattrs_btree_search(name_hash, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT |
			SSDFS_BTREE_SEARCH_HAS_VALID_NAME;
		search->request.start.hash = name_hash;
		search->request.start.name = name;
		search->request.start.name_len = len;
		search->request.end.hash = name_hash;
		search->request.end.name = name;
		search->request.end.name_len = len;
		search->request.count = 1;
	}

	return __ssdfs_xattrs_tree_find(tree, search);
}

/*
 * ssdfs_xattrs_tree_find_leaf_node() - find a leaf node in the tree
 * @tree: xattrs tree
 * @name_hash: name hash
 * @search: search object
 *
 * This method tries to find a leaf node for the requested @name_hash.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_xattrs_tree_find_leaf_node(struct ssdfs_xattrs_btree_info *tree,
				     u64 name_hash,
				     struct ssdfs_btree_search *search)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, name_hash %llx, search %p\n",
		  tree, name_hash, search);

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_xattrs_btree_search(name_hash, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
		search->request.start.hash = name_hash;
		search->request.start.name = NULL;
		search->request.start.name_len = 0;
		search->request.end.hash = name_hash;
		search->request.end.name = NULL;
		search->request.end.name_len = 0;
		search->request.count = 1;
	}

	err = __ssdfs_xattrs_tree_find(tree, search);
	if (err == -ENODATA) {
		switch (search->result.state) {
		case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
		case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
		case SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE:
			switch (search->node.state) {
			case SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC:
				/* expected state */
				err = 0;
				break;

			default:
				err = -ERANGE;
				SSDFS_ERR("unexpected node state %#x\n",
					  search->node.state);
				break;
			}
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("unexpected result's state %#x\n",
				  search->result.state);
			break;
		}
	}

	return err;
}

/*
 * can_name_be_inline() - check that name can be inline
 * @name_len: length of the name
 */
static inline
bool can_name_be_inline(size_t name_len)
{
	SSDFS_DBG("name_len %zu\n", name_len);

	return name_len <= SSDFS_XATTR_INLINE_NAME_MAX_LEN;
}

/*
 * can_blob_be_inline() - check that blob can be inline
 * @size: size of the blob
 */
static inline
bool can_blob_be_inline(size_t size)
{
	SSDFS_DBG("size %zu\n", size);

	return size <= SSDFS_XATTR_INLINE_BLOB_MAX_LEN;
}

/*
 * ssdfs_define_name_type() - define type of the name
 * @name: name string
 * @name_len: length of the name
 * @name_type: pointer on the value of name type [out]
 */
static
int ssdfs_define_name_type(const char *name, size_t name_len,
			   u8 *name_type)
{
	size_t len;
	int i;
	int res;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!name || !name_type);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("name_len %zu\n", name_len);

	if (name_len == 0 || name_len > SSDFS_MAX_NAME_LEN) {
		*name_type = SSDFS_XATTR_NAME_UNKNOWN_TYPE;
		SSDFS_ERR("invalid name_len %zu\n",
			  name_len);
		return -ERANGE;
	}

	if (can_name_be_inline(name_len)) {
		i = SSDFS_USER_NS_INDEX;
		for (; i < SSDFS_REGISTERED_NS_NUMBER; i++) {
			len = min_t(size_t, name_len,
				    strlen(SSDFS_NS_PREFIX[i]));

			res = strncmp(name, SSDFS_NS_PREFIX[i], len);
			if (res == 0)
				break;
		}

		if (res != 0) {
			*name_type = SSDFS_XATTR_INLINE_NAME;
			return 0;
		}

		switch (i) {
		case SSDFS_USER_NS_INDEX:
			*name_type = SSDFS_XATTR_USER_INLINE_NAME;
			return 0;

		case SSDFS_TRUSTED_NS_INDEX:
			*name_type = SSDFS_XATTR_TRUSTED_INLINE_NAME;
			return 0;

		case SSDFS_SYSTEM_NS_INDEX:
			*name_type = SSDFS_XATTR_SYSTEM_INLINE_NAME;
			return 0;

		case SSDFS_SECURITY_NS_INDEX:
			*name_type = SSDFS_XATTR_SECURITY_INLINE_NAME;
			return 0;

		default:
			*name_type = SSDFS_XATTR_NAME_UNKNOWN_TYPE;
			SSDFS_ERR("unsupported index %d\n",
				  i);
			return -ERANGE;
		}
	} else {
		i = SSDFS_USER_NS_INDEX;
		for (; i < SSDFS_REGISTERED_NS_NUMBER; i++) {
			len = min_t(size_t, name_len,
				    strlen(SSDFS_NS_PREFIX[i]));

			res = strncmp(name, SSDFS_NS_PREFIX[i], len);
			if (res == 0)
				break;
		}

		if (res != 0) {
			*name_type = SSDFS_XATTR_REGULAR_NAME;
			return 0;
		}

		switch (i) {
		case SSDFS_USER_NS_INDEX:
			*name_type = SSDFS_XATTR_USER_REGULAR_NAME;
			return 0;

		case SSDFS_TRUSTED_NS_INDEX:
			*name_type = SSDFS_XATTR_TRUSTED_REGULAR_NAME;
			return 0;

		case SSDFS_SYSTEM_NS_INDEX:
			*name_type = SSDFS_XATTR_SYSTEM_REGULAR_NAME;
			return 0;

		case SSDFS_SECURITY_NS_INDEX:
			*name_type = SSDFS_XATTR_SECURITY_REGULAR_NAME;
			return 0;

		default:
			*name_type = SSDFS_XATTR_NAME_UNKNOWN_TYPE;
			SSDFS_ERR("unsupported index %d\n",
				  i);
			return -ERANGE;
		}
	}

	*name_type = SSDFS_XATTR_NAME_UNKNOWN_TYPE;
	return -ERANGE;
}

/*
 * ssdfs_define_name_length() - define name's length without prefix
 * @name: name string
 * @name_len: length of the name
 */
static
size_t ssdfs_define_name_length(const char *name, size_t name_len)
{
	size_t len;
	int i;
	int res;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!name);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("name_len %zu\n", name_len);

	i = SSDFS_USER_NS_INDEX;
	for (; i < SSDFS_REGISTERED_NS_NUMBER; i++) {
		len = min_t(size_t, name_len,
			    strlen(SSDFS_NS_PREFIX[i]));

		res = strncmp(name, SSDFS_NS_PREFIX[i], len);
		if (res == 0)
			break;
	}

	if (res != 0)
		return name_len;

	switch (i) {
	case SSDFS_USER_NS_INDEX:
	case SSDFS_TRUSTED_NS_INDEX:
	case SSDFS_SYSTEM_NS_INDEX:
	case SSDFS_SECURITY_NS_INDEX:
		return name_len - strlen(SSDFS_NS_PREFIX[i]);
	}

	return name_len;
}

/*
 * generate_value_hash() - generate the blob's hash
 * @value: pointer on xattr's blob
 * @size: size of the blob in bytes
 */
static inline
u64 generate_value_hash(const void *value, size_t size)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!value);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u64)crc32(~0, value, size);
}

/*
 * ssdfs_save_external_blob() - save the external blob
 * @fsi:  pointer on shared file system object
 * @ii: inode descriptor
 * @value: pointer on xattr's blob
 * @size: size of the blob in bytes
 * @desc: blob's extent descriptor [out]
 */
static
int ssdfs_save_external_blob(struct ssdfs_fs_info *fsi,
			     struct ssdfs_inode_info *ii,
			     const void *value, size_t size,
			     struct ssdfs_blob_extent *desc)
{
	struct ssdfs_segment_request *req;
	struct page *page;
	void *kaddr;
	int pages_count;
	size_t copied_data = 0;
	size_t cur_len;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !value || !ii || !desc);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, ino %lu, value %p, size %zu, desc %p\n",
		  fsi, ii->vfs_inode.i_ino, value, size, desc);

	memset(desc, 0xFF, sizeof(struct ssdfs_blob_extent));

	if (size == 0) {
		SSDFS_ERR("size == 0\n");
		return -ERANGE;
	}

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		return err;
	}

	ssdfs_request_init(req);
	ssdfs_get_request(req);

	ssdfs_request_prepare_logical_extent(ii->vfs_inode.i_ino,
					     0, size, 0, 0, req);

	pages_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;
	for (i = 0; i < pages_count; i++) {
		page = ssdfs_request_allocate_and_add_page(req);
		if (IS_ERR_OR_NULL(page)) {
			err = (page == NULL ? -ENOMEM : PTR_ERR(page));
			SSDFS_ERR("fail to allocate page: err %d\n",
				  err);
			goto finish_save_external_blob;
		}

		get_page(page);
		lock_page(page);

		kaddr = kmap_atomic(page);
		cur_len = min_t(size_t, PAGE_SIZE,
				size - copied_data);
		memcpy(kaddr, (u8 *)value + copied_data, cur_len);
		copied_data += cur_len;
		kunmap_atomic(kaddr);

		unlock_page(page);
		put_page(page);

		set_page_writeback(page);
	}

	err = ssdfs_segment_add_data_extent_async(fsi, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add external blob: "
			  "size %zu, err %d\n",
			  size, err);
		goto finish_save_external_blob;
	}

	desc->hash = cpu_to_le64(generate_value_hash(value, size));
	desc->extent.seg_id = cpu_to_le64(req->place.start.seg_id);
	desc->extent.logical_blk = cpu_to_le32(req->place.start.blk_index);
	desc->extent.len = cpu_to_le32(req->place.len);

	return 0;

finish_save_external_blob:
	for (i = 0; i < pagevec_count(&req->result.pvec); i++) {
		page = req->result.pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		end_page_writeback(page);
	}

	pagevec_release(&req->result.pvec);
	ssdfs_put_request(req);
	ssdfs_request_free(req);

	return err;
}

/*
 * __ssdfs_invalidate_external_blob() - invalidate external blob
 * @fsi:  pointer on shared file system object
 * @desc: blob's extent descriptor
 */
static inline
int __ssdfs_invalidate_external_blob(struct ssdfs_fs_info *fsi,
				     struct ssdfs_blob_extent *desc)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !desc);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, desc %p\n", fsi, desc);

	return ssdfs_invalidate_extent(fsi, &desc->extent);
}

/*
 * ssdfs_invalidate_external_blob() - invalidate external blob
 * @fsi:  pointer on shared file system object
 * @search: search object
 */
static
int ssdfs_invalidate_external_blob(struct ssdfs_fs_info *fsi,
				   struct ssdfs_btree_search *search)
{
	struct ssdfs_blob_extent *desc;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, search %p\n",
		  fsi, search);

	desc = &search->raw.xattr.header.blob.descriptor;
	return __ssdfs_invalidate_external_blob(fsi, desc);
}

/*
 * ssdfs_prepare_xattr() - prepare xattr object
 * @fsi:  pointer on shared file system object
 * @ii: inode descriptor
 * @name: name string
 * @name_len: length of the name
 * @value: pointer on xattr's blob
 * @size: size of the blob in bytes
 * @search: search object
 *
 * This method tries to prepare an xattr for adding into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_prepare_xattr(struct ssdfs_fs_info *fsi,
			struct ssdfs_inode_info *ii,
			const char *name, size_t name_len,
			const void *value, size_t size,
			struct ssdfs_btree_search *search)
{
	struct ssdfs_shared_dict_btree_info *dict;
	struct ssdfs_blob_extent extent;
	const char *inline_name = NULL;
	struct ssdfs_raw_xattr *xattr;
	u64 name_hash;
	u8 blob_type, name_type;
	size_t inline_len;
	u8 name_flags = 0, blob_flags = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !ii || !name || !value || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("name_len %zu, value_size %zu\n",
		  name_len, size);

	dict = fsi->shdictree;
	if (!dict) {
		SSDFS_ERR("shared dictionary is absent\n");
		return -ERANGE;
	}

	if (name_len == 0 || name_len > SSDFS_MAX_NAME_LEN) {
		SSDFS_ERR("invalid name_len %zu\n",
			  name_len);
		return -ERANGE;
	}

	if (size >= U16_MAX) {
		SSDFS_ERR("invalid blob_size %zu\n", size);
		return -ERANGE;
	}

	name_hash = ssdfs_generate_name_hash(name, name_len);
	if (name_hash == U64_MAX) {
		SSDFS_ERR("fail to generate name hash\n");
		return -ERANGE;
	}

	if (can_blob_be_inline(size)) {
		/* blob can be stored inline */
		blob_type = SSDFS_XATTR_INLINE_BLOB;
	} else {
		blob_type = SSDFS_XATTR_REGULAR_BLOB;
		blob_flags |= SSDFS_XATTR_HAS_EXTERNAL_BLOB;

		err = ssdfs_save_external_blob(fsi, ii,
						value, size,
						&extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store the blob: "
				  "size %zu, err %d\n",
				  size, err);
			return err;
		}
	}

	err = ssdfs_define_name_type(name, name_len,
				     &name_type);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define name's type: "
			  "name_len %zu, err %d\n",
			  name_len, err);
		goto invalidate_blob;
	}

	if (!can_name_be_inline(name_len)) {
		struct qstr str = QSTR_INIT(name, name_len);

		name_flags |= SSDFS_XATTR_HAS_EXTERNAL_STRING;

		err = ssdfs_shared_dict_save_name(dict,
						  name_hash,
						  &str);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store name: "
				  "hash %llx, err %d\n",
				  name_hash, err);
			goto invalidate_blob;
		}
	}

	inline_len = ssdfs_define_name_length(name, name_len);
	if (inline_len > name_len) {
		err = -ERANGE;
		SSDFS_ERR("inline_len %zu > name_len %zu\n",
			  inline_len, name_len);
		goto invalidate_blob;
	} else if (inline_len < name_len)
		inline_name = name + (name_len - inline_len);
	else
		inline_name = name;

	search->result.buf_state = SSDFS_BTREE_SEARCH_INLINE_BUFFER;
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */
	search->result.buf = &search->raw.xattr;
	search->result.buf_size = sizeof(struct ssdfs_raw_xattr);
	search->result.items_in_buffer = 1;

	xattr = &search->raw.xattr;

	xattr->header.name_hash = cpu_to_le64(name_hash);
	xattr->header.name_len = cpu_to_le16(inline_len);
	xattr->header.name_type = name_type;
	xattr->header.name_flags = name_flags;

	inline_len = min_t(size_t, inline_len, SSDFS_XATTR_INLINE_NAME_MAX_LEN);
	memcpy(xattr->header.inline_string, inline_name, inline_len);

	xattr->header.blob_len = cpu_to_le16((u16)size);
	xattr->header.blob_type = blob_type;
	xattr->header.blob_flags = blob_flags;

	if (blob_flags & SSDFS_XATTR_HAS_EXTERNAL_BLOB) {
		memcpy(&xattr->header.blob.descriptor,
			&extent, sizeof(struct ssdfs_blob_extent));
	} else if (size > SSDFS_XATTR_INLINE_BLOB_MAX_LEN) {
		err = -ERANGE;
		SSDFS_ERR("invalid size %zu\n", size);
		goto invalidate_blob;
	} else {
		memcpy(xattr->header.blob.inline_value.bytes,
			value, size);
	}

invalidate_blob:
	if (err && blob_type == SSDFS_XATTR_REGULAR_BLOB)
		__ssdfs_invalidate_external_blob(fsi, &extent);

	return err;
}

/*
 * ssdfs_xattrs_tree_add_inline_xattr() - add inline xattr into the tree
 * @tree: xattrs tree
 * @search: search object
 *
 * This method tries to add the inline xattr into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - inline tree hasn't room for the new xattr.
 * %-EEXIST     - xattr exists in the tree.
 */
static
int ssdfs_xattrs_tree_add_inline_xattr(struct ssdfs_xattrs_btree_info *tree,
					struct ssdfs_btree_search *search)
{
	struct ssdfs_xattr_entry *cur;
	int private_flags;
	u64 hash1, hash2;
	u16 start_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_XATTR:
	case SSDFS_INLINE_XATTR_ARRAY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid xattrs tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

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

	if (!tree->inline_xattrs) {
		SSDFS_ERR("empty inline tree %p\n",
			  tree->inline_xattrs);
		return -ERANGE;
	}

	if (!tree->owner) {
		SSDFS_ERR("empty owner inode\n");
		return -ERANGE;
	}

	private_flags = atomic_read(&tree->owner->private_flags);

	if (private_flags & SSDFS_INODE_HAS_INLINE_XATTR) {
		/*
		 * expected state
		 */
	} else if (private_flags & SSDFS_INODE_HAS_XATTR_BTREE) {
		SSDFS_ERR("the xattrs tree is generic\n");
		return -ERANGE;
	} else {
		SSDFS_ERR("the xattrs tree is absent\n");
		return -ERANGE;
	}

	if (tree->inline_count > tree->inline_capacity) {
		SSDFS_WARN("xattrs tree is corrupted: "
			   "inline_count %u, inline_capacity %u\n",
			   tree->inline_count,
			   tree->inline_capacity);
		atomic_set(&tree->state, SSDFS_XATTR_BTREE_CORRUPTED);
		return -ERANGE;
	} else if (tree->inline_count == tree->inline_capacity) {
		SSDFS_DBG("inline tree hasn't room for the new xattr: "
			  "inline_count %u, inline_capacity %u\n",
			  tree->inline_count,
			  tree->inline_capacity);
		return -ENOSPC;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND) {
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	hash1 = search->request.start.hash;
	hash2 = le64_to_cpu(search->raw.xattr.header.name_hash);

	if (hash1 != hash2) {
		SSDFS_ERR("corrupted xattr: "
			  "request hash %llx, "
			  "xattr hash %llx\n",
			  hash1, hash2);
		return -ERANGE;
	}

	start_index = search->result.start_index;

	if (tree->inline_count == 0) {
		if (start_index != 0) {
			SSDFS_ERR("invalid start_index %u\n",
				  start_index);
			return -ERANGE;
		}

		cur = &tree->inline_xattrs[start_index];

		memcpy(cur, &search->raw.xattr.header,
			sizeof(struct ssdfs_xattr_entry));
	} else {
		if (start_index >= tree->inline_count) {
			SSDFS_ERR("start_index %u >= inline_count %u\n",
				  start_index,
				  tree->inline_count);
			return -ERANGE;
		}

		cur = &tree->inline_xattrs[start_index];
		hash2 = le64_to_cpu(cur->name_hash);

		if (hash1 == hash2) {
			SSDFS_DBG("hash1 %llu == hash2 %llu\n",
				  hash1, hash2);
			return -EEXIST;
		}

		if ((start_index + 1) <= tree->inline_count) {
			memmove(&tree->inline_xattrs[start_index + 1],
				cur,
				(tree->inline_count - start_index) *
					sizeof(struct ssdfs_xattr_entry));
			memcpy(cur, &search->raw.xattr.header,
				sizeof(struct ssdfs_xattr_entry));

			hash1 = le64_to_cpu(cur->name_hash);

			cur = &tree->inline_xattrs[start_index + 1];

			hash2 = le64_to_cpu(cur->name_hash);
		} else {
			memcpy(cur, &search->raw.xattr.header,
				sizeof(struct ssdfs_xattr_entry));

			if (start_index > 0) {
				hash2 = le64_to_cpu(cur->name_hash);

				cur =
				    &tree->inline_xattrs[start_index - 1];

				hash1 = le64_to_cpu(cur->name_hash);
			}
		}

		if (hash1 < hash2) {
			/*
			 * Correct order. Do nothing.
			 */
		} else {
			SSDFS_ERR("invalid hash order: "
				  "hash1 %llu, hash2 %llu\n",
				  hash1, hash2);
			atomic_set(&tree->state,
				    SSDFS_XATTR_BTREE_CORRUPTED);
			return -ERANGE;
		}
	}

	tree->inline_count++;
	if (tree->inline_count > tree->inline_capacity) {
		SSDFS_WARN("inline_count is too much: "
			   "count %u, capacity %u\n",
			   tree->inline_count,
			   tree->inline_capacity);
		atomic_set(&tree->state, SSDFS_XATTR_BTREE_CORRUPTED);
		return -ERANGE;
	}

	atomic_set(&tree->state, SSDFS_XATTR_BTREE_DIRTY);
	return 0;
}

/*
 * ssdfs_xattrs_tree_add_xattr() - add the xattr into the generic tree
 * @tree: xattrs tree
 * @search: search object
 *
 * This method tries to add the xattr into the generic tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - xattr exists in the tree.
 */
static
int ssdfs_xattrs_tree_add_xattr(struct ssdfs_xattrs_btree_info *tree,
				struct ssdfs_btree_search *search)
{
	u64 hash1, hash2;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->type)) {
	case SSDFS_PRIVATE_XATTR_BTREE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid xattrs tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

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

	if (!tree->generic_tree) {
		SSDFS_ERR("empty generic tree %p\n",
			  tree->generic_tree);
		return -ERANGE;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND) {
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	hash1 = search->request.start.hash;
	hash2 = le64_to_cpu(search->raw.xattr.header.name_hash);

	if (hash1 != hash2) {
		SSDFS_ERR("corrupted xattr: "
			  "requested hash %llx, "
			  "xattr's hash %llx\n",
			  hash1, hash2);
		return -ERANGE;
	}

	err = ssdfs_btree_add_item(tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add the xattr into the tree: "
			  "err %d\n", err);
		return err;
	}

	atomic_set(&tree->state, SSDFS_XATTR_BTREE_DIRTY);
	return 0;
}

/*
 * ssdfs_migrate_inline2generic_tree() - convert inline tree into generic
 * @tree: xattrs tree
 *
 * This method tries to convert the inline tree into generic one.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EFAULT     - the tree is empty.
 */
static
int ssdfs_migrate_inline2generic_tree(struct ssdfs_xattrs_btree_info *tree)
{
	struct ssdfs_xattr_entry *xattrs = NULL;
	struct ssdfs_xattr_entry xattr_buf;
	struct ssdfs_xattr_entry *cur = NULL;
	size_t xattr_size = sizeof(struct ssdfs_xattr_entry);
	struct ssdfs_btree_search *search;
	size_t buf_size;
	int private_flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", tree);

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_XATTR:
	case SSDFS_INLINE_XATTR_ARRAY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid xattrs tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

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

	if (!tree->owner) {
		SSDFS_ERR("empty owner inode\n");
		return -ERANGE;
	}

	private_flags = atomic_read(&tree->owner->private_flags);
	if (private_flags & SSDFS_INODE_HAS_XATTR_BTREE) {
		SSDFS_ERR("the xattrs tree is generic\n");
		return -ERANGE;
	}

	if (tree->inline_count > tree->inline_capacity) {
		SSDFS_WARN("xattrs tree is corrupted: "
			   "inline_count %u, inline_capacity %u\n",
			   tree->inline_count,
			   tree->inline_capacity);
		atomic_set(&tree->state, SSDFS_XATTR_BTREE_CORRUPTED);
		return -ERANGE;
	} else if (tree->inline_count == 0) {
		SSDFS_DBG("empty tree\n");
		return -EFAULT;
	} else if (tree->inline_count < tree->inline_capacity) {
		SSDFS_WARN("inline_count %u, inline_capacity %u\n",
			   tree->inline_count,
			   tree->inline_capacity);
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree->inline_xattrs || tree->generic_tree);
#endif /* CONFIG_SSDFS_DEBUG */

	buf_size = xattr_size * tree->inline_capacity;

	if (tree->inline_capacity == 0) {
		SSDFS_ERR("inline_capacity == 0\n");
		return -ERANGE;
	} else if (tree->inline_capacity == 1) {
		/* use the buffer on stack */
		xattrs = &xattr_buf;
		memcpy(xattrs, tree->inline_xattrs, buf_size);
	} else {
		xattrs = kmalloc(buf_size, GFP_KERNEL);
		if (!xattrs) {
			SSDFS_ERR("fail to allocate memory: "
				  "size %zu\n", buf_size);
			return -ENOMEM;
		}

		memcpy(xattrs, tree->inline_xattrs, buf_size);
		kfree(tree->inline_xattrs);
	}

	err = ssdfs_btree_create(tree->fsi,
				 tree->owner->vfs_inode.i_ino,
				 &ssdfs_xattrs_btree_desc_ops,
				 &ssdfs_xattrs_btree_ops,
				 &tree->buffer.tree);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create generic tree: err %d\n",
			  err);
		goto recover_inline_tree;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto destroy_generic_tree;
	}

	ssdfs_btree_search_init(search);
	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
	search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;

	cur = &xattrs[0];
	search->request.start.hash = le64_to_cpu(cur->name_hash);
	if (tree->inline_count > 1) {
		cur = &xattrs[tree->inline_count - 1];
		search->request.end.hash = le64_to_cpu(cur->name_hash);
	} else
		search->request.end.hash = search->request.start.hash;

	search->request.count = tree->inline_count;

	err = ssdfs_btree_find_item(&tree->buffer.tree, search);
	if (err == -ENODATA) {
		/* expected error */
		err = 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find item: "
			  "start (hash %llx, ino %llu), "
			  "end (hash %llx, ino %llu), err %d\n",
			  search->request.start.hash,
			  search->request.start.ino,
			  search->request.end.hash,
			  search->request.end.ino,
			  err);
		goto finish_add_range;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND) {
		err = -ERANGE;
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		goto finish_add_range;
	}

	if (search->result.buf) {
		err = -ERANGE;
		SSDFS_ERR("search->result.buf %p\n",
			  search->result.buf);
		goto finish_add_range;
	}

	if (tree->inline_count == 1) {
		search->result.buf_state = SSDFS_BTREE_SEARCH_INLINE_BUFFER;
		search->result.buf_size = sizeof(struct ssdfs_xattr_entry);
		search->result.items_in_buffer = tree->inline_count;
		search->result.buf = &search->raw.xattr;
		memcpy(&search->raw.xattr, xattrs, search->result.buf_size);
	} else {
		search->result.buf_state = SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER;
		search->result.buf_size = buf_size;
		search->result.items_in_buffer = tree->inline_count;
		search->result.buf = kmalloc(search->result.buf_size,
					     GFP_KERNEL);
		if (!search->result.buf) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate memory for buffer\n");
			goto finish_add_range;
		}
		memcpy(search->result.buf, xattrs, search->result.buf_size);
	}

	err = ssdfs_btree_add_range(&tree->buffer.tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add the range into tree: "
			   "start_hash %llx, end_hash %llx, err %d\n",
			   search->request.start.hash,
			   search->request.end.hash,
			   err);
		goto finish_add_range;
	}

finish_add_range:
	ssdfs_btree_search_free(search);

	if (unlikely(err))
		goto destroy_generic_tree;

	atomic_set(&tree->type, SSDFS_PRIVATE_XATTR_BTREE);
	atomic_set(&tree->state, SSDFS_XATTR_BTREE_DIRTY);
	tree->generic_tree = &tree->buffer.tree;

	if (tree->inline_capacity > 1) {
		kfree(xattrs);
		kfree(tree->inline_xattrs);
	}

	tree->inline_count = 0;
	tree->inline_capacity = 0;
	tree->inline_xattrs = NULL;

	atomic_or(SSDFS_INODE_HAS_XATTR_BTREE,
		  &tree->owner->private_flags);
	atomic_and(~SSDFS_INODE_HAS_INLINE_XATTR,
		  &tree->owner->private_flags);
	return 0;

destroy_generic_tree:
	ssdfs_btree_destroy(&tree->buffer.tree);

recover_inline_tree:
	memcpy(tree->inline_xattrs, xattrs, buf_size);
	tree->generic_tree = NULL;

	if (tree->inline_capacity > 1)
		kfree(xattrs);

	return err;
}

/*
 * ssdfs_xattrs_tree_add() - add the xattr into the tree
 * @tree: xattrs tree
 * @name: xattr's name
 * @name_len: length of the name
 * @value: xattr's blob
 * @size: size of the blob
 * @ii: inode info
 * @search: search object
 *
 * This method tries to add the extended attribute into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - xattr exists in the tree.
 */
int ssdfs_xattrs_tree_add(struct ssdfs_xattrs_btree_info *tree,
			 const char *name, size_t name_len,
			 const void *value, size_t size,
			 struct ssdfs_inode_info *ii,
			 struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_shared_dict_btree_info *dict;
	u64 name_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !name || !value || !ii || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, ii %p, ino %lu\n",
		  tree, ii, ii->vfs_inode.i_ino);

	fsi = tree->fsi;
	dict = fsi->shdictree;
	if (!dict) {
		SSDFS_ERR("shared dictionary is absent\n");
		return -ERANGE;
	}

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	name_hash = ssdfs_generate_name_hash(name, name_len);
	if (name_hash == U64_MAX) {
		SSDFS_ERR("fail to generate name hash\n");
		return -ERANGE;
	}

	if (need_initialize_xattrs_btree_search(name_hash, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT |
			SSDFS_BTREE_SEARCH_HAS_VALID_NAME;
		search->request.start.hash = name_hash;
		search->request.start.name = name;
		search->request.start.name_len = name_len;
		search->request.end.hash = name_hash;
		search->request.end.name = name;
		search->request.end.name_len = name_len;
		search->request.count = 1;
	}

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
		down_write(&tree->lock);

		err = ssdfs_xattrs_tree_find_inline_xattr(tree, search);
		if (err == -ENODATA) {
			/*
			 * Xattr doesn't exist for requested name hash.
			 * It needs to create a new xattr.
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find the inline xattr: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_add_inline_xattr;
		}

		if (err == -ENODATA) {
			err = ssdfs_prepare_xattr(fsi, ii, name, name_len,
						  value, size, search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare the xattr: "
					  "name_hash %llx, ino %lu, "
					  "err %d\n",
					  name_hash,
					  ii->vfs_inode.i_ino,
					  err);
				goto finish_add_inline_xattr;
			}

			search->request.type = SSDFS_BTREE_SEARCH_ADD_ITEM;
			err = ssdfs_xattrs_tree_add_inline_xattr(tree,
								 search);
			if (err == -ENOSPC) {
				err = ssdfs_migrate_inline2generic_tree(tree);
				if (unlikely(err)) {
					SSDFS_ERR("fail to migrate the tree: "
						  "err %d\n",
						  err);
					goto invalidate_blob_inline_xattr;
				} else {
					search->request.type =
						SSDFS_BTREE_SEARCH_FIND_ITEM;
					downgrade_write(&tree->lock);
					goto try_to_add_into_generic_tree;
				}
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to add the xattr: "
					  "name_hash %llx, ino %lu, "
					  "err %d\n",
					  name_hash,
					  ii->vfs_inode.i_ino,
					  err);
				goto invalidate_blob_inline_xattr;
			}

invalidate_blob_inline_xattr:
			if (err && !can_blob_be_inline(size)) {
				ssdfs_invalidate_external_blob(fsi, search);
				goto finish_add_inline_xattr;
			}
		} else {
			err = -EEXIST;
			SSDFS_DBG("xattr exists in the tree: "
				  "name_hash %llx, ino %lu\n",
				  name_hash, ii->vfs_inode.i_ino);
			goto finish_add_inline_xattr;
		}

finish_add_inline_xattr:
		up_write(&tree->lock);
		break;

	case SSDFS_INLINE_XATTR_ARRAY:
		/* TODO: implement support */
		break;

	case SSDFS_PRIVATE_XATTR_BTREE:
		down_read(&tree->lock);

try_to_add_into_generic_tree:
		err = ssdfs_btree_find_item(tree->generic_tree, search);
		if (err == -ENODATA) {
			/*
			 * Xattr doesn't exist for requested name.
			 * It needs to create a new xattr.
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find the xattr: "
				  "name_hash %llx, ino %lu, "
				  "err %d\n",
				  name_hash,
				  ii->vfs_inode.i_ino,
				  err);
			goto finish_add_generic_xattr;
		}

		if (err == -ENODATA) {
			err = ssdfs_prepare_xattr(fsi, ii, name, name_len,
						  value, size, search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare the xattr: "
					  "name_hash %llx, ino %lu, "
					  "err %d\n",
					  name_hash,
					  ii->vfs_inode.i_ino,
					  err);
				goto invalidate_blob_generic_xattr;
			}

			search->request.type = SSDFS_BTREE_SEARCH_ADD_ITEM;
			err = ssdfs_xattrs_tree_add_xattr(tree, search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add the xattr: "
					  "name_hash %llx, ino %lu, "
					  "err %d\n",
					  name_hash,
					  ii->vfs_inode.i_ino,
					  err);
				goto invalidate_blob_generic_xattr;
			}

invalidate_blob_generic_xattr:
			if (err && !can_blob_be_inline(size)) {
				ssdfs_invalidate_external_blob(fsi, search);
				goto finish_add_generic_xattr;
			}
		} else {
			err = -EEXIST;
			SSDFS_DBG("xattr exists in the tree: "
				  "name_hash %llx, ino %lu\n",
				  name_hash, ii->vfs_inode.i_ino);
			goto finish_add_generic_xattr;
		}

finish_add_generic_xattr:
		up_read(&tree->lock);
		break;

	default:
		SSDFS_ERR("invalid xattrs tree type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	return err;
}

/*
 * ssdfs_change_xattr() - change the existing xattr object
 * @fsi:  pointer on shared file system object
 * @ii: inode descriptor
 * @name: name string
 * @name_len: length of the name
 * @value: pointer on xattr's blob
 * @size: size of the blob in bytes
 * @search: search object
 *
 * This method tries to change the existing xattr in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_change_xattr(struct ssdfs_fs_info *fsi,
			struct ssdfs_inode_info *ii,
			const char *name, size_t name_len,
			const void *value, size_t size,
			struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_xattr *xattr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !ii || !name || !value || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("name_len %zu, value_size %zu\n",
		  name_len, size);

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER ||
	    !search->result.buf ||
	    search->result.buf_size != sizeof(struct ssdfs_raw_xattr)) {
		SSDFS_ERR("invalid buffer state: "
			  "state %#x, buf %p\n",
			  search->result.buf_state,
			  search->result.buf);
		return -ERANGE;
	}

	xattr = &search->raw.xattr;

	switch (xattr->header.blob_type) {
	case SSDFS_XATTR_INLINE_BLOB:
		if (xattr->header.blob_flags & SSDFS_XATTR_HAS_EXTERNAL_BLOB) {
			SSDFS_ERR("invalid blob flags %#x\n",
				  xattr->header.blob_flags);
			return -EIO;
		}

		memset(xattr->header.blob.inline_value.bytes, 0,
			SSDFS_XATTR_INLINE_BLOB_MAX_LEN);
		break;

	case SSDFS_XATTR_REGULAR_BLOB:
		if (xattr->header.blob_flags & ~SSDFS_XATTR_HAS_EXTERNAL_BLOB) {
			SSDFS_ERR("invalid blob flags %#x\n",
				  xattr->header.blob_flags);
			return -EIO;
		}

		err = ssdfs_invalidate_external_blob(fsi, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to invalidate external blob: "
				  "err %d\n", err);
			return err;
		}
		break;

	default:
		SSDFS_ERR("invalid blob type %#x\n",
			  xattr->header.blob_type);
		return -EIO;
	}

	return ssdfs_prepare_xattr(fsi, ii,
				   name, name_len,
				   value, size,
				   search);
}

/*
 * ssdfs_xattrs_tree_change_inline_xattr() - change inline xattr
 * @tree: xattrs tree
 * @search: search object
 *
 * This method tries to change the existing inline xattr.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - xattr doesn't exist in the tree.
 */
static
int ssdfs_xattrs_tree_change_inline_xattr(struct ssdfs_xattrs_btree_info *tree,
					  struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_xattr *cur1;
	struct ssdfs_xattr_entry *cur2;
	u64 hash1, hash2;
	u16 start_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_XATTR:
	case SSDFS_INLINE_XATTR_ARRAY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid xattrs tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

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

	if (!tree->inline_xattrs) {
		SSDFS_ERR("empty inline tree %p\n",
			  tree->inline_xattrs);
		return -ERANGE;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_VALID_ITEM) {
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	hash1 = search->request.start.hash;

	cur1 = &search->raw.xattr;
	hash2 = le64_to_cpu(cur1->header.name_hash);

	if (hash1 != hash2) {
		SSDFS_ERR("hash1 %llu, hash2 %llu\n",
			  hash1, hash2);
		return -ERANGE;
	}

	if (!tree->owner) {
		SSDFS_ERR("empty owner inode\n");
		return -ERANGE;
	}

	if (tree->inline_count > tree->inline_capacity) {
		SSDFS_WARN("xattrs tree is corrupted: "
			   "inline_count %u, inline_capacity %u\n",
			   tree->inline_count,
			   tree->inline_capacity);
		atomic_set(&tree->state, SSDFS_XATTR_BTREE_CORRUPTED);
		return -ERANGE;
	} else if (tree->inline_count == 0) {
		SSDFS_DBG("empty tree\n");
		return -EFAULT;
	}

	start_index = search->result.start_index;

	if (start_index >= tree->inline_count) {
		SSDFS_ERR("start_index %u >= inline_count %u\n",
			  start_index, tree->inline_count);
		return -ENODATA;
	}

	cur2 = &tree->inline_xattrs[start_index];
	memcpy(cur2, &search->raw.xattr.header,
		sizeof(struct ssdfs_xattr_entry));
	atomic_set(&tree->state, SSDFS_XATTR_BTREE_DIRTY);

	return 0;
}

/*
 * ssdfs_xattrs_tree_change_xattr() - change the generic xattr
 * @tree: xattrs tree
 * @search: search object
 *
 * This method tries to change the existing generic xattr.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - xattr doesn't exist in the tree.
 */
static
int ssdfs_xattrs_tree_change_xattr(struct ssdfs_xattrs_btree_info *tree,
				   struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_xattr *cur;
	u64 hash1, hash2;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->type)) {
	case SSDFS_PRIVATE_XATTR_BTREE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid xattrs tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

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

	if (!tree->generic_tree) {
		SSDFS_ERR("empty generic tree %p\n",
			  tree->generic_tree);
		return -ERANGE;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_VALID_ITEM) {
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	hash1 = search->request.start.hash;

	cur = &search->raw.xattr;
	hash2 = le64_to_cpu(cur->header.name_hash);

	if (hash1 != hash2) {
		SSDFS_ERR("hash1 %llu, hash2 %llu\n",
			  hash1, hash2);
		return -ERANGE;
	}

	err = ssdfs_btree_change_item(tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change the xattr in the tree: "
			  "err %d\n", err);
		return err;
	}

	atomic_set(&tree->state, SSDFS_XATTR_BTREE_DIRTY);
	return 0;
}

/*
 * ssdfs_xattrs_tree_change() - change xattr in the tree
 * @tree: xattrs tree
 * @name_hash: hash of the name
 * @name: name string of xattr
 * @name_len: length of the name
 * @value: blob pointer
 * @size: size of the blob in bytes
 * @search: search object
 *
 * This method tries to change xattr in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - xattr doesn't exist in the tree.
 */
int ssdfs_xattrs_tree_change(struct ssdfs_xattrs_btree_info *tree,
			    u64 name_hash,
			    const char *name, size_t name_len,
			    const void *value, size_t size,
			    struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !name || !value || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p, "
		  "name_hash %llx, name_size %zu, "
		  "value_size %zu\n",
		  tree, search, name_hash, name_len, size);

	fsi = tree->fsi;

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

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_xattrs_btree_search(name_hash, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
		search->request.start.hash = name_hash;
		search->request.start.name = NULL;
		search->request.start.name_len = U32_MAX;
		search->request.end.hash = name_hash;
		search->request.end.name = NULL;
		search->request.end.name_len = U32_MAX;
		search->request.count = 1;
	}

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_XATTR:
	case SSDFS_INLINE_XATTR_ARRAY:
		down_write(&tree->lock);

		err = ssdfs_xattrs_tree_find_inline_xattr(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the inline xattr: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_change_inline_xattr;
		}

		err = ssdfs_change_xattr(fsi, tree->owner,
					 name, name_len,
					 value, size,
					 search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change xattr: err %d\n",
				  err);
			goto finish_change_inline_xattr;
		}

		search->request.type = SSDFS_BTREE_SEARCH_CHANGE_ITEM;

		err = ssdfs_xattrs_tree_change_inline_xattr(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change inline xattr: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_change_inline_xattr;
		}

finish_change_inline_xattr:
		up_write(&tree->lock);
		break;

	case SSDFS_PRIVATE_XATTR_BTREE:
		down_read(&tree->lock);

		err = ssdfs_btree_find_item(tree->generic_tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the xattr: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_change_generic_xattr;
		}

		err = ssdfs_change_xattr(fsi, tree->owner,
					 name, name_len,
					 value, size,
					 search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change xattr: err %d\n",
				  err);
			goto finish_change_generic_xattr;
		}

		search->request.type = SSDFS_BTREE_SEARCH_CHANGE_ITEM;

		err = ssdfs_xattrs_tree_change_xattr(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change xattr: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_change_generic_xattr;
		}

finish_change_generic_xattr:
		up_read(&tree->lock);
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid xattrs tree type %#x\n",
			  atomic_read(&tree->type));
		break;
	}

	return err;
}

/*
 * ssdfs_xattrs_tree_delete_inline_xattr() - delete inline xattr
 * @tree: xattrs tree
 * @search: search object
 *
 * This method tries to delete the inline xattr from the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - xattr doesn't exist in the tree.
 * %-ENOENT     - no more xattrs in the tree.
 */
static
int ssdfs_xattrs_tree_delete_inline_xattr(struct ssdfs_xattrs_btree_info *tree,
					  struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_raw_xattr *cur;
	struct ssdfs_xattr_entry *xattr1, *xattr2;
	u64 hash1, hash2;
	u16 index;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	fsi = tree->fsi;

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_XATTR:
	case SSDFS_INLINE_XATTR_ARRAY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid xattrs tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

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

	if (!tree->inline_xattrs) {
		SSDFS_ERR("empty inline tree %p\n",
			  tree->inline_xattrs);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	if (!search->result.buf) {
		SSDFS_ERR("empty buffer pointer\n");
		return -ERANGE;
	}

	hash1 = search->request.start.hash;

	cur = &search->raw.xattr;
	hash2 = le64_to_cpu(cur->header.name_hash);

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		if (hash1 != hash2) {
			SSDFS_ERR("hash1 %llu, hash2 %llu\n",
				  hash1, hash2);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_WARN("unexpected result state %#x\n",
			   search->result.state);
		return -ERANGE;
	}

	if (tree->inline_count == 0) {
		SSDFS_DBG("empty tree\n");
		return -ENOENT;
	} else if (tree->inline_count > tree->inline_capacity) {
		SSDFS_ERR("invalid xattrs count %u\n",
			  tree->inline_count);
		return -ERANGE;
	}

	if (search->result.start_index >= tree->inline_count) {
		SSDFS_ERR("invalid search result: "
			  "start_index %u, inline_count %u\n",
			  search->result.start_index,
			  tree->inline_count);
		return -ENODATA;
	}

	index = search->result.start_index;
	xattr1 = &tree->inline_xattrs[index];

	switch (xattr1->blob_type) {
	case SSDFS_XATTR_INLINE_BLOB:
		if (xattr1->blob_flags & SSDFS_XATTR_HAS_EXTERNAL_BLOB) {
			SSDFS_ERR("invalid xattr: "
				  "blob_type %#x, blob_flags %#x\n",
				  xattr1->blob_type,
				  xattr1->blob_flags);
			return -ERANGE;
		}
		break;

	case SSDFS_XATTR_REGULAR_BLOB:
		if (xattr1->blob_flags & ~SSDFS_XATTR_HAS_EXTERNAL_BLOB) {
			SSDFS_ERR("invalid xattr: "
				  "blob_type %#x, blob_flags %#x\n",
				  xattr1->blob_type,
				  xattr1->blob_flags);
			return -ERANGE;
		}

		err = __ssdfs_invalidate_external_blob(fsi,
						&xattr1->blob.descriptor);
		if (unlikely(err)) {
			SSDFS_ERR("fail to make the blob pre-invalid: "
				  "index %u, err %d\n",
				  index, err);
			return err;
		}
		break;

	default:
		SSDFS_ERR("invalid blob_type %#x\n",
			  xattr1->blob_type);
		return -ERANGE;
	}

	if ((index + 1) < tree->inline_count) {
		xattr1 = &tree->inline_xattrs[index];
		xattr2 = &tree->inline_xattrs[index + 1];

		memmove(xattr1, xattr2,
			(tree->inline_count - index) *
			sizeof(struct ssdfs_xattr_entry));
	}

	index = (u16)(tree->inline_count - 1);
	xattr1 = &tree->inline_xattrs[index];
	memset(xattr1, 0xFF, sizeof(struct ssdfs_xattr_entry));

	atomic_set(&tree->state, SSDFS_XATTR_BTREE_DIRTY);

	if (tree->inline_count == 0) {
		SSDFS_WARN("invalid inline_count %u\n",
			   tree->inline_count);
		atomic_set(&tree->state, SSDFS_XATTR_BTREE_CORRUPTED);
		return -ERANGE;
	}

	tree->inline_count--;

	if (tree->inline_count == 0) {
		SSDFS_DBG("tree is empty now\n");
		return -ENOENT;
	}

	return 0;
}

/*
 * ssdfs_xattrs_tree_delete_xattr() - delete generic xattr
 * @tree: xattrs tree
 * @search: search object
 *
 * This method tries to delete the generic xattr from the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - xattr doesn't exist in the tree.
 * %-ENOENT     - no more xattrs in the tree.
 */
static
int ssdfs_xattrs_tree_delete_xattr(struct ssdfs_xattrs_btree_info *tree,
				   struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_xattr *cur;
	u64 hash1, hash2;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->type)) {
	case SSDFS_PRIVATE_XATTR_BTREE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid xattrs tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

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

	if (!tree->generic_tree) {
		SSDFS_ERR("empty generic tree %p\n",
			  tree->generic_tree);
		return -ERANGE;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_VALID_ITEM) {
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	hash1 = search->request.start.hash;

	cur = &search->raw.xattr;
	hash2 = le64_to_cpu(cur->header.name_hash);

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		if (hash1 != hash2) {
			SSDFS_ERR("hash1 %llu, hash2 %llu\n",
				  hash1, hash2);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_WARN("unexpected result state %#x\n",
			   search->result.state);
		return -ERANGE;
	}

	err = ssdfs_btree_delete_item(tree->generic_tree,
				      search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete the xattr from the tree: "
			  "err %d\n", err);
		return err;
	}

	atomic_set(&tree->state, SSDFS_XATTR_BTREE_DIRTY);

	return 0;
}

/*
 * ssdfs_migrate_generic2inline_tree() - convert generic tree into inline
 * @tree: xattrs tree
 *
 * This method tries to convert the generic tree into inline one.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - the tree cannot be converted into inline again.
 */
static
int ssdfs_migrate_generic2inline_tree(struct ssdfs_xattrs_btree_info *tree)
{
	struct ssdfs_btree_search *search;
	struct ssdfs_xattr_entry *xattrs = NULL;
	struct ssdfs_xattr_entry xattr_buf;
	size_t xattr_size = sizeof(struct ssdfs_xattr_entry);
	u32 private_flags;
	u16 inline_capacity;
	u16 found_range = 0;
	size_t buf_size = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", tree);

	switch (atomic_read(&tree->type)) {
	case SSDFS_PRIVATE_XATTR_BTREE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid xattrs tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

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

	if (!tree->owner) {
		SSDFS_ERR("empty owner inode\n");
		return -ERANGE;
	}

	private_flags = atomic_read(&tree->owner->private_flags);
	if (!(private_flags & SSDFS_INODE_HAS_XATTR_BTREE)) {
		SSDFS_ERR("the xattrs tree is not generic\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(tree->inline_xattrs || !tree->generic_tree);
#endif /* CONFIG_SSDFS_DEBUG */

	inline_capacity = ssdfs_calculate_inline_capacity(tree->fsi);
	if (inline_capacity >= U16_MAX) {
		SSDFS_ERR("invalid inline_capacity %u\n",
			  inline_capacity);
		return -ERANGE;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);
	search->request.type = SSDFS_BTREE_SEARCH_FIND_RANGE;
	search->request.flags = 0;
	search->request.start.hash = U64_MAX;
	search->request.end.hash = U64_MAX;
	search->request.count = 0;

	err = ssdfs_btree_get_head_range(&tree->buffer.tree,
					 inline_capacity, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract xattrs: "
			  "inline_capacity %u, err %d\n",
			  inline_capacity, err);
		goto finish_process_range;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_VALID_ITEM) {
		err = -ERANGE;
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		goto finish_process_range;
	}

	switch (search->result.buf_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
		if (search->result.items_in_buffer != 1) {
			err = -ERANGE;
			SSDFS_ERR("invalid items_in_buffer %u\n",
				  search->result.items_in_buffer);
			goto finish_process_range;
		}

		if (!search->result.buf) {
			err = -ERANGE;
			SSDFS_ERR("empty buffer\n");
			goto finish_process_range;
		}

		xattrs = &xattr_buf;
		found_range = search->result.items_in_buffer;
		buf_size = xattr_size;
		memcpy(xattrs, search->result.buf, xattr_size);
		break;

	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		if (search->result.items_in_buffer <= 1 ||
		    search->result.items_in_buffer > inline_capacity) {
			err = -ERANGE;
			SSDFS_ERR("invalid items_in_buffer %u\n",
				  search->result.items_in_buffer);
			goto finish_process_range;
		}

		if (!search->result.buf) {
			err = -ERANGE;
			SSDFS_ERR("empty buffer\n");
			goto finish_process_range;
		}

		found_range = search->result.items_in_buffer;
		buf_size = found_range * xattr_size;
		xattrs = kmalloc(buf_size, GFP_KERNEL);
		if (!xattrs) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate memory: "
				  "size %zu\n",
				  buf_size);
			goto finish_process_range;
		}

		memcpy(xattrs, search->result.buf, buf_size);
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid buffer's state %#x\n",
			  search->result.buf_state);
		goto finish_process_range;
	}

	search->request.type = SSDFS_BTREE_SEARCH_DELETE_RANGE;
	search->request.flags = SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
				SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
	search->request.start.hash = le64_to_cpu(xattrs[0].name_hash);
	search->request.end.hash =
		le64_to_cpu(xattrs[found_range - 1].name_hash);
	search->request.count = found_range;

	err = ssdfs_btree_delete_range(&tree->buffer.tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete range: "
			  "start_hash %llx, "
			  "end_hash %llx, "
			  "count %u, err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  search->request.count,
			  err);
		goto finish_process_range;
	}

	if (!is_ssdfs_btree_empty(&tree->buffer.tree)) {
		err = -ERANGE;
		SSDFS_WARN("xattrs tree is not empty\n");
		atomic_set(&tree->state, SSDFS_XATTR_BTREE_CORRUPTED);
		goto finish_process_range;
	}

	search->result.state = SSDFS_BTREE_SEARCH_PLEASE_DELETE_NODE;

	err = ssdfs_btree_delete_node(&tree->buffer.tree, search);
	if (unlikely(err)) {
		SSDFS_WARN("fail to delete node %u\n",
			   search->node.id);
		atomic_set(&tree->state, SSDFS_XATTR_BTREE_CORRUPTED);
		goto finish_process_range;
	}

	err = ssdfs_btree_destroy_node_range(&tree->buffer.tree,
					     0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to destroy nodes' range: err %d\n",
			  err);
		goto finish_process_range;
	}

finish_process_range:
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		if (buf_size > xattr_size && xattrs)
			kfree(xattrs);

		return err;
	}

	ssdfs_btree_destroy(&tree->buffer.tree);

	if (buf_size == xattr_size) {
		memcpy(&tree->buffer.xattr, xattrs, xattr_size);
		tree->inline_xattrs = &tree->buffer.xattr;
		atomic_set(&tree->type, SSDFS_INLINE_XATTR);
	} else {
		tree->inline_xattrs = xattrs;
		xattrs = NULL;
		atomic_set(&tree->type, SSDFS_INLINE_XATTR_ARRAY);
	}

	tree->generic_tree = NULL;
	tree->inline_count = found_range;
	tree->inline_capacity = inline_capacity;

	atomic_set(&tree->state, SSDFS_XATTR_BTREE_DIRTY);

	atomic_and(~SSDFS_INODE_HAS_XATTR_BTREE,
		   &tree->owner->private_flags);
	atomic_or(SSDFS_INODE_HAS_INLINE_XATTR,
		   &tree->owner->private_flags);

	return 0;
}

/*
 * ssdfs_xattrs_tree_delete() - delete xattr from the tree
 * @tree: xattrs tree
 * @name_hash: hash of the name
 * @search: search object
 *
 * This method tries to delete xattr from the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - xattr doesn't exist in the tree.
 */
int ssdfs_xattrs_tree_delete(struct ssdfs_xattrs_btree_info *tree,
			     u64 name_hash,
			     struct ssdfs_btree_search *search)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p, name_hash %llx\n",
		  tree, search, name_hash);

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

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_xattrs_btree_search(name_hash, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
		search->request.start.hash = name_hash;
		search->request.start.name = NULL;
		search->request.start.name_len = U32_MAX;
		search->request.end.hash = name_hash;
		search->request.end.name = NULL;
		search->request.end.name_len = U32_MAX;
		search->request.count = 1;
	}

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_XATTR:
	case SSDFS_INLINE_XATTR_ARRAY:
		down_write(&tree->lock);

		err = ssdfs_xattrs_tree_find_inline_xattr(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the inline xattr: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_delete_inline_xattr;
		}

		search->request.type = SSDFS_BTREE_SEARCH_DELETE_ITEM;

		err = ssdfs_xattrs_tree_delete_inline_xattr(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to delete xattr: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_delete_inline_xattr;
		}

finish_delete_inline_xattr:
		up_write(&tree->lock);
		break;

	case SSDFS_PRIVATE_XATTR_BTREE:
		down_read(&tree->lock);

		err = ssdfs_btree_find_item(tree->generic_tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the xattr: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_delete_generic_xattr;
		}

		search->request.type = SSDFS_BTREE_SEARCH_DELETE_ITEM;

		err = ssdfs_xattrs_tree_delete_xattr(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to delete xattr: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_delete_generic_xattr;
		}

finish_delete_generic_xattr:
		up_read(&tree->lock);

		if (!err && is_ssdfs_btree_empty(tree->generic_tree)) {
			down_write(&tree->lock);
			err = ssdfs_migrate_generic2inline_tree(tree);
			up_write(&tree->lock);

			if (err == -ENOSPC) {
				/* continue to use the generic tree */
				err = 0;
				SSDFS_DBG("unable to re-create inline tree\n");
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to re-create inline tree: "
					  "err %d\n",
					  err);
			}
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid xattrs tree type %#x\n",
			  atomic_read(&tree->type));
		break;
	}

	return err;
}

/*
 * ssdfs_delete_all_inline_xattrs() - delete all inline xattrs
 * @tree: xattrs tree
 *
 * This method tries to delete all inline xattrs in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - empty tree.
 */
static
int ssdfs_delete_all_inline_xattrs(struct ssdfs_xattrs_btree_info *tree)
{
	struct ssdfs_fs_info *fsi;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", tree);

	fsi = tree->fsi;

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_XATTR:
	case SSDFS_INLINE_XATTR_ARRAY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid xattrs tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

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

	if (!tree->inline_xattrs) {
		SSDFS_ERR("empty inline xattrs %p\n",
			  tree->inline_xattrs);
		return -ERANGE;
	}

	if (tree->inline_count == 0) {
		SSDFS_DBG("empty tree\n");
		return -ENOENT;
	} else if (tree->inline_count > tree->inline_capacity) {
		atomic_set(&tree->state,
			   SSDFS_XATTR_BTREE_CORRUPTED);
		SSDFS_ERR("xattrs tree is corupted: "
			  "inline_count %u, inline_capacity %u",
			  tree->inline_count,
			  tree->inline_capacity);
		return -ERANGE;
	}

	for (i = 0; i < tree->inline_count; i++) {
		struct ssdfs_xattr_entry *xattr;
		u8 type;
		u8 flags;

		xattr = &tree->inline_xattrs[i];
		type = xattr->blob_type;
		flags = xattr->blob_flags;

		switch (type) {
		case SSDFS_XATTR_INLINE_BLOB:
			if (flags & SSDFS_XATTR_HAS_EXTERNAL_BLOB) {
				SSDFS_ERR("invalid xattr: "
					  "blob_type %#x, "
					  "blob_flags %#x\n",
					  xattr->blob_type,
					  xattr->blob_flags);
				return -ERANGE;
			} else {
				/* skip invalidation for the inline blob */
				continue;
			}
			break;

		case SSDFS_XATTR_REGULAR_BLOB:
			if (flags & ~SSDFS_XATTR_HAS_EXTERNAL_BLOB) {
				SSDFS_ERR("invalid xattr: "
					  "blob_type %#x, blob_flags %#x\n",
					  xattr->blob_type,
					  xattr->blob_flags);
				return -ERANGE;
			}

			err = __ssdfs_invalidate_external_blob(fsi,
						&xattr->blob.descriptor);
			if (unlikely(err)) {
				SSDFS_ERR("fail to make the blob pre-invalid: "
					  "index %d, err %d\n",
					  i, err);
				return err;
			}
			break;

		default:
			SSDFS_ERR("invalid blob_type %#x\n",
				  xattr->blob_type);
			return -ERANGE;
		}
	}

	tree->inline_count = 0;
	memset(tree->inline_xattrs, 0xFF,
		sizeof(struct ssdfs_xattr_entry) * tree->inline_capacity);

	atomic_set(&tree->state, SSDFS_XATTR_BTREE_DIRTY);
	return 0;
}

/*
 * ssdfs_xattrs_tree_delete_all() - delete all xattrs in the tree
 * @tree: xattrs tree
 *
 * This method tries to delete all xattrs in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_xattrs_tree_delete_all(struct ssdfs_xattrs_btree_info *tree)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", tree);

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
		down_write(&tree->lock);
		err = ssdfs_delete_all_inline_xattrs(tree);
		up_write(&tree->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to delete all inline xattrs: "
				  "err %d\n",
				  err);
		}
		break;

	case SSDFS_PRIVATE_XATTR_BTREE:
		down_write(&tree->lock);
		err = ssdfs_btree_delete_all(tree->generic_tree);
		if (!err) {
			err = ssdfs_migrate_generic2inline_tree(tree);
			if (err == -ENOSPC) {
				/* continue to use the generic tree */
				err = 0;
				SSDFS_DBG("unable to re-create inline tree\n");
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to re-create inline tree: "
					  "err %d\n",
					  err);
			}
		}
		up_write(&tree->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to delete the all xattrs: "
				  "err %d\n",
				  err);
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid xattrs tree type %#x\n",
			  atomic_read(&tree->type));
		break;
	}

	return err;
}

/*
 * ssdfs_xattrs_tree_extract_inline_range() - extract inline range
 * @tree: dentries tree
 * @start_index: start item index
 * @count: requested count of items
 * @search: search object
 *
 * This method tries to extract a range of inline items.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENOENT     - unable to extract any items.
 */
static int
ssdfs_xattrs_tree_extract_inline_range(struct ssdfs_xattrs_btree_info *tree,
					u16 start_index, u16 count,
					struct ssdfs_btree_search *search)
{
	struct ssdfs_xattr_entry *src, *dst;
	size_t xattr_size = sizeof(struct ssdfs_xattr_entry);
	u16 inline_count;
	size_t buf_size;
	u16 i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
	BUG_ON(!tree->inline_xattrs);

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_XATTR:
	case SSDFS_INLINE_XATTR_ARRAY:
		/* expected state */
		break;
	default:
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, start_index %u, count %u, search %p\n",
		  tree, start_index, count, search);

	search->result.count = 0;

	inline_count = tree->inline_count;
	if (inline_count == 0) {
		SSDFS_DBG("xattrs_count %u\n",
			  inline_count);
		return -ENOENT;
	} else if (inline_count > tree->inline_capacity) {
		SSDFS_ERR("xattrs_count %u > capacity %u\n",
			  inline_count,
			  tree->inline_capacity);
		return -ERANGE;
	}

	if (start_index >= inline_count) {
		SSDFS_ERR("start_index %u >= inline_count %u\n",
			  start_index, inline_count);
		return -ERANGE;
	}

	count = min_t(u16, count, inline_count - start_index);
	buf_size = xattr_size * count;

	switch (search->result.buf_state) {
	case SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE:
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
		if (count == 1) {
			search->result.buf = &search->raw.xattr;
			search->result.buf_state =
					SSDFS_BTREE_SEARCH_INLINE_BUFFER;
			search->result.buf_size = buf_size;
			search->result.items_in_buffer = 0;
		} else {
			search->result.buf = kzalloc(buf_size, GFP_KERNEL);
			if (!search->result.buf) {
				SSDFS_ERR("fail to allocate buffer\n");
				return -ENOMEM;
			}
			search->result.buf_state =
					SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER;
			search->result.buf_size = buf_size;
			search->result.items_in_buffer = 0;
		}
		break;

	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		if (count == 1) {
			if (search->result.buf)
				kfree(search->result.buf);

			search->result.buf = &search->raw.xattr;
			search->result.buf_state =
					SSDFS_BTREE_SEARCH_INLINE_BUFFER;
			search->result.buf_size = buf_size;
			search->result.items_in_buffer = 0;
		} else {
			search->result.buf = krealloc(search->result.buf,
						      buf_size, GFP_KERNEL);
			if (!search->result.buf) {
				SSDFS_ERR("fail to allocate buffer\n");
				return -ENOMEM;
			}
			search->result.buf_state =
					SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER;
			search->result.buf_size = buf_size;
			search->result.items_in_buffer = 0;
		}
		break;

	default:
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	for (i = start_index; i < (start_index + count); i++) {
		src = &tree->inline_xattrs[i];
		dst = (struct ssdfs_xattr_entry *)(search->result.buf +
						    (i * xattr_size));
		memcpy(dst, src, xattr_size);
		search->result.items_in_buffer++;
		search->result.count++;
	}

	search->result.state = SSDFS_BTREE_SEARCH_VALID_ITEM;
	return 0;
}

/*
 * ssdfs_xattrs_tree_extract_range() - extract range of items
 * @tree: dentries tree
 * @start_index: start item index in the node
 * @count: requested count of items
 * @search: search object
 *
 * This method tries to extract a range of items from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENOENT     - unable to extract any items.
 */
int ssdfs_xattrs_tree_extract_range(struct ssdfs_xattrs_btree_info *tree,
				    u16 start_index, u16 count,
				    struct ssdfs_btree_search *search)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, start_index %u, count %u, search %p\n",
		  tree, start_index, count, search);

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
		err = ssdfs_xattrs_tree_extract_inline_range(tree,
							     start_index,
							     count,
							     search);
		up_read(&tree->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the inline range: "
				  "start_index %u, count %u, err %d\n",
				  start_index, count, err);
		}
		break;

	case SSDFS_PRIVATE_XATTR_BTREE:
		down_read(&tree->lock);
		err = ssdfs_btree_extract_range(tree->generic_tree,
						start_index, count,
						search);
		up_read(&tree->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the range: "
				  "start_index %u, count %u, err %d\n",
				  start_index, count, err);
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid xattrs tree type %#x\n",
			  atomic_read(&tree->type));
		break;
	}

	return err;
}

/******************************************************************************
 *               SPECIALIZED XATTR BTREE DESCRIPTOR OPERATIONS                *
 ******************************************************************************/

/*
 * ssdfs_xattrs_btree_desc_init() - specialized btree descriptor init
 * @fsi: pointer on shared file system object
 * @tree: pointer on xattrs btree object
 */
static
int ssdfs_xattrs_btree_desc_init(struct ssdfs_fs_info *fsi,
				struct ssdfs_btree *tree)
{
	struct ssdfs_xattrs_btree_info *tree_info = NULL;
	struct ssdfs_btree_descriptor *desc;
	u32 erasesize;
	u32 node_size;
	size_t xattr_size = sizeof(struct ssdfs_xattr_entry);
	u16 item_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !tree);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, tree %p\n",
		  fsi, tree);

	tree_info = container_of(tree,
				 struct ssdfs_xattrs_btree_info,
				 buffer.tree);

	erasesize = fsi->erasesize;

	desc = &tree_info->desc.desc;

	if (le32_to_cpu(desc->magic) != SSDFS_XATTR_BTREE_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid magic %#x\n",
			  le32_to_cpu(desc->magic));
		goto finish_btree_desc_init;
	}

	/* TODO: check flags */

	if (desc->type != SSDFS_XATTR_BTREE) {
		err = -EIO;
		SSDFS_ERR("invalid btree type %#x\n",
			  desc->type);
		goto finish_btree_desc_init;
	}

	node_size = 1 << desc->log_node_size;
	if (node_size < SSDFS_4KB || node_size > erasesize) {
		err = -EIO;
		SSDFS_ERR("invalid node size: "
			  "log_node_size %u, node_size %u, erasesize %u\n",
			  desc->log_node_size,
			  node_size, erasesize);
		goto finish_btree_desc_init;
	}

	item_size = le16_to_cpu(desc->item_size);

	if (item_size != xattr_size) {
		err = -EIO;
		SSDFS_ERR("invalid item size %u\n",
			  item_size);
		goto finish_btree_desc_init;
	}

	if (le16_to_cpu(desc->index_area_min_size) != xattr_size) {
		err = -EIO;
		SSDFS_ERR("invalid index_area_min_size %u\n",
			  le16_to_cpu(desc->index_area_min_size));
		goto finish_btree_desc_init;
	}

	err = ssdfs_btree_desc_init(fsi, tree, desc, 0, item_size);

finish_btree_desc_init:
	if (unlikely(err)) {
		SSDFS_ERR("fail to init btree descriptor: err %d\n",
			  err);
	}

	return err;
}

/*
 * ssdfs_xattrs_btree_desc_flush() - specialized btree's descriptor flush
 * @tree: pointer on btree object
 */
static
int ssdfs_xattrs_btree_desc_flush(struct ssdfs_btree *tree)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_xattrs_btree_info *tree_info = NULL;
	struct ssdfs_btree_descriptor desc;
	size_t xattr_size = sizeof(struct ssdfs_xattr_entry);
	u32 erasesize;
	u32 node_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("owner_ino %llu, type %#x, state %#x\n",
		  tree->owner_ino, tree->type,
		  atomic_read(&tree->state));

	fsi = tree->fsi;

	if (tree->type != SSDFS_XATTR_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_xattrs_btree_info,
					 buffer.tree);
	}

	memset(&desc, 0xFF, sizeof(struct ssdfs_btree_descriptor));

	desc.magic = cpu_to_le32(SSDFS_XATTR_BTREE_MAGIC);
	desc.item_size = cpu_to_le16(xattr_size);

	err = ssdfs_btree_desc_flush(tree, &desc);
	if (unlikely(err)) {
		SSDFS_ERR("invalid btree descriptor: err %d\n",
			  err);
		return err;
	}

	if (desc.type != SSDFS_XATTR_BTREE) {
		SSDFS_ERR("invalid btree type %#x\n",
			  desc.type);
		return -ERANGE;
	}

	erasesize = fsi->erasesize;
	node_size = 1 << desc.log_node_size;

	if (node_size < SSDFS_4KB || node_size > erasesize) {
		SSDFS_ERR("invalid node size: "
			  "log_node_size %u, node_size %u, erasesize %u\n",
			  desc.log_node_size,
			  node_size, erasesize);
		return -ERANGE;
	}

	if (le16_to_cpu(desc.index_area_min_size) != xattr_size) {
		SSDFS_ERR("invalid index_area_min_size %u\n",
			  le16_to_cpu(desc.index_area_min_size));
		return -ERANGE;
	}

	memcpy(&tree_info->desc.desc, &desc,
		sizeof(struct ssdfs_btree_descriptor));

	return 0;
}

/******************************************************************************
 *                   SPECIALIZED DENTRIES BTREE OPERATIONS                    *
 ******************************************************************************/

/*
 * ssdfs_xattrs_btree_create_root_node() - specialized root node creation
 * @fsi: pointer on shared file system object
 * @node: pointer on node object [out]
 */
static
int ssdfs_xattrs_btree_create_root_node(struct ssdfs_fs_info *fsi,
				       struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_xattrs_btree_info *tree_info = NULL;
	struct ssdfs_btree_inline_root_node tmp_buffer;
	struct ssdfs_inode *raw_inode = NULL;
	int private_flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, node %p\n",
		  fsi, node);

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (atomic_read(&tree->state) != SSDFS_BTREE_UNKNOWN_STATE) {
		SSDFS_ERR("unexpected tree state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	}

	if (tree->type != SSDFS_XATTR_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_xattrs_btree_info,
					 buffer.tree);
	}

	if (!tree_info->owner) {
		SSDFS_ERR("empty inode pointer\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rwsem_is_locked(&tree_info->owner->lock));
	BUG_ON(!rwsem_is_locked(&tree_info->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	private_flags = atomic_read(&tree_info->owner->private_flags);

	if (private_flags & SSDFS_INODE_HAS_XATTR_BTREE) {
		switch (atomic_read(&tree_info->type)) {
		case SSDFS_PRIVATE_XATTR_BTREE:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid tree type %#x\n",
				  atomic_read(&tree_info->type));
			return -ERANGE;
		}

		raw_inode = &tree_info->owner->raw_inode;
		memcpy(&tmp_buffer,
			&raw_inode->internal[0].area2.xattr_root,
			sizeof(struct ssdfs_btree_inline_root_node));
	} else {
		switch (atomic_read(&tree_info->type)) {
		case SSDFS_INLINE_XATTR:
		case SSDFS_INLINE_XATTR_ARRAY:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid tree type %#x\n",
				  atomic_read(&tree_info->type));
			return -ERANGE;
		}

		memset(&tmp_buffer, 0xFF,
			sizeof(struct ssdfs_btree_inline_root_node));

		tmp_buffer.header.height = SSDFS_BTREE_LEAF_NODE_HEIGHT + 1;
		tmp_buffer.header.items_count = 0;
		tmp_buffer.header.flags = 0;
		tmp_buffer.header.type = SSDFS_BTREE_ROOT_NODE;
		tmp_buffer.header.upper_node_id =
				cpu_to_le32(SSDFS_BTREE_ROOT_NODE_ID);
	}

	memcpy(&tree_info->root_buffer, &tmp_buffer,
		sizeof(struct ssdfs_btree_inline_root_node));
	tree_info->root = &tree_info->root_buffer;
	err = ssdfs_btree_create_root_node(node, tree_info->root);

	if (unlikely(err)) {
		SSDFS_ERR("fail to create root node: err %d\n",
			  err);
	}

	return err;
}

/*
 * ssdfs_xattrs_btree_pre_flush_root_node() - specialized root node pre-flush
 * @node: pointer on node object
 */
static
int ssdfs_xattrs_btree_pre_flush_root_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_state_bitmap *bmap;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_INITIALIZED:
		SSDFS_DBG("node %u is clean\n",
			  node->node_id);
		return 0;

	case SSDFS_BTREE_NODE_CORRUPTED:
		SSDFS_WARN("node %u is corrupted\n",
			   node->node_id);
		down_read(&node->bmap_array.lock);
		bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
		spin_lock(&bmap->lock);
		bitmap_clear(bmap->ptr, 0, node->bmap_array.bits_count);
		spin_unlock(&bmap->lock);
		up_read(&node->bmap_array.lock);
		clear_ssdfs_btree_node_dirty(node);
		return -EFAULT;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (tree->type != SSDFS_XATTR_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	}

	down_write(&node->full_lock);
	down_write(&node->header_lock);

	err = ssdfs_btree_pre_flush_root_node(node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to pre-flush root node: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
	}

	up_write(&node->header_lock);
	up_write(&node->full_lock);

	return err;
}

/*
 * ssdfs_xattrs_btree_flush_root_node() - specialized root node flush
 * @node: pointer on node object
 */
static
int ssdfs_xattrs_btree_flush_root_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_xattrs_btree_info *tree_info = NULL;
	struct ssdfs_btree_inline_root_node tmp_buffer;
	struct ssdfs_inode *raw_inode = NULL;
	int private_flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node %p, node_id %u\n",
		  node, node->node_id);

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (tree->type != SSDFS_XATTR_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_xattrs_btree_info,
					 buffer.tree);
	}

	if (!tree_info->owner) {
		SSDFS_ERR("empty inode pointer\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rwsem_is_locked(&tree_info->owner->lock));
	BUG_ON(!rwsem_is_locked(&tree_info->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	private_flags = atomic_read(&tree_info->owner->private_flags);

	if (private_flags & SSDFS_INODE_HAS_XATTR_BTREE) {
		switch (atomic_read(&tree_info->type)) {
		case SSDFS_PRIVATE_XATTR_BTREE:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid tree type %#x\n",
				  atomic_read(&tree_info->type));
			return -ERANGE;
		}

		if (!tree_info->root) {
			SSDFS_ERR("root node pointer is NULL\n");
			return -ERANGE;
		}

		ssdfs_btree_flush_root_node(node, tree_info->root);
		memcpy(&tmp_buffer, tree_info->root,
			sizeof(struct ssdfs_btree_inline_root_node));

		raw_inode = &tree_info->owner->raw_inode;
		memcpy(&raw_inode->internal[0].area2.xattr_root,
			&tmp_buffer,
			sizeof(struct ssdfs_btree_inline_root_node));
	} else {
		err = -ERANGE;
		SSDFS_ERR("xattrs tree is inline xattrs array\n");
	}

	return err;
}

/*
 * ssdfs_xattrs_btree_create_node() - specialized node creation
 * @node: pointer on node object
 */
static
int ssdfs_xattrs_btree_create_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct page *page;
	void *addr[SSDFS_BTREE_NODE_BMAP_COUNT];
	size_t hdr_size = sizeof(struct ssdfs_xattrs_btree_node_header);
	u32 node_size;
	u32 items_area_size = 0;
	u16 item_size = 0;
	u16 index_size = 0;
	u16 index_area_min_size;
	u16 items_capacity = 0;
	u16 index_capacity = 0;
	u32 index_area_size = 0;
	size_t bmap_bytes;
	u32 pages_count;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);
	WARN_ON(atomic_read(&node->state) != SSDFS_BTREE_NODE_CREATED);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

	tree = node->tree;
	node_size = tree->node_size;
	index_area_min_size = tree->index_area_min_size;

	node->node_ops = &ssdfs_xattrs_btree_node_ops;

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid items area's state %#x\n",
			  atomic_read(&node->items_area.state));
		return -ERANGE;
	}

	down_write(&node->header_lock);
	down_write(&node->bmap_array.lock);

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_INDEX_NODE:
		node->index_area.offset = (u32)hdr_size;
		node->index_area.area_size = node_size - hdr_size;

		index_area_size = node->index_area.area_size;
		index_size = node->index_area.index_size;

		node->index_area.index_capacity = index_area_size / index_size;
		index_capacity = node->index_area.index_capacity;

		node->bmap_array.index_start_bit =
			SSDFS_BTREE_NODE_HEADER_INDEX + 1;
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		node->index_area.offset = (u32)hdr_size;

		if (index_area_min_size == 0 ||
		    index_area_min_size >= (node_size - hdr_size)) {
			err = -ERANGE;
			SSDFS_ERR("invalid index area desc: "
				  "index_area_min_size %u, "
				  "node_size %u, hdr_size %zu\n",
				  index_area_min_size,
				  node_size, hdr_size);
			goto finish_create_node;
		}

		node->index_area.area_size = index_area_min_size;

		index_area_size = node->index_area.area_size;
		index_size = node->index_area.index_size;
		node->index_area.index_capacity = index_area_size / index_size;
		index_capacity = node->index_area.index_capacity;

		node->items_area.offset = node->index_area.offset +
						node->index_area.area_size;

		if (node->items_area.offset >= node_size) {
			err = -ERANGE;
			SSDFS_ERR("invalid items area desc: "
				  "area_offset %u, node_size %u\n",
				  node->items_area.offset,
				  node_size);
			goto finish_create_node;
		}

		node->items_area.area_size = node_size -
						node->items_area.offset;
		node->items_area.free_space = node->items_area.area_size;
		node->items_area.item_size = tree->item_size;
		node->items_area.min_item_size = tree->min_item_size;
		node->items_area.max_item_size = tree->max_item_size;

		items_area_size = node->items_area.area_size;
		item_size = node->items_area.item_size;

		node->items_area.items_count = 0;
		node->items_area.items_capacity = items_area_size / item_size;
		items_capacity = node->items_area.items_capacity;

		if (node->items_area.items_capacity == 0) {
			err = -ERANGE;
			SSDFS_ERR("items area's capacity %u\n",
				  node->items_area.items_capacity);
			goto finish_create_node;
		}

		node->items_area.end_hash = node->items_area.start_hash +
					    node->items_area.items_capacity - 1;

		node->bmap_array.index_start_bit =
			SSDFS_BTREE_NODE_HEADER_INDEX + 1;
		node->bmap_array.item_start_bit =
			node->bmap_array.index_start_bit + index_capacity;
		break;

	case SSDFS_BTREE_LEAF_NODE:
		node->items_area.offset = (u32)hdr_size;
		node->items_area.area_size = node_size - hdr_size;
		node->items_area.free_space = node->items_area.area_size;
		node->items_area.item_size = tree->item_size;
		node->items_area.min_item_size = tree->min_item_size;
		node->items_area.max_item_size = tree->max_item_size;

		items_area_size = node->items_area.area_size;
		item_size = node->items_area.item_size;

		node->items_area.items_count = 0;
		node->items_area.items_capacity = items_area_size / item_size;
		items_capacity = node->items_area.items_capacity;

		node->items_area.end_hash = node->items_area.start_hash +
					    node->items_area.items_capacity - 1;

		node->bmap_array.item_start_bit =
				SSDFS_BTREE_NODE_HEADER_INDEX + 1;
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid node type %#x\n",
			   atomic_read(&node->type));
		goto finish_create_node;
	}

	node->bmap_array.bits_count = index_capacity + items_capacity + 1;

	if (item_size > 0)
		items_capacity = node_size / item_size;
	else
		items_capacity = 0;

	if (index_size > 0)
		index_capacity = node_size / index_size;
	else
		index_capacity = 0;

	bmap_bytes = index_capacity + items_capacity + 1;
	bmap_bytes += BITS_PER_LONG;
	bmap_bytes /= BITS_PER_BYTE;

	node->bmap_array.bmap_bytes = bmap_bytes;

	if (bmap_bytes == 0 || bmap_bytes > SSDFS_XATTRS_BMAP_SIZE) {
		err = -EIO;
		SSDFS_ERR("invalid bmap_bytes %zu\n",
			  bmap_bytes);
		goto finish_create_node;
	}


finish_create_node:
	up_write(&node->bmap_array.lock);
	up_write(&node->header_lock);

	if (unlikely(err))
		return err;

	for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
		addr[i] = kzalloc(bmap_bytes, GFP_KERNEL);
		if (!addr[i]) {
			SSDFS_ERR("fail to allocate node's bmap: index %d\n",
				  i);
			for (; i >= 0; i--)
				kfree(addr[i]);
			return -ENOMEM;
		}
	}

	down_write(&node->bmap_array.lock);
	for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
		spin_lock(&node->bmap_array.bmap[i].lock);
		node->bmap_array.bmap[i].ptr = addr[i];
		addr[i] = NULL;
		spin_unlock(&node->bmap_array.bmap[i].lock);
	}
	up_write(&node->bmap_array.lock);

	pages_count = node_size / PAGE_SIZE;

	if (pages_count == 0 || pages_count > PAGEVEC_SIZE) {
		SSDFS_ERR("invalid pages_count %u\n",
			  pages_count);
		return -ERANGE;
	}

	down_write(&node->full_lock);

	pagevec_init(&node->content.pvec);
	for (i = 0; i < pages_count; i++) {
		page = alloc_page(GFP_KERNEL | GFP_NOFS | __GFP_ZERO);
		if (unlikely(!page)) {
			err = -ENOMEM;
			SSDFS_ERR("unable to allocate memory page\n");
			goto finish_init_pvec;
		}

		get_page(page);

		pagevec_add(&node->content.pvec, page);
	}

finish_init_pvec:
	up_write(&node->full_lock);

	return err;
}

/*
 * ssdfs_xattrs_btree_init_node() - init xattrs tree's node
 * @node: pointer on node object
 *
 * This method tries to init the node of xattrs btree.
 *
 *       It makes sense to allocate the bitmap with taking into
 *       account that we will resize the node. So, it needs
 *       to allocate the index area in bitmap is equal to
 *       the whole node and items area is equal to the whole node.
 *       This technique provides opportunity not to resize or
 *       to shift the content of the bitmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 * %-EIO        - invalid node's header content
 */
static
int ssdfs_xattrs_btree_init_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_xattrs_btree_info *tree_info = NULL;
	struct ssdfs_xattrs_btree_node_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_xattrs_btree_node_header);
	void *addr[SSDFS_BTREE_NODE_BMAP_COUNT];
	struct page *page;
	void *kaddr;
	u64 start_hash, end_hash;
	u32 node_size;
	u16 item_size;
	u64 parent_ino;
	u32 xattrs_count;
	u16 items_capacity;
	u16 free_space;
	u32 calculated_used_space;
	u32 items_count;
	u16 flags;
	u8 index_size;
	u32 index_area_size;
	u16 index_capacity = 0;
	size_t bmap_bytes;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (tree->type != SSDFS_XATTR_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_xattrs_btree_info,
					 buffer.tree);
	}

	if (atomic_read(&node->state) != SSDFS_BTREE_NODE_CONTENT_PREPARED) {
		SSDFS_WARN("fail to init node: id %u, state %#x\n",
			   node->node_id, atomic_read(&node->state));
		return -ERANGE;
	}

	down_read(&node->full_lock);

	if (pagevec_count(&node->content.pvec) == 0) {
		err = -ERANGE;
		SSDFS_ERR("empty node's content: id %u\n",
			  node->node_id);
		goto finish_init_node;
	}

	page = node->content.pvec.pages[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

	kaddr = kmap(page);

	hdr = (struct ssdfs_xattrs_btree_node_header *)kaddr;

	if (!is_csum_valid(&hdr->node.check, hdr, hdr_size)) {
		err = -EIO;
		SSDFS_ERR("invalid checksum: node_id %u\n",
			  node->node_id);
		goto finish_init_operation;
	}

	if (le32_to_cpu(hdr->node.magic.common) != SSDFS_SUPER_MAGIC ||
	    le16_to_cpu(hdr->node.magic.key) != SSDFS_XATTR_BNODE_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid magic: common %#x, key %#x\n",
			  le32_to_cpu(hdr->node.magic.common),
			  le16_to_cpu(hdr->node.magic.key));
		goto finish_init_operation;
	}

	down_write(&node->header_lock);

	memcpy(&node->raw.xattrs_header, hdr, hdr_size);

	err = ssdfs_btree_init_node(node, &hdr->node,
				    hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init node: id %u, err %d\n",
			  node->node_id, err);
		goto finish_header_init;
	}

	flags = atomic_read(&node->flags);

	start_hash = le64_to_cpu(hdr->node.start_hash);
	end_hash = le64_to_cpu(hdr->node.end_hash);
	node_size = 1 << hdr->node.log_node_size;
	index_size = hdr->node.index_size;
	item_size = hdr->node.min_item_size;
	items_capacity = le16_to_cpu(hdr->node.items_capacity);
	parent_ino = le64_to_cpu(hdr->parent_ino);
	xattrs_count = le16_to_cpu(hdr->xattrs_count);
	free_space = le16_to_cpu(hdr->free_space);

	if (start_hash >= U64_MAX || end_hash >= U64_MAX) {
		err = -EIO;
		SSDFS_ERR("invalid hash range: "
			  "start_hash %llx, end_hash %llx\n",
			  start_hash, end_hash);
		goto finish_header_init;
	}

	if (parent_ino != tree_info->owner->vfs_inode.i_ino) {
		err = -EIO;
		SSDFS_ERR("parent_ino %llu != ino %lu\n",
			  parent_ino,
			  tree_info->owner->vfs_inode.i_ino);
		goto finish_header_init;
	}

	if (item_size == 0 || node_size % item_size) {
		err = -EIO;
		SSDFS_ERR("invalid size: item_size %u, node_size %u\n",
			  item_size, node_size);
		goto finish_header_init;
	}

	if (item_size != sizeof(struct ssdfs_xattr_entry)) {
		err = -EIO;
		SSDFS_ERR("invalid item_size: "
			  "size %u, expected size %zu\n",
			  item_size,
			  sizeof(struct ssdfs_xattr_entry));
		goto finish_header_init;
	}

	if (items_capacity == 0 ||
	    items_capacity > (node_size / item_size)) {
		err = -EIO;
		SSDFS_ERR("invalid items_capacity %u\n",
			  items_capacity);
		goto finish_header_init;
	}

	if (xattrs_count > items_capacity) {
		err = -EIO;
		SSDFS_ERR("items_capacity %u != xattrs_count %u\n",
			  items_capacity,
			  xattrs_count);
		goto finish_header_init;
	}

	calculated_used_space = hdr_size;
	calculated_used_space += xattrs_count * item_size;

	if (flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA) {
		index_area_size = 1 << hdr->node.log_index_area_size;
		calculated_used_space += index_area_size;
	}

	if (free_space != (node_size - calculated_used_space)) {
		err = -EIO;
		SSDFS_ERR("free_space %u, node_size %u, "
			  "calculated_used_space %u\n",
			  free_space, node_size,
			  calculated_used_space);
		goto finish_header_init;
	}

	node->items_area.free_space = free_space;
	node->items_area.items_count = (u16)xattrs_count;
	node->items_area.items_capacity = items_capacity;

finish_header_init:
	up_write(&node->header_lock);

	if (unlikely(err))
		goto finish_init_operation;

	items_count = node_size / item_size;

	if (item_size > 0)
		items_capacity = node_size / item_size;
	else
		items_capacity = 0;

	if (index_size > 0)
		index_capacity = node_size / index_size;
	else
		index_capacity = 0;

	bmap_bytes = index_capacity + items_capacity + 1;
	bmap_bytes += BITS_PER_LONG;
	bmap_bytes /= BITS_PER_BYTE;

	if (bmap_bytes == 0 || bmap_bytes > SSDFS_XATTRS_BMAP_SIZE) {
		err = -EIO;
		SSDFS_ERR("invalid bmap_bytes %zu\n",
			  bmap_bytes);
		goto finish_init_operation;
	}

	for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
		addr[i] = kzalloc(bmap_bytes, GFP_KERNEL);
		if (!addr[i]) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate node's bmap: index %d\n",
				  i);
			for (; i >= 0; i--)
				kfree(addr[i]);
			goto finish_init_operation;
		}
	}

	down_write(&node->bmap_array.lock);

	if (flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA) {
		node->bmap_array.index_start_bit =
			SSDFS_BTREE_NODE_HEADER_INDEX + 1;
		/*
		 * Reserve the whole node space as
		 * potential space for indexes.
		 */

		index_capacity = node_size / index_size;
		node->bmap_array.item_start_bit =
			node->bmap_array.index_start_bit + index_capacity;
	} else if (flags & SSDFS_BTREE_NODE_HAS_ITEMS_AREA) {
		node->bmap_array.item_start_bit =
				SSDFS_BTREE_NODE_HEADER_INDEX + 1;
	} else
		BUG();

	node->bmap_array.bits_count = index_capacity + items_capacity + 1;
	node->bmap_array.bmap_bytes = bmap_bytes;

	for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
		spin_lock(&node->bmap_array.bmap[i].lock);
		node->bmap_array.bmap[i].ptr = addr[i];
		addr[i] = NULL;
		spin_unlock(&node->bmap_array.bmap[i].lock);
	}

	spin_lock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);
	bitmap_set(node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].ptr,
		   0, xattrs_count);
	spin_unlock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);

	up_write(&node->bmap_array.lock);
finish_init_operation:
	kunmap(page);

finish_init_node:
	up_read(&node->full_lock);

	return err;
}

static
void ssdfs_xattrs_btree_destroy_node(struct ssdfs_btree_node *node)
{
	SSDFS_DBG("operation is unavailable\n");
}

/*
 * ssdfs_xattrs_btree_add_node() - add node into xattrs btree
 * @node: pointer on node object
 *
 * This method tries to finish addition of node into xattrs btree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_xattrs_btree_add_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree_index_key key;
	int type;
	u16 items_capacity = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected states */
		break;

	default:
		SSDFS_WARN("invalid node: id %u, state %#x\n",
			   node->node_id, atomic_read(&node->state));
		return -ERANGE;
	}

	type = atomic_read(&node->type);

	switch (type) {
	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_LEAF_NODE:
		/* expected states */
		break;

	default:
		SSDFS_WARN("invalid node type %#x\n", type);
		return -ERANGE;
	};

	down_write(&node->header_lock);

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		items_capacity = node->items_area.items_capacity;
		break;
	default:
		items_capacity = 0;
		break;
	};

	if (items_capacity == 0) {
		if (type == SSDFS_BTREE_LEAF_NODE ||
		    type == SSDFS_BTREE_HYBRID_NODE) {
			err = -ERANGE;
			SSDFS_ERR("invalid node state: "
				  "type %#x, items_capacity %u\n",
				  type, items_capacity);
			goto finish_add_node;
		}
	} else {
		node->raw.xattrs_header.xattrs_count = cpu_to_le16(0);
		node->raw.xattrs_header.free_space =
				cpu_to_le16((u16)node->items_area.area_size);
	}

finish_add_node:
	up_write(&node->header_lock);

	if (err)
		return err;

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_HYBRID_NODE:
		spin_lock(&node->descriptor_lock);
		memcpy(&key, &node->node_index,
			sizeof(struct ssdfs_btree_index_key));
		spin_unlock(&node->descriptor_lock);

		SSDFS_DBG("node_id %u, node_type %#x, "
			  "node_height %u, hash %llx\n",
			  le32_to_cpu(key.node_id),
			  key.node_type,
			  key.height,
			  le64_to_cpu(key.index.hash));

		err = ssdfs_btree_node_add_index(node, &key);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add index: err %d\n", err);
			return err;
		}
		break;

	default:
		/* do nothing */
		break;
	}

	return 0;
}

static
int ssdfs_xattrs_btree_delete_node(struct ssdfs_btree_node *node)
{
	/* TODO: implement */
	SSDFS_DBG("TODO: implement\n");
	return -ENOSYS;

/*
 * TODO: it needs to add special free space descriptor in the
 *       index area for the case of deleted nodes. Code of
 *       allocation of new items should create empty node
 *       with completely free items during passing through
 *       index level.
 */



/*
 * TODO: node can be really deleted/invalidated. But index
 *       area should contain index for deleted node with
 *       special flag. In this case it will be clear that
 *       we have some capacity without real node allocation.
 *       If some item will be added in the node then node
 *       has to be allocated. It means that if you delete
 *       a node then index hierachy will be the same without
 *       necessity to delete or modify it.
 */



	/* TODO:  decrement nodes_count and/or leaf_nodes counters */
	/* TODO:  decrease inodes_capacity and/or free_inodes */
}

/*
 * ssdfs_xattrs_btree_pre_flush_node() - pre-flush node's header
 * @node: pointer on node object
 *
 * This method tries to flush node's header.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_xattrs_btree_pre_flush_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_xattrs_btree_node_header xattrs_header;
	size_t hdr_size = sizeof(struct ssdfs_xattrs_btree_node_header);
	struct ssdfs_btree *tree;
	struct ssdfs_xattrs_btree_info *tree_info = NULL;
	struct ssdfs_state_bitmap *bmap;
	struct page *page;
	void *kaddr;
	u16 items_count;
	u32 items_area_size;
	u16 xattrs_count;
	u16 free_space;
	u32 used_space;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_INITIALIZED:
		SSDFS_DBG("node %u is clean\n",
			  node->node_id);
		return 0;

	case SSDFS_BTREE_NODE_CORRUPTED:
		SSDFS_WARN("node %u is corrupted\n",
			   node->node_id);
		down_read(&node->bmap_array.lock);
		bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
		spin_lock(&bmap->lock);
		bitmap_clear(bmap->ptr, 0, node->bmap_array.bits_count);
		spin_unlock(&bmap->lock);
		up_read(&node->bmap_array.lock);
		clear_ssdfs_btree_node_dirty(node);
		return -EFAULT;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (tree->type != SSDFS_XATTR_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_xattrs_btree_info,
					 buffer.tree);
	}

	down_write(&node->full_lock);
	down_write(&node->header_lock);

	memcpy(&xattrs_header, &node->raw.xattrs_header, hdr_size);

	xattrs_header.node.magic.common = cpu_to_le32(SSDFS_SUPER_MAGIC);
	xattrs_header.node.magic.key = cpu_to_le16(SSDFS_XATTR_BNODE_MAGIC);
	xattrs_header.node.magic.version.major = SSDFS_MAJOR_REVISION;
	xattrs_header.node.magic.version.minor = SSDFS_MINOR_REVISION;

	err = ssdfs_btree_node_pre_flush_header(node, &xattrs_header.node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to flush generic header: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		goto finish_xattrs_header_preparation;
	}

	if (!tree_info->owner) {
		err = -ERANGE;
		SSDFS_WARN("fail to extract parent_ino\n");
		goto finish_xattrs_header_preparation;
	}

	xattrs_header.parent_ino =
		cpu_to_le64(tree_info->owner->vfs_inode.i_ino);

	items_count = node->items_area.items_count;
	items_area_size = node->items_area.area_size;
	xattrs_count = le16_to_cpu(xattrs_header.xattrs_count);
	free_space = le16_to_cpu(xattrs_header.free_space);

	if (xattrs_count != items_count) {
		err = -ERANGE;
		SSDFS_ERR("xattrs_count %u != items_count %u\n",
			  xattrs_count, items_count);
		goto finish_xattrs_header_preparation;
	}

	used_space = (u32)items_count * sizeof(struct ssdfs_xattr_entry);

	if (used_space > items_area_size) {
		err = -ERANGE;
		SSDFS_ERR("used_space %u > items_area_size %u\n",
			  used_space, items_area_size);
		goto finish_xattrs_header_preparation;
	}

	if (free_space != (items_area_size - used_space)) {
		err = -ERANGE;
		SSDFS_ERR("free_space %u, items_area_size %u, "
			  "used_space %u\n",
			  free_space, items_area_size,
			  used_space);
		goto finish_xattrs_header_preparation;
	}

	xattrs_header.node.check.bytes = cpu_to_le16((u16)hdr_size);
	xattrs_header.node.check.flags = cpu_to_le16(SSDFS_CRC32);

	err = ssdfs_calculate_csum(&xattrs_header.node.check,
				   &xattrs_header, hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("unable to calculate checksum: err %d\n", err);
		goto finish_xattrs_header_preparation;
	}

	memcpy(&node->raw.xattrs_header, &xattrs_header, hdr_size);

finish_xattrs_header_preparation:
	up_write(&node->header_lock);

	if (unlikely(err))
		goto finish_node_pre_flush;

	if (pagevec_count(&node->content.pvec) < 1) {
		err = -ERANGE;
		SSDFS_ERR("pagevec is empty\n");
		goto finish_node_pre_flush;
	}

	page = node->content.pvec.pages[0];
	kaddr = kmap_atomic(page);
	memcpy(kaddr, &xattrs_header,
		sizeof(struct ssdfs_xattrs_btree_node_header));
	kunmap_atomic(kaddr);

finish_node_pre_flush:
	up_write(&node->full_lock);

	return err;
}

/*
 * ssdfs_xattrs_btree_flush_node() - flush node
 * @node: pointer on node object
 *
 * This method tries to flush node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_xattrs_btree_flush_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_xattrs_btree_info *tree_info = NULL;
	int private_flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node %p, node_id %u\n",
		  node, node->node_id);

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (tree->type != SSDFS_XATTR_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_xattrs_btree_info,
					 buffer.tree);
	}

	private_flags = atomic_read(&tree_info->owner->private_flags);

	if (private_flags & SSDFS_INODE_HAS_XATTR_BTREE) {
		switch (atomic_read(&tree_info->type)) {
		case SSDFS_PRIVATE_XATTR_BTREE:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid tree type %#x\n",
				  atomic_read(&tree_info->type));
			return -ERANGE;
		}

		err = ssdfs_btree_common_node_flush(node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to flush node: "
				  "node_id %u, height %u, err %d\n",
				  node->node_id,
				  atomic_read(&node->height),
				  err);
		}
	} else {
		err = -ERANGE;
		SSDFS_ERR("xattrs tree is inline xattrs array\n");
	}

	return err;
}

/******************************************************************************
 *                 SPECIALIZED XATTR BTREE NODE OPERATIONS                    *
 ******************************************************************************/

/*
 * ssdfs_convert_lookup2item_index() - convert lookup into item index
 * @node_size: size of the node in bytes
 * @lookup_index: lookup index
 */
static inline
u16 ssdfs_convert_lookup2item_index(u32 node_size, u16 lookup_index)
{
	SSDFS_DBG("node_size %u, lookup_index %u\n",
		  node_size, lookup_index);

	return __ssdfs_convert_lookup2item_index(lookup_index, node_size,
					sizeof(struct ssdfs_xattr_entry),
					SSDFS_XATTRS_BTREE_LOOKUP_TABLE_SIZE);
}

/*
 * ssdfs_convert_item2lookup_index() - convert item into lookup index
 * @node_size: size of the node in bytes
 * @item_index: item index
 */
static inline
u16 ssdfs_convert_item2lookup_index(u32 node_size, u16 item_index)
{
	SSDFS_DBG("node_size %u, item_index %u\n",
		  node_size, item_index);

	return __ssdfs_convert_item2lookup_index(item_index, node_size,
					sizeof(struct ssdfs_xattr_entry),
					SSDFS_XATTRS_BTREE_LOOKUP_TABLE_SIZE);
}

/*
 * is_hash_for_lookup_table() - should item's hash be into lookup table?
 * @node_size: size of the node in bytes
 * @item_index: item index
 */
static inline
bool is_hash_for_lookup_table(u32 node_size, u16 item_index)
{
	u16 lookup_index;
	u16 calculated;

	lookup_index = ssdfs_convert_item2lookup_index(node_size, item_index);
	calculated = ssdfs_convert_lookup2item_index(node_size, lookup_index);

	return calculated == item_index;
}

/*
 * ssdfs_xattrs_btree_node_find_lookup_index() - find lookup index
 * @node: node object
 * @search: search object
 * @lookup_index: lookup index [out]
 *
 * This method tries to find a lookup index for requested items.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - lookup index doesn't exist for requested hash.
 */
static
int ssdfs_xattrs_btree_node_find_lookup_index(struct ssdfs_btree_node *node,
					      struct ssdfs_btree_search *search,
					      u16 *lookup_index)
{
	__le64 *lookup_table;
	int array_size = SSDFS_XATTRS_BTREE_LOOKUP_TABLE_SIZE;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search || !lookup_index);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	down_read(&node->header_lock);
	lookup_table = node->raw.xattrs_header.lookup_table;
	err = ssdfs_btree_node_find_lookup_index_nolock(search,
							lookup_table,
							array_size,
							lookup_index);
	up_read(&node->header_lock);

	return err;
}

/*
 * ssdfs_get_xattrs_hash_range() - get xattr's hash range
 * @kaddr: pointer on xattr object
 * @start_hash: pointer on start_hash value [out]
 * @end_hash: pointer on end_hash value [out]
 */
static
void ssdfs_get_xattrs_hash_range(void *kaddr,
				 u64 *start_hash,
				 u64 *end_hash)
{
	struct ssdfs_xattr_entry *xattr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !start_hash || !end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p\n", kaddr);

	xattr = (struct ssdfs_xattr_entry *)kaddr;
	*start_hash = le64_to_cpu(xattr->name_hash);
	*end_hash = *start_hash;
}

/*
 * ssdfs_check_found_xattr() - check found xattr
 * @fsi: pointer on shared file system object
 * @search: search object
 * @kaddr: pointer on xattr object
 * @item_index: index of the xattr
 * @start_hash: pointer on start_hash value [out]
 * @end_hash: pointer on end_hash value [out]
 * @found_index: pointer on found index [out]
 *
 * This method tries to check the found xattr.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - corrupted xattr.
 * %-EAGAIN     - continue the search.
 * %-ENODATA    - possible place was found.
 */
static
int ssdfs_check_found_xattr(struct ssdfs_fs_info *fsi,
			    struct ssdfs_btree_search *search,
			    void *kaddr,
			    u16 item_index,
			    u64 *start_hash,
			    u64 *end_hash,
			    u16 *found_index)
{
	struct ssdfs_xattr_entry *xattr;
	u64 hash_code;
	u8 name_type;
	u8 name_flags;
	u16 name_len;
	u8 blob_type;
	u8 blob_flags;
	u16 blob_len;
	u32 req_flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !kaddr || !found_index);
	BUG_ON(!start_hash || !end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("item_index %u\n", item_index);

	*start_hash = U64_MAX;
	*end_hash = U64_MAX;
	*found_index = U16_MAX;

	req_flags = search->request.flags;

	xattr = (struct ssdfs_xattr_entry *)kaddr;
	hash_code = le64_to_cpu(xattr->name_hash);
	name_type = xattr->name_type;
	name_flags = xattr->name_flags;
	name_len = le16_to_cpu(xattr->name_len);
	blob_type = xattr->blob_type;
	blob_flags = xattr->blob_flags;
	blob_len = le16_to_cpu(xattr->blob_len);

	if (name_flags & ~SSDFS_XATTR_NAME_FLAGS_MASK) {
		SSDFS_ERR("corrupted xattr: "
			  "hash_code %llu, name_len %u, "
			  "name_type %#x, name_flags %#x\n",
			  hash_code, name_len,
			  name_type, name_flags);
		return -ERANGE;
	}

	switch (name_type) {
	case SSDFS_XATTR_INLINE_NAME:
	case SSDFS_XATTR_USER_INLINE_NAME:
	case SSDFS_XATTR_TRUSTED_INLINE_NAME:
	case SSDFS_XATTR_SYSTEM_INLINE_NAME:
	case SSDFS_XATTR_SECURITY_INLINE_NAME:
		if (name_flags & SSDFS_XATTR_HAS_EXTERNAL_STRING ||
		    name_len > SSDFS_XATTR_INLINE_NAME_MAX_LEN) {
			SSDFS_ERR("corrupted xattr: "
				  "hash_code %llu, name_len %u, "
				  "name_type %#x, name_flags %#x\n",
				  hash_code, name_len,
				  name_type, name_flags);
			return -ERANGE;
		}
		break;

	case SSDFS_XATTR_REGULAR_NAME:
	case SSDFS_XATTR_USER_REGULAR_NAME:
	case SSDFS_XATTR_TRUSTED_REGULAR_NAME:
	case SSDFS_XATTR_SYSTEM_REGULAR_NAME:
	case SSDFS_XATTR_SECURITY_REGULAR_NAME:
		if (name_flags & ~SSDFS_XATTR_HAS_EXTERNAL_STRING ||
		    name_len <= SSDFS_XATTR_INLINE_NAME_MAX_LEN ||
		    name_len > SSDFS_MAX_NAME_LEN) {
			SSDFS_ERR("corrupted xattr: "
				  "hash_code %llu, name_len %u, "
				  "name_type %#x, name_flags %#x\n",
				  hash_code, name_len,
				  name_type, name_flags);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("corrupted xattr: "
			  "hash_code %llu, name_len %u, "
			  "name_type %#x, name_flags %#x\n",
			  hash_code, name_len,
			  name_type, name_flags);
		return -ERANGE;
	}

	if (blob_flags & ~SSDFS_XATTR_BLOB_FLAGS_MASK) {
		SSDFS_ERR("corrupted xattr: "
			  "hash_code %llu, blob_len %u, "
			  "blob_type %#x, blob_flags %#x\n",
			  hash_code, blob_len,
			  blob_type, blob_flags);
		return -ERANGE;
	}

	switch (blob_type) {
	case SSDFS_XATTR_INLINE_BLOB:
		if (blob_flags & SSDFS_XATTR_HAS_EXTERNAL_BLOB ||
		    blob_len > SSDFS_XATTR_INLINE_BLOB_MAX_LEN) {
			SSDFS_ERR("corrupted xattr: "
				  "hash_code %llu, blob_len %u, "
				  "blob_type %#x, blob_flags %#x\n",
				  hash_code, blob_len,
				  blob_type, blob_flags);
			return -ERANGE;
		}
		break;

	case SSDFS_XATTR_REGULAR_BLOB:
		if (blob_flags & ~SSDFS_XATTR_HAS_EXTERNAL_BLOB ||
		    blob_len <= SSDFS_XATTR_INLINE_BLOB_MAX_LEN ||
		    blob_len > fsi->erasesize) {
			SSDFS_ERR("corrupted xattr: "
				  "hash_code %llu, blob_len %u, "
				  "blob_type %#x, blob_flags %#x\n",
				  hash_code, blob_len,
				  blob_type, blob_flags);
		}
		break;

	default:
		SSDFS_ERR("corrupted xattr: "
			  "hash_code %llu, blob_len %u, "
			  "blob_type %#x, blob_flags %#x\n",
			  hash_code, blob_len,
			  blob_type, blob_flags);
		return -ERANGE;
	}

	if (hash_code >= U64_MAX) {
		SSDFS_ERR("corrupted xattr: "
			  "hash_code %llu\n",
			  hash_code);
		return -ERANGE;
	}

	if (!(req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE)) {
		SSDFS_ERR("invalid request: hash is absent\n");
		return -ERANGE;
	}

	memcpy(&search->raw.xattr.header, xattr,
		sizeof(struct ssdfs_xattr_entry));

	ssdfs_get_xattrs_hash_range(kaddr, start_hash, end_hash);

	err = ssdfs_check_xattr_for_request(fsi, xattr, search);
	if (err == -ENODATA) {
		search->result.state =
			SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
		search->result.err = err;
		search->result.start_index = item_index;
		search->result.count = 1;
		search->result.buf_state =
			SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
		search->result.buf = NULL;
		search->result.buf_size = 0;
		search->result.items_in_buffer = 0;
	} else if (err == -EAGAIN) {
		/* continue to search */
		err = 0;
		*found_index = U16_MAX;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to check xattr: err %d\n",
			  err);
	} else {
		*found_index = item_index;
		search->result.state =
			SSDFS_BTREE_SEARCH_VALID_ITEM;
	}

	return err;
}

/*
 * ssdfs_prepare_xattrs_buffer() - prepare buffer for xattrs
 * @search: search object
 * @found_index: found index of xattr
 * @start_hash: starting hash
 * @end_hash: ending hash
 * @items_count: count of items in the sequence
 * @item_size: size of the item
 */
static
int ssdfs_prepare_xattrs_buffer(struct ssdfs_btree_search *search,
				u16 found_index,
				u64 start_hash,
				u64 end_hash,
				u16 items_count,
				size_t item_size)
{
	u16 found_xattrs = 0;
	size_t buf_size = sizeof(struct ssdfs_raw_xattr);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("found_index %u, start_hash %llx, end_hash %llx, "
		  "items_count %u, item_size %zu\n",
		   found_index, start_hash, end_hash,
		   items_count, item_size);

	if (start_hash <= search->request.end.hash &&
	    search->request.end.hash < end_hash) {
		/* use inline buffer */
		found_xattrs = 1;
	} else {
		/* use external buffer */
		if (found_index >= items_count) {
			SSDFS_ERR("found_index %u >= items_count %u\n",
				  found_index, items_count);
			return -ERANGE;
		}
		found_xattrs = items_count - found_index;
	}

	if (found_xattrs == 1) {
		search->result.buf_state =
			SSDFS_BTREE_SEARCH_INLINE_BUFFER;
		search->result.buf = &search->raw.xattr;
		search->result.buf_size = buf_size;
		search->result.items_in_buffer = 0;

		search->result.name_state =
			SSDFS_BTREE_SEARCH_INLINE_BUFFER;
		search->result.name = &search->name;
		search->result.name_string_size =
			sizeof(struct ssdfs_name_string);
		search->result.names_in_buffer = 0;
	} else {
		search->result.buf_state =
			SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER;
		search->result.buf_size = buf_size;
		search->result.buf_size *= found_xattrs;
		search->result.buf = kzalloc(search->result.buf_size,
					     GFP_KERNEL);
		if (!search->result.buf) {
			SSDFS_ERR("fail to allocate buffer: "
				  "size %zu\n",
				  search->result.buf_size);
			return -ENOMEM;
		}
		search->result.items_in_buffer = 0;

		search->result.name_state =
			SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER;
		search->result.name_string_size =
			sizeof(struct ssdfs_name_string);
		search->result.name_string_size *= found_xattrs;
		search->result.name = kzalloc(search->result.name_string_size,
					      GFP_KERNEL);
		if (!search->result.buf) {
			SSDFS_ERR("fail to allocate buffer: "
				  "size %zu\n",
				  search->result.name_string_size);
			kfree(search->result.buf);
			search->result.buf = NULL;
			return -ENOMEM;
		}
		search->result.names_in_buffer = 0;
	}

	return 0;
}

/*
 * ssdfs_extract_found_xattr() - extract found xattr
 * @fsi: pointer on shared file system object
 * @search: search object
 * @item_size: size of the item
 * @kaddr: pointer on xattr
 * @start_hash: pointer on start_hash value [out]
 * @end_hash: pointer on end_hash value [out]
 *
 * This method tries to extract the found xattr.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_extract_found_xattr(struct ssdfs_fs_info *fsi,
			      struct ssdfs_btree_search *search,
			      size_t item_size,
			      void *kaddr,
			      u64 *start_hash,
			      u64 *end_hash)
{
	struct ssdfs_shared_dict_btree_info *dict;
	struct ssdfs_xattr_entry *xattr;
	struct ssdfs_raw_xattr *buf;
	size_t buf_size = sizeof(struct ssdfs_raw_xattr);
	struct ssdfs_name_string *name;
	size_t name_size = sizeof(struct ssdfs_name_string);
	u32 calculated;
	u8 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !search || !kaddr);
	BUG_ON(!start_hash || !end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p\n", kaddr);

	*start_hash = U64_MAX;
	*end_hash = U64_MAX;

	dict = fsi->shdictree;
	if (!dict) {
		SSDFS_ERR("shared dictionary is absent\n");
		return -ERANGE;
	}

	calculated = search->result.items_in_buffer * buf_size;
	if (calculated >= search->result.buf_size) {
		SSDFS_ERR("calculated %u >= buf_size %zu\n",
			  calculated, search->result.buf_size);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */

	buf = (struct ssdfs_raw_xattr *)((u8 *)search->result.buf +
						calculated);
	xattr = (struct ssdfs_xattr_entry *)kaddr;

	ssdfs_get_xattrs_hash_range(xattr, start_hash, end_hash);
	memcpy(buf, xattr, item_size);
	search->result.items_in_buffer++;

	flags = xattr->name_flags;
	if (flags & SSDFS_XATTR_HAS_EXTERNAL_STRING) {
		calculated = search->result.names_in_buffer * name_size;
		if (calculated >= search->result.name_string_size) {
			SSDFS_ERR("calculated %u >= name_string_size %zu\n",
				  calculated,
				  search->result.name_string_size);
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!search->result.name);
#endif /* CONFIG_SSDFS_DEBUG */

		name = search->result.name + search->result.names_in_buffer;

		err = ssdfs_shared_dict_get_name(dict, *start_hash, name);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the name: "
				  "hash %llx, err %d\n",
				  *start_hash, err);
			return err;
		}

		search->result.names_in_buffer++;
	}

	search->result.count++;
	search->result.state = SSDFS_BTREE_SEARCH_VALID_ITEM;

	return 0;
}

/*
 * ssdfs_extract_range_by_lookup_index() - extract a range of items
 * @node: pointer on node object
 * @lookup_index: lookup index for requested range
 * @search: pointer on search request object
 *
 * This method tries to extract a range of items from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - requested range is out of the node.
 */
static
int ssdfs_extract_range_by_lookup_index(struct ssdfs_btree_node *node,
					u16 lookup_index,
					struct ssdfs_btree_search *search)
{
	int capacity = SSDFS_XATTRS_BTREE_LOOKUP_TABLE_SIZE;
	size_t item_size = sizeof(struct ssdfs_xattr_entry);

	return __ssdfs_extract_range_by_lookup_index(node, lookup_index,
						capacity, item_size,
						search,
						ssdfs_check_found_xattr,
						ssdfs_prepare_xattrs_buffer,
						ssdfs_extract_found_xattr);
}

/*
 * ssdfs_xattrs_btree_node_find_range() - find a range of items into the node
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to find a range of items into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - requested range is out of the node.
 * %-ENOMEM     - unable to allocate memory.
 */
static
int ssdfs_xattrs_btree_node_find_range(struct ssdfs_btree_node *node,
				      struct ssdfs_btree_search *search)
{
	int state;
	u16 items_count;
	u16 items_capacity;
	u64 start_hash;
	u64 end_hash;
	u16 lookup_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	down_read(&node->header_lock);
	state = atomic_read(&node->items_area.state);
	items_count = node->items_area.items_count;
	items_capacity = node->items_area.items_capacity;
	start_hash = node->items_area.start_hash;
	end_hash = node->items_area.end_hash;
	up_read(&node->header_lock);

	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  state);
		return -ERANGE;
	}

	if (items_capacity == 0 || items_count > items_capacity) {
		SSDFS_ERR("corrupted node description: "
			  "items_count %u, items_capacity %u\n",
			  items_count,
			  items_capacity);
		return -ERANGE;
	}

	if (search->request.count == 0 ||
	    search->request.count > items_capacity) {
		SSDFS_ERR("invalid request: "
			  "count %u, items_capacity %u\n",
			  search->request.count,
			  items_capacity);
		return -ERANGE;
	}

	err = ssdfs_btree_node_check_hash_range(node,
						items_count,
						items_capacity,
						start_hash,
						end_hash,
						search);
	if (err)
		return err;

	err = ssdfs_xattrs_btree_node_find_lookup_index(node, search,
							 &lookup_index);
	if (err == -ENODATA) {
		search->result.state =
			SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
		search->result.err = -ENODATA;
		search->result.start_index =
			ssdfs_convert_lookup2item_index(node->node_size,
							lookup_index);
		search->result.count = search->request.count;
		search->result.search_cno =
			ssdfs_current_cno(node->tree->fsi->sb);

		switch (search->request.type) {
		case SSDFS_BTREE_SEARCH_ADD_ITEM:
		case SSDFS_BTREE_SEARCH_ADD_RANGE:
		case SSDFS_BTREE_SEARCH_CHANGE_ITEM:
			/* do nothing */
			break;

		default:
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */

			search->result.buf_state =
				SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
			search->result.buf = NULL;
			search->result.buf_size = 0;
			search->result.items_in_buffer = 0;
			break;
		}

		return -ENODATA;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find the index: "
			  "start_hash %llx, end_hash %llx, err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(lookup_index >= SSDFS_XATTRS_BTREE_LOOKUP_TABLE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_extract_range_by_lookup_index(node, lookup_index,
						  search);
	search->result.search_cno = ssdfs_current_cno(node->tree->fsi->sb);

	if (err == -EAGAIN) {
		SSDFS_DBG("node contains not all requested xattrs: "
			  "node (start_hash %llx, end_hash %llx), "
			  "request (start_hash %llx, end_hash %llx)\n",
			  start_hash, end_hash,
			  search->request.start.hash,
			  search->request.end.hash);
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to extract range: "
			  "node (start_hash %llx, end_hash %llx), "
			  "request (start_hash %llx, end_hash %llx), "
			  "err %d\n",
			  start_hash, end_hash,
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_xattrs_btree_node_find_item() - find item into node
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to find an item into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_xattrs_btree_node_find_item(struct ssdfs_btree_node *node,
				     struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	if (search->request.count != 1 ||
	    search->request.start.hash != search->request.end.hash) {
		SSDFS_ERR("invalid request state: "
			  "count %d, start_hash %llx, end_hash %llx\n",
			  search->request.count,
			  search->request.start.hash,
			  search->request.end.hash);
		return -ERANGE;
	}

	return ssdfs_xattrs_btree_node_find_range(node, search);
}

static
int ssdfs_xattrs_btree_node_allocate_item(struct ssdfs_btree_node *node,
					 struct ssdfs_btree_search *search)
{
	SSDFS_DBG("operation is unavailable\n");
	return -EOPNOTSUPP;
}

static
int ssdfs_xattrs_btree_node_allocate_range(struct ssdfs_btree_node *node,
					  struct ssdfs_btree_search *search)
{
	SSDFS_DBG("operation is unavailable\n");
	return -EOPNOTSUPP;
}

/*
 * __ssdfs_xattrs_btree_node_get_xattr() - extract the xattr from pagevec
 * @pvec: pointer on pagevec
 * @area_offset: area offset from the node's beginning
 * @area_size: area size
 * @node_size: size of the node
 * @item_index: index of the xattr in the node
 * @xattr: pointer on xattr's buffer [out]
 *
 * This method tries to extract the xattr from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int __ssdfs_xattrs_btree_node_get_xattr(struct pagevec *pvec,
					u32 area_offset,
					u32 area_size,
					u32 node_size,
					u16 item_index,
					struct ssdfs_xattr_entry *xattr)
{
	struct ssdfs_xattr_entry *found_xattr;
	size_t item_size = sizeof(struct ssdfs_xattr_entry);
	u32 item_offset;
	int page_index;
	struct page *page;
	void *kaddr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec || !xattr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("area_offset %u, area_size %u, item_index %u\n",
		  area_offset, area_size, item_index);

	item_offset = (u32)item_index * item_size;
	if (item_offset >= area_size) {
		SSDFS_ERR("item_offset %u >= area_size %u\n",
			  item_offset, area_size);
		return -ERANGE;
	}

	item_offset += area_offset;
	if (item_offset >= node_size) {
		SSDFS_ERR("item_offset %u >= node_size %u\n",
			  item_offset, node_size);
		return -ERANGE;
	}

	page_index = item_offset >> PAGE_SHIFT;

	if (page_index > 0)
		item_offset %= page_index * PAGE_SIZE;

	if (page_index >= pagevec_count(pvec)) {
		SSDFS_ERR("invalid page_index: "
			  "index %d, pvec_size %u\n",
			  page_index,
			  pagevec_count(pvec));
		return -ERANGE;
	}

	page = pvec->pages[page_index];

	kaddr = kmap_atomic(page);
	found_xattr = (struct ssdfs_xattr_entry *)((u8 *)kaddr + item_offset);
	memcpy(xattr, found_xattr, item_size);
	kunmap_atomic(kaddr);

	return 0;
}

/*
 * ssdfs_xattrs_btree_node_get_xattr() - extract xattr from the node
 * @node: pointer on node object
 * @area: items area descriptor
 * @item_index: index of the dentry
 * @xattr: pointer on extracted xattr [out]
 *
 * This method tries to extract the xattr from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_xattrs_btree_node_get_xattr(struct ssdfs_btree_node *node,
				struct ssdfs_btree_node_items_area *area,
				u16 item_index,
				struct ssdfs_xattr_entry *xattr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !xattr);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, item_index);

	return __ssdfs_xattrs_btree_node_get_xattr(&node->content.pvec,
						   area->offset,
						   area->area_size,
						   node->node_size,
						   item_index,
						   xattr);
}

/*
 * is_requested_position_correct() - check that requested position is correct
 * @node: pointer on node object
 * @area: items area descriptor
 * @search: search object
 *
 * This method tries to check that requested position of an xattr
 * into the node is correct.
 *
 * RETURN:
 * [success]
 *
 * %SSDFS_CORRECT_POSITION        - requested position is correct.
 * %SSDFS_SEARCH_LEFT_DIRECTION   - correct position from the left.
 * %SSDFS_SEARCH_RIGHT_DIRECTION  - correct position from the right.
 *
 * [failure] - error code:
 *
 * %SSDFS_CHECK_POSITION_FAILURE  - internal error.
 */
static
int is_requested_position_correct(struct ssdfs_btree_node *node,
				  struct ssdfs_btree_node_items_area *area,
				  struct ssdfs_btree_search *search)
{
	struct ssdfs_xattr_entry xattr;
	u16 item_index;
	u64 hash;
	int direction = SSDFS_CHECK_POSITION_FAILURE;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, search->result.start_index);

	item_index = search->result.start_index;
	if ((item_index + search->request.count) >= area->items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, count %u\n",
			  item_index, search->request.count);
		return SSDFS_CHECK_POSITION_FAILURE;
	}

	if (item_index >= area->items_count) {
		if (area->items_count == 0)
			item_index = area->items_count;
		else
			item_index = area->items_count - 1;

		search->result.start_index = item_index;
	}

	if (item_index == 0)
		return SSDFS_CORRECT_POSITION;

	err = ssdfs_xattrs_btree_node_get_xattr(node, area,
						item_index, &xattr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract the xattr: "
			  "item_index %u, err %d\n",
			  item_index, err);
		return SSDFS_CHECK_POSITION_FAILURE;
	}

	hash = le64_to_cpu(xattr.name_hash);

	if (search->request.end.hash < hash)
		direction = SSDFS_SEARCH_LEFT_DIRECTION;
	else if (hash < search->request.start.hash)
		direction = SSDFS_SEARCH_RIGHT_DIRECTION;
	else
		direction = SSDFS_CORRECT_POSITION;

	return direction;
}

/*
 * ssdfs_find_correct_position_from_left() - find position from the left
 * @node: pointer on node object
 * @area: items area descriptor
 * @search: search object
 *
 * This method tries to find a correct position of the xattr
 * from the left side of xattrs' sequence in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_find_correct_position_from_left(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_node_items_area *area,
				    struct ssdfs_btree_search *search)
{
	struct ssdfs_xattr_entry xattr;
	int item_index;
	u64 hash;
	u32 req_flags;
	size_t name_len;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, search->result.start_index);

	item_index = search->result.start_index;
	if ((item_index + search->request.count) >= area->items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, count %u\n",
			  item_index, search->request.count);
		return -ERANGE;
	}

	if (item_index >= area->items_count) {
		if (area->items_count == 0)
			item_index = area->items_count;
		else
			item_index = area->items_count - 1;

		search->result.start_index = (u16)item_index;
	}

	if (item_index == 0)
		return 0;

	req_flags = search->request.flags;

	for (; item_index >= 0; item_index--) {
		err = ssdfs_xattrs_btree_node_get_xattr(node, area,
							(u16)item_index,
							&xattr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the xattr: "
				  "item_index %d, err %d\n",
				  item_index, err);
			return err;
		}

		hash = le64_to_cpu(xattr.name_hash);

		if (search->request.start.hash == hash) {
			if (req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME) {
				int res;

				if (!search->request.start.name) {
					SSDFS_ERR("empty name pointer\n");
					return -ERANGE;
				}

				name_len = min_t(size_t,
					    search->request.start.name_len,
					    SSDFS_XATTR_INLINE_NAME_MAX_LEN);
				res = strncmp(search->request.start.name,
						xattr.inline_string,
						name_len);
				if (res == 0) {
					search->result.start_index =
							(u16)item_index;
					return 0;
				} else if (res < 0) {
					search->result.start_index =
							(u16)(item_index + 1);
					return 0;
				} else
					continue;
			}

			search->result.start_index = (u16)item_index;
			return 0;
		} else if (hash < search->request.start.hash) {
			search->result.start_index = (u16)(item_index + 1);
			return 0;
		}
	}

	search->result.start_index = 0;
	return 0;
}

/*
 * ssdfs_find_correct_position_from_right() - find position from the right
 * @node: pointer on node object
 * @area: items area descriptor
 * @search: search object
 *
 * This method tries to find a correct position of the xattr
 * from the right side of xattrs' sequence in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_find_correct_position_from_right(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_node_items_area *area,
				    struct ssdfs_btree_search *search)
{
	struct ssdfs_xattr_entry xattr;
	int item_index;
	u64 hash;
	u32 req_flags;
	size_t name_len;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, search->result.start_index);

	item_index = search->result.start_index;
	if ((item_index + search->request.count) >= area->items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, count %u\n",
			  item_index, search->request.count);
		return -ERANGE;
	}

	if (item_index >= area->items_count) {
		if (area->items_count == 0)
			item_index = area->items_count;
		else
			item_index = area->items_count - 1;

		search->result.start_index = (u16)item_index;
	}

	if (item_index == 0)
		return 0;

	req_flags = search->request.flags;

	for (; item_index < area->items_count; item_index++) {
		err = ssdfs_xattrs_btree_node_get_xattr(node, area,
							(u16)item_index,
							&xattr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the xattr: "
				  "item_index %d, err %d\n",
				  item_index, err);
			return err;
		}

		hash = le64_to_cpu(xattr.name_hash);

		if (search->request.start.hash == hash) {
			if (req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME) {
				int res;

				if (!search->request.start.name) {
					SSDFS_ERR("empty name pointer\n");
					return -ERANGE;
				}

				name_len = min_t(size_t,
					    search->request.start.name_len,
					    SSDFS_XATTR_INLINE_NAME_MAX_LEN);
				res = strncmp(search->request.start.name,
						xattr.inline_string,
						name_len);
				if (res == 0) {
					search->result.start_index =
							(u16)item_index;
					return 0;
				} else if (res > 0) {
					search->result.start_index =
							(u16)(item_index - 1);
					return 0;
				} else
					continue;
			}

			search->result.start_index = (u16)item_index;
			return 0;
		} else if (search->request.end.hash < hash) {
			if (item_index == 0) {
				search->result.start_index =
						(u16)item_index;
			} else {
				search->result.start_index =
						(u16)(item_index - 1);
			}
			return 0;
		}
	}

	search->result.start_index = area->items_count - 1;
	return 0;
}

/*
 * ssdfs_correct_lookup_table() - correct lookup table of the node
 * @node: pointer on node object
 * @area: items area descriptor
 * @start_index: starting index of the range
 * @range_len: number of items in the range
 *
 * This method tries to correct the lookup table of the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_correct_lookup_table(struct ssdfs_btree_node *node,
				struct ssdfs_btree_node_items_area *area,
				u16 start_index, u16 range_len)
{
	__le64 *lookup_table;
	struct ssdfs_xattr_entry xattr;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u\n", node->node_id);

	if (range_len == 0) {
		SSDFS_WARN("search->request.count == 0\n");
		return -ERANGE;
	}

	lookup_table = node->raw.xattrs_header.lookup_table;

	for (i = 0; i < range_len; i++) {
		int item_index = start_index + i;
		u16 lookup_index;

		if (is_hash_for_lookup_table(node->node_size, item_index)) {
			lookup_index =
				ssdfs_convert_item2lookup_index(node->node_size,
								item_index);

			err = ssdfs_xattrs_btree_node_get_xattr(node, area,
								item_index,
								&xattr);
			if (unlikely(err)) {
				SSDFS_ERR("fail to extract xattr: "
					  "item_index %d, err %d\n",
					  item_index, err);
				return err;
			}

			lookup_table[lookup_index] = xattr.name_hash;
		}
	}

	return 0;
}

/*
 * ssdfs_initialize_lookup_table() - initialize lookup table
 * @node: pointer on node object
 */
static
void ssdfs_initialize_lookup_table(struct ssdfs_btree_node *node)
{
	__le64 *lookup_table;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->header_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u\n", node->node_id);

	lookup_table = node->raw.xattrs_header.lookup_table;
	memset(lookup_table, 0xFF,
		sizeof(__le64) * SSDFS_XATTRS_BTREE_LOOKUP_TABLE_SIZE);
}

/*
 * __ssdfs_xattrs_btree_node_insert_range() - insert range into node
 * @node: pointer on node object
 * @search: search object
 *
 * This method tries to insert the range of xattrs into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int __ssdfs_xattrs_btree_node_insert_range(struct ssdfs_btree_node *node,
					   struct ssdfs_btree_search *search)
{
	struct ssdfs_btree *tree;
	struct ssdfs_xattrs_btree_info *xtree;
	struct ssdfs_xattrs_btree_node_header *hdr;
	struct ssdfs_btree_node_items_area items_area;
	struct ssdfs_xattr_entry xattr;
	size_t item_size = sizeof(struct ssdfs_xattr_entry);
	u16 item_index;
	int free_items;
	u16 range_len;
	u16 xattrs_count = 0;
	int direction;
	u32 used_space;
	u64 start_hash, end_hash, cur_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid items_area state %#x\n",
			  atomic_read(&node->items_area.state));
		return -ERANGE;
	}

	tree = node->tree;

	switch (tree->type) {
	case SSDFS_XATTR_BTREE:
		/* expected btree type */
		break;

	default:
		SSDFS_ERR("invalid btree type %#x\n", tree->type);
		return -ERANGE;
	}

	xtree = container_of(tree, struct ssdfs_xattrs_btree_info,
			     buffer.tree);

	down_read(&node->header_lock);
	memcpy(&items_area, &node->items_area,
		sizeof(struct ssdfs_btree_node_items_area));
	up_read(&node->header_lock);

	if (items_area.items_capacity == 0 ||
	    items_area.items_capacity < items_area.items_count) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid items accounting: "
			  "node_id %u, items_capacity %u, items_count %u\n",
			  node->node_id, items_area.items_capacity,
			  items_area.items_count);
		return -EFAULT;
	}

	if (items_area.min_item_size != item_size ||
	    items_area.max_item_size != item_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("min_item_size %u, max_item_size %u, "
			  "item_size %zu\n",
			  items_area.min_item_size, items_area.max_item_size,
			  item_size);
		return -EFAULT;
	}

	if (items_area.area_size == 0 ||
	    items_area.area_size >= node->node_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid area_size %u\n",
			  items_area.area_size);
		return -EFAULT;
	}

	if (items_area.free_space > items_area.area_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("free_space %u > area_size %u\n",
			  items_area.free_space, items_area.area_size);
		return -EFAULT;
	}

	free_items = items_area.items_capacity - items_area.items_count;
	if (unlikely(free_items < 0)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_WARN("invalid free_items %d\n",
			   free_items);
		return -EFAULT;
	} else if (free_items == 0) {
		SSDFS_DBG("node hasn't free items\n");
		return -ENOSPC;
	}

	if (((u64)free_items * item_size) > items_area.free_space) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid free_items: "
			  "free_items %d, item_size %zu, free_space %u\n",
			  free_items, item_size, items_area.free_space);
		return -EFAULT;
	}

	item_index = search->result.start_index;
	if ((item_index + search->request.count) >= items_area.items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, count %u\n",
			  item_index, search->request.count);
		return -ERANGE;
	}

	start_hash = items_area.start_hash;
	end_hash = items_area.end_hash;

	down_write(&node->full_lock);

	direction = is_requested_position_correct(node, &items_area,
						  search);
	switch (direction) {
	case SSDFS_CORRECT_POSITION:
		/* do nothing */
		break;

	case SSDFS_SEARCH_LEFT_DIRECTION:
		err = ssdfs_find_correct_position_from_left(node, &items_area,
							    search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the correct position: "
				  "err %d\n",
				  err);
			goto finish_detect_affected_items;
		}
		break;

	case SSDFS_SEARCH_RIGHT_DIRECTION:
		err = ssdfs_find_correct_position_from_right(node, &items_area,
							     search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the correct position: "
				  "err %d\n",
				  err);
			goto finish_detect_affected_items;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("fail to check requested position\n");
		goto finish_detect_affected_items;
	}

	range_len = items_area.items_count - search->result.start_index;
	xattrs_count = range_len + search->request.count;

	item_index = search->result.start_index;
	if ((item_index + xattrs_count) > items_area.items_capacity) {
		err = -ERANGE;
		SSDFS_ERR("invalid xattrs_count: "
			  "item_index %u, xattrs_count %u, "
			  "items_capacity %u\n",
			  item_index, xattrs_count,
			  items_area.items_capacity);
		goto finish_detect_affected_items;
	}

	if (items_area.items_count == 0)
		goto lock_items_range;

	if (item_index > 0) {
		err = ssdfs_xattrs_btree_node_get_xattr(node,
							&items_area,
							item_index - 1,
							&xattr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get xattr: err %d\n", err);
			goto finish_detect_affected_items;
		}

		cur_hash = le64_to_cpu(xattr.name_hash);

		if (cur_hash < start_hash) {
			/*
			 * expected state
			 */
		} else {
			err = -ERANGE;
			SSDFS_ERR("invalid range: cur_hash %llx, "
				  "start_hash %llx, end_hash %llx\n",
				  cur_hash, start_hash, end_hash);
			goto finish_detect_affected_items;
		}
	}

	if (item_index < items_area.items_count) {
		err = ssdfs_xattrs_btree_node_get_xattr(node,
							&items_area,
							item_index,
							&xattr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get xattr: err %d\n", err);
			goto finish_detect_affected_items;
		}

		cur_hash = le64_to_cpu(xattr.name_hash);

		if (end_hash < cur_hash) {
			/*
			 * expected state
			 */
		} else {
			err = -ERANGE;
			SSDFS_ERR("invalid range: cur_hash %llx, "
				  "start_hash %llx, end_hash %llx\n",
				  cur_hash, start_hash, end_hash);
			goto finish_detect_affected_items;
		}
	}

lock_items_range:
	err = ssdfs_lock_items_range(node, item_index, xattrs_count);
	if (err == -ENOENT) {
		up_write(&node->full_lock);
		wake_up_all(&node->wait_queue);
		return -ERANGE;
	} else if (err == -ENODATA) {
		up_write(&node->full_lock);
		wake_up_all(&node->wait_queue);
		return -ERANGE;
	} else if (unlikely(err))
		BUG();

finish_detect_affected_items:
	downgrade_write(&node->full_lock);

	if (unlikely(err))
		goto finish_insert_item;

	err = ssdfs_shift_range_right(node, &items_area, item_size,
				      item_index, range_len,
				      search->request.count);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to shift dentries range: "
			  "start %u, count %u, err %d\n",
			  item_index, search->request.count,
			  err);
		goto unlock_items_range;
	}

	err = ssdfs_generic_insert_range(node, &items_area,
					 item_size, search);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to insert item: err %d\n",
			  err);
		goto unlock_items_range;
	}

	down_write(&node->header_lock);

	node->items_area.items_count += search->request.count;
	if (node->items_area.items_count > node->items_area.items_capacity) {
		err = -ERANGE;
		SSDFS_ERR("items_count %u > items_capacity %u\n",
			  node->items_area.items_count,
			  node->items_area.items_capacity);
		goto finish_items_area_correction;
	}

	used_space = (u32)search->request.count * item_size;
	if (used_space > node->items_area.free_space) {
		err = -ERANGE;
		SSDFS_ERR("used_space %u > free_space %u\n",
			  used_space,
			  node->items_area.free_space);
		goto finish_items_area_correction;
	}
	node->items_area.free_space -= used_space;

	err = ssdfs_xattrs_btree_node_get_xattr(node, &node->items_area,
						0, &xattr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get xattr: err %d\n", err);
		goto finish_items_area_correction;
	}
	start_hash = le64_to_cpu(xattr.name_hash);

	err = ssdfs_xattrs_btree_node_get_xattr(node,
					&node->items_area,
					node->items_area.items_count - 1,
					&xattr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get xattr: err %d\n", err);
		goto finish_items_area_correction;
	}
	end_hash = le64_to_cpu(xattr.name_hash);

	if (start_hash >= U64_MAX || end_hash >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("start_hash %llx, end_hash %llx\n",
			  start_hash, end_hash);
		goto finish_items_area_correction;
	}

	node->items_area.start_hash = start_hash;
	node->items_area.end_hash = end_hash;

	err = ssdfs_correct_lookup_table(node, &node->items_area,
					 item_index, xattrs_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to correct lookup table: "
			  "err %d\n", err);
		goto finish_items_area_correction;
	}

	hdr = &node->raw.xattrs_header;
	le16_add_cpu(&hdr->xattrs_count, search->request.count);

finish_items_area_correction:
	up_write(&node->header_lock);

	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		goto unlock_items_range;
	}

	err = ssdfs_set_node_header_dirty(node, items_area.items_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set header dirty: err %d\n",
			  err);
		goto unlock_items_range;
	}

	err = ssdfs_set_dirty_items_range(node, items_area.items_capacity,
					  item_index, xattrs_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set items range as dirty: "
			  "start %u, count %u, err %d\n",
			  item_index, xattrs_count, err);
		goto unlock_items_range;
	}

unlock_items_range:
	ssdfs_unlock_items_range(node, item_index, xattrs_count);

finish_insert_item:
	up_read(&node->full_lock);

	return err;
}

/*
 * ssdfs_xattrs_btree_node_insert_item() - insert item in the node
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to insert an item in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - node hasn't free items.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_xattrs_btree_node_insert_item(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
	int state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	if (search->result.state != SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND) {
		SSDFS_ERR("invalid result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.err == -ENODATA) {
		search->result.err = 0;
		/*
		 * Node doesn't contain an item.
		 */
	} else if (search->result.err) {
		SSDFS_WARN("invalid search result: err %d\n",
			   search->result.err);
		return search->result.err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.count != 1);
	BUG_ON(!search->result.buf);
	BUG_ON(search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&node->items_area.state);
	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  state);
		return -ERANGE;
	}

	err = __ssdfs_xattrs_btree_node_insert_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert item: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_xattrs_btree_node_insert_range() - insert range of items
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to insert a range of items in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - node hasn't free items.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_xattrs_btree_node_insert_range(struct ssdfs_btree_node *node,
					 struct ssdfs_btree_search *search)
{
	int state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	if (search->result.state != SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND) {
		SSDFS_ERR("invalid result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.err == -ENODATA) {
		search->result.err = 0;
		/*
		 * Node doesn't contain an item.
		 */
	} else if (search->result.err) {
		SSDFS_WARN("invalid search result: err %d\n",
			   search->result.err);
		return search->result.err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.count <= 1);
	BUG_ON(!search->result.buf);
	BUG_ON(search->result.buf_state != SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&node->items_area.state);
	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  state);
		return -ERANGE;
	}

	err = __ssdfs_xattrs_btree_node_insert_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert range: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_change_item_only() - change xattr in the node
 * @node: pointer on node object
 * @area: pointer on items area's descriptor
 * @search: pointer on search request object
 *
 * This method tries to change an item in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_change_item_only(struct ssdfs_btree_node *node,
			   struct ssdfs_btree_node_items_area *area,
			   struct ssdfs_btree_search *search)
{
	struct ssdfs_xattr_entry xattr;
	size_t item_size = sizeof(struct ssdfs_xattr_entry);
	u16 range_len;
	u16 item_index;
	u64 start_hash, end_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	range_len = search->request.count;

	if (range_len == 0) {
		err = -ERANGE;
		SSDFS_ERR("empty range\n");
		return err;
	}

	item_index = search->result.start_index;
	if ((item_index + range_len) > area->items_count) {
		err = -ERANGE;
		SSDFS_ERR("invalid request: "
			  "item_index %u, range_len %u, items_count %u\n",
			  item_index, range_len,
			  area->items_count);
		return err;
	}

	err = ssdfs_generic_insert_range(node, area,
					 item_size, search);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to insert range: err %d\n",
			  err);
		return err;
	}

	down_write(&node->header_lock);

	start_hash = node->items_area.start_hash;
	end_hash = node->items_area.end_hash;

	if (item_index == 0) {
		err = ssdfs_xattrs_btree_node_get_xattr(node,
							&node->items_area,
							item_index,
							&xattr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get xattr: err %d\n", err);
			goto finish_items_area_correction;
		}
		start_hash = le64_to_cpu(xattr.name_hash);
	}

	if ((item_index + range_len) == node->items_area.items_count) {
		err = ssdfs_xattrs_btree_node_get_xattr(node,
						    &node->items_area,
						    item_index + range_len - 1,
						    &xattr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get xattr: err %d\n", err);
			goto finish_items_area_correction;
		}
		end_hash = le64_to_cpu(xattr.name_hash);
	} else if ((item_index + range_len) > node->items_area.items_count) {
		err = -ERANGE;
		SSDFS_ERR("invalid range_len: "
			  "item_index %u, range_len %u, items_count %u\n",
			  item_index, range_len,
			  node->items_area.items_count);
		goto finish_items_area_correction;
	}

	node->items_area.start_hash = start_hash;
	node->items_area.end_hash = end_hash;

	err = ssdfs_correct_lookup_table(node, &node->items_area,
					 item_index, range_len);
	if (unlikely(err)) {
		SSDFS_ERR("fail to correct lookup table: "
			  "err %d\n", err);
		goto finish_items_area_correction;
	}

finish_items_area_correction:
	up_write(&node->header_lock);

	if (unlikely(err))
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);

	return err;
}

/*
 * ssdfs_xattrs_btree_node_change_item() - change item in the node
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to change an item in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_xattrs_btree_node_change_item(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
	size_t item_size = sizeof(struct ssdfs_xattr_entry);
	struct ssdfs_btree_node_items_area items_area;
	u16 item_index = 0;
	int direction;
	u16 range_len = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	if (search->result.state != SSDFS_BTREE_SEARCH_VALID_ITEM) {
		SSDFS_ERR("invalid result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.err) {
		SSDFS_WARN("invalid search result: err %d\n",
			   search->result.err);
		return search->result.err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.count != 1);
	BUG_ON(!search->result.buf);
	BUG_ON(search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER);
	BUG_ON(search->result.items_in_buffer != 1);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid items_area state %#x\n",
			  atomic_read(&node->items_area.state));
		return -ERANGE;
	}

	down_read(&node->header_lock);
	memcpy(&items_area, &node->items_area,
		sizeof(struct ssdfs_btree_node_items_area));
	up_read(&node->header_lock);

	if (items_area.items_capacity == 0 ||
	    items_area.items_capacity < items_area.items_count) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid items accounting: "
			  "node_id %u, items_capacity %u, items_count %u\n",
			  node->node_id, items_area.items_capacity,
			  items_area.items_count);
		return -EFAULT;
	}

	if (items_area.min_item_size != item_size ||
	    items_area.max_item_size != item_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("min_item_size %u, max_item_size %u, "
			  "item_size %zu\n",
			  items_area.min_item_size, items_area.max_item_size,
			  item_size);
		return -EFAULT;
	}

	if (items_area.area_size == 0 ||
	    items_area.area_size >= node->node_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid area_size %u\n",
			  items_area.area_size);
		return -EFAULT;
	}

	down_write(&node->full_lock);

	direction = is_requested_position_correct(node, &items_area,
						  search);
	switch (direction) {
	case SSDFS_CORRECT_POSITION:
		/* do nothing */
		break;

	case SSDFS_SEARCH_LEFT_DIRECTION:
		err = ssdfs_find_correct_position_from_left(node, &items_area,
							    search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the correct position: "
				  "err %d\n",
				  err);
			goto finish_define_changing_items;
		}
		break;

	case SSDFS_SEARCH_RIGHT_DIRECTION:
		err = ssdfs_find_correct_position_from_right(node, &items_area,
							     search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the correct position: "
				  "err %d\n",
				  err);
			goto finish_define_changing_items;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("fail to check requested position\n");
		goto finish_define_changing_items;
	}

	range_len = search->request.count;

	if (range_len == 0) {
		err = -ERANGE;
		SSDFS_ERR("empty range\n");
		goto finish_define_changing_items;
	}

	item_index = search->result.start_index;
	if ((item_index + range_len) > items_area.items_count) {
		err = -ERANGE;
		SSDFS_ERR("invalid request: "
			  "item_index %u, range_len %u, items_count %u\n",
			  item_index, range_len,
			  items_area.items_count);
		goto finish_define_changing_items;
	}


	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_CHANGE_ITEM:
		/* range_len doesn't need to be changed */
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid request type: %#x\n",
			  search->request.type);
		goto finish_define_changing_items;
	}

	err = ssdfs_lock_items_range(node, item_index, range_len);
	if (err == -ENOENT) {
		up_write(&node->full_lock);
		wake_up_all(&node->wait_queue);
		return -ERANGE;
	} else if (err == -ENODATA) {
		up_write(&node->full_lock);
		wake_up_all(&node->wait_queue);
		return -ERANGE;
	} else if (unlikely(err))
		BUG();

finish_define_changing_items:
	downgrade_write(&node->full_lock);

	if (unlikely(err))
		goto finish_change_item;
	else {
		err = ssdfs_change_item_only(node, &items_area, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change item: err %d\n",
				  err);
			goto finish_change_item;
		}

		err = ssdfs_set_node_header_dirty(node,
					items_area.items_capacity);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set header dirty: err %d\n",
				  err);
			goto finish_change_item;
		}

		err = ssdfs_set_dirty_items_range(node,
					items_area.items_capacity,
					item_index, range_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set items range as dirty: "
				  "start %u, count %u, err %d\n",
				  item_index, range_len, err);
			goto finish_change_item;
		}
	}

finish_change_item:
	ssdfs_unlock_items_range(node, item_index, range_len);
	up_read(&node->full_lock);

	return err;
}

/*
 * ssdfs_invalidate_blobs_range() - invalidate range of external blobs
 * @node: pointer on node object
 * @area: pointer on items area's descriptor
 * @start_index: starting index of the xattr
 * @range_len: number of xattrs in the range
 *
 * This method tries to invalidate the range of external blobs.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_invalidate_blobs_range(struct ssdfs_btree_node *node,
				 struct ssdfs_btree_node_items_area *area,
				 u16 start_index, u16 range_len)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_shared_extents_tree *shextree;
	struct ssdfs_btree *tree;
	struct ssdfs_xattrs_btree_info *xattrs_tree;
	struct ssdfs_xattr_entry xattr;
	struct ssdfs_blob_extent *desc;
	struct ssdfs_raw_extent *extent;
	u64 owner_ino;
	u16 cur_index;
	u16 i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !node->tree || !node->tree->fsi);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, start_index %u, range_len %u\n",
		  node->node_id, start_index, range_len);

	fsi = node->tree->fsi;

	shextree = fsi->shextree;
	if (!shextree) {
		SSDFS_ERR("shared extents tree is absent\n");
		return -ERANGE;
	}

	tree = node->tree;

	if (tree->type != SSDFS_XATTR_BTREE) {
		SSDFS_ERR("invalid tree type %#x\n",
			  tree->type);
		return -ERANGE;
	}

	xattrs_tree = container_of(tree, struct ssdfs_xattrs_btree_info,
				   buffer.tree);

	owner_ino = xattrs_tree->owner->vfs_inode.i_ino;

	if ((start_index + range_len) >= area->items_count) {
		SSDFS_ERR("invalid request: "
			  "start_index %u, range_len %u\n",
			  start_index, range_len);
		return -ERANGE;
	}

	for (i = 0; i < range_len; i++) {
		cur_index = start_index + i;

		err = ssdfs_xattrs_btree_node_get_xattr(node, area,
							cur_index,
							&xattr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get xattr: "
				  "cur_index %u, err %d\n",
				  cur_index, err);
			return err;
		}

		switch (xattr.blob_type) {
		case SSDFS_XATTR_INLINE_BLOB:
			if (xattr.blob_flags & SSDFS_XATTR_HAS_EXTERNAL_BLOB) {
				SSDFS_ERR("invalid xattr: "
					  "blob_type %#x, blob_flags %#x\n",
					  xattr.blob_type,
					  xattr.blob_flags);
				return -ERANGE;
			} else {
				/* skip invalidation for the inline blob */
				continue;
			}
			break;

		case SSDFS_XATTR_REGULAR_BLOB:
			if (xattr.blob_flags & ~SSDFS_XATTR_HAS_EXTERNAL_BLOB) {
				SSDFS_ERR("invalid xattr: "
					  "blob_type %#x, blob_flags %#x\n",
					  xattr.blob_type,
					  xattr.blob_flags);
				return -ERANGE;
			}

			desc = &xattr.blob.descriptor;
			extent = &xattr.blob.descriptor.extent;
			err = ssdfs_shextree_add_pre_invalid_extent(shextree,
								    owner_ino,
								    extent);
			if (unlikely(err)) {
				SSDFS_ERR("fail to make the blob pre-invalid: "
					  "cur_index %u, err %d\n",
					  i, err);
				return err;
			}
			break;

		default:
			SSDFS_ERR("invalid blob_type %#x\n",
				  xattr.blob_type);
			return -ERANGE;
		}
	}

	return 0;
}

/*
 * __ssdfs_invalidate_items_area() - invalidate the items area
 * @node: pointer on node object
 * @area: pointer on items area's descriptor
 * @start_index: starting index of the item
 * @range_len: number of items in the range
 * @search: pointer on search request object
 *
 * The method tries to invalidate the items area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_invalidate_items_area(struct ssdfs_btree_node *node,
				  struct ssdfs_btree_node_items_area *area,
				  u16 start_index, u16 range_len,
				  struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node *parent = NULL;
	struct ssdfs_xattrs_btree_node_header *hdr;
	size_t item_size = sizeof(struct ssdfs_xattr_entry);
	bool is_hybrid = false;
	bool has_index_area = false;
	bool index_area_empty = false;
	bool items_area_empty = false;
	int parent_type = SSDFS_BTREE_LEAF_NODE;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, start_index %u, range_len %u\n",
		  node->node_id, start_index, range_len);

	if (((u32)start_index + range_len) > area->items_count) {
		SSDFS_ERR("start_index %u, range_len %u, items_count %u\n",
			  start_index, range_len,
			  area->items_count);
		return -ERANGE;
	}

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_HYBRID_NODE:
		is_hybrid = true;
		break;

	case SSDFS_BTREE_LEAF_NODE:
		is_hybrid = false;
		break;

	default:
		SSDFS_WARN("invalid node type %#x\n",
			   atomic_read(&node->type));
		return -ERANGE;
	}

	err = ssdfs_invalidate_blobs_range(node, area,
					   start_index, range_len);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to invalidate range of blobs: "
			  "node_id %u, start_index %u, "
			  "range_len %u, err %d\n",
			  node->node_id, start_index,
			  range_len, err);
		return err;
	}

	down_write(&node->header_lock);

	hdr = &node->raw.xattrs_header;
	if (node->items_area.items_count == range_len) {
		items_area_empty = true;
		node->items_area.items_count =
			node->items_area.items_count - range_len;
		node->items_area.free_space =
			node->items_area.area_size -
				(node->items_area.items_count * item_size);
		node->items_area.start_hash = U64_MAX;
		node->items_area.end_hash = U64_MAX;
		ssdfs_initialize_lookup_table(node);
		hdr->xattrs_count = cpu_to_le16(0);
	} else
		items_area_empty = false;

	switch (atomic_read(&node->index_area.state)) {
	case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
		has_index_area = true;
		if (node->index_area.index_count == 0)
			index_area_empty = true;
		else
			index_area_empty = false;
		break;

	default:
		has_index_area = false;
		index_area_empty = false;
		break;
	}

	up_write(&node->header_lock);

	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		return err;
	}

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_DELETE_ITEM:
	case SSDFS_BTREE_SEARCH_DELETE_RANGE:
		if (is_hybrid && has_index_area && !index_area_empty) {
			search->result.state =
				SSDFS_BTREE_SEARCH_OBSOLETE_RESULT;
		} else if (items_area_empty) {
			search->result.state =
				SSDFS_BTREE_SEARCH_PLEASE_DELETE_NODE;
		} else {
			search->result.state =
				SSDFS_BTREE_SEARCH_OBSOLETE_RESULT;
		}
		break;

	case SSDFS_BTREE_SEARCH_DELETE_ALL:
		search->result.state =
			SSDFS_BTREE_SEARCH_OBSOLETE_RESULT;

		parent = node;

		do {
			parent = parent->parent_node;

			if (!parent) {
				SSDFS_ERR("node %u hasn't parent\n",
					  node->node_id);
				return -ERANGE;
			}

			parent_type = atomic_read(&parent->type);
			switch (parent_type) {
			case SSDFS_BTREE_ROOT_NODE:
			case SSDFS_BTREE_INDEX_NODE:
			case SSDFS_BTREE_HYBRID_NODE:
				/* expected state */
				break;

			default:
				SSDFS_ERR("invalid parent node's type %#x\n",
					  parent_type);
				return -ERANGE;
			}
		} while (parent_type != SSDFS_BTREE_ROOT_NODE);

		err = ssdfs_invalidate_root_node_hierarchy(parent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to invalidate root node hierarchy: "
				  "err %d\n", err);
			return -ERANGE;
		}
		break;

	default:
		atomic_set(&node->state,
			   SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid request type %#x\n",
			  search->request.type);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_invalidate_whole_items_area() - invalidate the whole items area
 * @node: pointer on node object
 * @area: pointer on items area's descriptor
 * @search: pointer on search request object
 *
 * The method tries to invalidate the items area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_invalidate_whole_items_area(struct ssdfs_btree_node *node,
				      struct ssdfs_btree_node_items_area *area,
				      struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, area %p, search %p\n",
		  node->node_id, area, search);

	return __ssdfs_invalidate_items_area(node, area,
					     0, area->items_count,
					     search);
}

/*
 * ssdfs_invalidate_items_area_partially() - invalidate the items area
 * @node: pointer on node object
 * @area: pointer on items area's descriptor
 * @start_index: starting index
 * @range_len: number of items in the range
 * @search: pointer on search request object
 *
 * The method tries to invalidate the items area partially.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_invalidate_items_area_partially(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_node_items_area *area,
				    u16 start_index, u16 range_len,
				    struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, start_index %u, range_len %u\n",
		  node->node_id, start_index, range_len);

	return __ssdfs_invalidate_items_area(node, area,
					     start_index, range_len,
					     search);
}

/*
 * __ssdfs_xattrs_btree_node_delete_range() - delete range of items
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to delete a range of items in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 * %-EAGAIN     - continue deletion in the next node.
 */
static
int __ssdfs_xattrs_btree_node_delete_range(struct ssdfs_btree_node *node,
					   struct ssdfs_btree_search *search)
{
	struct ssdfs_btree *tree;
	struct ssdfs_xattrs_btree_node_header *hdr;
	struct ssdfs_btree_node_items_area items_area;
	struct ssdfs_xattr_entry xattr;
	size_t item_size = sizeof(struct ssdfs_xattr_entry);
	int free_items;
	u16 item_index;
	int direction;
	u16 range_len;
	u16 locked_len;
	u32 deleted_space, free_space;
	u64 start_hash, end_hash;
	u32 old_xattrs_count = 0, xattrs_count = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid result state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.err) {
		SSDFS_WARN("invalid search result: err %d\n",
			   search->result.err);
		return search->result.err;
	}

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid items_area state %#x\n",
			  atomic_read(&node->items_area.state));
		return -ERANGE;
	}

	tree = node->tree;

	switch (tree->type) {
	case SSDFS_XATTR_BTREE:
		/* expected btree type */
		break;

	default:
		SSDFS_ERR("invalid btree type %#x\n", tree->type);
		return -ERANGE;
	}

	down_read(&node->header_lock);
	memcpy(&items_area, &node->items_area,
		sizeof(struct ssdfs_btree_node_items_area));
	up_read(&node->header_lock);

	if (items_area.items_capacity == 0 ||
	    items_area.items_capacity < items_area.items_count) {
		SSDFS_ERR("invalid items accounting: "
			  "node_id %u, items_capacity %u, items_count %u\n",
			  search->node.id,
			  items_area.items_capacity,
			  items_area.items_count);
		return -ERANGE;
	}

	if (items_area.min_item_size != item_size ||
	    items_area.max_item_size != item_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("min_item_size %u, max_item_size %u, "
			  "item_size %zu\n",
			  items_area.min_item_size, items_area.max_item_size,
			  item_size);
		return -EFAULT;
	}

	if (items_area.area_size == 0 ||
	    items_area.area_size >= node->node_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid area_size %u\n",
			  items_area.area_size);
		return -EFAULT;
	}

	if (items_area.free_space > items_area.area_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("free_space %u > area_size %u\n",
			  items_area.free_space, items_area.area_size);
		return -EFAULT;
	}

	free_items = items_area.items_capacity - items_area.items_count;
	if (unlikely(free_items < 0)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_WARN("invalid free_items %d\n",
			   free_items);
		return -EFAULT;
	}

	if (((u64)free_items * item_size) > items_area.free_space) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid free_items: "
			  "free_items %d, item_size %zu, free_space %u\n",
			  free_items, item_size, items_area.free_space);
		return -EFAULT;
	}

	xattrs_count = items_area.items_count;
	item_index = search->result.start_index;

	range_len = search->request.count;
	if (range_len == 0) {
		SSDFS_ERR("range_len == 0\n");
		return -ERANGE;
	}

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_DELETE_ITEM:
		if ((item_index + range_len) >= items_area.items_count) {
			SSDFS_ERR("invalid request: "
				  "item_index %u, count %u\n",
				  item_index, range_len);
			return -ERANGE;
		}
		break;

	case SSDFS_BTREE_SEARCH_DELETE_RANGE:
	case SSDFS_BTREE_SEARCH_DELETE_ALL:
		/* request can be distributed between several nodes */
		break;

	default:
		atomic_set(&node->state,
			   SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid request type %#x\n",
			  search->request.type);
		return -ERANGE;
	}

	down_write(&node->full_lock);

	direction = is_requested_position_correct(node, &items_area,
						  search);
	switch (direction) {
	case SSDFS_CORRECT_POSITION:
		/* do nothing */
		break;

	case SSDFS_SEARCH_LEFT_DIRECTION:
		err = ssdfs_find_correct_position_from_left(node, &items_area,
							    search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the correct position: "
				  "err %d\n",
				  err);
			goto finish_detect_affected_items;
		}
		break;

	case SSDFS_SEARCH_RIGHT_DIRECTION:
		err = ssdfs_find_correct_position_from_right(node, &items_area,
							     search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the correct position: "
				  "err %d\n",
				  err);
			goto finish_detect_affected_items;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("fail to check requested position\n");
		goto finish_detect_affected_items;
	}

	item_index = search->result.start_index;

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_DELETE_ITEM:
		if ((item_index + range_len) > items_area.items_count) {
			err = -ERANGE;
			SSDFS_ERR("invalid xattrs_count: "
				  "item_index %u, xattrs_count %u, "
				  "items_count %u\n",
				  item_index, range_len,
				  items_area.items_count);
			goto finish_detect_affected_items;
		}
		break;

	case SSDFS_BTREE_SEARCH_DELETE_RANGE:
	case SSDFS_BTREE_SEARCH_DELETE_ALL:
		/* request can be distributed between several nodes */
		range_len = min_t(unsigned int, range_len,
				  items_area.items_count - item_index);
		SSDFS_DBG("node_id %u, item_index %u, "
			  "request.count %u, items_count %u\n",
			  node->node_id, item_index,
			  search->request.count,
			  items_area.items_count);
		break;

	default:
		BUG();
	}

	locked_len = items_area.items_count - item_index;

	err = ssdfs_lock_items_range(node, item_index, locked_len);
	if (err == -ENOENT) {
		up_write(&node->full_lock);
		wake_up_all(&node->wait_queue);
		return -ERANGE;
	} else if (err == -ENODATA) {
		up_write(&node->full_lock);
		wake_up_all(&node->wait_queue);
		return -ERANGE;
	} else if (unlikely(err))
		BUG();

finish_detect_affected_items:
	downgrade_write(&node->full_lock);

	if (unlikely(err))
		goto finish_delete_range;

	if (range_len == items_area.items_count) {
		/* items area is empty */
		err = ssdfs_invalidate_whole_items_area(node, &items_area,
							search);
	} else {
		err = ssdfs_invalidate_items_area_partially(node, &items_area,
							    item_index,
							    range_len,
							    search);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to invalidate items area: "
			  "node_id %u, start_index %u, "
			  "range_len %u, err %d\n",
			  node->node_id, item_index,
			  range_len, err);
		goto unlock_items;
	}

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_DELETE_ITEM:
	case SSDFS_BTREE_SEARCH_DELETE_RANGE:
		switch (search->result.state) {
		case SSDFS_BTREE_SEARCH_PLEASE_DELETE_NODE:
			err = ssdfs_set_node_header_dirty(node,
					items_area.items_capacity);
			if (unlikely(err)) {
				SSDFS_ERR("fail to set header dirty: "
					  "err %d\n", err);
			}
			goto unlock_items;

		default:
			/* continue to shift rest names to left */
			break;
		}
		break;

	case SSDFS_BTREE_SEARCH_DELETE_ALL:
		err = ssdfs_set_node_header_dirty(node,
						  items_area.items_capacity);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set header dirty: err %d\n",
				  err);
		}
		goto unlock_items;

	default:
		BUG();
	}

	err = ssdfs_shift_range_left(node, &items_area, item_size,
				     item_index, range_len,
				     range_len);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to shift the range: "
			  "start %u, count %u, err %d\n",
			  item_index, search->request.count,
			  err);
		goto unlock_items;
	}

	down_write(&node->header_lock);

	if (node->items_area.items_count < search->request.count)
		node->items_area.items_count = 0;
	else
		node->items_area.items_count -= search->request.count;

	deleted_space = (u32)search->request.count * item_size;
	free_space = node->items_area.free_space;
	if ((free_space + deleted_space) > node->items_area.area_size) {
		err = -ERANGE;
		SSDFS_ERR("deleted_space %u, free_space %u, area_size %u\n",
			  deleted_space,
			  node->items_area.free_space,
			  node->items_area.area_size);
		goto finish_items_area_correction;
	}
	node->items_area.free_space += deleted_space;

	if (node->items_area.items_count == 0) {
		start_hash = U64_MAX;
		end_hash = U64_MAX;
	} else {
		err = ssdfs_xattrs_btree_node_get_xattr(node,
							&node->items_area,
							0, &xattr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get xattr: err %d\n", err);
			goto finish_items_area_correction;
		}
		start_hash = le64_to_cpu(xattr.name_hash);

		err = ssdfs_xattrs_btree_node_get_xattr(node,
					&node->items_area,
					node->items_area.items_count - 1,
					&xattr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get xattr: err %d\n", err);
			goto finish_items_area_correction;
		}
		end_hash = le64_to_cpu(xattr.name_hash);
	}

	node->items_area.start_hash = start_hash;
	node->items_area.end_hash = end_hash;

	if (node->items_area.items_count == 0)
		ssdfs_initialize_lookup_table(node);
	else {
		range_len = node->items_area.items_count - item_index;
		err = ssdfs_correct_lookup_table(node,
						 &node->items_area,
						 item_index, range_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to correct lookup table: "
				  "err %d\n", err);
			goto finish_items_area_correction;
		}
	}

	hdr = &node->raw.xattrs_header;
	old_xattrs_count = le16_to_cpu(hdr->xattrs_count);

	if (node->items_area.items_count == 0) {
		hdr->xattrs_count = cpu_to_le16(0);
	} else {
		if (old_xattrs_count < search->request.count) {
			hdr->xattrs_count = cpu_to_le16(0);
		} else {
			xattrs_count = le16_to_cpu(hdr->xattrs_count);
			xattrs_count -= search->request.count;
			hdr->xattrs_count = cpu_to_le16(xattrs_count);
		}
	}

	memcpy(&items_area, &node->items_area,
		sizeof(struct ssdfs_btree_node_items_area));

	err = ssdfs_set_node_header_dirty(node, items_area.items_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set header dirty: err %d\n",
			  err);
		goto finish_items_area_correction;
	}

	if (xattrs_count != 0) {
		err = ssdfs_set_dirty_items_range(node,
					items_area.items_capacity,
					item_index,
					old_xattrs_count - item_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set items range as dirty: "
				  "start %u, count %u, err %d\n",
				  item_index,
				  old_xattrs_count - item_index,
				  err);
			goto finish_items_area_correction;
		}
	}

finish_items_area_correction:
	up_write(&node->header_lock);

	if (unlikely(err))
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);

unlock_items:
	ssdfs_unlock_items_range(node, item_index, locked_len);

finish_delete_range:
	up_read(&node->full_lock);

	if (unlikely(err))
		return err;

	if (xattrs_count == 0)
		search->result.state = SSDFS_BTREE_SEARCH_PLEASE_DELETE_NODE;
	else
		search->result.state = SSDFS_BTREE_SEARCH_OBSOLETE_RESULT;

	if (search->request.type == SSDFS_BTREE_SEARCH_DELETE_RANGE) {
		if (search->request.count > range_len) {
			search->request.start.hash = items_area.end_hash;
			search->request.count -= range_len;
			return -EAGAIN;
		}
	}

	return 0;
}

/*
 * ssdfs_xattrs_btree_node_delete_item() - delete an item from node
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to delete an item from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_xattrs_btree_node_delete_item(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.count != 1);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_xattrs_btree_node_delete_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete dentry: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_xattrs_btree_node_delete_range() - delete range of items from node
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to delete a range of items from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_xattrs_btree_node_delete_range(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	err = __ssdfs_xattrs_btree_node_delete_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete xattrs range: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_xattrs_btree_node_extract_range() - extract range of items from node
 * @node: pointer on node object
 * @start_index: starting index of the range
 * @count: count of items in the range
 * @search: pointer on search request object
 *
 * This method tries to extract a range of items from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENODATA    - no such range in the node.
 */
static
int ssdfs_xattrs_btree_node_extract_range(struct ssdfs_btree_node *node,
					 u16 start_index, u16 count,
					 struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_index %u, count %u, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  start_index, count,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	return __ssdfs_btree_node_extract_range(node, start_index, count,
						sizeof(struct ssdfs_xattr_entry),
						search);
}

/*
 * ssdfs_xattrs_btree_resize_items_area() - resize items area of the node
 * @node: node object
 * @new_size: new size of the items area
 *
 * This method tries to resize the items area of the node.
 *
 * TODO: It makes sense to allocate the bitmap with taking into
 *       account that we will resize the node. So, it needs
 *       to allocate the index area in bitmap is equal to
 *       the whole node and items area is equal to the whole node.
 *       This technique provides opportunity not to resize or
 *       to shift the content of the bitmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_xattrs_btree_resize_items_area(struct ssdfs_btree_node *node,
					 u32 new_size)
{
	struct ssdfs_fs_info *fsi;
	size_t item_size = sizeof(struct ssdfs_xattr_entry);
	size_t index_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, new_size %u\n",
		  node->node_id, new_size);

	fsi = node->tree->fsi;
	index_size = le16_to_cpu(fsi->vh->xattr_btree.desc.index_size);

	return __ssdfs_btree_node_resize_items_area(node,
						    item_size,
						    index_size,
						    new_size);
}

void ssdfs_debug_xattrs_btree_object(struct ssdfs_xattrs_btree_info *tree)
{
#ifdef CONFIG_SSDFS_DEBUG
	int i;

	BUG_ON(!tree);

	SSDFS_DBG("XATTRS TREE: type %#x, state %#x, "
		  "is_locked %d, generic_tree %p, inline_xattrs %p, "
		  "inline_count %u, inline_capacity %u, "
		  "root %p, owner %p, fsi %p\n",
		  atomic_read(&tree->type),
		  atomic_read(&tree->state),
		  rwsem_is_locked(&tree->lock),
		  tree->generic_tree,
		  tree->inline_xattrs,
		  tree->inline_count,
		  tree->inline_capacity,
		  tree->root,
		  tree->owner,
		  tree->fsi);

	if (tree->generic_tree) {
		/* debug dump of generic tree */
		ssdfs_debug_btree_object(tree->generic_tree);
	}

	if (tree->inline_xattrs) {
		struct ssdfs_xattr_entry *xattr;
		struct ssdfs_blob_extent *blob;

		xattr = &tree->inline_xattrs[0];

		SSDFS_DBG("INLINE XATTR: name_hash %llx, "
			  "inline_index %u, name_len %u, "
			  "name_type %#x, name_flags %#x, "
			  "blob_len %u, blob_type %#x, "
			  "blob_flags %#x\n",
			  le64_to_cpu(xattr->name_hash),
			  xattr->inline_index,
			  xattr->name_len,
			  xattr->name_type,
			  xattr->name_flags,
			  le16_to_cpu(xattr->blob_len),
			  xattr->blob_type,
			  xattr->blob_flags);

		SSDFS_DBG("INLINE STRING DUMP:\n");
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     xattr->inline_string,
				     SSDFS_XATTR_INLINE_NAME_MAX_LEN);
		SSDFS_DBG("\n");

		switch (xattr->blob_type) {
		case SSDFS_XATTR_INLINE_BLOB:
			SSDFS_DBG("INLINE BLOB DUMP:\n");
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     xattr->blob.inline_value.bytes,
					     SSDFS_XATTR_INLINE_BLOB_MAX_LEN);
			SSDFS_DBG("\n");
			break;

		case SSDFS_XATTR_REGULAR_BLOB:
			blob = &xattr->blob.descriptor;

			SSDFS_DBG("BLOB EXTENT: hash %llx, "
				  "seg_id %llu, logical_blk %u, "
				  "len %u\n",
				  blob->hash,
				  le64_to_cpu(blob->extent.seg_id),
				  le32_to_cpu(blob->extent.logical_blk),
				  le32_to_cpu(blob->extent.len));
			break;

		default:
			/* do nothing */
			break;
		}
	}

	if (tree->root) {
		SSDFS_DBG("ROOT NODE HEADER: height %u, items_count %u, "
			  "flags %#x, type %#x, upper_node_id %u, "
			  "node_ids (left %u, right %u)\n",
			  tree->root->header.height,
			  tree->root->header.items_count,
			  tree->root->header.flags,
			  tree->root->header.type,
			  le32_to_cpu(tree->root->header.upper_node_id),
			  le32_to_cpu(tree->root->header.node_ids[0]),
			  le32_to_cpu(tree->root->header.node_ids[1]));

		for (i = 0; i < SSDFS_BTREE_ROOT_NODE_INDEX_COUNT; i++) {
			struct ssdfs_btree_index *index;

			index = &tree->root->indexes[i];

			SSDFS_DBG("NODE_INDEX: index %d, hash %llx, "
				  "seg_id %llu, logical_blk %u, len %u\n",
				  i,
				  le64_to_cpu(index->hash),
				  le64_to_cpu(index->extent.seg_id),
				  le32_to_cpu(index->extent.logical_blk),
				  le32_to_cpu(index->extent.len));
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */
}

const struct ssdfs_btree_descriptor_operations ssdfs_xattrs_btree_desc_ops = {
	.init		= ssdfs_xattrs_btree_desc_init,
	.flush		= ssdfs_xattrs_btree_desc_flush,
};

const struct ssdfs_btree_operations ssdfs_xattrs_btree_ops = {
	.create_root_node	= ssdfs_xattrs_btree_create_root_node,
	.create_node		= ssdfs_xattrs_btree_create_node,
	.init_node		= ssdfs_xattrs_btree_init_node,
	.destroy_node		= ssdfs_xattrs_btree_destroy_node,
	.add_node		= ssdfs_xattrs_btree_add_node,
	.delete_node		= ssdfs_xattrs_btree_delete_node,
	.pre_flush_root_node	= ssdfs_xattrs_btree_pre_flush_root_node,
	.flush_root_node	= ssdfs_xattrs_btree_flush_root_node,
	.pre_flush_node		= ssdfs_xattrs_btree_pre_flush_node,
	.flush_node		= ssdfs_xattrs_btree_flush_node,
};

const struct ssdfs_btree_node_operations ssdfs_xattrs_btree_node_ops = {
	.find_item		= ssdfs_xattrs_btree_node_find_item,
	.find_range		= ssdfs_xattrs_btree_node_find_range,
	.extract_range		= ssdfs_xattrs_btree_node_extract_range,
	.allocate_item		= ssdfs_xattrs_btree_node_allocate_item,
	.allocate_range		= ssdfs_xattrs_btree_node_allocate_range,
	.insert_item		= ssdfs_xattrs_btree_node_insert_item,
	.insert_range		= ssdfs_xattrs_btree_node_insert_range,
	.change_item		= ssdfs_xattrs_btree_node_change_item,
	.delete_item		= ssdfs_xattrs_btree_node_delete_item,
	.delete_range		= ssdfs_xattrs_btree_node_delete_range,
	.resize_items_area	= ssdfs_xattrs_btree_resize_items_area,
};
