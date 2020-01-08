//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dentries_tree.c - dentries btree implementation.
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

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "shared_dictionary.h"
#include "segment_tree.h"
#include "dentries_tree.h"

#define S_SHIFT 12
static unsigned char
ssdfs_type_by_mode[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]	= SSDFS_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT]	= SSDFS_FT_DIR,
	[S_IFCHR >> S_SHIFT]	= SSDFS_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT]	= SSDFS_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT]	= SSDFS_FT_FIFO,
	[S_IFSOCK >> S_SHIFT]	= SSDFS_FT_SOCK,
	[S_IFLNK >> S_SHIFT]	= SSDFS_FT_SYMLINK,
};

static inline
void ssdfs_set_file_type(struct ssdfs_dir_entry *de, struct inode *inode)
{
	umode_t mode = inode->i_mode;

	de->file_type = ssdfs_type_by_mode[(mode & S_IFMT)>>S_SHIFT];
}

/*
 * ssdfs_dentries_tree_create() - create dentries tree of a new inode
 * @fsi: pointer on shared file system object
 * @ii: pointer on in-core SSDFS inode
 *
 * This method tries to create dentries btree for a new inode.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 */
int ssdfs_dentries_tree_create(struct ssdfs_fs_info *fsi,
				struct ssdfs_inode_info *ii)
{
	struct ssdfs_dentries_btree_info *ptr;
	size_t dentry_size = sizeof(struct ssdfs_dir_entry);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !ii);
	BUG_ON(!rwsem_is_locked(&ii->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ii %p, ino %lu\n",
		  ii, ii->vfs_inode.i_ino);

	if (S_ISDIR(ii->vfs_inode.i_mode))
		ii->dentries_tree = NULL;
	else {
		SSDFS_WARN("regular file cannot have dentries tree\n");
		return -ERANGE;
	}

	ptr = kzalloc(sizeof(struct ssdfs_dentries_btree_info),
			GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate dentries tree\n");
		return -ENOMEM;
	}

	atomic_set(&ptr->state, SSDFS_DENTRIES_BTREE_UNKNOWN_STATE);
	atomic_set(&ptr->type, SSDFS_INLINE_DENTRIES_ARRAY);
	atomic64_set(&ptr->dentries_count, 0);
	init_rwsem(&ptr->lock);
	ptr->generic_tree = NULL;
	memset(ptr->buffer.dentries, 0xFF,
		dentry_size * SSDFS_INLINE_DENTRIES_COUNT);
	ptr->inline_dentries = ptr->buffer.dentries;
	memset(&ptr->root_buffer, 0xFF,
		sizeof(struct ssdfs_btree_inline_root_node));
	ptr->root = NULL;
	memcpy(&ptr->desc, &fsi->segs_tree->dentries_btree,
		sizeof(struct ssdfs_dentries_btree_descriptor));
	ptr->owner = ii;
	ptr->fsi = fsi;
	atomic_set(&ptr->state, SSDFS_DENTRIES_BTREE_CREATED);

	ssdfs_debug_dentries_btree_object(ptr);

	ii->dentries_tree = ptr;

	return 0;
}

/*
 * ssdfs_dentries_tree_destroy() - destroy dentries tree
 * @ii: pointer on in-core SSDFS inode
 */
void ssdfs_dentries_tree_destroy(struct ssdfs_inode_info *ii)
{
	struct ssdfs_dentries_btree_info *tree;
	size_t dentry_size = sizeof(struct ssdfs_dir_entry);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ii);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ii %p, ino %lu\n",
		  ii, ii->vfs_inode.i_ino);

	tree = SSDFS_DTREE(ii);

	if (!tree) {
		SSDFS_DBG("dentries tree is absent: ino %lu\n",
			  ii->vfs_inode.i_ino);
		return;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
		/* expected state*/
		break;

	case SSDFS_DENTRIES_BTREE_CORRUPTED:
		SSDFS_WARN("dentries tree is corrupted: "
			   "ino %lu\n",
			   ii->vfs_inode.i_ino);
		break;

	case SSDFS_DENTRIES_BTREE_DIRTY:
		SSDFS_WARN("dentries tree is dirty: "
			   "ino %lu\n",
			   ii->vfs_inode.i_ino);
		break;

	default:
		SSDFS_WARN("invalid state of dentries tree: "
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
	case SSDFS_INLINE_DENTRIES_ARRAY:
		if (!tree->inline_dentries) {
			SSDFS_WARN("empty inline_dentries pointer\n");
			memset(tree->buffer.dentries, 0xFF,
				dentry_size * SSDFS_INLINE_DENTRIES_COUNT);
		} else {
			memset(tree->inline_dentries, 0xFF,
				dentry_size * SSDFS_INLINE_DENTRIES_COUNT);
		}
		tree->inline_dentries = NULL;
		break;

	case SSDFS_PRIVATE_DENTRIES_BTREE:
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
		SSDFS_WARN("invalid dentries btree state %#x\n",
			   atomic_read(&tree->state));
#endif /* CONFIG_SSDFS_DEBUG */
		break;
	}

	memset(&tree->root_buffer, 0xFF,
		sizeof(struct ssdfs_btree_inline_root_node));
	tree->root = NULL;

	tree->owner = NULL;
	tree->fsi = NULL;

	atomic_set(&tree->type, SSDFS_DENTRIES_BTREE_UNKNOWN_TYPE);
	atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_UNKNOWN_STATE);

	kfree(ii->dentries_tree);
	ii->dentries_tree = NULL;
}

/*
 * ssdfs_dentries_tree_init() - init dentries tree for existing inode
 * @fsi: pointer on shared file system object
 * @ii: pointer on in-core SSDFS inode
 *
 * This method tries to create the dentries tree and to initialize
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
int ssdfs_dentries_tree_init(struct ssdfs_fs_info *fsi,
			     struct ssdfs_inode_info *ii)
{
	struct ssdfs_inode raw_inode;
	struct ssdfs_btree_node *node;
	struct ssdfs_dentries_btree_info *tree;
	struct ssdfs_btree_inline_root_node *root_node;
	size_t dentry_size = sizeof(struct ssdfs_dir_entry);
	u16 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !ii);
	BUG_ON(!rwsem_is_locked(&ii->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, ii %p, ino %lu\n",
		  fsi, ii, ii->vfs_inode.i_ino);

	tree = SSDFS_DTREE(ii);
	if (!tree) {
		SSDFS_DBG("dentries tree is absent: ino %lu\n",
			  ii->vfs_inode.i_ino);
		return -ERANGE;
	}

	memcpy(&raw_inode, &ii->raw_inode, sizeof(struct ssdfs_inode));

	flags = le16_to_cpu(raw_inode.private_flags);

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
		/* expected tree state */
		break;

	default:
		SSDFS_WARN("unexpected state of tree %#x\n",
			   atomic_read(&tree->state));
		return -ERANGE;
	}

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_DENTRIES_ARRAY:
		/* expected tree type */
		break;

	case SSDFS_PRIVATE_DENTRIES_BTREE:
		SSDFS_WARN("unexpected type of tree %#x\n",
			   atomic_read(&tree->type));
		return -ERANGE;

	default:
		SSDFS_WARN("invalid type of tree %#x\n",
			   atomic_read(&tree->type));
		return -ERANGE;
	}

	down_write(&tree->lock);

	if (flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		atomic64_set(&tree->dentries_count,
			     le32_to_cpu(raw_inode.count_of.dentries));

		if (tree->generic_tree) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_DENTRIES_BTREE_CORRUPTED);
			SSDFS_WARN("generic tree exists\n");
			goto finish_tree_init;
		}

		tree->generic_tree = &tree->buffer.tree;
		tree->inline_dentries = NULL;
		atomic_set(&tree->type, SSDFS_PRIVATE_DENTRIES_BTREE);

		err = ssdfs_btree_create(fsi,
					 ii->vfs_inode.i_ino,
					 &ssdfs_dentries_btree_desc_ops,
					 &ssdfs_dentries_btree_ops,
					 tree->generic_tree);
		if (unlikely(err)) {
			atomic_set(&tree->state,
				   SSDFS_DENTRIES_BTREE_CORRUPTED);
			SSDFS_ERR("fail to create dentries tree: err %d\n",
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

		root_node = &raw_inode.internal[0].area1.dentries_root;
		err = ssdfs_btree_create_root_node(node, root_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init the root node: err %d\n",
				  err);
			goto fail_create_generic_tree;
		}

		tree->root = &tree->root_buffer;
		memcpy(tree->root, root_node,
			sizeof(struct ssdfs_btree_inline_root_node));

		atomic_set(&tree->type, SSDFS_PRIVATE_DENTRIES_BTREE);
		atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_INITIALIZED);

fail_create_generic_tree:
		if (unlikely(err)) {
			atomic_set(&tree->state,
				   SSDFS_DENTRIES_BTREE_CORRUPTED);
			ssdfs_btree_destroy(tree->generic_tree);
			tree->generic_tree = NULL;
			goto finish_tree_init;
		}
	} else if (flags & SSDFS_INODE_HAS_XATTR_BTREE) {
		atomic64_set(&tree->dentries_count,
			     le32_to_cpu(raw_inode.count_of.dentries));

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(atomic64_read(&tree->dentries_count) >
			SSDFS_INLINE_DENTRIES_PER_AREA);
#else
		if (atomic64_read(&tree->dentries_count) >
		    SSDFS_INLINE_DENTRIES_PER_AREA) {
			err = -EIO;
			atomic_set(&tree->state,
				   SSDFS_DENTRIES_BTREE_CORRUPTED);
			SSDFS_ERR("corrupted on-disk raw inode: "
				  "dentries_count %llu\n",
				  (u64)atomic64_read(&tree->dentries_count));
			goto finish_tree_init;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		if (!tree->inline_dentries) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_DENTRIES_BTREE_CORRUPTED);
			SSDFS_WARN("undefined inline dentries pointer\n");
			goto finish_tree_init;
		} else {
			memcpy(tree->inline_dentries,
				&raw_inode.internal[0].area1,
				dentry_size * SSDFS_INLINE_DENTRIES_PER_AREA);
		}

		atomic_set(&tree->type, SSDFS_INLINE_DENTRIES_ARRAY);
		atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_INITIALIZED);
	} else if (flags & SSDFS_INODE_HAS_INLINE_DENTRIES) {
		u32 dentries_count = le32_to_cpu(raw_inode.count_of.dentries);
		u32 i;

		atomic64_set(&tree->dentries_count, dentries_count);

		if (!tree->inline_dentries) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_DENTRIES_BTREE_CORRUPTED);
			SSDFS_WARN("undefined inline dentries pointer\n");
			goto finish_tree_init;
		} else {
			memcpy(tree->inline_dentries,
				&raw_inode.internal,
				dentry_size * SSDFS_INLINE_DENTRIES_COUNT);
		}

		for (i = 0; i < dentries_count; i++) {
			u64 hash;
			struct ssdfs_dir_entry *dentry =
					&tree->inline_dentries[i];

			hash = le64_to_cpu(dentry->hash_code);

			if (hash == 0) {
				size_t len = dentry->name_len;
				const char *name =
					(const char *)dentry->inline_string;

				if (len > SSDFS_DENTRY_INLINE_NAME_MAX_LEN) {
					err = -ERANGE;
					SSDFS_ERR("dentry hasn't hash code: "
						  "len %zu\n", len);
					goto finish_tree_init;
				}

				hash = __ssdfs_generate_name_hash(name, len);
				if (hash == U64_MAX) {
					err = -ERANGE;
					SSDFS_ERR("fail to generate hash\n");
					goto finish_tree_init;
				}

				dentry->hash_code = cpu_to_le64(hash);
			}
		}

		atomic_set(&tree->type, SSDFS_INLINE_DENTRIES_ARRAY);
		atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_INITIALIZED);
	} else
		BUG();

finish_tree_init:
	up_write(&tree->lock);

	ssdfs_debug_dentries_btree_object(tree);

	return err;
}

/*
 * ssdfs_migrate_inline2generic_tree() - convert inline tree into generic
 * @tree: dentries tree
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
int ssdfs_migrate_inline2generic_tree(struct ssdfs_dentries_btree_info *tree)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_dir_entry dentries[SSDFS_INLINE_DENTRIES_COUNT];
	struct ssdfs_dir_entry *cur;
	struct ssdfs_btree_search *search;
	s64 dentries_count, dentries_capacity;
	int private_flags;
	s64 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", tree);

	fsi = tree->fsi;

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_DENTRIES_ARRAY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	dentries_count = atomic64_read(&tree->dentries_count);

	if (!tree->owner) {
		SSDFS_ERR("empty owner inode\n");
		return -ERANGE;
	}

	private_flags = atomic_read(&tree->owner->private_flags);

	dentries_capacity = SSDFS_INLINE_DENTRIES_COUNT;
	if (private_flags & SSDFS_INODE_HAS_XATTR_BTREE)
		dentries_capacity -= SSDFS_INLINE_DENTRIES_PER_AREA;
	if (private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		SSDFS_ERR("the dentries tree is generic\n");
		return -ERANGE;
	}

	if (dentries_count > dentries_capacity) {
		SSDFS_WARN("dentries tree is corrupted: "
			   "dentries_count %lld, dentries_capacity %lld\n",
			   dentries_count, dentries_capacity);
		atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_CORRUPTED);
		return -ERANGE;
	} else if (dentries_count == 0) {
		SSDFS_DBG("empty tree\n");
		return -EFAULT;
	} else if (dentries_count < dentries_capacity) {
		SSDFS_WARN("dentries_count %lld, dentries_capacity %lld\n",
			   dentries_count, dentries_capacity);
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree->inline_dentries || tree->generic_tree);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(dentries, 0xFF,
		sizeof(struct ssdfs_dir_entry) * SSDFS_INLINE_DENTRIES_COUNT);
	memcpy(dentries, tree->inline_dentries,
		sizeof(struct ssdfs_dir_entry) * dentries_capacity);

	for (i = 0; i < dentries_count; i++) {
		cur = &dentries[i];

		cur->dentry_type = SSDFS_REGULAR_DENTRY;
	}

	tree->generic_tree = &tree->buffer.tree;
	tree->inline_dentries = NULL;

	err = ssdfs_btree_create(fsi,
				 tree->owner->vfs_inode.i_ino,
				 &ssdfs_dentries_btree_desc_ops,
				 &ssdfs_dentries_btree_ops,
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
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT |
			SSDFS_BTREE_SEARCH_HAS_VALID_INO;
	cur = &dentries[0];
	search->request.start.hash = le64_to_cpu(cur->hash_code);
	search->request.start.ino = le64_to_cpu(cur->ino);
	if (dentries_count > 1) {
		cur = &dentries[dentries_count - 1];
		search->request.end.hash = le64_to_cpu(cur->hash_code);
		search->request.end.ino = le64_to_cpu(cur->ino);
	} else {
		search->request.end.hash = search->request.start.hash;
		search->request.end.ino = search->request.start.ino;
	}
	search->request.count = (u16)dentries_count;

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

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
	case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
	case SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE:
		/* expected state */
		break;

	default:
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

	if (dentries_count == 1) {
		search->result.buf_state = SSDFS_BTREE_SEARCH_INLINE_BUFFER;
		search->result.buf_size = sizeof(struct ssdfs_dir_entry);
		search->result.items_in_buffer = dentries_count;
		search->result.buf = &search->raw.dentry;
		memcpy(&search->raw.dentry, dentries, search->result.buf_size);
	} else {
		search->result.buf_state = SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER;
		search->result.buf_size =
			dentries_count * sizeof(struct ssdfs_dir_entry);
		search->result.items_in_buffer = (u16)dentries_count;
		search->result.buf = kmalloc(search->result.buf_size,
					     GFP_KERNEL);
		if (!search->result.buf) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate memory for buffer\n");
			goto finish_add_range;
		}
		memcpy(search->result.buf, dentries, search->result.buf_size);
	}

	search->request.type = SSDFS_BTREE_SEARCH_ADD_RANGE;

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

	err = ssdfs_btree_synchronize_root_node(tree->generic_tree,
						tree->root);
	if (unlikely(err)) {
		SSDFS_ERR("fail to synchronize the root node: "
			  "err %d\n", err);
		goto destroy_generic_tree;
	}

	atomic_set(&tree->type, SSDFS_PRIVATE_DENTRIES_BTREE);
	atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_DIRTY);

	atomic_or(SSDFS_INODE_HAS_DENTRIES_BTREE,
		  &tree->owner->private_flags);
	atomic_and(~SSDFS_INODE_HAS_INLINE_DENTRIES,
		  &tree->owner->private_flags);

	return 0;

destroy_generic_tree:
	ssdfs_btree_destroy(&tree->buffer.tree);

recover_inline_tree:
	for (i = 0; i < dentries_count; i++) {
		cur = &dentries[i];

		cur->dentry_type = SSDFS_INLINE_DENTRY;
	}

	memcpy(tree->buffer.dentries, dentries,
		sizeof(struct ssdfs_dir_entry) * SSDFS_INLINE_DENTRIES_COUNT);
	tree->inline_dentries = tree->buffer.dentries;
	tree->generic_tree = NULL;

	return err;
}

/*
 * ssdfs_dentries_tree_flush() - save modified dentries tree
 * @fsi: pointer on shared file system object
 * @ii: pointer on in-core SSDFS inode
 *
 * This method tries to flush inode's dentries btree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_dentries_tree_flush(struct ssdfs_fs_info *fsi,
				struct ssdfs_inode_info *ii)
{
	struct ssdfs_dentries_btree_info *tree;
	size_t dentry_size = sizeof(struct ssdfs_dir_entry);
	int flags;
	u64 dentries_count;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !ii);
	BUG_ON(!rwsem_is_locked(&ii->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, ii %p, ino %lu\n",
		  fsi, ii, ii->vfs_inode.i_ino);

	tree = SSDFS_DTREE(ii);
	if (!tree) {
		SSDFS_DBG("dentries tree is absent: ino %lu\n",
			  ii->vfs_inode.i_ino);
		return -ERANGE;
	}

	flags = atomic_read(&ii->private_flags);

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* need to flush */
		break;

	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
		/* do nothing */
		return 0;

	case SSDFS_DENTRIES_BTREE_CORRUPTED:
		SSDFS_DBG("dentries btree corrupted: ino %lu\n",
			  ii->vfs_inode.i_ino);
		return -EOPNOTSUPP;

	default:
		SSDFS_WARN("unexpected state of tree %#x\n",
			   atomic_read(&tree->state));
		return -ERANGE;
	}

	down_write(&tree->lock);

	dentries_count = atomic64_read(&tree->dentries_count);

	if (dentries_count >= U32_MAX) {
		err = -EOPNOTSUPP;
		SSDFS_ERR("fail to store dentries_count %llu\n",
			  dentries_count);
		goto finish_dentries_tree_flush;
	}

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_DENTRIES_ARRAY:
		if (!tree->inline_dentries) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_DENTRIES_BTREE_CORRUPTED);
			SSDFS_WARN("undefined inline dentries pointer\n");
			goto finish_dentries_tree_flush;
		}

		if (dentries_count == 0) {
			flags = atomic_read(&ii->private_flags);

			if (flags & SSDFS_INODE_HAS_XATTR_BTREE) {
				memset(&ii->raw_inode.internal[0].area1, 0xFF,
					dentry_size *
					    SSDFS_INLINE_DENTRIES_PER_AREA);
			} else {
				memset(&ii->raw_inode.internal, 0xFF,
					dentry_size *
					    SSDFS_INLINE_DENTRIES_COUNT);
			}
		} else if (dentries_count <= SSDFS_INLINE_DENTRIES_PER_AREA) {
			flags = atomic_read(&ii->private_flags);

			if (flags & SSDFS_INODE_HAS_XATTR_BTREE) {
				memset(&ii->raw_inode.internal[0].area1, 0xFF,
					dentry_size *
					    SSDFS_INLINE_DENTRIES_PER_AREA);
				memcpy(&ii->raw_inode.internal[0].area1,
					tree->inline_dentries,
					dentries_count * dentry_size);
			} else {
				memset(&ii->raw_inode.internal, 0xFF,
					dentry_size *
					    SSDFS_INLINE_DENTRIES_COUNT);
				memcpy(&ii->raw_inode.internal,
					tree->inline_dentries,
					dentries_count * dentry_size);
			}
		} else if (dentries_count <= SSDFS_INLINE_DENTRIES_COUNT) {
			flags = atomic_read(&ii->private_flags);

			if (flags & SSDFS_INODE_HAS_XATTR_BTREE) {
				err = -EAGAIN;
				SSDFS_DBG("tree should be converted: "
					  "ino %lu\n",
					  ii->vfs_inode.i_ino);
			} else {
				memset(&ii->raw_inode.internal, 0xFF,
					dentry_size *
					    SSDFS_INLINE_DENTRIES_COUNT);
				memcpy(&ii->raw_inode.internal,
					tree->inline_dentries,
					dentries_count * dentry_size);
			}

			if (err == -EAGAIN) {
				err = ssdfs_migrate_inline2generic_tree(tree);
				if (unlikely(err)) {
					atomic_set(&tree->state,
						SSDFS_DENTRIES_BTREE_CORRUPTED);
					SSDFS_ERR("fail to convert tree: "
						  "err %d\n", err);
					goto finish_dentries_tree_flush;
				} else
					goto try_generic_tree_flush;
			}
		} else {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_DENTRIES_BTREE_CORRUPTED);
			SSDFS_WARN("invalid dentries_count %llu\n",
				   (u64)atomic64_read(&tree->dentries_count));
			goto finish_dentries_tree_flush;
		}

		atomic_or(SSDFS_INODE_HAS_INLINE_DENTRIES,
			  &ii->private_flags);
		break;

	case SSDFS_PRIVATE_DENTRIES_BTREE:
try_generic_tree_flush:
		if (!tree->generic_tree) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_DENTRIES_BTREE_CORRUPTED);
			SSDFS_WARN("undefined generic tree pointer\n");
			goto finish_dentries_tree_flush;
		}

		err = ssdfs_btree_flush(tree->generic_tree);
		if (unlikely(err)) {
			SSDFS_ERR("fail to flush dentries btree: "
				  "ino %lu, err %d\n",
				  ii->vfs_inode.i_ino, err);
			goto finish_dentries_tree_flush;
		}

		if (!tree->root) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_DENTRIES_BTREE_CORRUPTED);
			SSDFS_WARN("undefined root node pointer\n");
			goto finish_dentries_tree_flush;
		}

		memcpy(&ii->raw_inode.internal[0].area1.dentries_root,
			tree->root,
			sizeof(struct ssdfs_btree_inline_root_node));

		atomic_or(SSDFS_INODE_HAS_DENTRIES_BTREE,
			  &ii->private_flags);
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid type of tree %#x\n",
			   atomic_read(&tree->type));
		goto finish_dentries_tree_flush;
	}

	ii->raw_inode.count_of.dentries = cpu_to_le32((u32)dentries_count);
	atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_INITIALIZED);

finish_dentries_tree_flush:
	up_write(&tree->lock);

	SSDFS_DBG("RAW INODE DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     &ii->raw_inode,
			     sizeof(struct ssdfs_inode));
	SSDFS_DBG("\n");

	return err;
}

/******************************************************************************
 *                     DENTRIES TREE OBJECT FUNCTIONALITY                     *
 ******************************************************************************/

/*
 * need_initialize_dentries_btree_search() - check necessity to init the search
 * @name_hash: name hash
 * @search: search object
 */
static inline
bool need_initialize_dentries_btree_search(u64 name_hash,
					   struct ssdfs_btree_search *search)
{
	return need_initialize_btree_search(search) ||
		search->request.start.hash != name_hash;
}

/*
 * __ssdfs_generate_name_hash() - generate a name's hash
 * @name: pointer on the name's string
 * @len: length of the name
 */
u64 __ssdfs_generate_name_hash(const char *name, size_t len)
{
	u32 hash32_lo, hash32_hi;
	size_t copy_len;
	u64 name_hash;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!name);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("name %s, len %zu\n",
		  name, len);

	if (len == 0) {
		SSDFS_ERR("invalid len %zu\n", len);
		return U64_MAX;
	}

	copy_len = min_t(size_t, len, (size_t)SSDFS_DENTRY_INLINE_NAME_MAX_LEN);
	hash32_lo = full_name_hash(NULL, name, copy_len);

	if (len <= SSDFS_DENTRY_INLINE_NAME_MAX_LEN)
		hash32_hi = 0;
	else {
		hash32_hi = full_name_hash(NULL,
					name + SSDFS_DENTRY_INLINE_NAME_MAX_LEN,
					len - copy_len);
	}

	name_hash = SSDFS_NAME_HASH(hash32_lo, hash32_hi);

	SSDFS_DBG("name %s, len %zu, name_hash %llx\n",
		  name, len, name_hash);

	return name_hash;
}

/*
 * ssdfs_generate_name_hash() - generate a name's hash
 * @str: string descriptor
 */
u64 ssdfs_generate_name_hash(const struct qstr *str)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!str);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("name %s, len %u\n",
		  str->name, str->len);

	return __ssdfs_generate_name_hash(str->name, str->len);
}

/*
 * ssdfs_check_dentry_for_request() - check dentry
 * @fsi:  pointer on shared file system object
 * @dentry: pointer on dentry object
 * @search: search object
 *
 * This method tries to check @dentry for the @search request.
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
int ssdfs_check_dentry_for_request(struct ssdfs_fs_info *fsi,
				   struct ssdfs_dir_entry *dentry,
				   struct ssdfs_btree_search *search)
{
	struct ssdfs_shared_dict_btree_info *dict;
	u32 req_flags;
	u64 search_hash;
	u64 req_ino;
	const char *req_name;
	size_t req_name_len;
	u64 hash_code;
	u64 ino;
	u8 dentry_type;
	u8 file_type;
	u8 flags;
	u8 name_len;
	int res, err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !dentry || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, dentry %p, search %p\n",
		  fsi, dentry, search);

	dict = fsi->shdictree;
	if (!dict) {
		SSDFS_ERR("shared dictionary is absent\n");
		return -ERANGE;
	}

	req_flags = search->request.flags;
	search_hash = search->request.start.hash;
	req_ino = search->request.start.ino;
	req_name = search->request.start.name;
	req_name_len = search->request.start.name_len;

	SSDFS_DBG("search_hash %llx, req_ino %llu\n",
		  search_hash, req_ino);

	hash_code = le64_to_cpu(dentry->hash_code);
	ino = le64_to_cpu(dentry->ino);
	dentry_type = dentry->dentry_type;
	file_type = dentry->file_type;
	flags = dentry->flags;
	name_len = dentry->name_len;

	SSDFS_DBG("hash_code %llx, ino %llu, "
		  "type %#x, file_type %#x, flags %#x, name_len %u\n",
		  hash_code, ino, dentry_type,
		  file_type, flags, name_len);

	if (dentry_type <= SSDFS_DENTRY_UNKNOWN_TYPE ||
	    dentry_type >= SSDFS_DENTRY_TYPE_MAX) {
		SSDFS_ERR("corrupted dentry: dentry_type %#x\n",
			  dentry_type);
		return -EIO;
	}

	if (file_type <= SSDFS_FT_UNKNOWN ||
	    file_type >= SSDFS_FT_MAX) {
		SSDFS_ERR("corrupted dentry: file_type %#x\n",
			  file_type);
		return -EIO;
	}

	if (hash_code != 0 && search_hash < hash_code) {
		err = -ENODATA;
		search->result.err = -ENODATA;
		search->result.state =
			SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
		goto finish_check_dentry;
	} else if (hash_code != 0 && search_hash > hash_code) {
		/* continue the search */
		err = -EAGAIN;
		goto finish_check_dentry;
	} else {
		/* search_hash == hash_code */

		if (req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_INO) {
			if (req_ino < ino) {
				/* hash collision case */
				err = -ENODATA;
				search->result.err = -ENODATA;
				search->result.state =
					SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
				goto finish_check_dentry;
			} else if (req_ino == ino) {
				search->result.state =
					SSDFS_BTREE_SEARCH_VALID_ITEM;
				goto extract_full_name;
			} else {
				/* hash collision case */
				/* continue the search */
				err = -EAGAIN;
				goto finish_check_dentry;
			}
		}

		if (req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME) {
			int res;

			if (!req_name) {
				SSDFS_ERR("empty name pointer\n");
				return -ERANGE;
			}

			name_len = min_t(u8, name_len,
					 SSDFS_DENTRY_INLINE_NAME_MAX_LEN);
			res = strncmp(req_name, dentry->inline_string,
					name_len);
			if (res < 0) {
				/* hash collision case */
				err = -ENODATA;
				search->result.err = -ENODATA;
				search->result.state =
					SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
				goto finish_check_dentry;
			} else if (res == 0) {
				search->result.state =
					SSDFS_BTREE_SEARCH_VALID_ITEM;
				goto extract_full_name;
			} else {
				/* hash collision case */
				/* continue the search */
				err = -EAGAIN;
				goto finish_check_dentry;
			}
		}

extract_full_name:
		if (flags & SSDFS_DENTRY_HAS_EXTERNAL_STRING) {
			err = ssdfs_shared_dict_get_name(dict, search_hash,
							 &search->name);
			if (unlikely(err)) {
				SSDFS_ERR("fail to extract the name: "
					  "hash %llx, err %d\n",
					  search_hash, err);
				goto finish_check_dentry;
			}
		} else
			goto finish_check_dentry;

		if (req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME) {
			name_len = dentry->name_len;

			res = strncmp(req_name, search->name.str,
					name_len);
			if (res < 0) {
				/* hash collision case */
				err = -ENODATA;
				search->result.err = -ENODATA;
				search->result.state =
					SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
				goto finish_check_dentry;
			} else if (res == 0) {
				search->result.state =
					SSDFS_BTREE_SEARCH_VALID_ITEM;
				goto finish_check_dentry;
			} else {
				/* hash collision case */
				/* continue the search */
				err = -EAGAIN;
				goto finish_check_dentry;
			}
		}
	}

finish_check_dentry:
	return err;
}

/*
 * ssdfs_dentries_tree_find_inline_dentry() - find inline dentry
 * @tree: btree object
 * @search: search object
 *
 * This method tries to find an inline dentry.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - possible place was found.
 */
static int
ssdfs_dentries_tree_find_inline_dentry(struct ssdfs_dentries_btree_info *tree,
					struct ssdfs_btree_search *search)
{
	s64 dentries_count;
	u32 req_flags;
	s64 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	if (atomic_read(&tree->type) != SSDFS_INLINE_DENTRIES_ARRAY) {
		SSDFS_ERR("invalid tree type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	dentries_count = atomic64_read(&tree->dentries_count);

	if (dentries_count < 0) {
		SSDFS_ERR("invalid dentries_count %lld\n",
			  dentries_count);
		return -ERANGE;
	} else if (dentries_count == 0) {
		SSDFS_DBG("empty tree\n");
		search->result.state = SSDFS_BTREE_SEARCH_OUT_OF_RANGE;
		search->result.err = -ENODATA;
		search->result.start_index = U16_MAX;
		search->result.count = 0;
		search->result.search_cno = ssdfs_current_cno(tree->fsi->sb);
		search->result.buf_state =
				SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */
		search->result.buf = NULL;
		search->result.buf_size = 0;
		search->result.items_in_buffer = 0;
		return -ENODATA;
	} else if (dentries_count > SSDFS_INLINE_DENTRIES_COUNT) {
		SSDFS_ERR("invalid dentries_count %lld\n",
			  dentries_count);
		return -ERANGE;
	}

	if (!tree->inline_dentries) {
		SSDFS_ERR("inline dentries haven't been initialized\n");
		return -ERANGE;
	}

	req_flags = search->request.flags;

	for (i = 0; i < dentries_count; i++) {
		struct ssdfs_dir_entry *dentry;
		u64 hash_code;
		u64 ino;
		u8 type;
		u8 flags;
		u8 name_len;

		search->result.buf = NULL;
		search->result.state = SSDFS_BTREE_SEARCH_UNKNOWN_RESULT;

		dentry = &tree->inline_dentries[i];
		hash_code = le64_to_cpu(dentry->hash_code);
		ino = le64_to_cpu(dentry->ino);
		type = dentry->dentry_type;
		flags = dentry->flags;
		name_len = dentry->name_len;

		SSDFS_DBG("i %llu, hash_code %llx, ino %llu, "
			  "type %#x, flags %#x, name_len %u\n",
			  (u64)i, hash_code, ino, type, flags, name_len);

		if (type != SSDFS_INLINE_DENTRY) {
			SSDFS_ERR("corrupted dentry: "
				  "hash_code %llx, ino %llu, "
				  "type %#x, flags %#x\n",
				  hash_code, ino,
				  type, flags);
			atomic_set(&tree->state,
				   SSDFS_DENTRIES_BTREE_CORRUPTED);
			return -ERANGE;
		}

		if (flags & ~SSDFS_DENTRY_FLAGS_MASK) {
			SSDFS_ERR("corrupted dentry: "
				  "hash_code %llx, ino %llu, "
				  "type %#x, flags %#x\n",
				  hash_code, ino,
				  type, flags);
			atomic_set(&tree->state,
				   SSDFS_DENTRIES_BTREE_CORRUPTED);
			return -ERANGE;
		}

		if (hash_code >= U64_MAX || ino >= U64_MAX) {
			SSDFS_ERR("corrupted dentry: "
				  "hash_code %llx, ino %llu, "
				  "type %#x, flags %#x\n",
				  hash_code, ino,
				  type, flags);
			atomic_set(&tree->state,
				   SSDFS_DENTRIES_BTREE_CORRUPTED);
			return -ERANGE;
		}

		if (!(req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE)) {
			SSDFS_ERR("invalid request: hash is absent\n");
			return -ERANGE;
		}

		memcpy(&search->raw.dentry.header, dentry,
			sizeof(struct ssdfs_dir_entry));

		search->result.err = 0;
		search->result.start_index = (u16)i;
		search->result.count = 1;
		search->result.search_cno = ssdfs_current_cno(tree->fsi->sb);
		search->result.buf_state = SSDFS_BTREE_SEARCH_INLINE_BUFFER;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */
		search->result.buf = &search->raw.dentry;
		search->result.buf_size = sizeof(struct ssdfs_dir_entry);
		search->result.items_in_buffer = 1;

		err = ssdfs_check_dentry_for_request(tree->fsi, dentry, search);
		if (err == -ENODATA)
			goto finish_search_inline_dentry;
		else if (err == -EAGAIN)
			continue;
		else if (unlikely(err)) {
			SSDFS_ERR("fail to check dentry: err %d\n", err);
			goto finish_search_inline_dentry;
		} else {
			search->result.state =
				SSDFS_BTREE_SEARCH_VALID_ITEM;
			goto finish_search_inline_dentry;
		}
	}

	err = -ENODATA;
	search->result.err = -ENODATA;
	search->result.start_index = dentries_count;
	search->result.state = SSDFS_BTREE_SEARCH_OUT_OF_RANGE;

finish_search_inline_dentry:
	return err;
}

/*
 * __ssdfs_dentries_tree_find() - find a dentry in the tree
 * @tree: dentries tree
 * @search: search object
 *
 * This method tries to find a dentry in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - item hasn't been found
 */
int __ssdfs_dentries_tree_find(struct ssdfs_dentries_btree_info *tree,
				struct ssdfs_btree_search *search)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_DENTRIES_ARRAY:
		down_read(&tree->lock);
		err = ssdfs_dentries_tree_find_inline_dentry(tree, search);
		up_read(&tree->lock);

		if (err == -ENODATA) {
			SSDFS_DBG("unable to find the inline dentry: "
				  "hash %llx\n",
				  search->request.start.hash);
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find the inline dentry: "
				  "hash %llx, err %d\n",
				  search->request.start.hash, err);
		}
		break;

	case SSDFS_PRIVATE_DENTRIES_BTREE:
		down_read(&tree->lock);
		err = ssdfs_btree_find_item(tree->generic_tree, search);
		up_read(&tree->lock);

		if (err == -ENODATA) {
			SSDFS_DBG("unable to find the dentry: "
				  "hash %llx\n",
				  search->request.start.hash);
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find the dentry: "
				  "hash %llx, err %d\n",
				  search->request.start.hash, err);
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid dentries tree type %#x\n",
			  atomic_read(&tree->type));
		break;
	}

	ssdfs_debug_dentries_btree_object(tree);

	return err;
}

/*
 * ssdfs_dentries_tree_find() - find a dentry in the tree
 * @tree: dentries tree
 * @name: name string
 * @len: length of the string
 * @search: search object
 *
 * This method tries to find a dentry for the requested @name.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - item hasn't been found
 */
int ssdfs_dentries_tree_find(struct ssdfs_dentries_btree_info *tree,
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

	name_hash = __ssdfs_generate_name_hash(name, len);
	if (name_hash == U64_MAX) {
		SSDFS_ERR("fail to generate name hash\n");
		return -ERANGE;
	}

	if (need_initialize_dentries_btree_search(name_hash, search)) {
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

	return __ssdfs_dentries_tree_find(tree, search);
}

/*
 * ssdfs_dentries_tree_find_leaf_node() - find a leaf node in the tree
 * @tree: dentries tree
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
int ssdfs_dentries_tree_find_leaf_node(struct ssdfs_dentries_btree_info *tree,
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

	if (need_initialize_dentries_btree_search(name_hash, search)) {
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

	err = __ssdfs_dentries_tree_find(tree, search);
	if (err == -ENODATA) {
		switch (search->result.state) {
		case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
		case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
		case SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE:
			/* expected state */
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("unexpected result's state %#x\n",
				  search->result.state);
			goto finish_find_leaf_node;
		}

		switch (atomic_read(&tree->type)) {
		case SSDFS_INLINE_DENTRIES_ARRAY:
			/* do nothing */
			break;

		case SSDFS_PRIVATE_DENTRIES_BTREE:
			switch (search->node.state) {
			case SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC:
			case SSDFS_BTREE_SEARCH_FOUND_INDEX_NODE_DESC:
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
			SSDFS_ERR("invalid dentries tree type %#x\n",
				  atomic_read(&tree->type));
			break;
		}
	}

finish_find_leaf_node:
	return err;
}

/*
 * can_name_be_inline() - check that name can be inline
 * @str: string descriptor
 */
static inline
bool can_name_be_inline(const struct qstr *str)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!str || !str->name);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("name %s, len %u\n",
		  str->name, str->len);

	return str->len <= SSDFS_DENTRY_INLINE_NAME_MAX_LEN;
}

/*
 * ssdfs_prepare_dentry() - prepare dentry object
 * @str: string descriptor
 * @ii: inode descriptor
 * @dentry_type: dentry type
 * @search: search object
 *
 * This method tries to prepare a dentry for adding into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_prepare_dentry(const struct qstr *str,
			 struct ssdfs_inode_info *ii,
			 int dentry_type,
			 struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_dentry *dentry;
	u64 name_hash;
	u32 copy_len;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!str || !str->name || !ii || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("name %s, len %u, ino %lu\n",
		  str->name, str->len, ii->vfs_inode.i_ino);

	if (dentry_type <= SSDFS_DENTRIES_BTREE_UNKNOWN_TYPE ||
	    dentry_type >= SSDFS_DENTRIES_BTREE_TYPE_MAX) {
		SSDFS_ERR("invalid dentry type %#x\n",
			  dentry_type);
		return -EINVAL;
	}

	name_hash = ssdfs_generate_name_hash(str);
	if (name_hash == U64_MAX) {
		SSDFS_ERR("fail to generate name hash\n");
		return -ERANGE;
	}

	switch (search->result.buf_state) {
	case SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE:
		search->result.buf_state = SSDFS_BTREE_SEARCH_INLINE_BUFFER;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */
		search->result.buf = &search->raw.dentry;
		search->result.buf_size = sizeof(struct ssdfs_raw_dentry);
		search->result.items_in_buffer = 1;
		break;

	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!search->result.buf);
		BUG_ON(search->result.buf_size !=
			sizeof(struct ssdfs_raw_dentry));
		BUG_ON(search->result.items_in_buffer != 1);
#endif /* CONFIG_SSDFS_DEBUG */
		break;

	default:
		SSDFS_ERR("unexpected buffer state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	dentry = &search->raw.dentry;

	dentry->header.ino = cpu_to_le64(ii->vfs_inode.i_ino);
	dentry->header.hash_code = cpu_to_le64(name_hash);
	dentry->header.flags = 0;

	if (str->len > SSDFS_MAX_NAME_LEN) {
		SSDFS_ERR("invalid name_len %u\n",
			  str->len);
		return -ERANGE;
	}

	dentry->header.dentry_type = (u8)dentry_type;
	ssdfs_set_file_type(&dentry->header, &ii->vfs_inode);

	if (str->len > SSDFS_DENTRY_INLINE_NAME_MAX_LEN)
		dentry->header.flags |= SSDFS_DENTRY_HAS_EXTERNAL_STRING;

	dentry->header.name_len = (u8)str->len;

	memset(dentry->header.inline_string, 0,
		SSDFS_DENTRY_INLINE_NAME_MAX_LEN);
	copy_len = min_t(u32, (u32)str->len, SSDFS_DENTRY_INLINE_NAME_MAX_LEN);
	memcpy(dentry->header.inline_string, str->name, copy_len);

	memset(search->name.str, 0, SSDFS_MAX_NAME_LEN);
	search->name.len = (u8)str->len;
	memcpy(search->name.str, str->name, str->len);

	return 0;
}

/*
 * ssdfs_dentries_tree_add_inline_dentry() - add inline dentry into the tree
 * @tree: dentries tree
 * @search: search object
 *
 * This method tries to add the inline dentry into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - inline tree hasn't room for the new dentry.
 * %-EEXIST     - dentry exists in the tree.
 */
static int
ssdfs_dentries_tree_add_inline_dentry(struct ssdfs_dentries_btree_info *tree,
					struct ssdfs_btree_search *search)
{
	struct ssdfs_dir_entry *cur;
	s64 dentries_count, dentries_capacity;
	int private_flags;
	u64 hash1, hash2;
	u64 ino1, ino2;
	u16 start_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_DENTRIES_ARRAY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	if (!tree->inline_dentries) {
		SSDFS_ERR("empty inline tree %p\n",
			  tree->inline_dentries);
		return -ERANGE;
	}

	dentries_count = atomic64_read(&tree->dentries_count);

	if (!tree->owner) {
		SSDFS_ERR("empty owner inode\n");
		return -ERANGE;
	}

	private_flags = atomic_read(&tree->owner->private_flags);

	dentries_capacity = SSDFS_INLINE_DENTRIES_COUNT;
	if (private_flags & SSDFS_INODE_HAS_XATTR_BTREE)
		dentries_capacity -= SSDFS_INLINE_DENTRIES_PER_AREA;
	if (private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		SSDFS_ERR("the dentries tree is generic\n");
		return -ERANGE;
	}

	SSDFS_DBG("dentries_count %lld, dentries_capacity %lld\n",
		  dentries_count, dentries_capacity);

	if (dentries_count > dentries_capacity) {
		SSDFS_WARN("dentries tree is corrupted: "
			   "dentries_count %lld, dentries_capacity %lld\n",
			   dentries_count, dentries_capacity);
		atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_CORRUPTED);
		return -ERANGE;
	} else if (dentries_count == dentries_capacity) {
		SSDFS_DBG("inline tree hasn't room for the new dentry: "
			  "dentries_count %lld, dentries_capacity %lld\n",
			  dentries_count, dentries_capacity);
		return -ENOSPC;
	}

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
	case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid search result's state %#x, "
			  "start_index %u\n",
			  search->result.state,
			  search->result.start_index);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	hash1 = search->request.start.hash;
	ino1 = search->request.start.ino;
	hash2 = le64_to_cpu(search->raw.dentry.header.hash_code);
	ino2 = le64_to_cpu(search->raw.dentry.header.ino);

	if (hash1 != hash2 || ino1 != ino2) {
		SSDFS_ERR("corrupted dentry: "
			  "request (hash %llx, ino %llu), "
			  "dentry (hash %llx, ino %llu)\n",
			  hash1, ino1, hash2, ino2);
		return -ERANGE;
	}

	start_index = search->result.start_index;

	if (dentries_count == 0) {
		if (start_index != 0) {
			SSDFS_ERR("invalid start_index %u\n",
				  start_index);
			return -ERANGE;
		}

		cur = &tree->inline_dentries[start_index];

		memcpy(cur, &search->raw.dentry.header,
			sizeof(struct ssdfs_dir_entry));
	} else {
		if (start_index >= dentries_capacity) {
			SSDFS_ERR("start_index %u >= dentries_capacity %lld\n",
				  start_index, dentries_capacity);
			return -ERANGE;
		}

		cur = &tree->inline_dentries[start_index];

		if ((start_index + 1) <= dentries_count) {
			memmove(&tree->inline_dentries[start_index + 1],
				cur,
				(dentries_count - start_index) *
					sizeof(struct ssdfs_dir_entry));
			memcpy(cur, &search->raw.dentry.header,
				sizeof(struct ssdfs_dir_entry));

			hash1 = le64_to_cpu(cur->hash_code);
			ino1 = le64_to_cpu(cur->ino);

			cur = &tree->inline_dentries[start_index + 1];

			hash2 = le64_to_cpu(cur->hash_code);
			ino2 = le64_to_cpu(cur->ino);
		} else {
			memcpy(cur, &search->raw.dentry.header,
				sizeof(struct ssdfs_dir_entry));

			if (start_index > 0) {
				hash2 = le64_to_cpu(cur->hash_code);
				ino2 = le64_to_cpu(cur->ino);

				cur =
				    &tree->inline_dentries[start_index - 1];

				hash1 = le64_to_cpu(cur->hash_code);
				ino1 = le64_to_cpu(cur->ino);
			}
		}

		if (hash1 < hash2) {
			/*
			 * Correct order. Do nothing.
			 */
		} else if (hash1 == hash2) {
			if (ino1 < ino2) {
				/*
				 * Correct order. Do nothing.
				 */
			} else if (ino1 < ino2) {
				SSDFS_ERR("duplicated dentry: "
					  "hash1 %llx, ino1 %llu, "
					  "hash2 %llx, ino2 %llu\n",
					  hash1, ino1, hash2, ino2);
				atomic_set(&tree->state,
					SSDFS_DENTRIES_BTREE_CORRUPTED);
				return -ERANGE;
			} else {
				SSDFS_ERR("invalid dentries oredring: "
					  "hash1 %llx, ino1 %llu, "
					  "hash2 %llx, ino2 %llu\n",
					  hash1, ino1, hash2, ino2);
				atomic_set(&tree->state,
					SSDFS_DENTRIES_BTREE_CORRUPTED);
				return -ERANGE;
			}
		} else {
			SSDFS_ERR("invalid hash order: "
				  "hash1 %llx > hash2 %llx\n",
				  hash1, hash2);
			atomic_set(&tree->state,
				    SSDFS_DENTRIES_BTREE_CORRUPTED);
			return -ERANGE;
		}
	}

	dentries_count = atomic64_inc_return(&tree->dentries_count);
	if (dentries_count > dentries_capacity) {
		SSDFS_WARN("dentries_count is too much: "
			   "count %lld, capacity %lld\n",
			   dentries_count, dentries_capacity);
		atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_CORRUPTED);
		return -ERANGE;
	}

	atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_DIRTY);
	return 0;
}

/*
 * ssdfs_dentries_tree_add_dentry() - add the dentry into the tree
 * @tree: dentries tree
 * @search: search object
 *
 * This method tries to add the generic dentry into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - dentry exists in the tree.
 */
static
int ssdfs_dentries_tree_add_dentry(struct ssdfs_dentries_btree_info *tree,
				   struct ssdfs_btree_search *search)
{
	s64 dentries_count;
	u64 hash1, hash2;
	u64 ino1, ino2;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->type)) {
	case SSDFS_PRIVATE_DENTRIES_BTREE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	if (!tree->generic_tree) {
		SSDFS_ERR("empty generic tree %p\n",
			  tree->generic_tree);
		return -ERANGE;
	}

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
	case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
	case SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE:
		/* expected state */
		break;

	default:
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
	ino1 = search->request.start.ino;
	hash2 = le64_to_cpu(search->raw.dentry.header.hash_code);
	ino2 = le64_to_cpu(search->raw.dentry.header.ino);

	if (hash1 != hash2 || ino1 != ino2) {
		SSDFS_ERR("corrupted dentry: "
			  "request (hash %llx, ino %llu), "
			  "dentry (hash %llx, ino %llu)\n",
			  hash1, ino1, hash2, ino2);
		return -ERANGE;
	}

	err = ssdfs_btree_add_item(tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add the dentry into the tree: "
			  "err %d\n", err);
		return err;
	}

	dentries_count = atomic64_inc_return(&tree->dentries_count);
	if (dentries_count >= S64_MAX) {
		SSDFS_WARN("dentries_count is too much\n");
		atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_CORRUPTED);
		return -ERANGE;
	}

	err = ssdfs_btree_synchronize_root_node(tree->generic_tree,
						tree->root);
	if (unlikely(err)) {
		SSDFS_ERR("fail to synchronize the root node: "
			  "err %d\n", err);
		return err;
	}

	atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_DIRTY);
	return 0;
}

/*
 * ssdfs_dentries_tree_add() - add dentry into the tree
 * @tree: dentries tree
 * @str: name of the file/folder
 * @ii: inode info
 * @search: search object
 *
 * This method tries to add dentry into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - dentry exists in the tree.
 */
int ssdfs_dentries_tree_add(struct ssdfs_dentries_btree_info *tree,
			    const struct qstr *str,
			    struct ssdfs_inode_info *ii,
			    struct ssdfs_btree_search *search)
{
	struct ssdfs_shared_dict_btree_info *dict;
	u64 name_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !str || !ii || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, ii %p, ino %lu\n",
		  tree, ii, ii->vfs_inode.i_ino);

	dict = tree->fsi->shdictree;
	if (!dict) {
		SSDFS_ERR("shared dictionary is absent\n");
		return -ERANGE;
	}

	search->request.type = SSDFS_BTREE_SEARCH_ADD_ITEM;

	name_hash = ssdfs_generate_name_hash(str);
	if (name_hash == U64_MAX) {
		SSDFS_ERR("fail to generate name hash\n");
		return -ERANGE;
	}

	if (need_initialize_dentries_btree_search(name_hash, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_ADD_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT |
			SSDFS_BTREE_SEARCH_HAS_VALID_NAME |
			SSDFS_BTREE_SEARCH_HAS_VALID_INO;
		search->request.start.hash = name_hash;
		search->request.start.name = str->name;
		search->request.start.name_len = str->len;
		search->request.start.ino = ii->vfs_inode.i_ino;
		search->request.end.hash = name_hash;
		search->request.end.name = str->name;
		search->request.end.name_len = str->len;
		search->request.end.ino = ii->vfs_inode.i_ino;
		search->request.count = 1;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_DENTRIES_ARRAY:
		down_write(&tree->lock);

		err = ssdfs_dentries_tree_find_inline_dentry(tree, search);
		if (err == -ENODATA) {
			/*
			 * Dentry doesn't exist for requested name hash.
			 * It needs to create a new dentry.
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find the inline dentry: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_add_inline_dentry;
		}

		if (err == -ENODATA) {
			err = ssdfs_prepare_dentry(str, ii,
						   SSDFS_INLINE_DENTRY,
						   search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare the dentry: "
					  "name_hash %llx, ino %lu, "
					  "err %d\n",
					  name_hash,
					  ii->vfs_inode.i_ino,
					  err);
				goto finish_add_inline_dentry;
			}

			search->request.type = SSDFS_BTREE_SEARCH_ADD_ITEM;
			err = ssdfs_dentries_tree_add_inline_dentry(tree,
								    search);
			if (err == -ENOSPC) {
				err = ssdfs_migrate_inline2generic_tree(tree);
				if (unlikely(err)) {
					SSDFS_ERR("fail to migrate the tree: "
						  "err %d\n",
						  err);
					goto finish_add_inline_dentry;
				} else {
					search->request.type =
						SSDFS_BTREE_SEARCH_ADD_ITEM;
					downgrade_write(&tree->lock);
					goto try_to_add_into_generic_tree;
				}
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to add the dentry: "
					  "name_hash %llx, ino %lu, "
					  "err %d\n",
					  name_hash,
					  ii->vfs_inode.i_ino,
					  err);
				goto finish_add_inline_dentry;
			}

			if (!can_name_be_inline(str)) {
				err = ssdfs_shared_dict_save_name(dict,
								  name_hash,
								  str);
				if (unlikely(err)) {
					SSDFS_ERR("fail to store name: "
						  "hash %llx, err %d\n",
						  name_hash, err);
					goto finish_add_inline_dentry;
				}
			}
		} else {
			err = -EEXIST;
			SSDFS_DBG("dentry exists in the tree: "
				  "name_hash %llx, ino %lu\n",
				  name_hash, ii->vfs_inode.i_ino);
			goto finish_add_inline_dentry;
		}

finish_add_inline_dentry:
		up_write(&tree->lock);
		break;

	case SSDFS_PRIVATE_DENTRIES_BTREE:
		down_read(&tree->lock);
try_to_add_into_generic_tree:
		err = ssdfs_btree_find_item(tree->generic_tree, search);
		if (err == -ENODATA) {
			/*
			 * Dentry doesn't exist for requested name.
			 * It needs to create a new dentry.
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find the dentry: "
				  "name_hash %llx, ino %lu, "
				  "err %d\n",
				  name_hash,
				  ii->vfs_inode.i_ino,
				  err);
			goto finish_add_generic_dentry;
		}

		if (err == -ENODATA) {
			err = ssdfs_prepare_dentry(str, ii,
						   SSDFS_REGULAR_DENTRY,
						   search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare the dentry: "
					  "name_hash %llx, ino %lu, "
					  "err %d\n",
					  name_hash,
					  ii->vfs_inode.i_ino,
					  err);
				goto finish_add_generic_dentry;
			}

			search->request.type = SSDFS_BTREE_SEARCH_ADD_ITEM;
			err = ssdfs_dentries_tree_add_dentry(tree, search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add the dentry: "
					  "name_hash %llx, ino %lu, "
					  "err %d\n",
					  name_hash,
					  ii->vfs_inode.i_ino,
					  err);
				goto finish_add_generic_dentry;
			}

			if (!can_name_be_inline(str)) {
				err = ssdfs_shared_dict_save_name(dict,
								  name_hash,
								  str);
				if (unlikely(err)) {
					SSDFS_ERR("fail to store name: "
						  "hash %llx, err %d\n",
						  name_hash, err);
					goto finish_add_generic_dentry;
				}
			}
		} else {
			err = -EEXIST;
			SSDFS_DBG("dentry exists in the tree: "
				  "name_hash %llx, ino %lu\n",
				  name_hash, ii->vfs_inode.i_ino);
			goto finish_add_generic_dentry;
		}

finish_add_generic_dentry:
		up_read(&tree->lock);
		break;

	default:
		SSDFS_ERR("invalid dentries tree type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	ssdfs_debug_dentries_btree_object(tree);

	return err;
}

/*
 * ssdfs_change_dentry() - change a dentry
 * @str: string descriptor
 * @new_ii: new inode info
 * @dentry_type: dentry type
 * @search: search object
 *
 * This method tries to prepare a new state of the dentry object.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_change_dentry(const struct qstr *str,
			struct ssdfs_inode_info *new_ii,
			int dentry_type,
			struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_dentry *dentry;
	ino_t ino;
	u64 name_hash;
	u32 copy_len;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!str || !str->name || !new_ii || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	ino = new_ii->vfs_inode.i_ino;

	SSDFS_DBG("name %s, len %u, ino %lu\n",
		  str->name, str->len, ino);

	if (dentry_type <= SSDFS_DENTRIES_BTREE_UNKNOWN_TYPE ||
	    dentry_type >= SSDFS_DENTRIES_BTREE_TYPE_MAX) {
		SSDFS_ERR("invalid dentry type %#x\n",
			  dentry_type);
		return -EINVAL;
	}

	name_hash = ssdfs_generate_name_hash(str);
	if (name_hash == U64_MAX) {
		SSDFS_ERR("fail to generate name hash\n");
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER ||
	    !search->result.buf ||
	    search->result.buf_size != sizeof(struct ssdfs_raw_dentry)) {
		SSDFS_ERR("invalid buffer state: "
			  "state %#x, buf %p\n",
			  search->result.buf_state,
			  search->result.buf);
		return -ERANGE;
	}

	dentry = &search->raw.dentry;

	if (ino != le64_to_cpu(dentry->header.ino)) {
		SSDFS_ERR("invalid ino: "
			  "ino1 %lu != ino2 %llu\n",
			 ino,
			 le64_to_cpu(dentry->header.ino));
		return -ERANGE;
	}

	dentry->header.hash_code = cpu_to_le64(name_hash);
	dentry->header.flags = 0;

	dentry->header.dentry_type = (u8)dentry_type;
	ssdfs_set_file_type(&dentry->header, &new_ii->vfs_inode);

	if (str->len > SSDFS_MAX_NAME_LEN) {
		SSDFS_ERR("invalid name_len %u\n",
			  str->len);
		return -ERANGE;
	}

	if (str->len > SSDFS_DENTRY_INLINE_NAME_MAX_LEN)
		dentry->header.flags |= SSDFS_DENTRY_HAS_EXTERNAL_STRING;

	dentry->header.name_len = (u8)str->len;

	memset(dentry->header.inline_string, 0,
		SSDFS_DENTRY_INLINE_NAME_MAX_LEN);
	copy_len = min_t(u32, (u32)str->len, SSDFS_DENTRY_INLINE_NAME_MAX_LEN);
	memcpy(dentry->header.inline_string, str->name, copy_len);

	memset(search->name.str, 0, SSDFS_MAX_NAME_LEN);
	search->name.len = (u8)str->len;
	memcpy(search->name.str, str->name, str->len);

	return 0;
}

/*
 * ssdfs_dentries_tree_change_inline_dentry() - change inline dentry
 * @tree: dentries tree
 * @search: search object
 *
 * This method tries to change the existing inline dentry.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - dentry doesn't exist in the tree.
 */
static int
ssdfs_dentries_tree_change_inline_dentry(struct ssdfs_dentries_btree_info *tree,
					 struct ssdfs_btree_search *search)
{
	struct ssdfs_dir_entry *cur;
	u64 hash1, hash2;
	u64 ino1, ino2;
	int private_flags;
	s64 dentries_count, dentries_capacity;
	u16 start_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_DENTRIES_ARRAY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	if (!tree->inline_dentries) {
		SSDFS_ERR("empty inline tree %p\n",
			  tree->inline_dentries);
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
	ino1 = search->request.start.ino;

	cur = &search->raw.dentry.header;
	hash2 = le64_to_cpu(cur->hash_code);
	ino2 = le64_to_cpu(cur->ino);

	if (hash1 != hash2 || ino1 != ino2) {
		SSDFS_ERR("hash1 %llx, hash2 %llx, "
			  "ino1 %llu, ino2 %llu\n",
			  hash1, hash2, ino1, ino2);
		return -ERANGE;
	}

	if (!tree->owner) {
		SSDFS_ERR("empty owner inode\n");
		return -ERANGE;
	}

	dentries_count = atomic64_read(&tree->dentries_count);
	private_flags = atomic_read(&tree->owner->private_flags);

	dentries_capacity = SSDFS_INLINE_DENTRIES_COUNT;
	if (private_flags & SSDFS_INODE_HAS_XATTR_BTREE)
		dentries_capacity -= SSDFS_INLINE_DENTRIES_PER_AREA;
	if (private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		SSDFS_ERR("the dentries tree is generic\n");
		return -ERANGE;
	}

	if (dentries_count > dentries_capacity) {
		SSDFS_WARN("dentries tree is corrupted: "
			   "dentries_count %lld, dentries_capacity %lld\n",
			   dentries_count, dentries_capacity);
		atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_CORRUPTED);
		return -ERANGE;
	} else if (dentries_count == 0) {
		SSDFS_DBG("empty tree\n");
		return -EFAULT;
	}

	start_index = search->result.start_index;

	if (start_index >= dentries_count) {
		SSDFS_ERR("start_index %u >= dentries_count %lld\n",
			  start_index, dentries_count);
		return -ENODATA;
	}

	cur = &tree->inline_dentries[start_index];
	memcpy(cur, &search->raw.dentry.header,
		sizeof(struct ssdfs_dir_entry));
	atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_DIRTY);

	return 0;
}

/*
 * ssdfs_dentries_tree_change_dentry() - change the generic dentry
 * @tree: dentries tree
 * @search: search object
 *
 * This method tries to change the existing generic dentry.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - dentry doesn't exist in the tree.
 */
static
int ssdfs_dentries_tree_change_dentry(struct ssdfs_dentries_btree_info *tree,
				      struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_dentry *cur;
	u64 hash1, hash2;
	u64 ino1, ino2;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->type)) {
	case SSDFS_PRIVATE_DENTRIES_BTREE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
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
	ino1 = search->request.start.ino;

	cur = &search->raw.dentry;
	hash2 = le64_to_cpu(cur->header.hash_code);
	ino2 = le64_to_cpu(cur->header.ino);

	if (hash1 != hash2 || ino1 != ino2) {
		SSDFS_ERR("hash1 %llx, hash2 %llx, "
			  "ino1 %llu, ino2 %llu\n",
			  hash1, hash2, ino1, ino2);
		return -ERANGE;
	}

	err = ssdfs_btree_change_item(tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change the dentry into the tree: "
			  "err %d\n", err);
		return err;
	}

	err = ssdfs_btree_synchronize_root_node(tree->generic_tree,
						tree->root);
	if (unlikely(err)) {
		SSDFS_ERR("fail to synchronize the root node: "
			  "err %d\n", err);
		return err;
	}

	atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_DIRTY);
	return 0;
}

/*
 * ssdfs_dentries_tree_change() - change dentry in the tree
 * @tree: dentries tree
 * @name_hash: hash of the name
 * @old_ino: old inode ID
 * @new_str: new name of the file/folder
 * @new_ii: new inode info
 * @search: search object
 *
 * This method tries to change dentry in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - dentry doesn't exist in the tree.
 */
int ssdfs_dentries_tree_change(struct ssdfs_dentries_btree_info *tree,
				u64 name_hash, ino_t old_ino,
				const struct qstr *str,
				struct ssdfs_inode_info *new_ii,
				struct ssdfs_btree_search *search)
{
	struct ssdfs_shared_dict_btree_info *dict;
	u64 new_name_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p, name_hash %llx\n",
		  tree, search, name_hash);

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	dict = tree->fsi->shdictree;
	if (!dict) {
		SSDFS_ERR("shared dictionary is absent\n");
		return -ERANGE;
	}

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_dentries_btree_search(name_hash, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT |
			SSDFS_BTREE_SEARCH_HAS_VALID_INO;
		search->request.start.hash = name_hash;
		search->request.start.name = NULL;
		search->request.start.name_len = U32_MAX;
		search->request.start.ino = old_ino;
		search->request.end.hash = name_hash;
		search->request.end.name = NULL;
		search->request.end.name_len = U32_MAX;
		search->request.end.ino = old_ino;
		search->request.count = 1;
	}

	new_name_hash = ssdfs_generate_name_hash(str);
	if (new_name_hash == U64_MAX) {
		SSDFS_ERR("fail to generate name hash\n");
		return -ERANGE;
	}

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_DENTRIES_ARRAY:
		down_write(&tree->lock);

		err = ssdfs_dentries_tree_find_inline_dentry(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the inline dentry: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_change_inline_dentry;
		}

		err = ssdfs_change_dentry(str, new_ii,
					  SSDFS_INLINE_DENTRY, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change dentry: err %d\n",
				  err);
			goto finish_change_inline_dentry;
		}

		search->request.type = SSDFS_BTREE_SEARCH_CHANGE_ITEM;

		err = ssdfs_dentries_tree_change_inline_dentry(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change inline dentry: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_change_inline_dentry;
		}

		if (!can_name_be_inline(str)) {
			err = ssdfs_shared_dict_save_name(dict,
							  new_name_hash,
							  str);
			if (unlikely(err)) {
				SSDFS_ERR("fail to store name: "
					  "hash %llx, err %d\n",
					  new_name_hash, err);
				goto finish_change_inline_dentry;
			}
		}

finish_change_inline_dentry:
		up_write(&tree->lock);
		break;

	case SSDFS_PRIVATE_DENTRIES_BTREE:
		down_read(&tree->lock);

		err = ssdfs_btree_find_item(tree->generic_tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the dentry: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_change_generic_dentry;
		}

		err = ssdfs_change_dentry(str, new_ii,
					  SSDFS_REGULAR_DENTRY, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change dentry: err %d\n",
				  err);
			goto finish_change_generic_dentry;
		}

		search->request.type = SSDFS_BTREE_SEARCH_CHANGE_ITEM;

		err = ssdfs_dentries_tree_change_dentry(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change dentry: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_change_generic_dentry;
		}

		if (!can_name_be_inline(str)) {
			err = ssdfs_shared_dict_save_name(dict,
							  new_name_hash,
							  str);
			if (unlikely(err)) {
				SSDFS_ERR("fail to store name: "
					  "hash %llx, err %d\n",
					  new_name_hash, err);
				goto finish_change_generic_dentry;
			}
		}

finish_change_generic_dentry:
		up_read(&tree->lock);
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid dentries tree type %#x\n",
			  atomic_read(&tree->type));
		break;
	}

	ssdfs_debug_dentries_btree_object(tree);

	return err;
}

/*
 * ssdfs_dentries_tree_delete_inline_dentry() - delete inline dentry
 * @tree: dentries tree
 * @search: search object
 *
 * This method tries to delete the inline dentry from the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - dentry doesn't exist in the tree.
 * %-ENOENT     - no more dentries in the tree.
 */
static int
ssdfs_dentries_tree_delete_inline_dentry(struct ssdfs_dentries_btree_info *tree,
					 struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_dentry *cur;
	struct ssdfs_dir_entry *dentry1, *dentry2;
	u64 hash1, hash2;
	u64 ino1, ino2;
	s64 dentries_count;
	u16 index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_DENTRIES_ARRAY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	if (!tree->inline_dentries) {
		SSDFS_ERR("empty inline tree %p\n",
			  tree->inline_dentries);
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
	ino1 = search->request.start.ino;

	cur = &search->raw.dentry;
	hash2 = le64_to_cpu(cur->header.hash_code);
	ino2 = le64_to_cpu(cur->header.ino);

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		if (hash1 != hash2 || ino1 != ino2) {
			SSDFS_ERR("hash1 %llx, hash2 %llx, "
				  "ino1 %llu, ino2 %llu\n",
				  hash1, hash2, ino1, ino2);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_WARN("unexpected result state %#x\n",
			   search->result.state);
		return -ERANGE;
	}

	dentries_count = atomic64_read(&tree->dentries_count);
	if (dentries_count == 0) {
		SSDFS_DBG("empty tree\n");
		return -ENOENT;
	} else if (dentries_count > SSDFS_INLINE_DENTRIES_COUNT) {
		SSDFS_ERR("invalid dentries count %llu\n",
			  dentries_count);
		return -ERANGE;
	}

	if (search->result.start_index >= dentries_count) {
		SSDFS_ERR("invalid search result: "
			  "start_index %u, dentries_count %lld\n",
			  search->result.start_index,
			  dentries_count);
		return -ENODATA;
	}

	index = search->result.start_index;

	if ((index + 1) < dentries_count) {
		dentry1 = &tree->inline_dentries[index];
		dentry2 = &tree->inline_dentries[index + 1];

		memmove(dentry1, dentry2,
			(dentries_count - index) *
			sizeof(struct ssdfs_dir_entry));
	}

	index = (u16)(dentries_count - 1);
	dentry1 = &tree->inline_dentries[index];
	memset(dentry1, 0xFF, sizeof(struct ssdfs_dir_entry));

	atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_DIRTY);

	dentries_count = atomic64_dec_return(&tree->dentries_count);
	if (dentries_count == 0) {
		SSDFS_DBG("tree is empty now\n");
		return -ENOENT;
	} else if (dentries_count < 0) {
		SSDFS_WARN("invalid dentries_count %lld\n",
			   dentries_count);
		atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_CORRUPTED);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_dentries_tree_delete_dentry() - delete generic dentry
 * @tree: dentries tree
 * @search: search object
 *
 * This method tries to delete the generic dentry from the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - dentry doesn't exist in the tree.
 * %-ENOENT     - no more dentries in the tree.
 */
static
int ssdfs_dentries_tree_delete_dentry(struct ssdfs_dentries_btree_info *tree,
				      struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_dentry *cur;
	u64 hash1, hash2;
	u64 ino1, ino2;
	s64 dentries_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->type)) {
	case SSDFS_PRIVATE_DENTRIES_BTREE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
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
	ino1 = search->request.start.ino;

	cur = &search->raw.dentry;
	hash2 = le64_to_cpu(cur->header.hash_code);
	ino2 = le64_to_cpu(cur->header.ino);

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		if (hash1 != hash2 || ino1 != ino2) {
			SSDFS_ERR("hash1 %llx, hash2 %llx, "
				  "ino1 %llu, ino2 %llu\n",
				  hash1, hash2, ino1, ino2);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_WARN("unexpected result state %#x\n",
			   search->result.state);
		return -ERANGE;
	}

	dentries_count = atomic64_read(&tree->dentries_count);
	if (dentries_count == 0) {
		SSDFS_DBG("empty tree\n");
		return -ENOENT;
	}

	if (search->result.start_index >= dentries_count) {
		SSDFS_ERR("invalid search result: "
			  "start_index %u, dentries_count %lld\n",
			  search->result.start_index,
			  dentries_count);
		return -ENODATA;
	}

	err = ssdfs_btree_delete_item(tree->generic_tree,
				      search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete the dentry from the tree: "
			  "err %d\n", err);
		return err;
	}

	atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_DIRTY);

	dentries_count = atomic64_dec_return(&tree->dentries_count);
	if (dentries_count == 0) {
		SSDFS_DBG("tree is empty now\n");
		return -ENOENT;
	} else if (dentries_count < 0) {
		SSDFS_WARN("invalid dentries_count %lld\n",
			   dentries_count);
		atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_CORRUPTED);
		return -ERANGE;
	}

	err = ssdfs_btree_synchronize_root_node(tree->generic_tree,
						tree->root);
	if (unlikely(err)) {
		SSDFS_ERR("fail to synchronize the root node: "
			  "err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_migrate_generic2inline_tree() - convert generic tree into inline
 * @tree: dentries tree
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
int ssdfs_migrate_generic2inline_tree(struct ssdfs_dentries_btree_info *tree)
{
	struct ssdfs_dir_entry dentries[SSDFS_INLINE_DENTRIES_COUNT];
	struct ssdfs_btree_search *search;
	size_t dentry_size = sizeof(struct ssdfs_dir_entry);
	s64 dentries_count, dentries_capacity;
	int private_flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", tree);

	switch (atomic_read(&tree->type)) {
	case SSDFS_PRIVATE_DENTRIES_BTREE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	if (!tree->owner) {
		SSDFS_ERR("empty owner inode\n");
		return -ERANGE;
	}

	dentries_count = atomic64_read(&tree->dentries_count);
	private_flags = atomic_read(&tree->owner->private_flags);

	dentries_capacity = SSDFS_INLINE_DENTRIES_COUNT;
	if (private_flags & SSDFS_INODE_HAS_XATTR_BTREE)
		dentries_capacity -= SSDFS_INLINE_DENTRIES_PER_AREA;

	if (private_flags & SSDFS_INODE_HAS_INLINE_DENTRIES) {
		SSDFS_ERR("the dentries tree is not generic\n");
		return -ERANGE;
	}

	if (dentries_count > dentries_capacity) {
		SSDFS_DBG("dentries_count %lld > dentries_capacity %lld\n",
			  dentries_count, dentries_capacity);
		return -ENOSPC;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(tree->inline_dentries || !tree->generic_tree);
#endif /* CONFIG_SSDFS_DEBUG */

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);
	search->request.type = SSDFS_BTREE_SEARCH_FIND_RANGE;
	search->request.flags = 0;
	search->request.start.hash = U64_MAX;
	search->request.start.ino = U64_MAX;
	search->request.end.hash = U64_MAX;
	search->request.end.ino = U64_MAX;
	search->request.count = 0;

	err = ssdfs_btree_get_head_range(&tree->buffer.tree,
					 dentries_count, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract dentries: "
			  "dentries_count %lld, err %d\n",
			  dentries_count, err);
		goto finish_process_range;
	} else if (dentries_count != search->result.items_in_buffer) {
		err = -ERANGE;
		SSDFS_ERR("dentries_count %lld != items_in_buffer %u\n",
			  dentries_count,
			  search->result.items_in_buffer);
		goto finish_process_range;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_VALID_ITEM) {
		err = -ERANGE;
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		goto finish_process_range;
	}

	memset(dentries, 0xFF, dentry_size * SSDFS_INLINE_DENTRIES_COUNT);

	if (search->result.buf_size != (dentry_size * dentries_count) ||
	    search->result.items_in_buffer != dentries_count) {
		err = -ERANGE;
		SSDFS_ERR("invalid search result: "
			  "buf_size %zu, items_in_buffer %u, "
			  "dentries_count %lld\n",
			  search->result.buf_size,
			  search->result.items_in_buffer,
			  dentries_count);
		goto finish_process_range;
	}

	switch (search->result.buf_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
		memcpy(dentries, &search->raw.dentry.header,
			dentry_size);
		break;

	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		if (!search->result.buf) {
			err = -ERANGE;
			SSDFS_ERR("empty buffer\n");
			goto finish_process_range;
		}

		memcpy(dentries, search->result.buf,
			(u64)dentry_size * dentries_count);
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid buffer's state %#x\n",
			  search->result.buf_state);
		goto finish_process_range;
	}

	search->request.type = SSDFS_BTREE_SEARCH_DELETE_RANGE;
	search->request.flags = SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
				SSDFS_BTREE_SEARCH_HAS_VALID_COUNT |
				SSDFS_BTREE_SEARCH_HAS_VALID_INO;
	search->request.start.hash = le64_to_cpu(dentries[0].hash_code);
	search->request.start.ino = le64_to_cpu(dentries[0].ino);
	search->request.end.hash =
		le64_to_cpu(dentries[dentries_count - 1].hash_code);
	search->request.start.ino =
		le64_to_cpu(dentries[dentries_count - 1].ino);
	search->request.count = dentries_count;

	err = ssdfs_btree_delete_range(&tree->buffer.tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete range: "
			  "start (hash %llx, ino %llu), "
			  "end (hash %llx, ino %llu), "
			  "count %u, err %d\n",
			  search->request.start.hash,
			  search->request.start.ino,
			  search->request.end.hash,
			  search->request.end.ino,
			  search->request.count,
			  err);
		goto finish_process_range;
	}

	if (!is_ssdfs_btree_empty(&tree->buffer.tree)) {
		err = -ERANGE;
		SSDFS_WARN("dentries tree is not empty\n");
		atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_CORRUPTED);
		goto finish_process_range;
	}

	search->result.state = SSDFS_BTREE_SEARCH_PLEASE_DELETE_NODE;

	err = ssdfs_btree_delete_node(&tree->buffer.tree, search);
	if (unlikely(err)) {
		SSDFS_WARN("fail to delete node %u\n",
			   search->node.id);
		atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_CORRUPTED);
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

	if (unlikely(err))
		return err;

	ssdfs_btree_destroy(&tree->buffer.tree);
	memcpy(tree->buffer.dentries, dentries, dentry_size * dentries_count);

	atomic_set(&tree->type, SSDFS_INLINE_DENTRIES_ARRAY);
	atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_DIRTY);
	tree->inline_dentries = tree->buffer.dentries;
	tree->generic_tree = NULL;

	atomic_and(~SSDFS_INODE_HAS_DENTRIES_BTREE,
		   &tree->owner->private_flags);
	atomic_or(SSDFS_INODE_HAS_INLINE_DENTRIES,
		  &tree->owner->private_flags);

	return 0;
}

/*
 * ssdfs_dentries_tree_delete() - delete dentry from the tree
 * @tree: dentries tree
 * @name_hash: hash of the name
 * @ino: inode ID
 * @search: search object
 *
 * This method tries to delete dentry from the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - dentry doesn't exist in the tree.
 */
int ssdfs_dentries_tree_delete(struct ssdfs_dentries_btree_info *tree,
				u64 name_hash, ino_t ino,
				struct ssdfs_btree_search *search)
{
	int threshold = SSDFS_INLINE_DENTRIES_PER_AREA;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p, name_hash %llx\n",
		  tree, search, name_hash);

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_dentries_btree_search(name_hash, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT |
			SSDFS_BTREE_SEARCH_HAS_VALID_INO;
		search->request.start.hash = name_hash;
		search->request.start.name = NULL;
		search->request.start.name_len = U32_MAX;
		search->request.start.ino = ino;
		search->request.end.hash = name_hash;
		search->request.end.name = NULL;
		search->request.end.name_len = U32_MAX;
		search->request.end.ino = ino;
		search->request.count = 1;
	}

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_DENTRIES_ARRAY:
		down_write(&tree->lock);

		err = ssdfs_dentries_tree_find_inline_dentry(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the inline dentry: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_delete_inline_dentry;
		}

		search->request.type = SSDFS_BTREE_SEARCH_DELETE_ITEM;

		err = ssdfs_dentries_tree_delete_inline_dentry(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to delete dentry: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_delete_inline_dentry;
		}

finish_delete_inline_dentry:
		up_write(&tree->lock);
		break;

	case SSDFS_PRIVATE_DENTRIES_BTREE:
		down_read(&tree->lock);

		err = ssdfs_btree_find_item(tree->generic_tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the dentry: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_delete_generic_dentry;
		}

		search->request.type = SSDFS_BTREE_SEARCH_DELETE_ITEM;

		err = ssdfs_dentries_tree_delete_dentry(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to delete dentry: "
				  "name_hash %llx, err %d\n",
				  name_hash, err);
			goto finish_delete_generic_dentry;
		}

finish_delete_generic_dentry:
		up_read(&tree->lock);

		if (!err && atomic64_read(&tree->dentries_count) <= threshold) {
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
		SSDFS_ERR("invalid dentries tree type %#x\n",
			  atomic_read(&tree->type));
		break;
	}

	ssdfs_debug_dentries_btree_object(tree);

	return err;
}

/*
 * ssdfs_delete_all_inline_dentries() - delete all inline dentries
 * @tree: dentries tree
 *
 * This method tries to delete all inline dentries in the tree.
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
int ssdfs_delete_all_inline_dentries(struct ssdfs_dentries_btree_info *tree)
{
	s64 dentries_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", tree);

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_DENTRIES_ARRAY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	if (!tree->inline_dentries) {
		SSDFS_ERR("empty inline dentries %p\n",
			  tree->inline_dentries);
		return -ERANGE;
	}

	dentries_count = atomic64_read(&tree->dentries_count);
	if (dentries_count == 0) {
		SSDFS_DBG("empty tree\n");
		return -ENOENT;
	} else if (dentries_count > SSDFS_INLINE_DENTRIES_COUNT) {
		atomic_set(&tree->state,
			   SSDFS_DENTRIES_BTREE_CORRUPTED);
		SSDFS_ERR("dentries tree is corupted: "
			  "dentries_count %lld",
			  dentries_count);
		return -ERANGE;
	}

	memset(tree->inline_dentries, 0xFF,
		sizeof(struct ssdfs_dir_entry) * SSDFS_INLINE_DENTRIES_COUNT);

	atomic_set(&tree->state, SSDFS_DENTRIES_BTREE_DIRTY);
	return 0;
}

/*
 * ssdfs_dentries_tree_delete_all() - delete all dentries in the tree
 * @tree: dentries tree
 *
 * This method tries to delete all dentries in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_dentries_tree_delete_all(struct ssdfs_dentries_btree_info *tree)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", tree);

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_DENTRIES_ARRAY:
		down_write(&tree->lock);
		err = ssdfs_delete_all_inline_dentries(tree);
		if (!err)
			atomic64_set(&tree->dentries_count, 0);
		up_write(&tree->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to delete all inline dentries: "
				  "err %d\n",
				  err);
		}
		break;

	case SSDFS_PRIVATE_DENTRIES_BTREE:
		down_write(&tree->lock);
		err = ssdfs_btree_delete_all(tree->generic_tree);
		if (!err) {
			atomic64_set(&tree->dentries_count, 0);
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
			SSDFS_ERR("fail to delete the all dentries: "
				  "err %d\n",
				  err);
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid dentries tree type %#x\n",
			  atomic_read(&tree->type));
		break;
	}

	return err;
}

/*
 * ssdfs_dentries_tree_extract_inline_range() - extract inline range
 * @tree: dentries tree
 * @start_index: start item index
 * @count: requested count of items
 * @search: search object
 *
 * This method tries to extract a range of items from the inline tree.
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
ssdfs_dentries_tree_extract_inline_range(struct ssdfs_dentries_btree_info *tree,
					 u16 start_index, u16 count,
					 struct ssdfs_btree_search *search)
{
	struct ssdfs_dir_entry *src, *dst;
	size_t dentry_size = sizeof(struct ssdfs_dir_entry);
	u64 dentries_count;
	size_t buf_size;
	u16 i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
	BUG_ON(atomic_read(&tree->type) != SSDFS_INLINE_DENTRIES_ARRAY);
	BUG_ON(!tree->inline_dentries);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, start_index %u, count %u, search %p\n",
		  tree, start_index, count, search);

	search->result.count = 0;

	dentries_count = atomic64_read(&tree->dentries_count);
	if (dentries_count == 0) {
		SSDFS_DBG("dentries_count %llu\n",
			  dentries_count);
		return -ENOENT;
	} else if (dentries_count > SSDFS_INLINE_DENTRIES_COUNT) {
		SSDFS_ERR("unexpected dentries_count %llu\n",
			  dentries_count);
		return -ERANGE;
	}

	if (start_index >= dentries_count) {
		SSDFS_ERR("start_index %u >= dentries_count %llu\n",
			  start_index, dentries_count);
		return -ERANGE;
	}

	count = min_t(u16, count, (u16)(dentries_count - start_index));
	buf_size = dentry_size * count;

	switch (search->result.buf_state) {
	case SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE:
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
		if (count == 1) {
			search->result.buf = &search->raw.dentry;
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

			search->result.buf = &search->raw.dentry;
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
		src = &tree->inline_dentries[i];
		dst = (struct ssdfs_dir_entry *)((u8 *)search->result.buf +
						    (i * dentry_size));
		memcpy(dst, src, dentry_size);
		search->result.items_in_buffer++;
		search->result.count++;
	}

	search->result.state = SSDFS_BTREE_SEARCH_VALID_ITEM;
	return 0;
}

/*
 * ssdfs_dentries_tree_extract_range() - extract range of items
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
int ssdfs_dentries_tree_extract_range(struct ssdfs_dentries_btree_info *tree,
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
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_DENTRIES_ARRAY:
		down_read(&tree->lock);
		err = ssdfs_dentries_tree_extract_inline_range(tree,
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

	case SSDFS_PRIVATE_DENTRIES_BTREE:
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
		SSDFS_ERR("invalid dentries tree type %#x\n",
			  atomic_read(&tree->type));
		break;
	}

	return err;
}

/******************************************************************************
 *             SPECIALIZED DENTRIES BTREE DESCRIPTOR OPERATIONS               *
 ******************************************************************************/

/*
 * ssdfs_dentries_btree_desc_init() - specialized btree descriptor init
 * @fsi: pointer on shared file system object
 * @tree: pointer on dentries btree object
 */
static
int ssdfs_dentries_btree_desc_init(struct ssdfs_fs_info *fsi,
				   struct ssdfs_btree *tree)
{
	struct ssdfs_dentries_btree_info *tree_info = NULL;
	struct ssdfs_btree_descriptor *desc;
	u32 erasesize;
	u32 node_size;
	size_t dentry_size = sizeof(struct ssdfs_dir_entry);
	u16 item_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !tree);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, tree %p\n",
		  fsi, tree);

	tree_info = container_of(tree,
				 struct ssdfs_dentries_btree_info,
				 buffer.tree);
	desc = &tree_info->desc.desc;
	erasesize = fsi->erasesize;

	if (le32_to_cpu(desc->magic) != SSDFS_DENTRIES_BTREE_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid magic %#x\n",
			  le32_to_cpu(desc->magic));
		goto finish_btree_desc_init;
	}

	/* TODO: check flags */

	if (desc->type != SSDFS_DENTRIES_BTREE) {
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

	if (item_size != dentry_size) {
		err = -EIO;
		SSDFS_ERR("invalid item size %u\n",
			  item_size);
		goto finish_btree_desc_init;
	}

	if (le16_to_cpu(desc->index_area_min_size) < (2 * dentry_size)) {
		err = -EIO;
		SSDFS_ERR("invalid index_area_min_size %u\n",
			  le16_to_cpu(desc->index_area_min_size));
		goto finish_btree_desc_init;
	}

	err = ssdfs_btree_desc_init(fsi, tree, desc, (u8)item_size, item_size);

finish_btree_desc_init:
	if (unlikely(err)) {
		SSDFS_ERR("fail to init btree descriptor: err %d\n",
			  err);
	}

	return err;
}

/*
 * ssdfs_dentries_btree_desc_flush() - specialized btree's descriptor flush
 * @tree: pointer on btree object
 */
static
int ssdfs_dentries_btree_desc_flush(struct ssdfs_btree *tree)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_dentries_btree_info *tree_info = NULL;
	struct ssdfs_btree_descriptor desc;
	size_t dentry_size = sizeof(struct ssdfs_dir_entry);
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

	if (tree->type != SSDFS_DENTRIES_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_dentries_btree_info,
					 buffer.tree);
	}

	memset(&desc, 0xFF, sizeof(struct ssdfs_btree_descriptor));

	desc.magic = cpu_to_le32(SSDFS_DENTRIES_BTREE_MAGIC);
	desc.item_size = cpu_to_le16(dentry_size);

	err = ssdfs_btree_desc_flush(tree, &desc);
	if (unlikely(err)) {
		SSDFS_ERR("invalid btree descriptor: err %d\n",
			  err);
		return err;
	}

	if (desc.type != SSDFS_DENTRIES_BTREE) {
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

	if (le16_to_cpu(desc.index_area_min_size) < (2 * dentry_size)) {
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
 * ssdfs_dentries_btree_create_root_node() - specialized root node creation
 * @fsi: pointer on shared file system object
 * @node: pointer on node object [out]
 */
static
int ssdfs_dentries_btree_create_root_node(struct ssdfs_fs_info *fsi,
					  struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_dentries_btree_info *tree_info = NULL;
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

	if (tree->type != SSDFS_DENTRIES_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_dentries_btree_info,
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

	if (private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		switch (atomic_read(&tree_info->type)) {
		case SSDFS_PRIVATE_DENTRIES_BTREE:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid tree type %#x\n",
				  atomic_read(&tree_info->type));
			return -ERANGE;
		}

		raw_inode = &tree_info->owner->raw_inode;
		memcpy(&tmp_buffer,
			&raw_inode->internal[0].area1.dentries_root,
			sizeof(struct ssdfs_btree_inline_root_node));
	} else {
		switch (atomic_read(&tree_info->type)) {
		case SSDFS_INLINE_DENTRIES_ARRAY:
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
 * ssdfs_dentries_btree_pre_flush_root_node() - specialized root node pre-flush
 * @node: pointer on node object
 */
static
int ssdfs_dentries_btree_pre_flush_root_node(struct ssdfs_btree_node *node)
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

	if (tree->type != SSDFS_DENTRIES_BTREE) {
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
 * ssdfs_dentries_btree_flush_root_node() - specialized root node flush
 * @node: pointer on node object
 */
static
int ssdfs_dentries_btree_flush_root_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_dentries_btree_info *tree_info = NULL;
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

	if (tree->type != SSDFS_DENTRIES_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_dentries_btree_info,
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

	if (private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		switch (atomic_read(&tree_info->type)) {
		case SSDFS_PRIVATE_DENTRIES_BTREE:
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
		memcpy(&raw_inode->internal[0].area1.dentries_root,
			&tmp_buffer,
			sizeof(struct ssdfs_btree_inline_root_node));
	} else {
		err = -ERANGE;
		SSDFS_ERR("dentries tree is inline dentries array\n");
	}

	return err;
}

/*
 * ssdfs_dentries_btree_create_node() - specialized node creation
 * @node: pointer on node object
 */
static
int ssdfs_dentries_btree_create_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct page *page;
	void *addr[SSDFS_BTREE_NODE_BMAP_COUNT];
	size_t hdr_size = sizeof(struct ssdfs_dentries_btree_node_header);
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

	node->node_ops = &ssdfs_dentries_btree_node_ops;

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

		SSDFS_DBG("node_size %u, hdr_size %zu, free_space %u\n",
			  node_size, hdr_size,
			  node->items_area.free_space);

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

		SSDFS_DBG("node_size %u, hdr_size %zu, free_space %u\n",
			  node_size, hdr_size,
			  node->items_area.free_space);

		items_area_size = node->items_area.area_size;
		item_size = node->items_area.item_size;

		node->items_area.items_count = 0;
		node->items_area.items_capacity = items_area_size / item_size;
		items_capacity = node->items_area.items_capacity;

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

	if (bmap_bytes == 0 || bmap_bytes > SSDFS_DENTRIES_BMAP_SIZE) {
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
 * ssdfs_dentries_btree_init_node() - init dentries tree's node
 * @node: pointer on node object
 *
 * This method tries to init the node of dentries btree.
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
int ssdfs_dentries_btree_init_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_dentries_btree_info *tree_info = NULL;
	struct ssdfs_dentries_btree_node_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_dentries_btree_node_header);
	void *addr[SSDFS_BTREE_NODE_BMAP_COUNT];
	struct page *page;
	void *kaddr;
	u64 start_hash, end_hash;
	u32 node_size;
	u16 item_size;
	u64 parent_ino;
	u32 dentries_count;
	u16 items_capacity;
	u16 inline_names;
	u16 free_space;
	u32 calculated_used_space;
	u32 items_count;
	u16 flags;
	u8 index_size;
	u32 index_area_size = 0;
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

	if (tree->type != SSDFS_DENTRIES_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_dentries_btree_info,
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

	hdr = (struct ssdfs_dentries_btree_node_header *)kaddr;

	if (!is_csum_valid(&hdr->node.check, hdr, hdr_size)) {
		err = -EIO;
		SSDFS_ERR("invalid checksum: node_id %u\n",
			  node->node_id);
		goto finish_init_operation;
	}

	if (le32_to_cpu(hdr->node.magic.common) != SSDFS_SUPER_MAGIC ||
	    le16_to_cpu(hdr->node.magic.key) != SSDFS_DENTRIES_BNODE_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid magic: common %#x, key %#x\n",
			  le32_to_cpu(hdr->node.magic.common),
			  le16_to_cpu(hdr->node.magic.key));
		goto finish_init_operation;
	}

	down_write(&node->header_lock);

	memcpy(&node->raw.dentries_header, hdr, hdr_size);

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
	dentries_count = le16_to_cpu(hdr->dentries_count);
	inline_names = le16_to_cpu(hdr->inline_names);
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

	if (item_size != sizeof(struct ssdfs_dir_entry)) {
		err = -EIO;
		SSDFS_ERR("invalid item_size: "
			  "size %u, expected size %zu\n",
			  item_size,
			  sizeof(struct ssdfs_dir_entry));
		goto finish_header_init;
	}

	if (items_capacity == 0 ||
	    items_capacity > (node_size / item_size)) {
		err = -EIO;
		SSDFS_ERR("invalid items_capacity %u\n",
			  items_capacity);
		goto finish_header_init;
	}

	if (dentries_count > items_capacity) {
		err = -EIO;
		SSDFS_ERR("items_capacity %u != dentries_count %u\n",
			  items_capacity,
			  dentries_count);
		goto finish_header_init;
	}

	if (inline_names > dentries_count) {
		err = -EIO;
		SSDFS_ERR("inline_names %u > dentries_count %u\n",
			  inline_names, dentries_count);
		goto finish_header_init;
	}

	calculated_used_space = hdr_size;
	calculated_used_space += dentries_count * item_size;

	if (flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA) {
		index_area_size = 1 << hdr->node.log_index_area_size;
		calculated_used_space += index_area_size;
	}


	SSDFS_DBG("free_space %u, index_area_size %u, "
		  "hdr_size %zu, dentries_count %u, "
		  "item_size %u\n",
		  free_space, index_area_size, hdr_size,
		  dentries_count, item_size);

	if (free_space != (node_size - calculated_used_space)) {
		err = -EIO;
		SSDFS_ERR("free_space %u, node_size %u, "
			  "calculated_used_space %u\n",
			  free_space, node_size,
			  calculated_used_space);
		goto finish_header_init;
	}

	node->items_area.free_space = free_space;
	node->items_area.items_count = (u16)dentries_count;
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

	if (bmap_bytes == 0 || bmap_bytes > SSDFS_DENTRIES_BMAP_SIZE) {
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
		   0, dentries_count);
	spin_unlock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);

	up_write(&node->bmap_array.lock);
finish_init_operation:
	kunmap(page);

	if (unlikely(err))
		goto finish_init_node;

	atomic64_add((u64)dentries_count, &tree_info->dentries_count);

finish_init_node:
	up_read(&node->full_lock);

	return err;
}

static
void ssdfs_dentries_btree_destroy_node(struct ssdfs_btree_node *node)
{
	SSDFS_DBG("operation is unavailable\n");
}

/*
 * ssdfs_dentries_btree_add_node() - add node into dentries btree
 * @node: pointer on node object
 *
 * This method tries to finish addition of node into dentries btree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_dentries_btree_add_node(struct ssdfs_btree_node *node)
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
	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
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
		node->raw.dentries_header.dentries_count = cpu_to_le16(0);
		node->raw.dentries_header.inline_names = cpu_to_le16(0);
		node->raw.dentries_header.free_space =
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
int ssdfs_dentries_btree_delete_node(struct ssdfs_btree_node *node)
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
 * ssdfs_dentries_btree_pre_flush_node() - pre-flush node's header
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
int ssdfs_dentries_btree_pre_flush_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_dentries_btree_node_header dentries_header;
	size_t hdr_size = sizeof(struct ssdfs_dentries_btree_node_header);
	struct ssdfs_btree *tree;
	struct ssdfs_dentries_btree_info *tree_info = NULL;
	struct ssdfs_state_bitmap *bmap;
	struct page *page;
	void *kaddr;
	u16 items_count;
	u32 items_area_size;
	u16 dentries_count;
	u16 inline_names;
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

	if (tree->type != SSDFS_DENTRIES_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_dentries_btree_info,
					 buffer.tree);
	}

	down_write(&node->full_lock);
	down_write(&node->header_lock);

	memcpy(&dentries_header, &node->raw.dentries_header,
		sizeof(struct ssdfs_dentries_btree_node_header));

	dentries_header.node.magic.common = cpu_to_le32(SSDFS_SUPER_MAGIC);
	dentries_header.node.magic.key =
				cpu_to_le16(SSDFS_DENTRIES_BNODE_MAGIC);
	dentries_header.node.magic.version.major = SSDFS_MAJOR_REVISION;
	dentries_header.node.magic.version.minor = SSDFS_MINOR_REVISION;

	err = ssdfs_btree_node_pre_flush_header(node, &dentries_header.node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to flush generic header: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		goto finish_dentries_header_preparation;
	}

	if (!tree_info->owner) {
		err = -ERANGE;
		SSDFS_WARN("fail to extract parent_ino\n");
		goto finish_dentries_header_preparation;
	}

	dentries_header.parent_ino =
		cpu_to_le64(tree_info->owner->vfs_inode.i_ino);

	items_count = node->items_area.items_count;
	items_area_size = node->items_area.area_size;
	dentries_count = le16_to_cpu(dentries_header.dentries_count);
	inline_names = le16_to_cpu(dentries_header.inline_names);
	free_space = le16_to_cpu(dentries_header.free_space);

	if (dentries_count != items_count) {
		err = -ERANGE;
		SSDFS_ERR("dentries_count %u != items_count %u\n",
			  dentries_count, items_count);
		goto finish_dentries_header_preparation;
	}

	if (inline_names > dentries_count) {
		err = -ERANGE;
		SSDFS_ERR("inline_names %u > dentries_count %u\n",
			  inline_names, dentries_count);
		goto finish_dentries_header_preparation;
	}

	used_space = (u32)items_count * sizeof(struct ssdfs_dir_entry);

	if (used_space > items_area_size) {
		err = -ERANGE;
		SSDFS_ERR("used_space %u > items_area_size %u\n",
			  used_space, items_area_size);
		goto finish_dentries_header_preparation;
	}

	SSDFS_DBG("free_space %u, dentries_count %u, "
		  "items_area_size %u, item_size %zu\n",
		  free_space, dentries_count,
		  items_area_size,
		  sizeof(struct ssdfs_dir_entry));

	if (free_space != (items_area_size - used_space)) {
		err = -ERANGE;
		SSDFS_ERR("free_space %u, items_area_size %u, "
			  "used_space %u\n",
			  free_space, items_area_size,
			  used_space);
		goto finish_dentries_header_preparation;
	}

	dentries_header.node.check.bytes = cpu_to_le16((u16)hdr_size);
	dentries_header.node.check.flags = cpu_to_le16(SSDFS_CRC32);

	err = ssdfs_calculate_csum(&dentries_header.node.check,
				   &dentries_header, hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("unable to calculate checksum: err %d\n", err);
		goto finish_dentries_header_preparation;
	}

	memcpy(&node->raw.dentries_header, &dentries_header,
		sizeof(struct ssdfs_dentries_btree_node_header));

finish_dentries_header_preparation:
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
	memcpy(kaddr, &dentries_header,
		sizeof(struct ssdfs_dentries_btree_node_header));
	kunmap_atomic(kaddr);

finish_node_pre_flush:
	up_write(&node->full_lock);

	return err;
}

/*
 * ssdfs_dentries_btree_flush_node() - flush node
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
int ssdfs_dentries_btree_flush_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_dentries_btree_info *tree_info = NULL;
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

	if (tree->type != SSDFS_DENTRIES_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_dentries_btree_info,
					 buffer.tree);
	}

	private_flags = atomic_read(&tree_info->owner->private_flags);

	if (private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		switch (atomic_read(&tree_info->type)) {
		case SSDFS_PRIVATE_DENTRIES_BTREE:
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
		SSDFS_ERR("dentries tree is inline dentries array\n");
	}

	return err;
}

/******************************************************************************
 *               SPECIALIZED DENTRIES BTREE NODE OPERATIONS                   *
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
					sizeof(struct ssdfs_dir_entry),
					SSDFS_DENTRIES_BTREE_LOOKUP_TABLE_SIZE);
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
					sizeof(struct ssdfs_dir_entry),
					SSDFS_DENTRIES_BTREE_LOOKUP_TABLE_SIZE);
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

	SSDFS_DBG("node_size %u, item_index %u\n",
		  node_size, item_index);

	lookup_index = ssdfs_convert_item2lookup_index(node_size, item_index);
	calculated = ssdfs_convert_lookup2item_index(node_size, lookup_index);

	SSDFS_DBG("lookup_index %u, calculated %u\n",
		  lookup_index, calculated);

	return calculated == item_index;
}

/*
 * ssdfs_dentries_btree_node_find_lookup_index() - find lookup index
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
int ssdfs_dentries_btree_node_find_lookup_index(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search,
					    u16 *lookup_index)
{
	__le64 *lookup_table;
	int array_size = SSDFS_DENTRIES_BTREE_LOOKUP_TABLE_SIZE;
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
	lookup_table = node->raw.dentries_header.lookup_table;
	err = ssdfs_btree_node_find_lookup_index_nolock(search,
							lookup_table,
							array_size,
							lookup_index);
	up_read(&node->header_lock);

	return err;
}

/*
 * ssdfs_get_dentries_hash_range() - get dentry's hash range
 * @kaddr: pointer on dentry object
 * @start_hash: pointer on start_hash value [out]
 * @end_hash: pointer on end_hash value [out]
 */
static
void ssdfs_get_dentries_hash_range(void *kaddr,
				    u64 *start_hash,
				    u64 *end_hash)
{
	struct ssdfs_dir_entry *dentry;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !start_hash || !end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p\n", kaddr);

	dentry = (struct ssdfs_dir_entry *)kaddr;
	*start_hash = le64_to_cpu(dentry->hash_code);
	*end_hash = *start_hash;
}

/*
 * ssdfs_check_found_dentry() - check found dentry
 * @fsi: pointer on shared file system object
 * @search: search object
 * @kaddr: pointer on dentry object
 * @item_index: index of the dentry
 * @start_hash: pointer on start_hash value [out]
 * @end_hash: pointer on end_hash value [out]
 * @found_index: pointer on found index [out]
 *
 * This method tries to check the found dentry.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - corrupted dentry.
 * %-EAGAIN     - continue the search.
 * %-ENODATA    - possible place was found.
 */
static
int ssdfs_check_found_dentry(struct ssdfs_fs_info *fsi,
			     struct ssdfs_btree_search *search,
			     void *kaddr,
			     u16 item_index,
			     u64 *start_hash,
			     u64 *end_hash,
			     u16 *found_index)
{
	struct ssdfs_dir_entry *dentry;
	u64 hash_code;
	u64 ino;
	u8 type;
	u8 flags;
	u16 name_len;
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

	dentry = (struct ssdfs_dir_entry *)kaddr;
	hash_code = le64_to_cpu(dentry->hash_code);
	ino = le64_to_cpu(dentry->ino);
	type = dentry->dentry_type;
	flags = dentry->flags;
	name_len = le16_to_cpu(dentry->name_len);

	req_flags = search->request.flags;

	if (type != SSDFS_REGULAR_DENTRY) {
		SSDFS_ERR("corrupted dentry: "
			  "hash_code %llx, ino %llu, "
			  "type %#x, flags %#x\n",
			  hash_code, ino,
			  type, flags);
		return -ERANGE;
	}

	if (flags & ~SSDFS_DENTRY_FLAGS_MASK) {
		SSDFS_ERR("corrupted dentry: "
			  "hash_code %llx, ino %llu, "
			  "type %#x, flags %#x\n",
			  hash_code, ino,
			  type, flags);
		return -ERANGE;
	}

	if (hash_code >= U64_MAX || ino >= U64_MAX) {
		SSDFS_ERR("corrupted dentry: "
			  "hash_code %llx, ino %llu, "
			  "type %#x, flags %#x\n",
			  hash_code, ino,
			  type, flags);
		return -ERANGE;
	}

	if (!(req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE)) {
		SSDFS_ERR("invalid request: hash is absent\n");
		return -ERANGE;
	}

	ssdfs_get_dentries_hash_range(kaddr, start_hash, end_hash);

	err = ssdfs_check_dentry_for_request(fsi, dentry, search);
	if (err == -ENODATA) {
		search->result.state =
			SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
		search->result.err = err;
		search->result.start_index = item_index;
		search->result.count = 1;

		switch (search->request.type) {
		case SSDFS_BTREE_SEARCH_ADD_ITEM:
		case SSDFS_BTREE_SEARCH_ADD_RANGE:
		case SSDFS_BTREE_SEARCH_CHANGE_ITEM:
			/* do nothing */
			break;

		default:
			if (search->result.buf) {
				switch (search->result.buf_state) {
				case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
					kfree(search->result.buf);
					break;

				default:
					/* do nothing */
					break;
				}
			}

			search->result.buf_state =
				SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
			search->result.buf = NULL;
			search->result.buf_size = 0;
			search->result.items_in_buffer = 0;
			break;
		}
	} else if (err == -EAGAIN) {
		/* continue to search */
		err = 0;
		*found_index = U16_MAX;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to check dentry: err %d\n",
			  err);
	} else {
		*found_index = item_index;
		search->result.state =
			SSDFS_BTREE_SEARCH_VALID_ITEM;
	}

	return err;
}

/*
 * ssdfs_prepare_dentries_buffer() - prepare buffer for dentries
 * @search: search object
 * @found_index: found index of dentry
 * @start_hash: starting hash
 * @end_hash: ending hash
 * @items_count: count of items in the sequence
 * @item_size: size of the item
 */
static
int ssdfs_prepare_dentries_buffer(struct ssdfs_btree_search *search,
				  u16 found_index,
				  u64 start_hash,
				  u64 end_hash,
				  u16 items_count,
				  size_t item_size)
{
	u16 found_dentries = 0;
	size_t buf_size = sizeof(struct ssdfs_raw_dentry);

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
		found_dentries = 1;
	} else {
		/* use external buffer */
		if (found_index >= items_count) {
			SSDFS_ERR("found_index %u >= items_count %u\n",
				  found_index, items_count);
			return -ERANGE;
		}
		found_dentries = items_count - found_index;
	}

	if (found_dentries == 1) {
		search->result.buf_state =
			SSDFS_BTREE_SEARCH_INLINE_BUFFER;
		search->result.buf = &search->raw.dentry;
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
		search->result.buf_size *= found_dentries;
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
		search->result.name_string_size *= found_dentries;
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
 * ssdfs_extract_found_dentry() - extract found dentry
 * @fsi: pointer on shared file system object
 * @search: search object
 * @item_size: size of the item
 * @kaddr: pointer on dentry
 * @start_hash: pointer on start_hash value [out]
 * @end_hash: pointer on end_hash value [out]
 *
 * This method tries to extract the found dentry.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_extract_found_dentry(struct ssdfs_fs_info *fsi,
				struct ssdfs_btree_search *search,
				size_t item_size,
				void *kaddr,
				u64 *start_hash,
				u64 *end_hash)
{
	struct ssdfs_shared_dict_btree_info *dict;
	struct ssdfs_dir_entry *dentry;
	struct ssdfs_raw_dentry *buf;
	size_t buf_size = sizeof(struct ssdfs_raw_dentry);
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

	buf = (struct ssdfs_raw_dentry *)((u8 *)search->result.buf +
						calculated);
	dentry = (struct ssdfs_dir_entry *)kaddr;

	ssdfs_get_dentries_hash_range(dentry, start_hash, end_hash);
	memcpy(buf, dentry, item_size);
	search->result.items_in_buffer++;

	flags = dentry->flags;
	if (flags & SSDFS_DENTRY_HAS_EXTERNAL_STRING) {
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
	int capacity = SSDFS_DENTRIES_BTREE_LOOKUP_TABLE_SIZE;
	size_t item_size = sizeof(struct ssdfs_dir_entry);

	return __ssdfs_extract_range_by_lookup_index(node, lookup_index,
						capacity, item_size,
						search,
						ssdfs_check_found_dentry,
						ssdfs_prepare_dentries_buffer,
						ssdfs_extract_found_dentry);
}

/*
 * ssdfs_dentries_btree_node_find_range() - find a range of items into the node
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
int ssdfs_dentries_btree_node_find_range(struct ssdfs_btree_node *node,
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

	err = ssdfs_dentries_btree_node_find_lookup_index(node, search,
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
	BUG_ON(lookup_index >= SSDFS_DENTRIES_BTREE_LOOKUP_TABLE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_extract_range_by_lookup_index(node, lookup_index,
						  search);
	search->result.search_cno = ssdfs_current_cno(node->tree->fsi->sb);

	if (err == -EAGAIN) {
		SSDFS_DBG("node contains not all requested dentries: "
			  "node (start_hash %llx, end_hash %llx), "
			  "request (start_hash %llx, end_hash %llx)\n",
			  start_hash, end_hash,
			  search->request.start.hash,
			  search->request.end.hash);
		return err;
	} else if (err == -ENODATA) {
		SSDFS_DBG("unable to extract range: "
			  "node (start_hash %llx, end_hash %llx), "
			  "request (start_hash %llx, end_hash %llx), "
			  "err %d\n",
			  start_hash, end_hash,
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
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
 * ssdfs_dentries_btree_node_find_item() - find item into node
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
int ssdfs_dentries_btree_node_find_item(struct ssdfs_btree_node *node,
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

	return ssdfs_dentries_btree_node_find_range(node, search);
}

static
int ssdfs_dentries_btree_node_allocate_item(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search)
{
	SSDFS_DBG("operation is unavailable\n");
	return -EOPNOTSUPP;
}

static
int ssdfs_dentries_btree_node_allocate_range(struct ssdfs_btree_node *node,
					     struct ssdfs_btree_search *search)
{
	SSDFS_DBG("operation is unavailable\n");
	return -EOPNOTSUPP;
}

/*
 * __ssdfs_dentries_btree_node_get_dentry() - extract the dentry from pagevec
 * @pvec: pointer on pagevec
 * @area_offset: area offset from the node's beginning
 * @area_size: area size
 * @node_size: size of the node
 * @item_index: index of the dentry in the node
 * @dentry: pointer on dentry's buffer [out]
 *
 * This method tries to extract the dentry from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_dentries_btree_node_get_dentry(struct pagevec *pvec,
					   u32 area_offset,
					   u32 area_size,
					   u32 node_size,
					   u16 item_index,
					   struct ssdfs_dir_entry *dentry)
{
	struct ssdfs_dir_entry *found_dentry;
	size_t item_size = sizeof(struct ssdfs_dir_entry);
	u32 item_offset;
	int page_index;
	struct page *page;
	void *kaddr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec || !dentry);
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
	found_dentry = (struct ssdfs_dir_entry *)((u8 *)kaddr + item_offset);
	memcpy(dentry, found_dentry, item_size);
	kunmap_atomic(kaddr);

	return 0;
}

/*
 * ssdfs_dentries_btree_node_get_dentry() - extract dentry from the node
 * @node: pointer on node object
 * @area: items area descriptor
 * @item_index: index of the dentry
 * @dentry: pointer on extracted dentry [out]
 *
 * This method tries to extract the dentry from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_dentries_btree_node_get_dentry(struct ssdfs_btree_node *node,
				struct ssdfs_btree_node_items_area *area,
				u16 item_index,
				struct ssdfs_dir_entry *dentry)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !dentry);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, item_index);

	return __ssdfs_dentries_btree_node_get_dentry(&node->content.pvec,
						      area->offset,
						      area->area_size,
						      node->node_size,
						      item_index,
						      dentry);
}

/*
 * is_requested_position_correct() - check that requested position is correct
 * @node: pointer on node object
 * @area: items area descriptor
 * @search: search object
 *
 * This method tries to check that requested position of a dentry
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
	struct ssdfs_dir_entry dentry;
	u16 item_index;
	u64 ino;
	u64 hash;
	u32 req_flags;
	size_t name_len;
	int direction = SSDFS_CHECK_POSITION_FAILURE;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, search->result.start_index);

	item_index = search->result.start_index;
	if ((item_index + search->request.count) > area->items_capacity) {
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

	err = ssdfs_dentries_btree_node_get_dentry(node, area,
						   item_index, &dentry);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract the dentry: "
			  "item_index %u, err %d\n",
			  item_index, err);
		return SSDFS_CHECK_POSITION_FAILURE;
	}

	ino = le64_to_cpu(dentry.ino);
	hash = le64_to_cpu(dentry.hash_code);
	req_flags = search->request.flags;

	if (search->request.end.hash < hash)
		direction = SSDFS_SEARCH_LEFT_DIRECTION;
	else if (hash < search->request.start.hash)
		direction = SSDFS_SEARCH_RIGHT_DIRECTION;
	else {
		/* search->request.start.hash == hash */

		if (req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_INO) {
			if (search->request.start.ino < ino)
				direction = SSDFS_SEARCH_LEFT_DIRECTION;
			else if (ino < search->request.start.ino)
				direction = SSDFS_SEARCH_RIGHT_DIRECTION;
			else
				direction = SSDFS_CORRECT_POSITION;
		} else if (req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME) {
			int res;

			if (!search->request.start.name) {
				SSDFS_ERR("empty name pointer\n");
				return -ERANGE;
			}

			name_len = min_t(size_t, search->request.start.name_len,
					 SSDFS_DENTRY_INLINE_NAME_MAX_LEN);
			res = strncmp(search->request.start.name,
					dentry.inline_string,
					name_len);
			if (res < 0)
				direction = SSDFS_SEARCH_LEFT_DIRECTION;
			else if (res > 0)
				direction = SSDFS_SEARCH_RIGHT_DIRECTION;
			else
				direction = SSDFS_CORRECT_POSITION;
		} else
			direction = SSDFS_CORRECT_POSITION;
	}

	return direction;
}

/*
 * ssdfs_find_correct_position_from_left() - find position from the left
 * @node: pointer on node object
 * @area: items area descriptor
 * @search: search object
 *
 * This method tries to find a correct position of the dentry
 * from the left side of dentries' sequence in the node.
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
	struct ssdfs_dir_entry dentry;
	int item_index;
	u64 ino;
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
		err = ssdfs_dentries_btree_node_get_dentry(node, area,
							   (u16)item_index,
							   &dentry);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the dentry: "
				  "item_index %d, err %d\n",
				  item_index, err);
			return err;
		}

		ino = le64_to_cpu(dentry.ino);
		hash = le64_to_cpu(dentry.hash_code);

		if (search->request.start.hash == hash) {
			if (req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_INO) {
				if (ino == search->request.start.ino) {
					search->result.start_index =
							(u16)item_index;
					return 0;
				} else if (ino < search->request.start.ino) {
					search->result.start_index =
							(u16)(item_index + 1);
					return 0;
				} else
					continue;
			}

			if (req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME) {
				int res;

				if (!search->request.start.name) {
					SSDFS_ERR("empty name pointer\n");
					return -ERANGE;
				}

				name_len = min_t(size_t,
					    search->request.start.name_len,
					    SSDFS_DENTRY_INLINE_NAME_MAX_LEN);
				res = strncmp(search->request.start.name,
						dentry.inline_string,
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
 * This method tries to find a correct position of the dentry
 * from the right side of dentries' sequence in the node.
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
	struct ssdfs_dir_entry dentry;
	int item_index;
	u64 ino;
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
		err = ssdfs_dentries_btree_node_get_dentry(node, area,
							   (u16)item_index,
							   &dentry);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the dentry: "
				  "item_index %d, err %d\n",
				  item_index, err);
			return err;
		}

		ino = le64_to_cpu(dentry.ino);
		hash = le64_to_cpu(dentry.hash_code);

		if (search->request.start.hash == hash) {
			if (req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_INO) {
				if (ino == search->request.start.ino) {
					search->result.start_index =
							(u16)item_index;
					return 0;
				} else if (search->request.start.ino < ino) {
					if (item_index == 0) {
						search->result.start_index =
								(u16)item_index;
					} else {
						search->result.start_index =
							(u16)(item_index - 1);
					}
					return 0;
				} else
					continue;
			}

			if (req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME) {
				int res;

				if (!search->request.start.name) {
					SSDFS_ERR("empty name pointer\n");
					return -ERANGE;
				}

				name_len = min_t(size_t,
					    search->request.start.name_len,
					    SSDFS_DENTRY_INLINE_NAME_MAX_LEN);
				res = strncmp(search->request.start.name,
						dentry.inline_string,
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

	search->result.start_index = area->items_count;
	return 0;
}

/*
 * ssdfs_clean_lookup_table() - clean unused space of lookup table
 * @node: pointer on node object
 * @area: items area descriptor
 * @start_index: starting index
 *
 * This method tries to clean the unused space of lookup table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_clean_lookup_table(struct ssdfs_btree_node *node,
			     struct ssdfs_btree_node_items_area *area,
			     u16 start_index)
{
	__le64 *lookup_table;
	u16 lookup_index;
	u16 item_index;
	u16 items_count;
	u16 items_capacity;
	u16 cleaning_indexes;
	u32 cleaning_bytes;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, start_index %u\n",
		  node->node_id, start_index);

	items_capacity = node->items_area.items_capacity;
	if (start_index >= items_capacity) {
		SSDFS_DBG("start_index %u >= items_capacity %u\n",
			  start_index, items_capacity);
		return 0;
	}

	lookup_table = node->raw.dentries_header.lookup_table;

	lookup_index = ssdfs_convert_item2lookup_index(node->node_size,
						       start_index);
	if (unlikely(lookup_index >= SSDFS_DENTRIES_BTREE_LOOKUP_TABLE_SIZE)) {
		SSDFS_ERR("invalid lookup_index %u\n",
			  lookup_index);
		return -ERANGE;
	}

	items_count = node->items_area.items_count;
	item_index = ssdfs_convert_lookup2item_index(node->node_size,
						     lookup_index);
	if (unlikely(item_index >= items_count)) {
		SSDFS_ERR("item_index %u >= items_count %u\n",
			  item_index, items_count);
		return -ERANGE;
	}

	if (item_index != start_index)
		lookup_index++;

	cleaning_indexes =
		SSDFS_DENTRIES_BTREE_LOOKUP_TABLE_SIZE - lookup_index;
	cleaning_bytes = cleaning_indexes * sizeof(__le64);

	memset(&lookup_table[lookup_index], 0xFF, cleaning_bytes);

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
	struct ssdfs_dir_entry dentry;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, start_index %u, range_len %u\n",
		  node->node_id, start_index, range_len);

	if (range_len == 0) {
		SSDFS_DBG("range_len == 0\n");
		return 0;
	}

	lookup_table = node->raw.dentries_header.lookup_table;

	for (i = 0; i < range_len; i++) {
		int item_index = start_index + i;
		u16 lookup_index;

		if (is_hash_for_lookup_table(node->node_size, item_index)) {
			lookup_index =
				ssdfs_convert_item2lookup_index(node->node_size,
								item_index);

			err = ssdfs_dentries_btree_node_get_dentry(node, area,
								   item_index,
								   &dentry);
			if (unlikely(err)) {
				SSDFS_ERR("fail to extract dentry: "
					  "item_index %d, err %d\n",
					  item_index, err);
				return err;
			}

			lookup_table[lookup_index] = dentry.hash_code;
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

	lookup_table = node->raw.dentries_header.lookup_table;
	memset(lookup_table, 0xFF,
		sizeof(__le64) * SSDFS_DENTRIES_BTREE_LOOKUP_TABLE_SIZE);
}

/*
 * __ssdfs_dentries_btree_node_insert_range() - insert range into node
 * @node: pointer on node object
 * @search: search object
 *
 * This method tries to insert the range of dentries into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int __ssdfs_dentries_btree_node_insert_range(struct ssdfs_btree_node *node,
					     struct ssdfs_btree_search *search)
{
	struct ssdfs_btree *tree;
	struct ssdfs_dentries_btree_info *dtree;
	struct ssdfs_dentries_btree_node_header *hdr;
	struct ssdfs_btree_node_items_area items_area;
	struct ssdfs_dir_entry dentry;
	size_t item_size = sizeof(struct ssdfs_dir_entry);
	u16 item_index;
	int free_items;
	u16 range_len;
	u16 dentries_count = 0;
	int direction;
	u32 used_space;
	u64 start_hash, end_hash, cur_hash;
	u16 inline_names = 0;
	int i;
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
	case SSDFS_DENTRIES_BTREE:
		/* expected btree type */
		break;

	default:
		SSDFS_ERR("invalid btree type %#x\n", tree->type);
		return -ERANGE;
	}

	dtree = container_of(tree, struct ssdfs_dentries_btree_info,
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

	SSDFS_DBG("items_capacity %u, items_count %u\n",
		  items_area.items_capacity,
		  items_area.items_count);

	SSDFS_DBG("area_size %u, free_space %u\n",
		  items_area.area_size,
		  items_area.free_space);

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
	dentries_count = range_len + search->request.count;

	item_index = search->result.start_index;
	if ((item_index + dentries_count) > items_area.items_capacity) {
		err = -ERANGE;
		SSDFS_ERR("invalid dentries_count: "
			  "item_index %u, dentries_count %u, "
			  "items_capacity %u\n",
			  item_index, dentries_count,
			  items_area.items_capacity);
		goto finish_detect_affected_items;
	}

	if (items_area.items_count == 0)
		goto lock_items_range;

	start_hash = search->request.start.hash;
	end_hash = search->request.end.hash;

	if (item_index > 0) {
		err = ssdfs_dentries_btree_node_get_dentry(node,
							   &items_area,
							   item_index - 1,
							   &dentry);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get dentry: err %d\n", err);
			goto finish_detect_affected_items;
		}

		cur_hash = le64_to_cpu(dentry.hash_code);

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
		err = ssdfs_dentries_btree_node_get_dentry(node,
							   &items_area,
							   item_index,
							   &dentry);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get dentry: err %d\n", err);
			goto finish_detect_affected_items;
		}

		cur_hash = le64_to_cpu(dentry.hash_code);

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
	err = ssdfs_lock_items_range(node, item_index, dentries_count);
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

	ssdfs_debug_btree_node_object(node);

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

	err = ssdfs_dentries_btree_node_get_dentry(node, &node->items_area,
						   0, &dentry);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get dentry: err %d\n", err);
		goto finish_items_area_correction;
	}
	start_hash = le64_to_cpu(dentry.hash_code);

	err = ssdfs_dentries_btree_node_get_dentry(node,
					&node->items_area,
					node->items_area.items_count - 1,
					&dentry);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get dentry: err %d\n", err);
		goto finish_items_area_correction;
	}
	end_hash = le64_to_cpu(dentry.hash_code);

	if (start_hash >= U64_MAX || end_hash >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("start_hash %llx, end_hash %llx\n",
			  start_hash, end_hash);
		goto finish_items_area_correction;
	}

	node->items_area.start_hash = start_hash;
	node->items_area.end_hash = end_hash;

	err = ssdfs_correct_lookup_table(node, &node->items_area,
					 item_index, dentries_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to correct lookup table: "
			  "err %d\n", err);
		goto finish_items_area_correction;
	}

	hdr = &node->raw.dentries_header;

	le16_add_cpu(&hdr->dentries_count, search->request.count);

	inline_names = 0;
	for (i = 0; i < search->request.count; i++) {
		u16 name_len;

		err = ssdfs_dentries_btree_node_get_dentry(node,
							   &items_area,
							   (i + item_index),
							   &dentry);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get dentry: err %d\n", err);
			goto finish_items_area_correction;
		}

		name_len = le16_to_cpu(dentry.name_len);
		if (name_len <= SSDFS_DENTRY_INLINE_NAME_MAX_LEN)
			inline_names++;
	}

	le16_add_cpu(&hdr->inline_names, inline_names);
	hdr->free_space = cpu_to_le16(node->items_area.free_space);

	atomic64_add(search->request.count, &dtree->dentries_count);

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
					  item_index, dentries_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set items range as dirty: "
			  "start %u, count %u, err %d\n",
			  item_index, dentries_count, err);
		goto unlock_items_range;
	}

unlock_items_range:
	ssdfs_unlock_items_range(node, item_index, dentries_count);

finish_insert_item:
	up_read(&node->full_lock);

	ssdfs_debug_btree_node_object(node);

	return err;
}

/*
 * ssdfs_dentries_btree_node_insert_item() - insert item in the node
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
int ssdfs_dentries_btree_node_insert_item(struct ssdfs_btree_node *node,
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

	SSDFS_DBG("free_space %u\n", node->items_area.free_space);

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
	case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.err == -ENODATA) {
		search->result.err = 0;
		/*
		 * Node doesn't contain requested item.
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

	err = __ssdfs_dentries_btree_node_insert_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert item: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	SSDFS_DBG("free_space %u\n", node->items_area.free_space);

	return 0;
}

/*
 * ssdfs_dentries_btree_node_insert_range() - insert range of items
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
int ssdfs_dentries_btree_node_insert_range(struct ssdfs_btree_node *node,
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

	SSDFS_DBG("free_space %u\n", node->items_area.free_space);

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
	case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.err == -ENODATA) {
		/*
		 * Node doesn't contain inserting items.
		 */
	} else if (search->result.err) {
		SSDFS_WARN("invalid search result: err %d\n",
			   search->result.err);
		return search->result.err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.count < 1);
	BUG_ON(!search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&node->items_area.state);
	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  state);
		return -ERANGE;
	}

	err = __ssdfs_dentries_btree_node_insert_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert range: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	SSDFS_DBG("free_space %u\n", node->items_area.free_space);

	return 0;
}

/*
 * ssdfs_change_item_only() - change dentry in the node
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
	struct ssdfs_dentries_btree_node_header *hdr;
	struct ssdfs_dir_entry dentry;
	size_t item_size = sizeof(struct ssdfs_dir_entry);
	u16 range_len;
	u16 old_name_len, name_len;
	bool name_was_inline, name_become_inline;
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

	err = ssdfs_dentries_btree_node_get_dentry(node, area, item_index,
						   &dentry);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get dentry: err %d\n", err);
		return err;
	}

	old_name_len = le16_to_cpu(dentry.name_len);

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
		err = ssdfs_dentries_btree_node_get_dentry(node,
							   &node->items_area,
							   item_index,
							   &dentry);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get dentry: err %d\n", err);
			goto finish_items_area_correction;
		}
		start_hash = le64_to_cpu(dentry.hash_code);
	}

	if ((item_index + range_len) == node->items_area.items_count) {
		err = ssdfs_dentries_btree_node_get_dentry(node,
						    &node->items_area,
						    item_index + range_len - 1,
						    &dentry);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get dentry: err %d\n", err);
			goto finish_items_area_correction;
		}
		end_hash = le64_to_cpu(dentry.hash_code);
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

	err = ssdfs_dentries_btree_node_get_dentry(node,
						&node->items_area,
						item_index,
						&dentry);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get dentry: err %d\n", err);
		goto finish_items_area_correction;
	}

	name_len = le16_to_cpu(dentry.name_len);

	name_was_inline = old_name_len <= SSDFS_DENTRY_INLINE_NAME_MAX_LEN;
	name_become_inline = name_len <= SSDFS_DENTRY_INLINE_NAME_MAX_LEN;

	hdr = &node->raw.dentries_header;

	if (!name_was_inline && name_become_inline) {
		/* increment number of inline names */
		le16_add_cpu(&hdr->inline_names, 1);
	} else if (name_was_inline && !name_become_inline) {
		/* decrement number of inline names */
		if (le16_to_cpu(hdr->inline_names) == 0) {
			err = -ERANGE;
			SSDFS_ERR("invalid number of inline names: %u\n",
				  le16_to_cpu(hdr->inline_names));
			goto finish_items_area_correction;
		} else
			le16_add_cpu(&hdr->inline_names, -1);
	}

finish_items_area_correction:
	up_write(&node->header_lock);

	if (unlikely(err))
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);

	return err;
}

/*
 * ssdfs_dentries_btree_node_change_item() - change item in the node
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
int ssdfs_dentries_btree_node_change_item(struct ssdfs_btree_node *node,
					  struct ssdfs_btree_search *search)
{
	size_t item_size = sizeof(struct ssdfs_dir_entry);
	struct ssdfs_btree_node_items_area items_area;
	u16 item_index;
	int direction;
	u16 range_len;
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

	err = ssdfs_change_item_only(node, &items_area, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change item: err %d\n",
			  err);
		goto unlock_items_range;
	}

	err = ssdfs_set_node_header_dirty(node, items_area.items_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set header dirty: err %d\n",
			  err);
		goto unlock_items_range;
	}

	err = ssdfs_set_dirty_items_range(node, items_area.items_capacity,
					  item_index, range_len);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set items range as dirty: "
			  "start %u, count %u, err %d\n",
			  item_index, range_len, err);
		goto unlock_items_range;
	}

unlock_items_range:
	ssdfs_unlock_items_range(node, item_index, range_len);

finish_change_item:
	up_read(&node->full_lock);

	ssdfs_debug_btree_node_object(node);

	return err;
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
	struct ssdfs_dentries_btree_node_header *hdr;
	size_t item_size = sizeof(struct ssdfs_dir_entry);
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

	down_write(&node->header_lock);

	hdr = &node->raw.dentries_header;
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
		hdr->dentries_count = cpu_to_le16(0);
		hdr->inline_names = cpu_to_le16(0);
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
 * __ssdfs_dentries_btree_node_delete_range() - delete range of items
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
int __ssdfs_dentries_btree_node_delete_range(struct ssdfs_btree_node *node,
					     struct ssdfs_btree_search *search)
{
	struct ssdfs_btree *tree;
	struct ssdfs_dentries_btree_info *dtree;
	struct ssdfs_dentries_btree_node_header *hdr;
	struct ssdfs_btree_node_items_area items_area;
	struct ssdfs_dir_entry dentry;
	size_t item_size = sizeof(struct ssdfs_dir_entry);
	int free_items;
	u16 item_index;
	int direction;
	u16 range_len;
	u16 locked_len = 0;
	u32 deleted_space, free_space;
	u64 start_hash, end_hash;
	u32 old_dentries_count = 0, dentries_count = 0;
	u32 dentries_diff;
	u16 deleted_inline_names = 0, inline_names = 0;
	int i;
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
	case SSDFS_DENTRIES_BTREE:
		/* expected btree type */
		break;

	default:
		SSDFS_ERR("invalid btree type %#x\n", tree->type);
		return -ERANGE;
	}

	dtree = container_of(tree, struct ssdfs_dentries_btree_info,
				buffer.tree);

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

	dentries_count = items_area.items_count;
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
			SSDFS_ERR("invalid dentries_count: "
				  "item_index %u, dentries_count %u, "
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

	for (i = 0; i < range_len; i++) {
		u16 name_len;

		err = ssdfs_dentries_btree_node_get_dentry(node,
							   &items_area,
							   (i + item_index),
							   &dentry);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get dentry: err %d\n", err);
			goto finish_delete_range;
		}

		name_len = le16_to_cpu(dentry.name_len);
		if (name_len <= SSDFS_DENTRY_INLINE_NAME_MAX_LEN)
			deleted_inline_names++;
	}

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
		goto finish_delete_range;
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
			goto finish_delete_range;

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
		goto finish_delete_range;

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
		goto finish_delete_range;
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
		err = ssdfs_dentries_btree_node_get_dentry(node,
						    &node->items_area,
						    0, &dentry);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get dentry: err %d\n", err);
			goto finish_items_area_correction;
		}
		start_hash = le64_to_cpu(dentry.hash_code);

		err = ssdfs_dentries_btree_node_get_dentry(node,
					&node->items_area,
					node->items_area.items_count - 1,
					&dentry);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get dentry: err %d\n", err);
			goto finish_items_area_correction;
		}
		end_hash = le64_to_cpu(dentry.hash_code);
	}

	node->items_area.start_hash = start_hash;
	node->items_area.end_hash = end_hash;

	if (node->items_area.items_count == 0)
		ssdfs_initialize_lookup_table(node);
	else {
		range_len = items_area.items_count - item_index;
		err = ssdfs_correct_lookup_table(node,
						 &node->items_area,
						 item_index, range_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to correct lookup table: "
				  "err %d\n", err);
			goto finish_items_area_correction;
		}

		err = ssdfs_clean_lookup_table(node,
						&node->items_area,
						node->items_area.items_count);
		if (unlikely(err)) {
			SSDFS_ERR("fail to clean the rest of lookup table: "
				  "start_index %u, err %d\n",
				  node->items_area.items_count, err);
			goto finish_items_area_correction;
		}
	}

	hdr = &node->raw.dentries_header;
	old_dentries_count = le16_to_cpu(hdr->dentries_count);

	if (node->items_area.items_count == 0) {
		hdr->dentries_count = cpu_to_le16(0);
		hdr->inline_names = cpu_to_le16(0);
	} else {
		if (old_dentries_count < search->request.count) {
			hdr->dentries_count = cpu_to_le16(0);
			hdr->inline_names = cpu_to_le16(0);
		} else {
			dentries_count = le16_to_cpu(hdr->dentries_count);
			dentries_count -= search->request.count;
			hdr->dentries_count = cpu_to_le16(dentries_count);

			inline_names = le16_to_cpu(hdr->inline_names);
			if (deleted_inline_names > inline_names) {
				err = -ERANGE;
				SSDFS_ERR("invalid inline names: "
					  "deleted_inline_names %u, "
					  "inline_names %u\n",
					  deleted_inline_names,
					  inline_names);
				goto finish_items_area_correction;
			}
			inline_names -= deleted_inline_names;
			hdr->inline_names = cpu_to_le16(inline_names);
		}
	}

	dentries_count = le16_to_cpu(hdr->dentries_count);
	dentries_diff = old_dentries_count - dentries_count;
	atomic64_sub(dentries_diff, &dtree->dentries_count);

	memcpy(&items_area, &node->items_area,
		sizeof(struct ssdfs_btree_node_items_area));

	err = ssdfs_set_node_header_dirty(node, items_area.items_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set header dirty: err %d\n",
			  err);
		goto finish_items_area_correction;
	}

	if (dentries_count != 0) {
		err = ssdfs_set_dirty_items_range(node,
					items_area.items_capacity,
					item_index,
					old_dentries_count - item_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set items range as dirty: "
				  "start %u, count %u, err %d\n",
				  item_index,
				  old_dentries_count - item_index,
				  err);
			goto finish_items_area_correction;
		}
	}

finish_items_area_correction:
	up_write(&node->header_lock);

	if (unlikely(err))
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);

finish_delete_range:
	ssdfs_unlock_items_range(node, item_index, locked_len);
	up_read(&node->full_lock);

	if (unlikely(err))
		return err;

	if (dentries_count == 0)
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

	ssdfs_debug_btree_node_object(node);

	return 0;
}

/*
 * ssdfs_dentries_btree_node_delete_item() - delete an item from node
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
int ssdfs_dentries_btree_node_delete_item(struct ssdfs_btree_node *node,
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

	err = __ssdfs_dentries_btree_node_delete_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete dentry: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_dentries_btree_node_delete_range() - delete range of items from node
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
int ssdfs_dentries_btree_node_delete_range(struct ssdfs_btree_node *node,
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

	err = __ssdfs_dentries_btree_node_delete_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete dentries range: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_dentries_btree_node_extract_range() - extract range of items from node
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
int ssdfs_dentries_btree_node_extract_range(struct ssdfs_btree_node *node,
					    u16 start_index, u16 count,
					    struct ssdfs_btree_search *search)
{
	struct ssdfs_dir_entry *dentry;
	int err;

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

	err = __ssdfs_btree_node_extract_range(node, start_index, count,
						sizeof(struct ssdfs_dir_entry),
						search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract a range: "
			  "start %u, count %u, err %d\n",
			  start_index, count, err);
		return err;
	}

	search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
	dentry = (struct ssdfs_dir_entry *)search->result.buf;
	search->request.start.hash = le64_to_cpu(dentry->hash_code);
	dentry += search->result.count - 1;
	search->request.end.hash = le64_to_cpu(dentry->hash_code);
	search->request.count = count;

	return 0;
}

/*
 * ssdfs_dentries_btree_resize_items_area() - resize items area of the node
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
int ssdfs_dentries_btree_resize_items_area(struct ssdfs_btree_node *node,
					   u32 new_size)
{
	struct ssdfs_fs_info *fsi;
	size_t item_size = sizeof(struct ssdfs_dir_entry);
	size_t index_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, new_size %u\n",
		  node->node_id, new_size);

	fsi = node->tree->fsi;
	index_size = le16_to_cpu(fsi->vh->dentries_btree.desc.index_size);

	return __ssdfs_btree_node_resize_items_area(node,
						    item_size,
						    index_size,
						    new_size);
}

void ssdfs_debug_dentries_btree_object(struct ssdfs_dentries_btree_info *tree)
{
#ifdef CONFIG_SSDFS_DEBUG
	int i;

	BUG_ON(!tree);

	SSDFS_DBG("DENTRIES TREE: type %#x, state %#x, "
		  "dentries_count %llu, is_locked %d, "
		  "generic_tree %p, inline_dentries %p, "
		  "root %p, owner %p, fsi %p\n",
		  atomic_read(&tree->type),
		  atomic_read(&tree->state),
		  (u64)atomic64_read(&tree->dentries_count),
		  rwsem_is_locked(&tree->lock),
		  tree->generic_tree,
		  tree->inline_dentries,
		  tree->root,
		  tree->owner,
		  tree->fsi);

	if (tree->generic_tree) {
		/* debug dump of generic tree */
		ssdfs_debug_btree_object(tree->generic_tree);
	}

	if (tree->inline_dentries) {
		for (i = 0; i < SSDFS_INLINE_DENTRIES_COUNT; i++) {
			struct ssdfs_dir_entry *dentry;

			dentry = &tree->inline_dentries[i];

			SSDFS_DBG("INLINE DENTRY: index %d, ino %llu, "
				  "hash_code %llx, name_len %u, "
				  "dentry_type %#x, file_type %#x, "
				  "flags %#x\n",
				  i,
				  le64_to_cpu(dentry->ino),
				  le64_to_cpu(dentry->hash_code),
				  dentry->name_len,
				  dentry->dentry_type,
				  dentry->file_type,
				  dentry->flags);

			SSDFS_DBG("RAW STRING DUMP: index %d\n",
				  i);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					    dentry->inline_string,
					    SSDFS_DENTRY_INLINE_NAME_MAX_LEN);
			SSDFS_DBG("\n");
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

const struct ssdfs_btree_descriptor_operations ssdfs_dentries_btree_desc_ops = {
	.init		= ssdfs_dentries_btree_desc_init,
	.flush		= ssdfs_dentries_btree_desc_flush,
};

const struct ssdfs_btree_operations ssdfs_dentries_btree_ops = {
	.create_root_node	= ssdfs_dentries_btree_create_root_node,
	.create_node		= ssdfs_dentries_btree_create_node,
	.init_node		= ssdfs_dentries_btree_init_node,
	.destroy_node		= ssdfs_dentries_btree_destroy_node,
	.add_node		= ssdfs_dentries_btree_add_node,
	.delete_node		= ssdfs_dentries_btree_delete_node,
	.pre_flush_root_node	= ssdfs_dentries_btree_pre_flush_root_node,
	.flush_root_node	= ssdfs_dentries_btree_flush_root_node,
	.pre_flush_node		= ssdfs_dentries_btree_pre_flush_node,
	.flush_node		= ssdfs_dentries_btree_flush_node,
};

const struct ssdfs_btree_node_operations ssdfs_dentries_btree_node_ops = {
	.find_item		= ssdfs_dentries_btree_node_find_item,
	.find_range		= ssdfs_dentries_btree_node_find_range,
	.extract_range		= ssdfs_dentries_btree_node_extract_range,
	.allocate_item		= ssdfs_dentries_btree_node_allocate_item,
	.allocate_range		= ssdfs_dentries_btree_node_allocate_range,
	.insert_item		= ssdfs_dentries_btree_node_insert_item,
	.insert_range		= ssdfs_dentries_btree_node_insert_range,
	.change_item		= ssdfs_dentries_btree_node_change_item,
	.delete_item		= ssdfs_dentries_btree_node_delete_item,
	.delete_range		= ssdfs_dentries_btree_node_delete_range,
	.resize_items_area	= ssdfs_dentries_btree_resize_items_area,
};
