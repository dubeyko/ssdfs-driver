//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dentries_tree.h - dentries btree declarations.
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

#ifndef _SSDFS_DENTRIES_TREE_H
#define _SSDFS_DENTRIES_TREE_H

/*
 * struct ssdfs_dentries_btree_info - dentries btree info
 * @type: dentries btree type
 * @state: dentries btree state
 * @dentries_count: count of the dentries in the whole dentries tree
 * @lock: dentries btree lock
 * @generic_tree: pointer on generic btree object
 * @inline_dentries: pointer on inline dentries array
 * @buffer.tree: piece of memory for generic btree object
 * @buffer.dentries: piece of memory for the inline dentries
 * @root: pointer on root node
 * @root_buffer: buffer for root node
 * @desc: b-tree descriptor
 * @owner: pointer on owner inode object
 * @fsi: pointer on shared file system object
 *
 * A newly created inode tries to store dentries into inline
 * dentries. The raw on-disk inode has internal private area
 * that is able to contain the four inline dentries or
 * root node of extents btree and extended attributes btree.
 * If inode hasn't extended attributes and the amount of dentries
 * are lesser than four then everithing can be stored inside of
 * inline dentries. Otherwise, the real dentries btree should
 * be created.
 */
struct ssdfs_dentries_btree_info {
	atomic_t type;
	atomic_t state;
	atomic64_t dentries_count;

	struct rw_semaphore lock;
	struct ssdfs_btree *generic_tree;
	struct ssdfs_dir_entry *inline_dentries;
	union {
		struct ssdfs_btree tree;
#define SSDFS_INLINE_DENTRIES_COUNT	(2 * SSDFS_INLINE_DENTRIES_PER_AREA)
		struct ssdfs_dir_entry dentries[SSDFS_INLINE_DENTRIES_COUNT];
	} buffer;
	struct ssdfs_btree_inline_root_node *root;
	struct ssdfs_btree_inline_root_node root_buffer;

	struct ssdfs_dentries_btree_descriptor desc;
	struct ssdfs_inode_info *owner;
	struct ssdfs_fs_info *fsi;
};

/* Dentries tree types */
enum {
	SSDFS_DENTRIES_BTREE_UNKNOWN_TYPE,
	SSDFS_INLINE_DENTRIES_ARRAY,
	SSDFS_PRIVATE_DENTRIES_BTREE,
	SSDFS_DENTRIES_BTREE_TYPE_MAX
};

/* Dentries tree states */
enum {
	SSDFS_DENTRIES_BTREE_UNKNOWN_STATE,
	SSDFS_DENTRIES_BTREE_CREATED,
	SSDFS_DENTRIES_BTREE_INITIALIZED,
	SSDFS_DENTRIES_BTREE_DIRTY,
	SSDFS_DENTRIES_BTREE_CORRUPTED,
	SSDFS_DENTRIES_BTREE_STATE_MAX
};

/*
 * Dentries tree API
 */
int ssdfs_dentries_tree_create(struct ssdfs_fs_info *fsi,
				struct ssdfs_inode_info *ii);
int ssdfs_dentries_tree_init(struct ssdfs_fs_info *fsi,
			     struct ssdfs_inode_info *ii);
void ssdfs_dentries_tree_destroy(struct ssdfs_inode_info *ii);
int ssdfs_dentries_tree_flush(struct ssdfs_fs_info *fsi,
				struct ssdfs_inode_info *ii);

int ssdfs_dentries_tree_find(struct ssdfs_dentries_btree_info *tree,
			     const char *name, size_t len,
			     struct ssdfs_btree_search *search);
int ssdfs_dentries_tree_add(struct ssdfs_dentries_btree_info *tree,
			    const struct qstr *str,
			    struct ssdfs_inode_info *ii,
			    struct ssdfs_btree_search *search);
int ssdfs_dentries_tree_change(struct ssdfs_dentries_btree_info *tree,
				u64 name_hash, ino_t old_ino,
				const struct qstr *str,
				struct ssdfs_inode_info *new_ii,
				struct ssdfs_btree_search *search);
int ssdfs_dentries_tree_delete(struct ssdfs_dentries_btree_info *tree,
				u64 name_hash, ino_t ino,
				struct ssdfs_btree_search *search);
int ssdfs_dentries_tree_delete_all(struct ssdfs_dentries_btree_info *tree);

/*
 * Internal dentries tree API
 */
u64 __ssdfs_generate_name_hash(const char *name, size_t len);
u64 ssdfs_generate_name_hash(const struct qstr *str);
int ssdfs_dentries_tree_find_leaf_node(struct ssdfs_dentries_btree_info *tree,
					u64 name_hash,
					struct ssdfs_btree_search *search);
int ssdfs_dentries_tree_extract_range(struct ssdfs_dentries_btree_info *tree,
				      u16 start_index, u16 count,
				      struct ssdfs_btree_search *search);

void ssdfs_debug_dentries_btree_object(struct ssdfs_dentries_btree_info *tree);

/*
 * Dentries btree specialized operations
 */
extern const struct ssdfs_btree_descriptor_operations
						ssdfs_dentries_btree_desc_ops;
extern const struct ssdfs_btree_operations ssdfs_dentries_btree_ops;
extern const struct ssdfs_btree_node_operations ssdfs_dentries_btree_node_ops;

#endif /* _SSDFS_DENTRIES_TREE_H */
