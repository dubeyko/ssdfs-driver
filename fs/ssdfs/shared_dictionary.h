//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/shared_dictionary.h - shared dictionary btree declarations.
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

#ifndef _SSDFS_SHARED_DICTIONARY_TREE_H
#define _SSDFS_SHARED_DICTIONARY_TREE_H

/*
 * struct ssdfs_names_queue - names queue descriptor
 * @lock: names queue's lock
 * @list: names queue's list
 */
struct ssdfs_names_queue {
	spinlock_t lock;
	struct list_head list;
};

/*
 * struct ssdfs_name_descriptor - name descriptor
 * @hash: name hash
 * @len: name length
 * @str_buf: name string
 */
struct ssdfs_name_descriptor {
	u64 hash;
	size_t len;
	unsigned char str_buf[SSDFS_MAX_NAME_LEN];
};

/*
 * struct ssdfs_name_info - name info
 * @list: names queue list
 * @type: operation type
 * @desc.name: name descriptor
 * @index: node's index
 */
struct ssdfs_name_info {
	struct list_head list;
	int type;

	union {
		struct ssdfs_name_descriptor name;
		struct ssdfs_btree_index index;
	} desc;
};

/* Possible type of operations with name */
enum {
	SSDFS_NAME_UNKNOWN_OP,
	SSDFS_INIT_SHDICT_NODE,
	SSDFS_NAME_ADD,
	SSDFS_NAME_CHANGE,
	SSDFS_NAME_DELETE,
	SSDFS_NAME_OP_MAX
};

/*
 * struct ssdfs_name_requests_queue - name requests queue
 * @queue: name requests queue object
 * @thread: descriptor of queue's thread
 */
struct ssdfs_name_requests_queue {
	struct ssdfs_names_queue queue;
	struct ssdfs_thread_info thread;
};

/*
 * struct ssdfs_shared_dict_btree_info - shared dictionary btree info
 * @state: shared dictionary btree state
 * @lock: shared dictionary tree's lock
 * @generic_tree: generic btree description
 * @read_reqs: current count of read requests
 * @requests: name requests queue
 * @wait_queue: wait queue of shared dictionary tree's thread
 */
struct ssdfs_shared_dict_btree_info {
	atomic_t state;
	struct rw_semaphore lock;
	struct ssdfs_btree generic_tree;

	atomic_t read_reqs;

	struct ssdfs_name_requests_queue requests;
	wait_queue_head_t wait_queue;
};

/* Shared dictionary tree states */
enum {
	SSDFS_SHDICT_BTREE_UNKNOWN_STATE,
	SSDFS_SHDICT_BTREE_CREATED,
	SSDFS_SHDICT_BTREE_UNDER_INIT,
	SSDFS_SHDICT_BTREE_INITIALIZED,
	SSDFS_SHDICT_BTREE_CORRUPTED,
	SSDFS_SHDICT_BTREE_STATE_MAX
};

/*
 * Shared dictionary tree API
 */
int ssdfs_shared_dict_btree_create(struct ssdfs_fs_info *fsi);
int ssdfs_shared_dict_btree_init(struct ssdfs_fs_info *fsi);
void ssdfs_shared_dict_btree_destroy(struct ssdfs_fs_info *fsi);
int ssdfs_shared_dict_btree_flush(struct ssdfs_shared_dict_btree_info *tree);

int ssdfs_shared_dict_get_name(struct ssdfs_shared_dict_btree_info *tree,
				u64 hash,
				struct ssdfs_name_string *name);
int ssdfs_shared_dict_save_name(struct ssdfs_shared_dict_btree_info *tree,
				u64 hash,
				const struct qstr *str);

/*
 * Shared dictionary tree internal API
 */
int ssdfs_shared_dict_tree_find(struct ssdfs_shared_dict_btree_info *tree,
				u64 name_hash,
				struct ssdfs_btree_search *search);
int ssdfs_shared_dict_tree_add(struct ssdfs_shared_dict_btree_info *tree,
				u64 name_hash,
				const char *name, size_t len,
				struct ssdfs_btree_search *search);

int ssdfs_shared_dict_start_thread(struct ssdfs_shared_dict_btree_info *tree);
int ssdfs_shared_dict_stop_thread(struct ssdfs_shared_dict_btree_info *tree);

/*
 * Name info's API
 */
int ssdfs_init_name_info_cache(void);
void ssdfs_destroy_name_info_cache(void);
struct ssdfs_name_info *ssdfs_name_info_alloc(void);
void ssdfs_name_info_free(struct ssdfs_name_info *ni);
void ssdfs_name_info_init(int type, u64 hash,
			  const unsigned char *str,
			  const size_t len,
			  struct ssdfs_name_info *ni);
void ssdfs_node_index_init(int type, struct ssdfs_btree_index *index,
			   struct ssdfs_name_info *ni);

/*
 * Names queue API
 */
void ssdfs_names_queue_init(struct ssdfs_names_queue *nq);
bool is_ssdfs_names_queue_empty(struct ssdfs_names_queue *nq);
bool has_queue_unprocessed_names(struct ssdfs_shared_dict_btree_info *tree);
void ssdfs_names_queue_add_tail(struct ssdfs_names_queue *nq,
				struct ssdfs_name_info *ni);
void ssdfs_names_queue_add_head(struct ssdfs_names_queue *nq,
				struct ssdfs_name_info *ni);
int ssdfs_names_queue_remove_first(struct ssdfs_names_queue *nq,
				   struct ssdfs_name_info **ni);
void ssdfs_names_queue_remove_all(struct ssdfs_names_queue *nq);

void ssdfs_debug_shdict_btree_object(struct ssdfs_shared_dict_btree_info *tree);

/*
 * Shared dictionary btree specialized operations
 */
extern const struct ssdfs_btree_descriptor_operations
					ssdfs_shared_dict_btree_desc_ops;
extern const struct ssdfs_btree_operations
					ssdfs_shared_dict_btree_ops;
extern const struct ssdfs_btree_node_operations
					ssdfs_shared_dict_btree_node_ops;

#endif /* _SSDFS_SHARED_DICTIONARY_TREE_H */
