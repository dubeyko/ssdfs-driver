// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/shared_dictionary.c - shared dictionary btree implementation.
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

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_dict_page_leaks;
atomic64_t ssdfs_dict_folio_leaks;
atomic64_t ssdfs_dict_memory_leaks;
atomic64_t ssdfs_dict_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_dict_cache_leaks_increment(void *kaddr)
 * void ssdfs_dict_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_dict_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_dict_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_dict_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_dict_kfree(void *kaddr)
 * struct page *ssdfs_dict_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_dict_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_dict_free_page(struct page *page)
 * void ssdfs_dict_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(dict)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(dict)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_dict_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_dict_page_leaks, 0);
	atomic64_set(&ssdfs_dict_folio_leaks, 0);
	atomic64_set(&ssdfs_dict_memory_leaks, 0);
	atomic64_set(&ssdfs_dict_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_dict_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_dict_page_leaks) != 0) {
		SSDFS_ERR("SHARED DICTIONARY: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_dict_page_leaks));
	}

	if (atomic64_read(&ssdfs_dict_folio_leaks) != 0) {
		SSDFS_ERR("SHARED DICTIONARY: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_dict_folio_leaks));
	}

	if (atomic64_read(&ssdfs_dict_memory_leaks) != 0) {
		SSDFS_ERR("SHARED DICTIONARY: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_dict_memory_leaks));
	}

	if (atomic64_read(&ssdfs_dict_cache_leaks) != 0) {
		SSDFS_ERR("SHARED DICTIONARY: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_dict_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/******************************************************************************
 *                         NAME INFO FUNCTIONALITY                            *
 ******************************************************************************/

static struct kmem_cache *ssdfs_name_info_cachep;

void ssdfs_zero_name_info_cache_ptr(void)
{
	ssdfs_name_info_cachep = NULL;
}

static
void ssdfs_init_name_info_once(void *obj)
{
	struct ssdfs_name_info *ni_obj = obj;

	memset(ni_obj, 0, sizeof(struct ssdfs_name_info));
}

void ssdfs_destroy_name_info_cache(void)
{
	if (ssdfs_name_info_cachep)
		kmem_cache_destroy(ssdfs_name_info_cachep);
}

int ssdfs_init_name_info_cache(void)
{
	ssdfs_name_info_cachep = kmem_cache_create("ssdfs_name_info_cache",
					sizeof(struct ssdfs_name_info), 0,
					SLAB_RECLAIM_ACCOUNT |
					SLAB_MEM_SPREAD |
					SLAB_ACCOUNT,
					ssdfs_init_name_info_once);
	if (!ssdfs_name_info_cachep) {
		SSDFS_ERR("unable to create name info objects cache\n");
		return -ENOMEM;
	}

	return 0;
}

/*
 * ssdfs_name_info_alloc() - allocate memory for name info object
 */
struct ssdfs_name_info *ssdfs_name_info_alloc(void)
{
	struct ssdfs_name_info *ptr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_name_info_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr = kmem_cache_alloc(ssdfs_name_info_cachep, GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate memory for name\n");
		return ERR_PTR(-ENOMEM);
	}

	return ptr;
}

/*
 * ssdfs_name_info_free() - free memory for name info object
 */
void ssdfs_name_info_free(struct ssdfs_name_info *ni)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_name_info_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!ni)
		return;

	kmem_cache_free(ssdfs_name_info_cachep, ni);
}

/*
 * ssdfs_name_info_init() - name info initialization
 * @type: operation type
 * @hash: name hash
 * @str: name string
 * @len: name length
 * @ni: name info [out]
 */
void ssdfs_name_info_init(int type, u64 hash,
			  const unsigned char *str,
			  const size_t len,
			  struct ssdfs_name_info *ni)
{
	size_t copy_len;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!str || !ni);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(ni, 0, sizeof(struct ssdfs_name_info));

	INIT_LIST_HEAD(&ni->list);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(type <= SSDFS_INIT_SHDICT_NODE ||
		type >= SSDFS_NAME_OP_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	ni->type = type;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(hash >= U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	ni->desc.name.hash = hash;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(len > SSDFS_MAX_NAME_LEN);
#endif /* CONFIG_SSDFS_DEBUG */
	copy_len = min_t(size_t, len, SSDFS_MAX_NAME_LEN);
	ni->desc.name.len = copy_len;

	ssdfs_memcpy(ni->desc.name.str_buf, 0, SSDFS_MAX_NAME_LEN,
		     str, 0, len,
		     copy_len);
}

/*
 * ssdfs_node_index_init() - node init info initialization
 * @type: operation type
 * @hash: name hash
 * @str: name string
 * @len: name length
 * @ni: name info [out]
 */
void ssdfs_node_index_init(int type, struct ssdfs_btree_index *index,
			   struct ssdfs_name_info *ni)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!index || !ni);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(ni, 0, sizeof(struct ssdfs_name_info));

	INIT_LIST_HEAD(&ni->list);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(type != SSDFS_INIT_SHDICT_NODE);
#endif /* CONFIG_SSDFS_DEBUG */
	ni->type = type;

	ssdfs_memcpy(&ni->desc.index,
		     0, sizeof(struct ssdfs_btree_index),
		     index, 0, sizeof(struct ssdfs_btree_index),
		     sizeof(struct ssdfs_btree_index));
}

/******************************************************************************
 *                         NAMES QUEUE FUNCTIONALITY                          *
 ******************************************************************************/

/*
 * ssdfs_names_queue_init() - initialize names queue
 * @nq: initialized names queue
 */
void ssdfs_names_queue_init(struct ssdfs_names_queue *nq)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!nq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock_init(&nq->lock);
	INIT_LIST_HEAD(&nq->list);
}

/*
 * is_ssdfs_names_queue_empty() - check that names queue is empty
 * @nq: names queue
 */
bool is_ssdfs_names_queue_empty(struct ssdfs_names_queue *nq)
{
	bool is_empty;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!nq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&nq->lock);
	is_empty = list_empty_careful(&nq->list);
	spin_unlock(&nq->lock);

	return is_empty;
}

/*
 * ssdfs_names_queue_add_head() - add name at the head of queue
 * @nq: names queue
 * @ni: name info
 */
void ssdfs_names_queue_add_head(struct ssdfs_names_queue *nq,
				struct ssdfs_name_info *ni)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!nq || !ni);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&nq->lock);
	list_add(&ni->list, &nq->list);
	spin_unlock(&nq->lock);
}

/*
 * ssdfs_names_queue_add_tail() - add name at the tail of queue
 * @nq: names queue
 * @ni: name info
 */
void ssdfs_names_queue_add_tail(struct ssdfs_names_queue *nq,
				struct ssdfs_name_info *ni)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!nq || !ni);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&nq->lock);
	list_add_tail(&ni->list, &nq->list);
	spin_unlock(&nq->lock);
}

/*
 * ssdfs_names_queue_remove_first() - get name and remove from queue
 * @nq: names queue
 * @ni: first name [out]
 *
 * This function get first name in @nq, remove it from queue
 * and return as @ni.
 *
 * RETURN:
 * [success] - @ni contains pointer on name.
 * [failure] - error code:
 *
 * %-ENODATA     - queue is empty.
 * %-ENOENT      - first entry is NULL.
 */
int ssdfs_names_queue_remove_first(struct ssdfs_names_queue *nq,
				   struct ssdfs_name_info **ni)
{
	bool is_empty;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!nq || !ni);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&nq->lock);
	is_empty = list_empty_careful(&nq->list);
	if (!is_empty) {
		*ni = list_first_entry_or_null(&nq->list,
						struct ssdfs_name_info,
						list);
		if (!*ni) {
			SSDFS_WARN("first entry is NULL\n");
			err = -ENOENT;
		} else
			list_del(&(*ni)->list);
	}
	spin_unlock(&nq->lock);

	if (is_empty) {
		SSDFS_DBG("names queue is empty\n");
		err = -ENODATA;
	}

	return err;
}

/*
 * ssdfs_names_queue_remove_all() - remove all names from queue
 * @nq: names queue
 *
 * This function removes all names from the queue.
 */
void ssdfs_names_queue_remove_all(struct ssdfs_names_queue *nq)
{
	bool is_empty;
	LIST_HEAD(tmp_list);
	struct list_head *this, *next;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!nq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&nq->lock);
	is_empty = list_empty_careful(&nq->list);
	if (!is_empty)
		list_replace_init(&nq->list, &tmp_list);
	spin_unlock(&nq->lock);

	if (is_empty)
		return;

	list_for_each_safe(this, next, &tmp_list) {
		struct ssdfs_name_info *ni;

		ni = list_entry(this, struct ssdfs_name_info, list);
		list_del(&ni->list);

		switch (ni->type) {
		case SSDFS_NAME_ADD:
		case SSDFS_NAME_CHANGE:
		case SSDFS_NAME_DELETE:
			SSDFS_WARN("delete name: "
				   "op_type %#x, hash %llx, len %zu\n",
				   ni->type,
				   ni->desc.name.hash,
				   ni->desc.name.len);
			break;

		default:
			SSDFS_WARN("invalid name operation type %#x\n",
				   ni->type);
			break;
		}
	}
}

/******************************************************************************
 *                SHARED DICTIONARY TREE OBJECT FUNCTIONALITY                 *
 ******************************************************************************/

/*
 * ssdfs_shared_dict_btree_create() - create shared dictionary btree
 * @fsi: pointer on shared file system object
 *
 * This method tries to create shared dictionary btree object.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
int ssdfs_shared_dict_btree_create(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_shared_dict_btree_info *ptr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("fsi %p\n", fsi);
#else
	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi->shdictree = NULL;

	ptr = ssdfs_dict_kzalloc(sizeof(struct ssdfs_shared_dict_btree_info),
				 GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate shared dictionary tree\n");
		return -ENOMEM;
	}

	atomic_set(&ptr->state, SSDFS_SHDICT_BTREE_UNKNOWN_STATE);

	err = ssdfs_btree_create(fsi,
				 SSDFS_SHARED_DICT_BTREE_INO,
				 &ssdfs_shared_dict_btree_desc_ops,
				 &ssdfs_shared_dict_btree_ops,
				 &ptr->generic_tree);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create shared dictionary tree: err %d\n",
			  err);
		goto fail_create_shared_dict_tree;
	}

	init_rwsem(&ptr->lock);
	atomic_set(&ptr->read_reqs, 0);
	init_waitqueue_head(&ptr->wait_queue);
	ssdfs_names_queue_init(&ptr->requests.queue);

	err = ssdfs_shared_dict_start_thread(ptr);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		goto destroy_shared_dict_object;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to start shared dictionary tree's thread: "
			  "err %d\n", err);
		goto destroy_shared_dict_object;
	}

	atomic_set(&ptr->state, SSDFS_SHDICT_BTREE_CREATED);

	ssdfs_debug_shdict_btree_object(ptr);

	fsi->shdictree = ptr;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("DONE: create shared dictionary\n");
#else
	SSDFS_DBG("DONE: create shared dictionary\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;

destroy_shared_dict_object:
	ssdfs_btree_destroy(&ptr->generic_tree);

fail_create_shared_dict_tree:
	ssdfs_dict_kfree(ptr);
	return err;
}

/*
 * ssdfs_shared_dict_btree_destroy - destroy shared dictionary btree
 * @fsi: file system info object
 */
void ssdfs_shared_dict_btree_destroy(struct ssdfs_fs_info *fsi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("shdictree %p\n", fsi->shdictree);
#else
	SSDFS_DBG("shdictree %p\n", fsi->shdictree);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (!fsi->shdictree)
		return;

	ssdfs_names_queue_remove_all(&fsi->shdictree->requests.queue);

	ssdfs_btree_destroy(&fsi->shdictree->generic_tree);
	ssdfs_dict_kfree(fsi->shdictree);
	fsi->shdictree = NULL;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */
}

/*
 * ssdfs_shared_dict_btree_init - prepare shared dictionary btree init
 * @fsi: file system info object
 */
int ssdfs_shared_dict_btree_init(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_shared_dict_btree_info *tree;
	struct ssdfs_btree_inline_root_node root_node;
	struct ssdfs_name_info *ni;
	u8 items_count;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("shdictree %p\n", fsi->shdictree);
#else
	SSDFS_DBG("shdictree %p\n", fsi->shdictree);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (!fsi->shdictree)
		return -ERANGE;

	tree = fsi->shdictree;

	switch (atomic_read(&tree->state)) {
	case SSDFS_SHDICT_BTREE_CREATED:
		atomic_set(&tree->state, SSDFS_SHDICT_BTREE_UNDER_INIT);
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid tree's state %#x\n",
			  atomic_read(&tree->state));
		goto finish_init;
	}

	ssdfs_memcpy(&root_node,
		     0, sizeof(struct ssdfs_btree_inline_root_node),
		     &fsi->vs->shared_dict_btree.root_node,
		     0, sizeof(struct ssdfs_btree_inline_root_node),
		     sizeof(struct ssdfs_btree_inline_root_node));

	tree->generic_tree.create_cno = 0;
	items_count = root_node.header.items_count;

	if (items_count == 0) {
		err = 0;
		atomic_set(&tree->state, SSDFS_SHDICT_BTREE_INITIALIZED);
		goto finish_init;
	} else if (items_count > SSDFS_BTREE_ROOT_NODE_INDEX_COUNT) {
		err = -EFAULT;
		SSDFS_WARN("btree's header is corrupted\n");
		atomic_set(&tree->state, SSDFS_SHDICT_BTREE_CORRUPTED);
		goto finish_init;
	}

	for (i = 0; i < items_count; i++) {
		ni = ssdfs_name_info_alloc();
		if (IS_ERR_OR_NULL(ni)) {
			err = !ni ? -ENOMEM : PTR_ERR(ni);
			SSDFS_ERR("fail to allocate name info: "
				  "err %d\n", err);
			goto finish_init;
		}

		ssdfs_node_index_init(SSDFS_INIT_SHDICT_NODE,
					&root_node.indexes[i], ni);
		ssdfs_names_queue_add_tail(&tree->requests.queue, ni);
	}

finish_init:
	ssdfs_debug_shdict_btree_object(tree);
	wake_up_all(&tree->wait_queue);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_shared_dict_read_req_inc() - increase number of read requests
 * @tree: pointer on shared dictionary btree object
 */
static inline
void ssdfs_shared_dict_read_req_inc(struct ssdfs_shared_dict_btree_info *tree)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	atomic_inc(&tree->read_reqs);
}

/*
 * ssdfs_shared_dict_read_req_dec() - decrease number of read requests
 * @tree: pointer on shared dictionary btree object
 */
static inline
void ssdfs_shared_dict_read_req_dec(struct ssdfs_shared_dict_btree_info *tree)
{
	int read_reqs;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	read_reqs = atomic_dec_return(&tree->read_reqs);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(read_reqs < 0);
#endif /* CONFIG_SSDFS_DEBUG */

	if (read_reqs == 0)
		wake_up_all(&tree->wait_queue);
}

/*
 * ssdfs_shared_dict_btree_flush() - flush dirty shared dictionary btree
 * @tree: pointer on shared dictionary btree object
 *
 * This method tries to flush the dirty inodes btree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_shared_dict_btree_flush(struct ssdfs_shared_dict_btree_info *tree)
{
	struct ssdfs_name_requests_queue *ptr;
	struct ssdfs_btree_search *search;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p\n", tree);
#else
	SSDFS_DBG("tree %p\n", tree);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (atomic_read(&tree->state) == SSDFS_SHDICT_BTREE_CORRUPTED) {
		SSDFS_WARN("shared dictionary is corrupted\n");
		return -ERANGE;
	}

	ptr = &tree->requests;

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	down_write(&tree->lock);

	while (has_queue_unprocessed_names(tree)) {
		struct ssdfs_name_info *ni = NULL;

		err = ssdfs_names_queue_remove_first(&ptr->queue, &ni);
		if (err == -ENODATA) {
			err = 0;
			goto try_to_flush;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get name: err %d\n", err);
			goto finish_flush;
		} else if (ni == NULL) {
			err = -ERANGE;
			SSDFS_ERR("invalid name info\n");
			goto finish_flush;
		}

		switch (ni->type) {
		case SSDFS_NAME_ADD:
			ssdfs_btree_search_init(search);

			err = ssdfs_shared_dict_tree_add(tree,
							 ni->desc.name.hash,
							 ni->desc.name.str_buf,
							 ni->desc.name.len,
							 search);
			if (err == -EEXIST) {
				/* name exist -> do nothing */
				err = 0;
				ssdfs_name_info_free(ni);
				continue;
			} else if (unlikely(err)) {
				ssdfs_fs_error(tree->generic_tree.fsi->sb,
						__FILE__, __func__, __LINE__,
						"fail to add name: "
						"hash %llx, name %s, len %zu, "
						"err %d\n",
						ni->desc.name.hash,
						ni->desc.name.str_buf,
						ni->desc.name.len,
						err);
				ssdfs_name_info_free(ni);
				goto finish_flush;
			} else
				ssdfs_name_info_free(ni);
			break;

		case SSDFS_NAME_CHANGE:
		case SSDFS_NAME_DELETE:
			SSDFS_ERR("unsupported operation: "
				  "type %#x, hash %llx, len %zu\n",
				  ni->type, ni->desc.name.hash,
				  ni->desc.name.len);
			ssdfs_name_info_free(ni);
			break;

		default:
			SSDFS_ERR("invalid operation type: "
				  "type %#x, hash %llx, len %zu\n",
				  ni->type, ni->desc.name.hash,
				  ni->desc.name.len);
			ssdfs_name_info_free(ni);
			break;
		};
	};

try_to_flush:
	err = ssdfs_btree_flush(&tree->generic_tree);
	if (unlikely(err)) {
		SSDFS_ERR("fail to flush shared dictionary btree: "
			  "err %d\n", err);
	}

finish_flush:
	up_write(&tree->lock);

	ssdfs_btree_search_free(search);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_shared_dict_get_name() - get name from dictionary
 * @tree: shared dictionary tree
 * @hash: name hash
 * @name: name buffer
 *
 * This method tries to retrieve the name from shared dictionary.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENODATA    - name doesn't exist in dictionary.
 */
int ssdfs_shared_dict_get_name(struct ssdfs_shared_dict_btree_info *tree,
				u64 hash,
				struct ssdfs_name_string *name)
{
	struct ssdfs_btree_search *search;
	bool is_second_try = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !name);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, hash %llx\n",
		  tree, hash);
#else
	SSDFS_DBG("tree %p, hash %llx\n",
		  tree, hash);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

try_check_state:
	switch (atomic_read(&tree->state)) {
	case SSDFS_SHDICT_BTREE_CREATED:
	case SSDFS_SHDICT_BTREE_INITIALIZED:
		/* tree is ready for operations */
		break;

	case SSDFS_SHDICT_BTREE_UNDER_INIT:
		if (is_second_try) {
			SSDFS_ERR("second try to wait the init ending\n");
			return -ERANGE;
		} else {
			DEFINE_WAIT(wait);

			prepare_to_wait(&tree->wait_queue, &wait,
					TASK_UNINTERRUPTIBLE);
			schedule();
			finish_wait(&tree->wait_queue, &wait);
		}

		is_second_try = true;
		goto try_check_state;

	case SSDFS_SHDICT_BTREE_CORRUPTED:
		SSDFS_WARN("tree is corrupted\n");
		return -EFAULT;

	default:
		SSDFS_ERR("invalid tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	}

	memset(name, 0, sizeof(struct ssdfs_name_string));

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);

	ssdfs_shared_dict_read_req_inc(tree);
	down_read(&tree->lock);
	err = ssdfs_shared_dict_tree_find(tree, hash, search);
	up_read(&tree->lock);
	ssdfs_shared_dict_read_req_dec(tree);

	if (err == -ENODATA) {
		/* name doesn't exist in dictionary */
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find the name: hash %llx\n", hash);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_get_name;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find the name: hash %llx, err %d\n",
			  hash, err);
		goto finish_get_name;
	}

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		/* expected state */
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid result state %#x\n",
			  search->result.state);
		goto finish_get_name;
	}

	if (unlikely(search->result.err)) {
		err = search->result.err;
		SSDFS_ERR("result has error %d\n",
			  search->result.err);
		goto finish_get_name;
	}

	if (search->result.name_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		err = -ERANGE;
		SSDFS_ERR("unsupported buffer state %#x\n",
			  search->result.name_state);
		goto finish_get_name;
	}

	if (search->result.names_in_buffer != 1) {
		err = -ERANGE;
		SSDFS_ERR("unexpected names_in_buffer %u\n",
			  search->result.names_in_buffer);
		goto finish_get_name;
	}

	if (!search->result.name) {
		err = -ERANGE;
		SSDFS_ERR("empty name buffer\n");
		goto finish_get_name;
	}

	if (hash != search->result.name->hash) {
		err = -ERANGE;
		SSDFS_ERR("hash1 %llu != hash2 %llu\n",
			  hash,
			  search->result.name->hash);
		goto finish_get_name;
	}

	if (search->result.name->len == 0 ||
	    search->result.name->len > SSDFS_MAX_NAME_LEN) {
		err = -ERANGE;
		SSDFS_ERR("invalid name length %zu\n",
			  search->result.name->len);
		goto finish_get_name;
	}

	ssdfs_memcpy(name, 0, sizeof(struct ssdfs_name_string),
		     search->result.name, 0, sizeof(struct ssdfs_name_string),
		     sizeof(struct ssdfs_name_string));

finish_get_name:
	ssdfs_btree_search_free(search);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_shared_dict_save_name() - add name into queue
 * @tree: shared dictionary tree
 * @hash: name hash
 * @str: name string
 *
 * This method tries to add name into requests queue.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
int ssdfs_shared_dict_save_name(struct ssdfs_shared_dict_btree_info *tree,
				u64 hash,
				const struct qstr *str)
{
	struct ssdfs_btree_search *search = NULL;
	struct ssdfs_name_info *ni = NULL;
	bool is_second_try = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !str);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("hash %llx, name %s, len %u\n",
		  hash, str->name, str->len);
#else
	SSDFS_DBG("hash %llx, name %s, len %u\n",
		  hash, str->name, str->len);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

try_check_state:
	switch (atomic_read(&tree->state)) {
	case SSDFS_SHDICT_BTREE_CREATED:
	case SSDFS_SHDICT_BTREE_INITIALIZED:
		/* tree is ready for operations */
		break;

	case SSDFS_SHDICT_BTREE_UNDER_INIT:
		if (is_second_try) {
			SSDFS_ERR("second try to wait the init ending\n");
			return -ERANGE;
		} else {
			DEFINE_WAIT(wait);

			prepare_to_wait(&tree->wait_queue, &wait,
					TASK_UNINTERRUPTIBLE);
			schedule();
			finish_wait(&tree->wait_queue, &wait);
		}

		is_second_try = true;
		goto try_check_state;

	case SSDFS_SHDICT_BTREE_CORRUPTED:
		SSDFS_WARN("tree is corrupted\n");
		return -EFAULT;

	default:
		SSDFS_ERR("invalid tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	}

	if (hash >= U64_MAX) {
		SSDFS_ERR("invalid hash\n");
		return -EINVAL;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto finish_save_name;
	}

	ni = ssdfs_name_info_alloc();
	if (IS_ERR_OR_NULL(ni)) {
		err = !ni ? -ENOMEM : PTR_ERR(ni);
		SSDFS_ERR("fail to allocate name info: "
			  "err %d\n", err);
		goto finish_save_name;
	}

	ssdfs_btree_search_init(search);
	ssdfs_name_info_init(SSDFS_NAME_ADD, hash, str->name, str->len, ni);

	down_write(&tree->lock);
	err = ssdfs_shared_dict_tree_add(tree,
					 ni->desc.name.hash,
					 ni->desc.name.str_buf,
					 ni->desc.name.len,
					 search);
	up_write(&tree->lock);

	if (err == -EEXIST) {
		/* name exist -> do nothing */
		err = 0;
		goto finish_save_name;
	} else if (unlikely(err)) {
		ssdfs_fs_error(tree->generic_tree.fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to add name: "
				"hash %llx, name %s, len %zu, "
				"err %d\n",
				ni->desc.name.hash,
				ni->desc.name.str_buf,
				ni->desc.name.len,
				err);
		goto finish_save_name;
	}

finish_save_name:
	if (ni)
		ssdfs_name_info_free(ni);
	if (search)
		ssdfs_btree_search_free(search);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/******************************************************************************
 *               SHARED DICTIONARY TREE OBJECT FUNCTIONALITY                  *
 ******************************************************************************/

/*
 * need_initialize_shared_dict_btree_search() - check necessity to init
 * @name_hash: name hash
 * @search: search object
 */
static inline
bool need_initialize_shared_dict_btree_search(u64 name_hash,
					      struct ssdfs_btree_search *search)
{
	return need_initialize_btree_search(search) ||
		search->request.start.hash != name_hash;
}

/*
 * ssdfs_shared_dict_tree_find() - find a name in the tree
 * @tree: shared diction tree
 * @name_hash: name hash
 * @search: search object
 *
 * This method tries to find a name for the requested @name_hash.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - item hasn't been found
 */
int ssdfs_shared_dict_tree_find(struct ssdfs_shared_dict_btree_info *tree,
				u64 name_hash,
				struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);

	SSDFS_DBG("tree %p, hash %llx, search %p\n",
		  tree, name_hash, search);
#endif /* CONFIG_SSDFS_DEBUG */

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (name_hash == U64_MAX) {
		SSDFS_ERR("invalid name hash\n");
		return -ERANGE;
	}

	if (need_initialize_shared_dict_btree_search(name_hash, search)) {
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

	return ssdfs_btree_find_item(&tree->generic_tree, search);
}

/*
 * ssdfs_shared_dict_tree_add() - add the name into the tree
 * @tree: shared dictionary tree
 * @name_hash: name hash
 * @name: name string
 * @len: length of the string
 * @search: search object
 *
 * This method tries to add the name into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - name exists in the tree.
 */
int ssdfs_shared_dict_tree_add(struct ssdfs_shared_dict_btree_info *tree,
				u64 name_hash,
				const char *name, size_t len,
				struct ssdfs_btree_search *search)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !name || !search);

	SSDFS_DBG("tree %p, hash %llx, name %s, len %zu, search %p\n",
		  tree, name_hash, name, len, search);
#endif /* CONFIG_SSDFS_DEBUG */

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (name_hash >= U64_MAX) {
		SSDFS_ERR("invalid name hash\n");
		return -ERANGE;
	}

	if (need_initialize_shared_dict_btree_search(name_hash, search)) {
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
	} else {
		search->request.flags =
				SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
				SSDFS_BTREE_SEARCH_HAS_VALID_COUNT |
				SSDFS_BTREE_SEARCH_HAS_VALID_NAME;
	}

	err = ssdfs_btree_find_item(&tree->generic_tree, search);
	if (err == -ENODATA) {
		/*
		 * Name doesn't exist in the tree.
		 */
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find the name: "
			  "name_hash %llx, err %d\n",
			  name_hash, err);
		return err;
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("name exists in the tree: "
			  "hash %llx, name %s, len %zu\n",
			  name_hash, name, len);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EEXIST;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("DEBUG SEARCH RESULT NAME:\n");
	ssdfs_debug_btree_search_result_name(search);
	SSDFS_DBG("END DEBUG OUTPUT\n");
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
	case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
	case SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE:
	case SSDFS_BTREE_SEARCH_OBSOLETE_RESULT:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	search->request.type = SSDFS_BTREE_SEARCH_ADD_ITEM;
	err = ssdfs_btree_add_item(&tree->generic_tree, search);

	ssdfs_btree_search_forget_parent_node(search);
	ssdfs_btree_search_forget_child_node(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to add the name into the tree: "
			  "err %d\n", err);
		return err;
	}

	return 0;
}

/******************************************************************************
 *        SPECIALIZED SHARED DICTIONARY BTREE DESCRIPTOR OPERATIONS           *
 ******************************************************************************/

/*
 * ssdfs_shared_dict_btree_desc_init() - specialized btree descriptor init
 * @fsi: pointer on shared file system object
 * @tree: pointer on shared dictionary btree object
 */
static
int ssdfs_shared_dict_btree_desc_init(struct ssdfs_fs_info *fsi,
					struct ssdfs_btree *tree)
{
	struct ssdfs_btree_descriptor *desc;
	u32 erasesize;
	u32 node_size;
	u16 item_size;
	u32 index_area_min_size = SSDFS_MAX_NAME_LEN + 1;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !tree);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));

	SSDFS_DBG("fsi %p, tree %p\n",
		  fsi, tree);
#endif /* CONFIG_SSDFS_DEBUG */

	erasesize = fsi->erasesize;

	desc = &fsi->vs->shared_dict_btree.desc;

	if (le32_to_cpu(desc->magic) != SSDFS_SHARED_DICT_BTREE_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid magic %#x\n",
			  le32_to_cpu(desc->magic));
		goto finish_btree_desc_init;
	}

	/* TODO: check flags */

	if (desc->type != SSDFS_SHARED_DICTIONARY_BTREE) {
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

	if (item_size != SSDFS_MAX_NAME_LEN) {
		err = -EIO;
		SSDFS_ERR("invalid item size %u\n",
			  item_size);
		goto finish_btree_desc_init;
	}

	if (le16_to_cpu(desc->index_area_min_size) != index_area_min_size) {
		err = -EIO;
		SSDFS_ERR("invalid index_area_min_size %u\n",
			  le16_to_cpu(desc->index_area_min_size));
		goto finish_btree_desc_init;
	}

	err = ssdfs_btree_desc_init(fsi, tree, desc,
				    (u8)SSDFS_DENTRY_INLINE_NAME_MAX_LEN,
				    SSDFS_MAX_NAME_LEN);

finish_btree_desc_init:
	if (unlikely(err)) {
		SSDFS_ERR("fail to init btree descriptor: err %d\n",
			  err);
	}

	return err;
}

/*
 * ssdfs_shared_dict_btree_desc_flush() - specialized btree's descriptor flush
 * @tree: pointer on shared dictionary btree object
 */
static
int ssdfs_shared_dict_btree_desc_flush(struct ssdfs_btree *tree)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_descriptor desc;
	u32 erasesize;
	u32 node_size;
	u32 index_area_min_size = SSDFS_MAX_NAME_LEN + 1;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi);

	SSDFS_DBG("owner_ino %llu, type %#x, state %#x\n",
		  tree->owner_ino, tree->type,
		  atomic_read(&tree->state));

	BUG_ON(!rwsem_is_locked(&tree->fsi->volume_sem));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = tree->fsi;

	memset(&desc, 0xFF, sizeof(struct ssdfs_btree_descriptor));

	desc.magic = cpu_to_le32(SSDFS_SHARED_DICT_BTREE_MAGIC);
	desc.item_size = cpu_to_le16(SSDFS_MAX_NAME_LEN);

	err = ssdfs_btree_desc_flush(tree, &desc);
	if (unlikely(err)) {
		SSDFS_ERR("invalid btree descriptor: err %d\n",
			  err);
		return err;
	}

	if (desc.type != SSDFS_SHARED_DICTIONARY_BTREE) {
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

	if (le16_to_cpu(desc.index_area_min_size) != index_area_min_size) {
		SSDFS_ERR("invalid index_area_min_size %u\n",
			  le16_to_cpu(desc.index_area_min_size));
		return -ERANGE;
	}

	ssdfs_memcpy(&fsi->vs->shared_dict_btree.desc,
		     0, sizeof(struct ssdfs_btree_descriptor),
		     &desc,
		     0, sizeof(struct ssdfs_btree_descriptor),
		     sizeof(struct ssdfs_btree_descriptor));

	return 0;
}

/******************************************************************************
 *             SPECIALIZED SHARED DICTIONARY BTREE OPERATIONS                 *
 ******************************************************************************/

/*
 * ssdfs_shared_dict_btree_create_root_node() - specialized root node creation
 * @fsi: pointer on shared file system object
 * @node: pointer on node object [out]
 */
static
int ssdfs_shared_dict_btree_create_root_node(struct ssdfs_fs_info *fsi,
					     struct ssdfs_btree_node *node)
{
	struct ssdfs_btree_inline_root_node *root_node;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->vs || !node);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));

	SSDFS_DBG("fsi %p, node %p\n",
		  fsi, node);
#endif /* CONFIG_SSDFS_DEBUG */

	root_node = &fsi->vs->shared_dict_btree.root_node;
	err = ssdfs_btree_create_root_node(node, root_node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create root node: err %d\n",
			  err);
	}

	return err;
}

/*
 * ssdfs_shared_dict_btree_pre_flush_root_node() - root node pre-flush
 * @node: pointer on node object
 */
static
int ssdfs_shared_dict_btree_pre_flush_root_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_state_bitmap *bmap;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_INITIALIZED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is clean\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
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

	if (tree->type != SSDFS_SHARED_DICTIONARY_BTREE) {
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
 * ssdfs_shared_dict_btree_flush_root_node() - specialized root node flush
 * @node: pointer on node object
 */
static
int ssdfs_shared_dict_btree_flush_root_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree_inline_root_node *root_node;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);
	BUG_ON(!rwsem_is_locked(&node->tree->fsi->volume_sem));

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_ssdfs_btree_node_dirty(node)) {
		SSDFS_WARN("node %u is not dirty\n",
			   node->node_id);
		return 0;
	}

	root_node = &node->tree->fsi->vs->shared_dict_btree.root_node;
	ssdfs_btree_flush_root_node(node, root_node);

	return 0;
}

/*
 * ssdfs_shared_dict_btree_create_node() - specialized node creation
 * @node: pointer on node object
 */
static
int ssdfs_shared_dict_btree_create_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	void *addr[SSDFS_BTREE_NODE_BMAP_COUNT];
	size_t hdr_size = sizeof(struct ssdfs_shared_dictionary_node_header);
	size_t ltbl2_item_size = sizeof(struct ssdfs_shdict_ltbl2_item);
	size_t htbl_item_size = sizeof(struct ssdfs_shdict_htbl_item);
	u32 node_size;
	u32 items_area_size = 0;
	u16 item_size = 0;
	u16 index_size = 0;
	u16 index_area_min_size;
	u16 items_capacity = 0;
	u16 index_capacity = 0;
	u32 index_area_size = 0;
	size_t bmap_bytes;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);
	WARN_ON(atomic_read(&node->state) != SSDFS_BTREE_NODE_CREATED);

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

	tree = node->tree;
	node_size = tree->node_size;
	index_area_min_size = tree->index_area_min_size;

	node->node_ops = &ssdfs_shared_dict_btree_node_ops;

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_INDEX_NODE:
		switch (atomic_read(&node->index_area.state)) {
		case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid index area's state %#x\n",
				  atomic_read(&node->items_area.state));
			return -ERANGE;
		}

		switch (atomic_read(&node->items_area.state)) {
		case SSDFS_BTREE_NODE_AREA_ABSENT:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid items area's state %#x\n",
				  atomic_read(&node->items_area.state));
			return -ERANGE;
		}
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		switch (atomic_read(&node->index_area.state)) {
		case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid index area's state %#x\n",
				  atomic_read(&node->items_area.state));
			return -ERANGE;
		}

		switch (atomic_read(&node->items_area.state)) {
		case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid items area's state %#x\n",
				  atomic_read(&node->items_area.state));
			return -ERANGE;
		}
		break;

	case SSDFS_BTREE_LEAF_NODE:
		switch (atomic_read(&node->index_area.state)) {
		case SSDFS_BTREE_NODE_AREA_ABSENT:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid index area's state %#x\n",
				  atomic_read(&node->items_area.state));
			return -ERANGE;
		}

		switch (atomic_read(&node->items_area.state)) {
		case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid items area's state %#x\n",
				  atomic_read(&node->items_area.state));
			return -ERANGE;
		}
		break;

	default:
		SSDFS_WARN("invalid node type %#x\n",
			   atomic_read(&node->type));
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
		node->bmap_array.item_start_bit =
			node->bmap_array.index_start_bit + index_capacity;
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

		atomic_set(&node->lookup_tbl_area.state,
			   SSDFS_BTREE_NODE_LOOKUP_TBL_EXIST);
		atomic_or(SSDFS_BTREE_NODE_HAS_L2TBL, &node->flags);
		atomic_or(SSDFS_BTREE_NODE_HAS_L1TBL, &node->flags);
		node->lookup_tbl_area.offset = node->node_size;
		node->lookup_tbl_area.index_size = ltbl2_item_size;

		atomic_set(&node->hash_tbl_area.state,
			   SSDFS_BTREE_NODE_HASH_TBL_EXIST);
		atomic_or(SSDFS_BTREE_NODE_HAS_HASH_TBL, &node->flags);
		node->hash_tbl_area.offset = node->node_size;
		node->hash_tbl_area.index_size = htbl_item_size;

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
		atomic_set(&node->lookup_tbl_area.state,
			   SSDFS_BTREE_NODE_LOOKUP_TBL_EXIST);
		atomic_or(SSDFS_BTREE_NODE_HAS_L2TBL, &node->flags);
		atomic_or(SSDFS_BTREE_NODE_HAS_L1TBL, &node->flags);
		node->lookup_tbl_area.offset = node->node_size;
		node->lookup_tbl_area.index_size = ltbl2_item_size;

		atomic_set(&node->hash_tbl_area.state,
			   SSDFS_BTREE_NODE_HASH_TBL_EXIST);
		atomic_or(SSDFS_BTREE_NODE_HAS_HASH_TBL, &node->flags);
		node->hash_tbl_area.offset = node->node_size;
		node->hash_tbl_area.index_size = htbl_item_size;

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

	if (bmap_bytes == 0 || bmap_bytes > SSDFS_SHARED_DICT_BMAP_SIZE) {
		err = -EIO;
		SSDFS_ERR("invalid bmap_bytes %zu\n",
			  bmap_bytes);
		goto finish_create_node;
	}

	node->bmap_array.bmap_bytes = bmap_bytes;

finish_create_node:
	up_write(&node->bmap_array.lock);
	up_write(&node->header_lock);

	if (unlikely(err))
		return err;

	err = ssdfs_btree_node_allocate_bmaps(addr, bmap_bytes);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate node's bitmaps: "
			  "bmap_bytes %zu, err %d\n",
			  bmap_bytes, err);
		return err;
	}

	down_write(&node->bmap_array.lock);
	for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
		spin_lock(&node->bmap_array.bmap[i].lock);
		node->bmap_array.bmap[i].ptr = addr[i];
		addr[i] = NULL;
		spin_unlock(&node->bmap_array.bmap[i].lock);
	}
	up_write(&node->bmap_array.lock);

	err = ssdfs_btree_node_allocate_content_space(node, node_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate content space: "
			  "node_size %u, err %d\n",
			  node_size, err);
		return err;
	}

	ssdfs_debug_btree_node_object(node);

	return err;
}

/*
 * ssdfs_init_lookup_table_hash_range() - extract hash range of lookup table
 * @node: node object
 * @area_offset: offset of the area in bytes
 * @area_size: size of the area in bytes
 * @desc_count: count of descriptors in the area
 * @start_hash: starting hash of lookup table [out]
 * @end_hash: ending hash of lookup table [out]
 *
 * This method tries to extract start and end hash from
 * the raw lookup table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_init_lookup_table_hash_range(struct ssdfs_btree_node *node,
					u16 area_offset, u16 area_size,
					u16 desc_count,
					u64 *start_hash, u64 *end_hash)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_shdict_ltbl2_item *ptr;
	struct ssdfs_smart_folio folio;
	void *kaddr;
	size_t desc_size = sizeof(struct ssdfs_shdict_ltbl2_item);
	u16 position;
	u32 hash32_lo;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);
	BUG_ON(!start_hash || !end_hash);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, height %u\n",
		  node->node_id,
		  atomic_read(&node->height));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	*start_hash = U64_MAX;
	*end_hash = U64_MAX;

	if (desc_count == 0)
		return 0;

	position = 0;

	err = __ssdfs_define_memory_folio(fsi, area_offset, area_size,
					  node->node_size, desc_size,
					  position,
					  &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define folio index: err %d\n",
			  err);
		return err;
	}

	if ((folio.desc.offset_inside_page + desc_size) > PAGE_SIZE) {
		SSDFS_ERR("invalid offset into the page: "
			  "offset %u, desc_size %zu\n",
			  folio.desc.offset_inside_page, desc_size);
		return -ERANGE;
	}

	if (folio.desc.folio_index >= folio_batch_count(&node->content.batch)) {
		SSDFS_ERR("invalid page index: "
			  "folio_index %u, folio_batch_count %u\n",
			  folio.desc.folio_index,
			  folio_batch_count(&node->content.batch));
		return -ERANGE;
	}

	folio.ptr = node->content.batch.folios[folio.desc.folio_index];
	kaddr = kmap_local_folio(folio.ptr, folio.desc.page_in_folio);
	ptr = (struct ssdfs_shdict_ltbl2_item *)((u8 *)kaddr +
						folio.desc.offset_inside_page);
	hash32_lo = le32_to_cpu(ptr->hash_lo);
	*start_hash = SSDFS_NAME_HASH(hash32_lo, 0);
	kunmap_local(kaddr);

	position = desc_count - 1;

	if (position == 0) {
		*end_hash = *start_hash;
		return 0;
	}

	err = __ssdfs_define_memory_folio(fsi, area_offset, area_size,
					  node->node_size, desc_size,
					  position,
					  &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define folio index: err %d\n",
			  err);
		return err;
	}

	if ((folio.desc.offset_inside_page + desc_size) > PAGE_SIZE) {
		SSDFS_ERR("invalid offset into the page: "
			  "offset %u, desc_size %zu\n",
			  folio.desc.offset_inside_page, desc_size);
		return -ERANGE;
	}

	if (folio.desc.folio_index >= folio_batch_count(&node->content.batch)) {
		SSDFS_ERR("invalid page index: "
			  "folio_index %u, folio_batch_count %u\n",
			  folio.desc.folio_index,
			  folio_batch_count(&node->content.batch));
		return -ERANGE;
	}

	folio.ptr = node->content.batch.folios[folio.desc.folio_index];
	kaddr = kmap_local_folio(folio.ptr, folio.desc.page_in_folio);
	ptr = (struct ssdfs_shdict_ltbl2_item *)((u8 *)kaddr +
						folio.desc.offset_inside_page);
	hash32_lo = le32_to_cpu(ptr->hash_lo);
	*end_hash = SSDFS_NAME_HASH(hash32_lo, 0);
	kunmap_local(kaddr);

	return 0;
}

/*
 * ssdfs_init_hash_table_range() - extract hash range of hash table
 * @node: node object
 * @area_offset: offset of the area in bytes
 * @area_size: size of the area in bytes
 * @desc_count: count of descriptors in the area
 * @start_hash: starting hash of hash table [out]
 * @end_hash: ending hash of hash table [out]
 *
 * This method tries to extract start and end hash from
 * the raw hash table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_init_hash_table_range(struct ssdfs_btree_node *node,
				u16 area_offset, u16 area_size,
				u16 desc_count,
				u64 *start_hash, u64 *end_hash)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_shdict_htbl_item *ptr;
	struct ssdfs_smart_folio folio;
	void *kaddr;
	size_t desc_size = sizeof(struct ssdfs_shdict_htbl_item);
	u16 position;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);
	BUG_ON(!start_hash || !end_hash);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, height %u\n",
		  node->node_id,
		  atomic_read(&node->height));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	*start_hash = U64_MAX;
	*end_hash = U64_MAX;

	if (desc_count == 0)
		return 0;

	position = 0;

	err = __ssdfs_define_memory_folio(fsi, area_offset, area_size,
					  node->node_size, desc_size,
					  position,
					  &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define folio index: err %d\n",
			  err);
		return err;
	}

	if ((folio.desc.offset_inside_page + desc_size) > PAGE_SIZE) {
		SSDFS_ERR("invalid offset into the page: "
			  "offset %u, desc_size %zu\n",
			  folio.desc.offset_inside_page, desc_size);
		return -ERANGE;
	}

	if (folio.desc.folio_index >= folio_batch_count(&node->content.batch)) {
		SSDFS_ERR("invalid page index: "
			  "folio_index %u, folio_batch_count %u\n",
			  folio.desc.folio_index,
			  folio_batch_count(&node->content.batch));
		return -ERANGE;
	}

	folio.ptr = node->content.batch.folios[folio.desc.folio_index];
	kaddr = kmap_local_folio(folio.ptr, folio.desc.page_in_folio);
	ptr = (struct ssdfs_shdict_htbl_item *)((u8 *)kaddr +
						folio.desc.offset_inside_page);
	*start_hash = SSDFS_NAME_HASH(0, le32_to_cpu(ptr->hash_hi));
	kunmap_local(kaddr);

	position = desc_count - 1;

	if (position == 0) {
		*end_hash = *start_hash;
		return 0;
	}

	err = __ssdfs_define_memory_folio(fsi, area_offset, area_size,
					  node->node_size, desc_size,
					  position,
					  &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define folio index: err %d\n",
			  err);
		return err;
	}

	if ((folio.desc.offset_inside_page + desc_size) > PAGE_SIZE) {
		SSDFS_ERR("invalid offset into the page: "
			  "offset %u, desc_size %zu\n",
			  folio.desc.offset_inside_page, desc_size);
		return -ERANGE;
	}

	if (folio.desc.folio_index >= folio_batch_count(&node->content.batch)) {
		SSDFS_ERR("invalid page index: "
			  "folio_index %u, folio_batch_count %u\n",
			  folio.desc.folio_index,
			  folio_batch_count(&node->content.batch));
		return -ERANGE;
	}

	folio.ptr = node->content.batch.folios[folio.desc.folio_index];
	kaddr = kmap_local_folio(folio.ptr, folio.desc.page_in_folio);
	ptr = (struct ssdfs_shdict_htbl_item *)((u8 *)kaddr +
						folio.desc.offset_inside_page);
	*end_hash = SSDFS_NAME_HASH(0, le32_to_cpu(ptr->hash_hi));
	kunmap_local(kaddr);

	return 0;
}

/*
 * ssdfs_shared_dict_init_lookup_table_area() - init lookup table
 * @node: node object
 * @hdr: node's header
 *
 * This method tries to init the lookup table's area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - header is corrupted.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_shared_dict_init_lookup_table_area(struct ssdfs_btree_node *node,
				struct ssdfs_shared_dictionary_node_header *hdr)
{
	u16 flags;
	u16 area_offset;
	u16 area_size;
	size_t desc_size = sizeof(struct ssdfs_shdict_ltbl2_item);
	u16 desc_capacity;
	u16 free_space;
	u16 items_count;
	u64 start_hash = U64_MAX;
	u64 end_hash = U64_MAX;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !hdr);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, height %u\n",
		  node->node_id,
		  atomic_read(&node->height));
#endif /* CONFIG_SSDFS_DEBUG */

	flags = le16_to_cpu(hdr->node.flags);

	if (flags & SSDFS_BTREE_NODE_HAS_L2TBL) {
		area_offset = le16_to_cpu(hdr->lookup_table2.offset);
		area_size = le16_to_cpu(hdr->lookup_table2.size);
		free_space = le16_to_cpu(hdr->lookup_table2.free_space);
		items_count = le16_to_cpu(hdr->lookup_table2.items_count);

		if (area_size % desc_size) {
			SSDFS_ERR("corrupted lookup table: "
				  "area_size %u, desc_size %zu\n",
				  area_size, desc_size);
			return -EIO;
		}

		if (area_size != ((items_count * desc_size) + free_space)) {
			SSDFS_ERR("invalid area descriptor: "
				  "area_size %u, items_count %u, "
				  "desc_size %zu, free_space %u\n",
				  area_size, items_count,
				  desc_size, free_space);
			return -EIO;
		}

		desc_capacity = area_size / desc_size;

		atomic_set(&node->lookup_tbl_area.state,
				SSDFS_BTREE_NODE_LOOKUP_TBL_EXIST);
		atomic_or(SSDFS_BTREE_NODE_HAS_L1TBL, &node->flags);
		atomic_or(SSDFS_BTREE_NODE_HAS_L2TBL, &node->flags);
		node->lookup_tbl_area.offset = area_offset;
		node->lookup_tbl_area.area_size = area_size;
		node->lookup_tbl_area.index_size = desc_size;
		node->lookup_tbl_area.index_count = items_count;
		node->lookup_tbl_area.index_capacity = desc_capacity;

		err = ssdfs_init_lookup_table_hash_range(node, area_offset,
							 area_size, items_count,
							 &start_hash,
							 &end_hash);
		if (unlikely(err)) {
			SSDFS_ERR("fail to retrieve hash range: "
				  "err %d\n",
				  err);
			return err;
		}

		node->lookup_tbl_area.start_hash = start_hash;
		node->lookup_tbl_area.end_hash = end_hash;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("flags %#x, items_count %u\n",
		  flags, node->lookup_tbl_area.index_count);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_shared_dict_init_hash_table_area() - init hash table
 * @node: node object
 * @hdr: node's header
 *
 * This method tries to init the hash table's area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - header is corrupted.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_shared_dict_init_hash_table_area(struct ssdfs_btree_node *node,
				struct ssdfs_shared_dictionary_node_header *hdr)
{
	u16 flags;
	u16 area_offset;
	u16 area_size;
	size_t desc_size = sizeof(struct ssdfs_shdict_htbl_item);
	u16 desc_capacity;
	u16 free_space;
	u16 items_count;
	u64 start_hash = U64_MAX;
	u64 end_hash = U64_MAX;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !hdr);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, height %u\n",
		  node->node_id,
		  atomic_read(&node->height));
#endif /* CONFIG_SSDFS_DEBUG */

	flags = le16_to_cpu(hdr->node.flags);

	if (flags & SSDFS_BTREE_NODE_HAS_HASH_TBL) {
		area_offset = le16_to_cpu(hdr->hash_table.offset);
		area_size = le16_to_cpu(hdr->hash_table.size);
		free_space = le16_to_cpu(hdr->hash_table.free_space);
		items_count = le16_to_cpu(hdr->hash_table.items_count);

		if (area_size % desc_size) {
			SSDFS_ERR("corrupted lookup table: "
				  "area_size %u, desc_size %zu\n",
				  area_size, desc_size);
			return -EIO;
		}

		if (area_size != ((items_count * desc_size) + free_space)) {
			SSDFS_ERR("invalid area descriptor: "
				  "area_size %u, items_count %u, "
				  "desc_size %zu, free_space %u\n",
				  area_size, items_count,
				  desc_size, free_space);
			return -EIO;
		}

		desc_capacity = area_size / desc_size;

		atomic_set(&node->hash_tbl_area.state,
				SSDFS_BTREE_NODE_HASH_TBL_EXIST);
		atomic_or(SSDFS_BTREE_NODE_HAS_HASH_TBL, &node->flags);
		node->hash_tbl_area.offset = area_offset;
		node->hash_tbl_area.area_size = area_size;
		node->hash_tbl_area.index_size = desc_size;
		node->hash_tbl_area.index_count = items_count;
		node->hash_tbl_area.index_capacity = desc_capacity;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("offset %u, area_size %u, desc_size %zu, "
			  "index_count %u, index_capacity %u\n",
			  area_offset, area_size, desc_size,
			  items_count, desc_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_init_hash_table_range(node, area_offset,
						  area_size, items_count,
						  &start_hash,
						  &end_hash);
		if (unlikely(err)) {
			SSDFS_ERR("fail to retrieve hash range: "
				  "err %d\n",
				  err);
			return err;
		}

		node->hash_tbl_area.start_hash = start_hash;
		node->hash_tbl_area.end_hash = end_hash;
	}

	return 0;
}

/*
 * ssdfs_shared_dict_btree_init_node() - init shared dictionary tree's node
 * @node: pointer on node object
 *
 * This method tries to init the node of shared dictionary btree.
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
int ssdfs_shared_dict_btree_init_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_shared_dict_btree_info *tree_info = NULL;
	struct ssdfs_shared_dictionary_node_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_shared_dictionary_node_header);
	void *addr[SSDFS_BTREE_NODE_BMAP_COUNT];
	struct folio *folio;
	void *kaddr;
	u64 start_hash, end_hash;
	u32 node_size;
	u8 min_item_size;
	u16 max_item_size;
	u16 items_capacity;
	u16 free_space;
	u16 str_area_offset;
	u16 str_area_bytes;
	u16 hash_tbl_offset;
	u16 hash_tbl_size;
	u16 lookup_tbl2_offset;
	u16 lookup_tbl2_size;
	u32 calculated_used_space;
	u16 strings_count;
	u16 flags;
	u8 index_size;
	u32 index_area_size = 0;
	u16 index_capacity = 0;
	size_t bmap_bytes;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (tree->type != SSDFS_SHARED_DICTIONARY_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_shared_dict_btree_info,
					 generic_tree);
	}

	if (atomic_read(&node->state) != SSDFS_BTREE_NODE_CONTENT_PREPARED) {
		SSDFS_WARN("fail to init node: id %u, state %#x\n",
			   node->node_id, atomic_read(&node->state));
		return -ERANGE;
	}

	down_read(&node->full_lock);

	if (folio_batch_count(&node->content.batch) == 0) {
		err = -ERANGE;
		SSDFS_ERR("empty node's content: id %u\n",
			  node->node_id);
		goto finish_init_node;
	}

	folio = node->content.batch.folios[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	kaddr = kmap_local_folio(folio, 0);

	hdr = (struct ssdfs_shared_dictionary_node_header *)kaddr;

	if (!is_csum_valid(&hdr->node.check, hdr, hdr_size)) {
		err = -EIO;
		SSDFS_ERR("invalid checksum: node_id %u\n",
			  node->node_id);
		goto finish_init_operation;
	}

	if (le32_to_cpu(hdr->node.magic.common) != SSDFS_SUPER_MAGIC ||
	    le16_to_cpu(hdr->node.magic.key) != SSDFS_DICTIONARY_BNODE_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid magic: common %#x, key %#x\n",
			  le32_to_cpu(hdr->node.magic.common),
			  le16_to_cpu(hdr->node.magic.key));
		goto finish_init_operation;
	}

	down_write(&node->header_lock);

	ssdfs_memcpy(&node->raw.dict_header, 0, hdr_size,
		     hdr, 0, hdr_size,
		     hdr_size);

	err = ssdfs_btree_init_node(node, &hdr->node,
				    hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init node: id %u, err %d\n",
			  node->node_id, err);
		goto finish_header_init;
	}

	start_hash = le64_to_cpu(hdr->node.start_hash);
	end_hash = le64_to_cpu(hdr->node.end_hash);
	node_size = 1 << hdr->node.log_node_size;
	index_size = hdr->node.index_size;
	min_item_size = hdr->node.min_item_size;
	max_item_size = le16_to_cpu(hdr->node.max_item_size);
	items_capacity = le16_to_cpu(hdr->node.items_capacity);
	strings_count = le16_to_cpu(hdr->str_area.items_count);
	free_space = le16_to_cpu(hdr->str_area.free_space);
	str_area_offset = le16_to_cpu(hdr->str_area.offset);
	str_area_bytes = le16_to_cpu(hdr->str_area.size);
	hash_tbl_offset = le16_to_cpu(hdr->hash_table.offset);
	hash_tbl_size = le16_to_cpu(hdr->hash_table.size);
	lookup_tbl2_offset = le16_to_cpu(hdr->lookup_table2.offset);
	lookup_tbl2_size = le16_to_cpu(hdr->lookup_table2.size);

	if (start_hash >= U64_MAX || end_hash >= U64_MAX) {
		err = -EIO;
		SSDFS_ERR("invalid hash range: "
			  "start_hash %llx, end_hash %llx\n",
			  start_hash, end_hash);
		goto finish_header_init;
	}

	if (min_item_size != SSDFS_DENTRY_INLINE_NAME_MAX_LEN ||
	    max_item_size != SSDFS_MAX_NAME_LEN) {
		err = -EIO;
		SSDFS_ERR("invalid item_size: "
			  "min_item_size %u, max_item_size %u\n",
			  min_item_size, max_item_size);
		goto finish_header_init;
	}

	if (items_capacity == 0 ||
	    items_capacity > (node_size / min_item_size)) {
		err = -EIO;
		SSDFS_ERR("invalid items_capacity %u\n",
			  items_capacity);
		goto finish_header_init;
	}

	if (strings_count > items_capacity) {
		err = -EIO;
		SSDFS_ERR("strings_count %u > items_capacity %u\n",
			  strings_count, items_capacity);
		goto finish_header_init;
	}

	if (hdr->node.log_index_area_size > 0)
		index_area_size = 1 << hdr->node.log_index_area_size;

	calculated_used_space = hdr_size + index_area_size;
	calculated_used_space += lookup_tbl2_size;
	calculated_used_space += hash_tbl_size;
	calculated_used_space += str_area_bytes;

	if (node_size != calculated_used_space) {
		err = -EIO;
		SSDFS_ERR("corrupted node: free_space %u, "
			  "node_size %u, calculated_used_space %u\n",
			  free_space, node_size,
			  calculated_used_space);
		goto finish_header_init;
	}

	if (free_space > str_area_bytes) {
		err = -EIO;
		SSDFS_ERR("free_space %u, str_area_bytes %u\n",
			  free_space, str_area_bytes);
		goto finish_header_init;
	}

	if (str_area_offset != (hdr_size + index_area_size)) {
		err = -EIO;
		SSDFS_ERR("corrupted strings area: "
			  "str_area_offset %u, hdr_size %zu, "
			  "index_area_size %u\n",
			  str_area_offset,
			  hdr_size,
			  index_area_size);
		goto finish_header_init;
	}

	if (hash_tbl_offset != (str_area_offset + str_area_bytes)) {
		err = -EIO;
		SSDFS_ERR("corrupted hash table: "
			  "hash_tbl_offset %u, str_area_offset %u, "
			  "str_area_bytes %u\n",
			  hash_tbl_offset,
			  str_area_offset,
			  str_area_bytes);
		goto finish_header_init;
	}

	if (lookup_tbl2_offset != (hash_tbl_offset + hash_tbl_size)) {
		err = -EIO;
		SSDFS_ERR("corrupted lookup table: "
			  "lookup_tbl2_offset %u, hash_tbl_offset %u, "
			  "hash_tbl_size %u\n",
			  lookup_tbl2_offset,
			  hash_tbl_offset,
			  hash_tbl_size);
		goto finish_header_init;
	}

	err = ssdfs_shared_dict_init_lookup_table_area(node, hdr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init lookup table: err %d\n",
			  err);
		goto finish_header_init;
	}

	err = ssdfs_shared_dict_init_hash_table_area(node, hdr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init hash table: err %d\n",
			  err);
		goto finish_header_init;
	}

	node->items_area.offset = str_area_offset;
	node->items_area.area_size = str_area_bytes;
	node->items_area.free_space = free_space;
	node->items_area.min_item_size = min_item_size;
	node->items_area.max_item_size = max_item_size;
	node->items_area.items_count = strings_count;
	node->items_area.items_capacity = items_capacity;

finish_header_init:
	up_write(&node->header_lock);

	if (unlikely(err))
		goto finish_init_operation;

	if (min_item_size > 0)
		items_capacity = node_size / min_item_size;
	else
		items_capacity = 0;

	if (index_size > 0)
		index_capacity = node_size / index_size;
	else
		index_capacity = 0;

	bmap_bytes = index_capacity + items_capacity + 1;
	bmap_bytes += BITS_PER_LONG;
	bmap_bytes /= BITS_PER_BYTE;

	if (bmap_bytes == 0 || bmap_bytes > SSDFS_SHARED_DICT_BMAP_SIZE) {
		err = -EIO;
		SSDFS_ERR("invalid bmap_bytes %zu\n",
			  bmap_bytes);
		goto finish_init_operation;
	}

	err = ssdfs_btree_node_allocate_bmaps(addr, bmap_bytes);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate node's bitmaps: "
			  "bmap_bytes %zu, err %d\n",
			  bmap_bytes, err);
		goto finish_init_operation;
	}

	down_write(&node->bmap_array.lock);

	flags = atomic_read(&node->flags);
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

	ssdfs_btree_node_init_bmaps(node, addr);

	spin_lock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);
	bitmap_set(node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].ptr,
		   0, strings_count);
	spin_unlock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);

	up_write(&node->bmap_array.lock);
finish_init_operation:
	kunmap_local(kaddr);

	if (unlikely(err))
		goto finish_init_node;

finish_init_node:
	up_read(&node->full_lock);

	ssdfs_debug_btree_node_object(node);

	return err;
}

static
void ssdfs_shared_dict_btree_destroy_node(struct ssdfs_btree_node *node)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("operation is unavailable\n");
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * ssdfs_shared_dict_btree_add_node() - add node into shared dictionary
 * @node: pointer on node object
 *
 * This method tries to finish addition of node into shared dictionary.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_shared_dict_btree_add_node(struct ssdfs_btree_node *node)
{
	int type;
	u16 items_capacity = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

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
		node->raw.dict_header.str_area.items_count = cpu_to_le16(0);
		node->raw.dict_header.str_area.free_space =
				cpu_to_le16((u16)node->items_area.area_size);

		node->raw.dict_header.hash_table.offset = cpu_to_le16(U16_MAX);
		node->raw.dict_header.hash_table.size = cpu_to_le16(0);
		node->raw.dict_header.hash_table.free_space = cpu_to_le16(0);
		node->raw.dict_header.hash_table.items_count = cpu_to_le16(0);

		node->raw.dict_header.lookup_table2.offset =
						cpu_to_le16(U16_MAX);
		node->raw.dict_header.lookup_table2.size =
							cpu_to_le16(0);
		node->raw.dict_header.lookup_table2.free_space =
							cpu_to_le16(0);
		node->raw.dict_header.lookup_table2.items_count =
							cpu_to_le16(0);

		node->raw.dict_header.lookup_table1_items =
							cpu_to_le16(0);

		memset(node->raw.dict_header.lookup_table1, 0xFF,
			sizeof(struct ssdfs_shdict_ltbl1_item) *
			SSDFS_SHDIC_LTBL1_SIZE);
	}

finish_add_node:
	up_write(&node->header_lock);

	if (err)
		return err;

	err = ssdfs_btree_update_parent_node_pointer(node->tree, node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to update parent pointer: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	ssdfs_debug_btree_node_object(node);

	return 0;
}


static
int ssdfs_shared_dict_btree_delete_node(struct ssdfs_btree_node *node)
{
#ifdef CONFIG_SSDFS_DEBUG
	/* TODO: implement */
	SSDFS_DBG("TODO: implement\n");
#endif /* CONFIG_SSDFS_DEBUG */
	return 0;


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
 * ssdfs_mark_hash_table_dirty() - mark the hash table as dirty
 * @node: node object
 */
static inline
void ssdfs_mark_hash_table_dirty(struct ssdfs_btree_node *node)
{
	struct ssdfs_state_bitmap *bmap;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);
	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
	spin_lock(&bmap->lock);
	bmap->flags |= SSDFS_HASH_TBL_IS_USING;
	spin_unlock(&bmap->lock);
	up_read(&node->bmap_array.lock);
}

/*
 * ssdfs_mark_hash_table_clean() - mark the hash table as clean
 * @node: node object
 */
static inline
void ssdfs_mark_hash_table_clean(struct ssdfs_btree_node *node)
{
	struct ssdfs_state_bitmap *bmap;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);
	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
	spin_lock(&bmap->lock);
	bmap->flags &= ~SSDFS_HASH_TBL_IS_USING;
	spin_unlock(&bmap->lock);
	up_read(&node->bmap_array.lock);
}

/*
 * ssdfs_mark_lookup2_table_dirty() - mark the lookup2 table as dirty
 * @node: node object
 */
static inline
void ssdfs_mark_lookup2_table_dirty(struct ssdfs_btree_node *node)
{
	struct ssdfs_state_bitmap *bmap;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);
	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
	spin_lock(&bmap->lock);
	bmap->flags |= SSDFS_LOOKUP_TBL2_IS_USING;
	spin_unlock(&bmap->lock);
	up_read(&node->bmap_array.lock);
}

/*
 * ssdfs_mark_lookup2_table_clean() - mark the lookup2 table as clean
 * @node: node object
 */
static inline
void ssdfs_mark_lookup2_table_clean(struct ssdfs_btree_node *node)
{
	struct ssdfs_state_bitmap *bmap;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);
	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
	spin_lock(&bmap->lock);
	bmap->flags &= ~SSDFS_LOOKUP_TBL2_IS_USING;
	spin_unlock(&bmap->lock);
	up_read(&node->bmap_array.lock);
}

/*
 * ssdfs_shared_dict_btree_pre_flush_node() - pre-flush node's header
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
int ssdfs_shared_dict_btree_pre_flush_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_shared_dictionary_node_header dict_header;
	size_t hdr_size = sizeof(struct ssdfs_shared_dictionary_node_header);
	size_t ltbl_desc_size = sizeof(struct ssdfs_shdict_ltbl2_item);
	size_t htbl_desc_size = sizeof(struct ssdfs_shdict_htbl_item);
	struct ssdfs_btree *tree;
	struct ssdfs_state_bitmap *bmap;
	struct folio *folio;
	u16 index_area_size;
	u16 strings_count;
	u32 str_area_offset;
	u32 str_area_size;
	u32 str_area_free_space;
	u32 hash_tbl_offset;
	u32 hash_tbl_size;
	u16 hash_tbl_items;
	u32 hash_tbl_free_space;
	u32 lookup_tbl2_offset;
	u32 lookup_tbl2_size;
	u16 lookup_tbl2_items;
	u32 lookup_tbl2_free_space;
	u32 used_space;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_INITIALIZED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is clean\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
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

	if (tree->type != SSDFS_SHARED_DICTIONARY_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	}

	down_write(&node->full_lock);
	down_write(&node->header_lock);

	ssdfs_memcpy(&dict_header, 0, hdr_size,
		     &node->raw.dict_header, 0, hdr_size,
		     hdr_size);

	dict_header.node.magic.common = cpu_to_le32(SSDFS_SUPER_MAGIC);
	dict_header.node.magic.key = cpu_to_le16(SSDFS_DICTIONARY_BNODE_MAGIC);
	dict_header.node.magic.version.major = SSDFS_MAJOR_REVISION;
	dict_header.node.magic.version.minor = SSDFS_MINOR_REVISION;

	err = ssdfs_btree_node_pre_flush_header(node, &dict_header.node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to flush generic header: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		goto finish_shared_dict_header_preparation;
	}

	switch (atomic_read(&node->index_area.state)) {
	case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
		index_area_size = node->index_area.area_size;
		break;

	case SSDFS_BTREE_NODE_AREA_ABSENT:
		index_area_size = 0;
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid area state %#x\n",
			  atomic_read(&node->index_area.state));
		goto finish_shared_dict_header_preparation;
	}

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		switch (atomic_read(&node->lookup_tbl_area.state)) {
		case SSDFS_BTREE_NODE_LOOKUP_TBL_EXIST:
			/* expected state */
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("lookup table is absent\n");
			goto finish_shared_dict_header_preparation;
		}

		switch (atomic_read(&node->hash_tbl_area.state)) {
		case SSDFS_BTREE_NODE_HASH_TBL_EXIST:
			/* expected state */
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("hash table is absent\n");
			goto finish_shared_dict_header_preparation;
		}

		strings_count = node->items_area.items_count;
		str_area_offset = node->items_area.offset;
		str_area_size = node->items_area.area_size;
		str_area_free_space = node->items_area.free_space;

		hash_tbl_offset = node->hash_tbl_area.offset;
		hash_tbl_size = node->hash_tbl_area.area_size;
		hash_tbl_items = node->hash_tbl_area.index_count;

		if (hash_tbl_size < (hash_tbl_items * htbl_desc_size)) {
			err = -ERANGE;
			SSDFS_ERR("corrupted hash table: "
				  "size %u, items %u, desc_size %zu\n",
				  hash_tbl_size,
				  hash_tbl_items,
				  htbl_desc_size);
			goto finish_shared_dict_header_preparation;
		}

		hash_tbl_free_space = hash_tbl_size;
		hash_tbl_free_space -= hash_tbl_items * htbl_desc_size;

		lookup_tbl2_offset = node->lookup_tbl_area.offset;
		lookup_tbl2_size = node->lookup_tbl_area.area_size;
		lookup_tbl2_items = node->lookup_tbl_area.index_count;

		if (lookup_tbl2_size < (lookup_tbl2_items * ltbl_desc_size)) {
			err = -ERANGE;
			SSDFS_ERR("corrupted lookup table: "
				  "size %u, items %u, desc_size %zu\n",
				  lookup_tbl2_size,
				  lookup_tbl2_items,
				  ltbl_desc_size);
			goto finish_shared_dict_header_preparation;
		}

		lookup_tbl2_free_space = lookup_tbl2_size;
		lookup_tbl2_free_space -= lookup_tbl2_items * ltbl_desc_size;
		break;

	case SSDFS_BTREE_NODE_AREA_ABSENT:
		strings_count = 0;
		str_area_offset = 0;
		str_area_size = 0;
		str_area_free_space = 0;
		hash_tbl_offset = 0;
		hash_tbl_size = 0;
		hash_tbl_items = 0;
		hash_tbl_free_space = 0;
		lookup_tbl2_offset = 0;
		lookup_tbl2_size = 0;
		lookup_tbl2_items = 0;
		lookup_tbl2_free_space = 0;
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid area state %#x\n",
			  atomic_read(&node->items_area.state));
		goto finish_shared_dict_header_preparation;
	}

	if (str_area_offset != (hdr_size + index_area_size)) {
		err = -ERANGE;
		SSDFS_ERR("corrupted strings area: "
			  "str_area_offset %u, hdr_size %zu, "
			  "index_area_size %u\n",
			  str_area_offset,
			  hdr_size,
			  index_area_size);
		goto finish_shared_dict_header_preparation;
	}

	if (hash_tbl_offset != (str_area_offset + str_area_size)) {
		err = -ERANGE;
		SSDFS_ERR("corrupted hash table: "
			  "hash_tbl_offset %u, str_area_offset %u, "
			  "str_area_size %u\n",
			  hash_tbl_offset,
			  str_area_offset,
			  str_area_size);
		goto finish_shared_dict_header_preparation;
	}

	if (lookup_tbl2_offset != (hash_tbl_offset + hash_tbl_size)) {
		err = -ERANGE;
		SSDFS_ERR("corrupted lookup table: "
			  "lookup_tbl2_offset %u, hash_tbl_offset %u, "
			  "hash_tbl_size %u\n",
			  lookup_tbl2_offset,
			  hash_tbl_offset,
			  hash_tbl_size);
		goto finish_shared_dict_header_preparation;
	}

	used_space = hdr_size + index_area_size;
	used_space += str_area_size;
	used_space += hash_tbl_size;
	used_space += lookup_tbl2_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("hdr_size %zu, index_area_size %u, "
		  "str_area_size %u, hash_tbl_size %u, "
		  "lookup_tbl2_size %u\n",
		  hdr_size, index_area_size,
		  str_area_size, hash_tbl_size,
		  lookup_tbl2_size);
#endif /* CONFIG_SSDFS_DEBUG */

	if (used_space != node->node_size) {
		err = -ERANGE;
		SSDFS_ERR("corrupted node: "
			  "node_size %u, used_space %u\n",
			  node->node_size,
			  used_space);
		goto finish_shared_dict_header_preparation;
	}

	if (str_area_free_space > str_area_size) {
		err = -ERANGE;
		SSDFS_ERR("corrupted node: free_space %u, area_size %u\n",
			  str_area_free_space, str_area_size);
		goto finish_shared_dict_header_preparation;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(str_area_offset >= U16_MAX);
	BUG_ON(str_area_size >= U16_MAX);
	BUG_ON(str_area_free_space >= U16_MAX);
	BUG_ON(hash_tbl_offset >= U16_MAX);
	BUG_ON(hash_tbl_size >= U16_MAX);
	BUG_ON(hash_tbl_free_space >= U16_MAX);
	BUG_ON(lookup_tbl2_offset >= U16_MAX);
	BUG_ON(lookup_tbl2_size >= U16_MAX);
	BUG_ON(lookup_tbl2_free_space >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	dict_header.str_area.offset = le16_to_cpu((u16)str_area_offset);
	dict_header.str_area.size =  le16_to_cpu((u16)str_area_size);
	dict_header.str_area.free_space = le16_to_cpu((u16)str_area_free_space);
	dict_header.str_area.items_count = le16_to_cpu(strings_count);

	dict_header.hash_table.offset = le16_to_cpu((u16)hash_tbl_offset);
	dict_header.hash_table.size =  le16_to_cpu((u16)hash_tbl_size);
	dict_header.hash_table.free_space =
					le16_to_cpu((u16)hash_tbl_free_space);
	dict_header.hash_table.items_count = le16_to_cpu(hash_tbl_items);

	dict_header.lookup_table2.offset = le16_to_cpu((u16)lookup_tbl2_offset);
	dict_header.lookup_table2.size = le16_to_cpu((u16)lookup_tbl2_size);
	dict_header.lookup_table2.free_space =
					le16_to_cpu((u16)lookup_tbl2_free_space);
	dict_header.lookup_table2.items_count = le16_to_cpu(lookup_tbl2_items);

	dict_header.node.check.bytes = cpu_to_le16((u16)hdr_size);
	dict_header.node.check.flags = cpu_to_le16(SSDFS_CRC32);

	err = ssdfs_calculate_csum(&dict_header.node.check,
				   &dict_header, hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("unable to calculate checksum: err %d\n", err);
		goto finish_shared_dict_header_preparation;
	}

	ssdfs_memcpy(&node->raw.dict_header, 0, hdr_size,
		     &dict_header, 0, hdr_size,
		     hdr_size);

	ssdfs_mark_hash_table_clean(node);
	ssdfs_mark_lookup2_table_clean(node);

finish_shared_dict_header_preparation:
	up_write(&node->header_lock);

	if (unlikely(err))
		goto finish_node_pre_flush;

	if (folio_batch_count(&node->content.batch) < 1) {
		err = -ERANGE;
		SSDFS_ERR("folio batch is empty\n");
		goto finish_node_pre_flush;
	}

	folio = node->content.batch.folios[0];
	__ssdfs_memcpy_to_folio(folio, 0, PAGE_SIZE,
				&dict_header, 0, hdr_size,
				hdr_size);

finish_node_pre_flush:
	up_write(&node->full_lock);

	return err;
}

/*
 * ssdfs_shared_dict_btree_flush_node() - flush node
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
int ssdfs_shared_dict_btree_flush_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree *tree;
	u64 fs_feature_compat;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node %p, node_id %u\n",
		  node, node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (tree->type != SSDFS_SHARED_DICTIONARY_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	}

	fsi = node->tree->fsi;

	spin_lock(&fsi->volume_state_lock);
	fs_feature_compat = fsi->fs_feature_compat;
	spin_unlock(&fsi->volume_state_lock);

	if (fs_feature_compat & SSDFS_HAS_SHARED_DICT_COMPAT_FLAG) {
		err = ssdfs_btree_common_node_flush(node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to flush node: "
				  "node_id %u, height %u, err %d\n",
				  node->node_id,
				  atomic_read(&node->height),
				  err);
		}
	} else {
		err = -EFAULT;
		SSDFS_CRIT("shared dictionary tree is absent\n");
	}

	ssdfs_debug_btree_node_object(node);

	return err;
}

/******************************************************************************
 *          SPECIALIZED SHARED DICTIONARY BTREE NODE OPERATIONS               *
 ******************************************************************************/

/*
 * The lookup1 table's capacity array
 */
static
const u16 lookup1_tbl_range_capacity[SSDFS_SHDIC_LTBL1_SIZE] = {
	2,	/* 00 */
	4,	/* 01 */
	8,	/* 02 */
	16,	/* 03 */
	32,	/* 04 */
	32,	/* 05 */
	32,	/* 06 */
	32,	/* 07 */
	32,	/* 08 */
	64,	/* 09 */
	64,	/* 10 */
	32,	/* 11 */
	32,	/* 12 */
	32,	/* 13 */
	32,	/* 14 */
	32,	/* 15 */
	16,	/* 16 */
	8,	/* 17 */
	4,	/* 18 */
	2,	/* 19 */
	};

/*
 * The lookup1 table's threshold array
 */
static
const u16 lookup1_tbl_threshold[SSDFS_SHDIC_LTBL1_SIZE] = {
	2,	/* 00 */
	6,	/* 01 */
	14,	/* 02 */
	30,	/* 03 */
	62,	/* 04 */
	94,	/* 05 */
	126,	/* 06 */
	158,	/* 07 */
	190,	/* 08 */
	254,	/* 09 */
	318,	/* 10 */
	350,	/* 11 */
	382,	/* 12 */
	414,	/* 13 */
	446,	/* 14 */
	478,	/* 15 */
	494,	/* 16 */
	502,	/* 17 */
	506,	/* 18 */
	508,	/* 19 */
	};

typedef int (*convert_hash64_to_hash32_fn)(struct ssdfs_btree_search *search,
					struct ssdfs_shdict_search_key *value);

/*
 * ssdfs_convert_hash64_to_hash32_lo() - convert hash64 to hash32_lo
 * @search: search object
 * @value: search key value [out]
 *
 * This method tries to convert hash64 to hash32_lo.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static inline
int ssdfs_convert_hash64_to_hash32_lo(struct ssdfs_btree_search *search,
				      struct ssdfs_shdict_search_key *value)
{
	u64 hash64;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !value);
#endif /* CONFIG_SSDFS_DEBUG */

	hash64 = search->request.start.hash;

	if (hash64 >= U64_MAX) {
		SSDFS_ERR("invalid hash for search\n");
		return -ERANGE;
	}

	value->name.hash_lo = cpu_to_le32(SSDFS_HASH32_LO(hash64));

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("hash64 %#llx, value->name.hash_lo %#x\n",
		  hash64, le32_to_cpu(value->name.hash_lo));
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_convert_hash64_to_hash32_hi() - convert hash64 to hash32_hi
 * @search: search object
 * @value: search key value [out]
 *
 * This method tries to convert hash64 to hash32_hi.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static inline
int ssdfs_convert_hash64_to_hash32_hi(struct ssdfs_btree_search *search,
				      struct ssdfs_shdict_search_key *value)
{
	u64 hash64;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !value);
#endif /* CONFIG_SSDFS_DEBUG */

	hash64 = search->request.start.hash;

	if (hash64 >= U64_MAX) {
		SSDFS_ERR("invalid hash for search\n");
		return -ERANGE;
	}

	value->name.hash_hi = cpu_to_le32(SSDFS_HASH32_HI(hash64));

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("hash64 %#llx, value->name.hash_hi %#x\n",
		  hash64, le32_to_cpu(value->name.hash_hi));
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

typedef bool (*is_search_key_valid_fn)(struct ssdfs_shdict_search_key *value);

/*
 * is_ssdfs_hash32_lo_valid() - check that hash32_lo is valid
 * @value: search key value
 */
static inline
bool is_ssdfs_hash32_lo_valid(struct ssdfs_shdict_search_key *value)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!value);
#endif /* CONFIG_SSDFS_DEBUG */

	return value->name.hash_lo < U32_MAX;
}

/*
 * is_ssdfs_hash32_hi_valid() - check that hash32_hi is valid
 * @value: search key value
 */
static inline
bool is_ssdfs_hash32_hi_valid(struct ssdfs_shdict_search_key *value)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!value);
#endif /* CONFIG_SSDFS_DEBUG */

	return value->name.hash_hi < U32_MAX;
}

typedef int (*search_key_compare_fn)(struct ssdfs_shdict_search_key *value1,
				     struct ssdfs_shdict_search_key *value2);

/*
 * ssdfs_hash32_lo_compare() - compare hash32_lo values
 * @value1: first search key value
 * @value2: second search key value
 *
 * This method compares two hash32_lo values.
 *
 * RETURN:
 * -1 - key1 < key2
 *  0 - key1 == key2
 *  1 - key1 > key2
 */
static inline
int ssdfs_hash32_lo_compare(struct ssdfs_shdict_search_key *value1,
			    struct ssdfs_shdict_search_key *value2)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!value1 || !value2);

	SSDFS_DBG("value1->name.hash_lo %#x (%#x), "
		  "value2->name.hash_lo %#x (%#x)\n",
		  value1->name.hash_lo,
		  le32_to_cpu(value1->name.hash_lo),
		  value2->name.hash_lo,
		  le32_to_cpu(value2->name.hash_lo));
#endif /* CONFIG_SSDFS_DEBUG */

	if (value1->name.hash_lo == value2->name.hash_lo)
		return 0;
	else if (value1->name.hash_lo < value2->name.hash_lo)
		return -1;
	else
		return 1;
}

/*
 * ssdfs_hash32_hi_compare() - compare hash32_hi values
 * @value1: first search key value
 * @value2: second search key value
 *
 * This method compares two hash32_hi values.
 *
 * RETURN:
 * -1 - key1 < key2
 *  0 - key1 == key2
 *  1 - key1 > key2
 */
static inline
int ssdfs_hash32_hi_compare(struct ssdfs_shdict_search_key *value1,
			    struct ssdfs_shdict_search_key *value2)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!value1 || !value2);

	SSDFS_DBG("value1->name.hash_high %#x (%#x), "
		  "value2->name.hash_high %#x (%#x)\n",
		  value1->name.hash_hi,
		  le32_to_cpu(value1->name.hash_hi),
		  value2->name.hash_hi,
		  le32_to_cpu(value2->name.hash_hi));
#endif /* CONFIG_SSDFS_DEBUG */

	if (value1->name.hash_hi == value2->name.hash_hi)
		return 0;
	else if (value1->name.hash_hi < value2->name.hash_hi)
		return -1;
	else
		return 1;
}

typedef int (*get_search_key_fn)(struct ssdfs_btree_node *node,
				 u16 index,
				 struct ssdfs_shdict_search_key *value);

/*
 * ssdfs_get_lookup1_table_search_key() - get a search key from lookup1 table
 * @node: node object
 * @index: index of the item in the lookup1 table
 * @value: search key value [out]
 *
 * This method tries to retrieve the descriptor from the lookup1 table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_get_lookup1_table_search_key(struct ssdfs_btree_node *node,
					u16 index,
					struct ssdfs_shdict_search_key *value)
{
	struct ssdfs_shdict_ltbl1_item *lookup_table;
	int array_size = SSDFS_SHDIC_LTBL1_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !value);
	BUG_ON(!rwsem_is_locked(&node->header_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	if (index >= array_size) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index %u >= array_size %d\n",
			  index, array_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	lookup_table = node->raw.dict_header.lookup_table1;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("LOOKUP1 TABLE DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     lookup_table,
			     sizeof(struct ssdfs_shdict_ltbl1_item) *
				array_size);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_memcpy(value,
		     0, sizeof(struct ssdfs_shdict_search_key),
		     &lookup_table[index],
		     0, sizeof(struct ssdfs_shdict_search_key),
		     sizeof(struct ssdfs_shdict_search_key));
	return 0;
}

/*
 * ssdfs_get_lookup2_descriptor() - get the lookup2 descriptor
 * @node: node object
 * @area: pointer on lookup2 table's area descriptor
 * @index: index of the item in the lookup2 table
 * @desc: pointer on lookup2 table's item value [out]
 *
 * This method tries to retrieve the descriptor from the lookup2 table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_get_lookup2_descriptor(struct ssdfs_btree_node *node,
				 struct ssdfs_btree_node_index_area *area,
				 u16 index,
				 struct ssdfs_shdict_ltbl2_item *desc)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	size_t item_size = sizeof(struct ssdfs_shdict_ltbl2_item);
	u32 area_offset;
	u32 area_size;
	u16 items_count;
	u32 item_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !desc);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("index %u\n", index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	area_offset = area->offset;
	area_size = area->area_size;
	items_count = area->index_count;

	if (index >= items_count) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index %u >= items_count %u\n",
			  index, items_count);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	item_offset = (u32)index * item_size;
	if (item_offset >= area_size) {
		SSDFS_ERR("item_offset %u >= area_size %u\n",
			  item_offset, area_size);
		return -ERANGE;
	}

	item_offset += area_offset;
	if (item_offset >= node->node_size) {
		SSDFS_ERR("item_offset %u >= node_size %u\n",
			  item_offset, node->node_size);
		return -ERANGE;
	}

	err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset, &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert offset into folio: "
			  "item_offset %u, err %d\n",
			  item_offset, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio.desc.folio_index >= folio_batch_count(&node->content.batch)) {
		SSDFS_ERR("invalid folio_index: "
			  "index %d, batch_size %u\n",
			  folio.desc.folio_index,
			  folio_batch_count(&node->content.batch));
		return -ERANGE;
	}

	folio.ptr = node->content.batch.folios[folio.desc.folio_index];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_memcpy_from_folio(desc, 0, item_size,
				      &folio, item_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_get_lookup2_table_search_key() - get a search key from lookup2 table
 * @node: node object
 * @index: index of the item in the lookup2 table
 * @value: search key value [out]
 *
 * This method tries to retrieve the descriptor from the lookup2 table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_get_lookup2_table_search_key(struct ssdfs_btree_node *node,
					u16 index,
					struct ssdfs_shdict_search_key *value)
{
	struct ssdfs_btree_node_index_area lookup_tbl_area;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !value);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("index %u\n", index);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->header_lock);
	ssdfs_memcpy(&lookup_tbl_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     &node->lookup_tbl_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     sizeof(struct ssdfs_btree_node_index_area));
	up_read(&node->header_lock);

	return ssdfs_get_lookup2_descriptor(node, &lookup_tbl_area, index,
				(struct ssdfs_shdict_ltbl2_item *)value);
}

/*
 * ssdfs_set_lookup2_descriptor() - set the lookup2 descriptor
 * @node: node object
 * @area: pointer on lookup2 table's area descriptor
 * @index: index of the item in the lookup2 table
 * @desc: pointer on prepared descriptor
 *
 * This method tries to save the descriptor into the lookup2 table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_set_lookup2_descriptor(struct ssdfs_btree_node *node,
				 struct ssdfs_btree_node_index_area *area,
				 u16 index,
				 struct ssdfs_shdict_ltbl2_item *desc)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	size_t item_size = sizeof(struct ssdfs_shdict_ltbl2_item);
	u32 area_offset;
	u32 area_size;
	u16 items_count;
	u32 item_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !desc);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("index %u\n", index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	area_offset = area->offset;
	area_size = area->area_size;
	items_count = area->index_count;

	if (index > items_count) {
		SSDFS_ERR("index %u > items_count %u\n",
			  index, items_count);
		return -ERANGE;
	}

	item_offset = (u32)index * item_size;
	if (item_offset >= area_size) {
		SSDFS_ERR("item_offset %u >= area_size %u\n",
			  item_offset, area_size);
		return -ERANGE;
	}

	item_offset += area_offset;
	if (item_offset >= node->node_size) {
		SSDFS_ERR("item_offset %u >= node_size %u\n",
			  item_offset, node->node_size);
		return -ERANGE;
	}

	err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset, &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert offset into folio: "
			  "item_offset %u, err %d\n",
			  item_offset, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio.desc.folio_index >= folio_batch_count(&node->content.batch)) {
		SSDFS_ERR("invalid folio_index: "
			  "index %d, batch_size %u\n",
			  folio.desc.folio_index,
			  folio_batch_count(&node->content.batch));
		return -ERANGE;
	}

	folio.ptr = node->content.batch.folios[folio.desc.folio_index];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_memcpy_to_folio(&folio,
				    desc, 0, item_size,
				    item_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_get_hash_descriptor() - get the hash descriptor
 * @node: node object
 * @area: pointer on hash table's area descriptor
 * @index: index of the item in the hash table
 * @desc: pointer on hash table's item value [out]
 *
 * This method tries to retrieve the descriptor from the hash table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_get_hash_descriptor(struct ssdfs_btree_node *node,
			      struct ssdfs_btree_node_index_area *area,
			      u16 index,
			      struct ssdfs_shdict_htbl_item *desc)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	size_t item_size = sizeof(struct ssdfs_shdict_htbl_item);
	u32 area_offset;
	u32 area_size;
	u16 items_count;
	u32 item_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !desc);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("index %u\n", index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	area_offset = area->offset;
	area_size = area->area_size;
	items_count = area->index_count;

	if (index >= items_count) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index %u >= items_count %u\n",
			  index, items_count);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	item_offset = (u32)index * item_size;
	if (item_offset >= area_size) {
		SSDFS_ERR("item_offset %u >= area_size %u\n",
			  item_offset, area_size);
		return -ERANGE;
	}

	item_offset += area_offset;
	if (item_offset >= node->node_size) {
		SSDFS_ERR("item_offset %u >= node_size %u\n",
			  item_offset, node->node_size);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area_offset %u, area_size %u, "
		  "items_count %u, index %u, "
		  "item_offset %u, item_size %zu\n",
		  area_offset, area_size,
		  items_count, index,
		  item_offset, item_size);
#endif /* CONFIG_SSDFS_DEBUG */

	err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset, &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert offset into folio: "
			  "item_offset %u, err %d\n",
			  item_offset, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio.desc.folio_index >= folio_batch_count(&node->content.batch)) {
		SSDFS_ERR("invalid folio_index: "
			  "index %d, batch_size %u\n",
			  folio.desc.folio_index,
			  folio_batch_count(&node->content.batch));
		return -ERANGE;
	}

	folio.ptr = node->content.batch.folios[folio.desc.folio_index];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_memcpy_from_folio(desc, 0, item_size,
				      &folio, item_size);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("item_offset %u, hash_hi %#x, str_offset %u\n",
		  item_offset,
		  le32_to_cpu(desc->hash_hi),
		  le16_to_cpu(desc->str_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_get_hash_table_search_key() - get a search key from hash table
 * @node: node object
 * @index: index of the item in the hash table
 * @value: search key value [out]
 *
 * This method tries to retrieve the descriptor from the hash table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_get_hash_table_search_key(struct ssdfs_btree_node *node,
				    u16 index,
				    struct ssdfs_shdict_search_key *value)
{
	struct ssdfs_btree_node_index_area hash_tbl_area;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !value);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("index %u\n", index);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->header_lock);
	ssdfs_memcpy(&hash_tbl_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     &node->hash_tbl_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     sizeof(struct ssdfs_btree_node_index_area));
	up_read(&node->header_lock);

	return ssdfs_get_hash_descriptor(node, &hash_tbl_area, index,
				(struct ssdfs_shdict_htbl_item *)value);
}

/*
 * ssdfs_set_hash_descriptor() - set the hash descriptor
 * @node: node object
 * @area: pointer on hash table's area descriptor
 * @index: index of the item in the hash table
 * @desc: pointer on prepared descriptor
 *
 * This method tries to save the descriptor into the hash table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_set_hash_descriptor(struct ssdfs_btree_node *node,
			      struct ssdfs_btree_node_index_area *area,
			      u16 index,
			      struct ssdfs_shdict_htbl_item *desc)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	size_t item_size = sizeof(struct ssdfs_shdict_htbl_item);
	u32 area_offset;
	u32 area_size;
	u16 items_count;
	u32 item_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !desc);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("index %u\n", index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	area_offset = area->offset;
	area_size = area->area_size;
	items_count = area->index_count;

	if (index > items_count) {
		SSDFS_ERR("index %u > items_count %u\n",
			  index, items_count);
		return -ERANGE;
	}

	item_offset = (u32)index * item_size;
	if (item_offset >= area_size) {
		SSDFS_ERR("item_offset %u >= area_size %u\n",
			  item_offset, area_size);
		return -ERANGE;
	}

	item_offset += area_offset;
	if (item_offset >= node->node_size) {
		SSDFS_ERR("item_offset %u >= node_size %u\n",
			  item_offset, node->node_size);
		return -ERANGE;
	}

	err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset, &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert offset into folio: "
			  "item_offset %u, err %d\n",
			  item_offset, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio.desc.folio_index >= folio_batch_count(&node->content.batch)) {
		SSDFS_ERR("invalid folio_index: "
			  "index %d, batch_size %u\n",
			  folio.desc.folio_index,
			  folio_batch_count(&node->content.batch));
		return -ERANGE;
	}

	folio.ptr = node->content.batch.folios[folio.desc.folio_index];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_memcpy_to_folio(&folio,
				    desc, 0, item_size,
				    item_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		return err;
	}

	return 0;
}

typedef int (*correct_lower_index_fn)(int index);

static inline
int ssdfs_correct_identity_search_lower_index(int index)
{
	return index + 1;
}

static inline
int ssdfs_correct_range_search_lower_index(int index)
{
	return index;
}

static inline
int ssdfs_check_lower_bound(struct ssdfs_shdict_search_key *key,
			    struct ssdfs_shdict_search_key *lower_bound,
			    int index,
			    is_search_key_valid_fn is_valid,
			    search_key_compare_fn key_compare,
			    int *upper_index,
			    u16 *found_index,
			    struct ssdfs_shdict_search_key *found_key)
{
	size_t key_size = sizeof(struct ssdfs_shdict_search_key);
	int res;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!key || !lower_bound || !upper_index);
	BUG_ON(!found_index || !found_key);
	SSDFS_DBG("index %d\n", index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_valid(lower_bound)) {
		*upper_index = index;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("upper_index %d\n",
			  *upper_index);
#endif /* CONFIG_SSDFS_DEBUG */
	} else {
		res = key_compare(key, lower_bound);
		if (res < 0) {
			*upper_index = index;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("upper_index %d\n",
				  *upper_index);
#endif /* CONFIG_SSDFS_DEBUG */
		} else if (res == 0) {
			*found_index = index;
			ssdfs_memcpy(found_key, 0, key_size,
				     lower_bound, 0, key_size,
				     key_size);
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("key is equal to lower_bound: "
				  "found_index %u\n",
				  *found_index);
#endif /* CONFIG_SSDFS_DEBUG */
			return -EEXIST;
		} else {
			SSDFS_DBG("needs to check upper bound\n");
			return -EAGAIN;
		}
	}

	return 0;
}

static inline
int ssdfs_check_upper_bound(struct ssdfs_shdict_search_key *key,
			    struct ssdfs_shdict_search_key *lower_bound,
			    struct ssdfs_shdict_search_key *upper_bound,
			    int index, int upper_index,
			    is_search_key_valid_fn is_valid,
			    search_key_compare_fn key_compare,
			    correct_lower_index_fn correct_lower_index,
			    int *lower_index,
			    u16 *found_index,
			    struct ssdfs_shdict_search_key *found_key)
{
	size_t key_size = sizeof(struct ssdfs_shdict_search_key);
	int res;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!key || !lower_bound || !upper_bound);
	BUG_ON(!lower_index || !found_index || !found_key);
	SSDFS_DBG("index %d\n", index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_valid(upper_bound)) {
		*found_index = index;
		ssdfs_memcpy(found_key, 0, key_size,
			     lower_bound, 0, key_size,
			     key_size);
		SSDFS_DBG("invalid upper_bound\n");
		return -ENODATA;
	} else {
		res = key_compare(key, upper_bound);
		if (res < 0) {
			if (index > 0 && (index + 1) < upper_index) {
				*lower_index = correct_lower_index(index);

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("lower_index %d\n",
					  *lower_index);
#endif /* CONFIG_SSDFS_DEBUG */
			} else {
				*found_index = index;
				ssdfs_memcpy(found_key, 0, key_size,
					     lower_bound, 0, key_size,
					     key_size);
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("no data: found_index %u\n",
					  *found_index);
#endif /* CONFIG_SSDFS_DEBUG */
				return -ENODATA;
			}
		} else if (res == 0) {
			*found_index = index + 1;
			ssdfs_memcpy(found_key, 0, key_size,
				     upper_bound, 0, key_size,
				     key_size);
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("key found: found_index %u\n",
				  *found_index);
#endif /* CONFIG_SSDFS_DEBUG */
			return -EEXIST;
		} else {
			*lower_index = correct_lower_index(index);
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("lower_index %d\n",
				  *lower_index);
#endif /* CONFIG_SSDFS_DEBUG */
		}
	}

	return 0;
}

/*
 * ssdfs_shared_dict_node_find_index_nolock() - find index in the table
 * @node: node object
 * @search: search object
 * @start_index: index to start the search
 * @range_len: maximum number of items for search
 * @table_size: number of items in the table
 * @hash64_to_key: pointer on function that convert hash64 to key
 * @get_key: pointer on function that extract descriptor from the table
 * @is_valid: pointer on function that check the validity of the key
 * @key_compare: pointer on function that is able to compare keys
 * @correct_lower_index: pointer on fuction to correct lower index
 * @found_index: pointer on the found index [out]
 * @found_key: pointer on the found key [out]
 *
 * This method is trying to find the search key for the requested
 * hash value.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - no such data in the node.
 * %-EEXIST     - exactly the requested data was found.
 */
static
int ssdfs_shared_dict_node_find_index_nolock(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_search *search,
				    u16 start_index, u16 range_len,
				    int table_size,
				    convert_hash64_to_hash32_fn hash64_to_key,
				    get_search_key_fn get_key,
				    is_search_key_valid_fn is_valid,
				    search_key_compare_fn key_compare,
				    correct_lower_index_fn correct_lower_index,
				    u16 *found_index,
				    struct ssdfs_shdict_search_key *found_key)
{
	struct ssdfs_shdict_search_key key, lower_bound, upper_bound;
	int index, lower_index, upper_index;
	size_t key_size = sizeof(struct ssdfs_shdict_search_key);
	int res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search || !found_index || !found_key);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_index %u, range_len %u, table_size %d, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  start_index, range_len, table_size,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	if (table_size < 0) {
		SSDFS_ERR("invalid table_size %d\n",
			  table_size);
		return -EINVAL;
	}

	if ((start_index + range_len) > table_size) {
		SSDFS_ERR("invalid request: "
			  "start_index %u, range_len %u, "
			  "table_size %d\n",
			  start_index, range_len, table_size);
		return -ERANGE;
	}

	*found_index = U16_MAX;
	memset(found_key, 0xFF, key_size);

	err = hash64_to_key(search, &key);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert hash to key: err %d\n", err);
		return err;
	}

	lower_index = start_index;
	err = get_key(node, lower_index, &lower_bound);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get key: index %u, err %d\n",
			  lower_index, err);
		return err;
	}

	if (!is_valid(&lower_bound)) {
		*found_index = lower_index;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("lower_bound is invalid: found_index %u\n",
			  *found_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	res = key_compare(&key, &lower_bound);
	if (res < 0) {
		*found_index = lower_index;
		ssdfs_memcpy(found_key, 0, key_size,
			     &lower_bound, 0, key_size,
			     key_size);
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("search key is lesser than lower_bound: "
			  "found_index %u\n", *found_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	} else if (res == 0) {
		*found_index = lower_index;
		ssdfs_memcpy(found_key, 0, key_size,
			     &lower_bound, 0, key_size,
			     key_size);
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("search key is equal to lower_bound: "
			  "found_index %u\n", *found_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EEXIST;
	}

	upper_index = start_index + range_len - 1;
	err = get_key(node, upper_index, &upper_bound);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get key: index %u, err %d\n",
			  upper_index, err);
		return err;
	}

	if (!is_valid(&upper_bound)) {
		/*
		 * continue to search
		 */
	} else {
		res = key_compare(&key, &upper_bound);
		if (res == 0) {
			*found_index = upper_index;
			ssdfs_memcpy(found_key, 0, key_size,
				     &upper_bound, 0, key_size,
				     key_size);
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("search key is equal to upper_bound: "
				  "found_index %u\n", *found_index);
#endif /* CONFIG_SSDFS_DEBUG */
			return -EEXIST;
		} else if (res > 0) {
			*found_index = upper_index;
			ssdfs_memcpy(found_key, 0, key_size,
				     &upper_bound, 0, key_size,
				     key_size);
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("search key is bigger than upper_bound: "
				  "found_index %u\n", *found_index);
#endif /* CONFIG_SSDFS_DEBUG */
			return -ENODATA;
		}
	}

	upper_index--;

	while (lower_index < upper_index) {
		int diff = upper_index - lower_index;

		index = lower_index + (diff / 2);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("lower_index %d, upper_index %d, "
			  "diff %d, index %d\n",
			  lower_index, upper_index, diff, index);
#endif /* CONFIG_SSDFS_DEBUG */

		err = get_key(node, index, &lower_bound);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get key: index %u, err %d\n",
				  index, err);
			return err;
		}

		err = get_key(node, index + 1, &upper_bound);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get key: index %u, err %d\n",
				  index + 1, err);
			return err;
		}

		err = ssdfs_check_lower_bound(&key, &lower_bound, index,
					      is_valid, key_compare,
					      &upper_index, found_index,
					      found_key);
		if (err == -EEXIST)
			return err;
		else if (err == -EAGAIN) {
			err = ssdfs_check_upper_bound(&key,
						      &lower_bound,
						      &upper_bound,
						      index,
						      upper_index,
						      is_valid,
						      key_compare,
						      correct_lower_index,
						      &lower_index,
						      found_index,
						      found_key);
			if (err == -EEXIST || err == -ENODATA) {
				/* finish search */
				return err;
			}
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("lower_index %d, upper_index %d\n",
			  lower_index, upper_index);
#endif /* CONFIG_SSDFS_DEBUG */
	};

	if (lower_index > upper_index) {
		SSDFS_ERR("lower_index %d > upper_index %d\n",
			  lower_index, upper_index);
		return -ERANGE;
	}

	*found_index = lower_index;

	err = get_key(node, *found_index, &lower_bound);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get key: index %u, err %d\n",
			  *found_index, err);
		return err;
	}

	ssdfs_memcpy(found_key, 0, key_size,
		     &lower_bound, 0, key_size,
		     key_size);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("no data: index %u\n",
		  *found_index);
#endif /* CONFIG_SSDFS_DEBUG */

	return -ENODATA;
}

/*
 * ssdfs_shared_dict_node_find_lookup1_index() - find lookup1 index
 * @node: node object
 * @search: search object
 * @index: lookup index [out]
 *
 * This method tries to find a lookup1 index for requested items.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - lookup1 index doesn't exist for requested hash.
 */
static
int ssdfs_shared_dict_node_find_lookup1_index(struct ssdfs_btree_node *node,
					      struct ssdfs_btree_search *search,
					      u16 *index)
{
	struct ssdfs_shdict_search_key found;
	int array_size = SSDFS_SHDIC_LTBL1_SIZE;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search || !index);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->header_lock);
	err = ssdfs_shared_dict_node_find_index_nolock(node, search,
					0, array_size, array_size,
					ssdfs_convert_hash64_to_hash32_lo,
					ssdfs_get_lookup1_table_search_key,
					is_ssdfs_hash32_lo_valid,
					ssdfs_hash32_lo_compare,
					ssdfs_correct_range_search_lower_index,
					index, &found);
	up_read(&node->header_lock);

	switch (err) {
	case -EEXIST:
		err = 0;
		/* FALLTHRU */
		fallthrough;
	case -ENODATA:
		/* FALLTHRU */
		fallthrough;
	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(*index >= array_size);
#endif /* CONFIG_SSDFS_DEBUG */

		switch (search->result.name_state) {
		case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
			/* expected state */
			break;

		default:
			SSDFS_ERR("unexpected name buffer's state\n");
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!search->result.name);
#endif /* CONFIG_SSDFS_DEBUG */

		search->result.name->lookup.index = *index;
		ssdfs_memcpy(&search->result.name->lookup.desc,
			     0, sizeof(struct ssdfs_shdict_ltbl1_item),
			     &found,
			     0, sizeof(struct ssdfs_shdict_ltbl1_item),
			     sizeof(struct ssdfs_shdict_ltbl1_item));
		break;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("index %u, hash_lo %#x, start_index %u, range_len %u\n",
		  *index,
		  le32_to_cpu(search->result.name->lookup.desc.hash_lo),
		  le16_to_cpu(search->result.name->lookup.desc.start_index),
		  le16_to_cpu(search->result.name->lookup.desc.range_len));

	SSDFS_DBG("DEBUG SEARCH RESULT NAME:\n");
	ssdfs_debug_btree_search_result_name(search);
	SSDFS_DBG("END DEBUG OUTPUT\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_shared_dict_node_find_lookup2_index() - find lookup2 index
 * @node: node object
 * @search: search object
 * @index: strings range index [out]
 *
 * This method tries to find a lookup2 index for requested items.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate the memory.
 * %-ENODATA    - lookup2 index doesn't exist for requested hash.
 */
static
int ssdfs_shared_dict_node_find_lookup2_index(struct ssdfs_btree_node *node,
					      struct ssdfs_btree_search *search,
					      u16 *index)
{
	struct ssdfs_shdict_search_key found;
	struct ssdfs_shdict_ltbl2_item *ltbl2_item;
	size_t ldesc_size = sizeof(struct ssdfs_lookup_descriptor);
	size_t ltbl2_item_len = sizeof(struct ssdfs_shdict_ltbl2_item);
	int table_size;
	int array_size;
	u16 start_index;
	u16 range_len;
	u16 found_items;
	u16 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search || !index);
	BUG_ON(*index >= SSDFS_SHDIC_LTBL1_SIZE);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->header_lock);
	table_size = node->lookup_tbl_area.index_capacity;
	up_read(&node->header_lock);

	array_size = lookup1_tbl_range_capacity[*index];
	start_index = le16_to_cpu(search->result.name->lookup.desc.start_index);
	range_len = le16_to_cpu(search->result.name->lookup.desc.range_len);

	if (range_len > array_size) {
		SSDFS_ERR("invalid request: "
			  "range_len %u > array_size %d\n",
			  range_len, array_size);
		return -ERANGE;
	}

	if ((start_index + range_len) > table_size) {
		SSDFS_ERR("invalid request: "
			  "start_index %u, range_len %u, "
			  "table_size %d\n",
			  start_index, range_len, table_size);
		return -ERANGE;
	}

	array_size = min_t(int, array_size, table_size - start_index);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_index %u, range_len %u, array_size %d\n",
		  start_index, range_len, array_size);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->full_lock);

	err = ssdfs_shared_dict_node_find_index_nolock(node, search,
				start_index, array_size, table_size,
				ssdfs_convert_hash64_to_hash32_lo,
				ssdfs_get_lookup2_table_search_key,
				is_ssdfs_hash32_lo_valid,
				ssdfs_hash32_lo_compare,
				ssdfs_correct_identity_search_lower_index,
				index, &found);

	if (err == -EEXIST) {
		err = 0;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(*index >= table_size);
#endif /* CONFIG_SSDFS_DEBUG */

		switch (search->result.name_state) {
		case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
			/* expected state */
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("unexpected name buffer's state\n");
			goto finish_index_search;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!search->result.name);
#endif /* CONFIG_SSDFS_DEBUG */

		ltbl2_item = (struct ssdfs_shdict_ltbl2_item *)&found;
		found_items = min_t(u16, le16_to_cpu(ltbl2_item->str_count),
				    (u16)search->request.count);

		if (found_items == 0) {
			err = -ERANGE;
			SSDFS_ERR("invalid found_items %u\n", found_items);
			goto finish_index_search;
		} else if (found_items > 1) {
			err = ssdfs_btree_search_alloc_result_name(search,
					(size_t)found_items *
					    sizeof(struct ssdfs_name_string));
			if (unlikely(err)) {
				SSDFS_ERR("fail to allocate buffer\n");
				goto finish_index_search;
			}

			for (i = 0; i < found_items; i++) {
				struct ssdfs_name_string *name;

				name = &search->result.name[i];
				ssdfs_memcpy(&name->lookup,
					     0, ldesc_size,
					     &search->name.lookup,
					     0, ldesc_size,
					     ldesc_size);

				name->strings_range.index = *index + i;
				ssdfs_memcpy(&name->strings_range.desc,
					     0, ltbl2_item_len,
					     &found,
					     0, ltbl2_item_len,
					     ltbl2_item_len);
			}
		} else {
			search->result.name->strings_range.index = *index;
			ssdfs_memcpy(&search->result.name->strings_range.desc,
				     0, ltbl2_item_len,
				     &found,
				     0, ltbl2_item_len,
				     ltbl2_item_len);
		}
	}

finish_index_search:
	up_read(&node->full_lock);

	switch (err) {
	case -ENODATA:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(*index >= table_size);
#endif /* CONFIG_SSDFS_DEBUG */

		switch (search->result.name_state) {
		case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
			/* expected state */
			break;

		default:
			SSDFS_ERR("unexpected name buffer's state\n");
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!search->result.name);
#endif /* CONFIG_SSDFS_DEBUG */

		search->result.name->strings_range.index = *index;
		ssdfs_memcpy(&search->result.name->strings_range.desc,
			     0, ltbl2_item_len,
			     &found,
			     0, ltbl2_item_len,
			     ltbl2_item_len);
		break;

	default:
		/* do nothing */
		break;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("index %u\n", *index);

	SSDFS_DBG("DEBUG SEARCH RESULT NAME:\n");
	ssdfs_debug_btree_search_result_name(search);
	SSDFS_DBG("END DEBUG OUTPUT\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_shared_dict_node_process_found_hash() - process found hash
 * @node: node object
 * @search: search object
 * @found: found key
 * @index: hash index
 * @name: name string descriptor [out]
 *
 * This method tries to prepare name string descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_shared_dict_node_process_found_hash(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search,
					struct ssdfs_shdict_search_key *found,
					u16 index,
					struct ssdfs_name_string *name)
{
	struct ssdfs_strings_range_descriptor *str_range;
	struct ssdfs_shdict_ltbl2_item *ltbl2_item;
	struct ssdfs_shdict_search_key prefix;
	struct ssdfs_shdict_search_key lookup2_key;
	struct ssdfs_shdict_search_key left_name;
	struct ssdfs_shdict_search_key right_name;
	struct ssdfs_shdict_search_key key = {0};
	u16 lookup2_index;
	u16 prefix_index;
	u16 calculated_index;
	int res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search || !found || !name);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p, index %u\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child, index);
#endif /* CONFIG_SSDFS_DEBUG */

	str_range = &search->result.name->strings_range;
	prefix_index = le16_to_cpu(str_range->desc.hash_index);

	calculated_index = prefix_index;
	calculated_index += str_range->desc.str_count;

	if (calculated_index < index) {
		lookup2_index = str_range->index;

		do {
			lookup2_index++;

			err = ssdfs_get_lookup2_table_search_key(node,
								 lookup2_index,
								 &lookup2_key);
			if (unlikely(err)) {
				SSDFS_ERR("fail to get lookup2 key: "
					  "node_id %u, index %u, err %d\n",
					  node->node_id, lookup2_index, err);
				return err;
			}

			ltbl2_item =
				(struct ssdfs_shdict_ltbl2_item *)&lookup2_key;

			prefix_index = le16_to_cpu(ltbl2_item->hash_index);

			calculated_index = prefix_index;
			calculated_index += ltbl2_item->str_count;
		} while (calculated_index < index);

		search->result.name->strings_range.index = lookup2_index;
		ssdfs_memcpy(&search->result.name->strings_range.desc,
			     0, sizeof(struct ssdfs_shdict_ltbl2_item),
			     &lookup2_key,
			     0, sizeof(struct ssdfs_shdict_search_key),
			     sizeof(struct ssdfs_shdict_ltbl2_item));

		err = ssdfs_get_hash_table_search_key(node, prefix_index,
						      &prefix);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get hash item: "
				  "node_id %u, index %u, err %d\n",
				  node->node_id, prefix_index, err);
			return err;
		}

		name->prefix.index = prefix_index;
		ssdfs_memcpy(&name->prefix.desc,
			     0, sizeof(struct ssdfs_shdict_htbl_item),
			     &prefix,
			     0, sizeof(struct ssdfs_shdict_search_key),
			     sizeof(struct ssdfs_shdict_htbl_item));
	} else {
		err = ssdfs_get_hash_table_search_key(node, prefix_index,
						      &prefix);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get hash item: "
				  "node_id %u, index %u, err %d\n",
				  node->node_id, str_range->index, err);
			return err;
		}

		name->prefix.index = prefix_index;
		ssdfs_memcpy(&name->prefix.desc,
			     0, sizeof(struct ssdfs_shdict_htbl_item),
			     &prefix,
			     0, sizeof(struct ssdfs_shdict_search_key),
			     sizeof(struct ssdfs_shdict_htbl_item));
	}

	switch (name->prefix.desc.type) {
	case SSDFS_FULL_NAME:
		name->right_name.index = index;
		ssdfs_memcpy(&name->right_name.desc,
			     0, sizeof(struct ssdfs_shdict_htbl_item),
			     found,
			     0, sizeof(struct ssdfs_shdict_search_key),
			     sizeof(struct ssdfs_shdict_htbl_item));
		break;

	case SSDFS_NAME_PREFIX:
		if (index == prefix_index) {
			/* switch from prefix to name */
			index++;
		}

		err = ssdfs_get_hash_table_search_key(node, index,
						      &right_name);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get hash item: "
				  "node_id %u, index %u, err %d\n",
				  node->node_id, index, err);
			return err;
		}

		err = ssdfs_convert_hash64_to_hash32_hi(search, &key);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert hash to key: err %d\n",
				  err);
			return err;
		}

		res = ssdfs_hash32_hi_compare(&key, &right_name);
		if (res > 0 && (index + 1) < calculated_index) {
			index++;

			err = ssdfs_get_hash_table_search_key(node, index,
							      &right_name);
			if (unlikely(err)) {
				SSDFS_ERR("fail to get hash item: "
					  "node_id %u, index %u, err %d\n",
					  node->node_id, index, err);
				return err;
			}
		}

		name->right_name.index = index;
		ssdfs_memcpy(&name->right_name.desc,
			     0, sizeof(struct ssdfs_shdict_htbl_item),
			     &right_name,
			     0, sizeof(struct ssdfs_shdict_search_key),
			     sizeof(struct ssdfs_shdict_htbl_item));
		break;

	default:
		SSDFS_ERR("invalid prefix type %#x\n",
			  name->prefix.desc.type);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(index < prefix_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if ((index - prefix_index) > 1) {
		u16 left_name_index = index - 1;

		err = ssdfs_get_hash_table_search_key(node, left_name_index,
						      &left_name);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get hash item: "
				  "node_id %u, index %u, err %d\n",
				  node->node_id, left_name_index, err);
			return err;
		}

		name->left_name.index = left_name_index;
		ssdfs_memcpy(&name->left_name.desc,
			     0, sizeof(struct ssdfs_shdict_htbl_item),
			     &left_name,
			     0, sizeof(struct ssdfs_shdict_search_key),
			     sizeof(struct ssdfs_shdict_htbl_item));
	} else {
		err = ssdfs_get_hash_table_search_key(node, index,
						      &left_name);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get hash item: "
				  "node_id %u, index %u, err %d\n",
				  node->node_id, index, err);
			return err;
		}

		name->left_name.index = index;
		ssdfs_memcpy(&name->left_name.desc,
			     0, sizeof(struct ssdfs_shdict_htbl_item),
			     &left_name,
			     0, sizeof(struct ssdfs_shdict_search_key),
			     sizeof(struct ssdfs_shdict_htbl_item));
	}

	return 0;
}

/*
 * ssdfs_shared_dict_node_find_hash_index() - find hash index
 * @node: node object
 * @search: search object
 * @index: hash index [out]
 *
 * This method tries to find a hash index for requested items.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - hash index doesn't exist for requested hash.
 */
static
int ssdfs_shared_dict_node_find_hash_index(struct ssdfs_btree_node *node,
					   struct ssdfs_btree_search *search,
					   u16 *index)
{
	struct ssdfs_shdict_ltbl2_item *ltbl2_item;
	struct ssdfs_shdict_search_key found;
	struct ssdfs_name_string *name;
	int table_size;
	u16 hashes_count;
	u16 start_index;
	u16 range_len;
	u32 found_items;
	u16 cur_index;
	u16 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search || !index);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->header_lock);
	table_size = node->hash_tbl_area.index_capacity;
	hashes_count = node->hash_tbl_area.index_count;
	up_read(&node->header_lock);

	ltbl2_item = &search->result.name->strings_range.desc;
	start_index = le16_to_cpu(ltbl2_item->hash_index);
	range_len = ltbl2_item->str_count;

	if ((start_index + range_len) > table_size) {
		SSDFS_ERR("invalid request: "
			  "start_index %u, range_len %u, "
			  "table_size %d\n",
			  start_index, range_len, table_size);
		return -ERANGE;
	}

	down_read(&node->full_lock);

	err = ssdfs_shared_dict_node_find_index_nolock(node, search,
				start_index, range_len, table_size,
				ssdfs_convert_hash64_to_hash32_hi,
				ssdfs_get_hash_table_search_key,
				is_ssdfs_hash32_hi_valid,
				ssdfs_hash32_hi_compare,
				ssdfs_correct_identity_search_lower_index,
				index, &found);

	if (err == -EEXIST) {
		err = 0;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(*index >= table_size);
#endif /* CONFIG_SSDFS_DEBUG */

		switch (search->result.name_state) {
		case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
		case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
			/* expected state */
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("unexpected name buffer's state\n");
			goto finish_index_search;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!search->result.name);
#endif /* CONFIG_SSDFS_DEBUG */

		found_items = search->result.name_string_size /
				sizeof(struct ssdfs_name_string);

		if (found_items == 0) {
			err = -ERANGE;
			SSDFS_ERR("invalid found_items %u\n", found_items);
			goto finish_index_search;
		}

		if (table_size == 0) {
			err = -ERANGE;
			SSDFS_ERR("invalid table_size %d\n", table_size);
			goto finish_index_search;
		}

		found_items = min_t(u32, found_items, (u32)table_size);

		for (i = 0; i < found_items; i++) {
			cur_index = *index + i;

			name = &search->result.name[i];

			err = ssdfs_shared_dict_node_process_found_hash(node,
								search, &found,
								cur_index,
								name);
			if (unlikely(err)) {
				SSDFS_ERR("fail to process found hash: "
					  "node_id %u, cur_index %u, err %d\n",
					  node->node_id, cur_index, err);
				goto finish_index_search;
			}
		}
	} else if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(*index >= table_size);
#endif /* CONFIG_SSDFS_DEBUG */

		switch (search->result.name_state) {
		case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
		case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
			/* expected state */
			break;

		default:
			SSDFS_ERR("unexpected name buffer's state\n");
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!search->result.name);
#endif /* CONFIG_SSDFS_DEBUG */

		name = &search->result.name[0];

		err = ssdfs_shared_dict_node_process_found_hash(node,
							search, &found,
							*index, name);
		if (unlikely(err)) {
			SSDFS_ERR("fail to process found hash: "
				  "node_id %u, err %d\n",
				  node->node_id, err);
			goto finish_index_search;
		}

		/* recover error code -> node hasn't requested hash */
		err = -ENODATA;
	}

finish_index_search:
	up_read(&node->full_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("index %u\n", *index);

	SSDFS_DBG("DEBUG SEARCH RESULT NAME:\n");
	ssdfs_debug_btree_search_result_name(search);
	SSDFS_DBG("END DEBUG OUTPUT\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_extract_string() - extract string from the items area
 * @node: node object
 * @desc: hash descriptor
 * @buf: buffer for the string [out]
 *
 * The method is trying to retrieve the string for @desc
 * from the items area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_extract_string(struct ssdfs_btree_node *node,
			 struct ssdfs_shdict_htbl_item *desc,
			 unsigned char *buf)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	u32 area_offset;
	u32 area_size;
	u32 item_offset;
	u32 copied_len = 0;
	u32 cur_len;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !desc || !buf);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, str_offset %u, str_len %u, type %#x\n",
		  node->node_id,
		  le16_to_cpu(desc->str_offset),
		  desc->str_len,
		  desc->type);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	down_read(&node->header_lock);
	area_offset = node->items_area.offset;
	area_size = node->items_area.area_size;
	up_read(&node->header_lock);

	if (desc->str_len == 0 || desc->str_len > SSDFS_MAX_NAME_LEN) {
		SSDFS_ERR("invalid string lenght\n");
		return -ERANGE;
	}

	while (copied_len < desc->str_len) {
		item_offset = le16_to_cpu(desc->str_offset);
		if ((item_offset + desc->str_len) >= area_size) {
			SSDFS_ERR("item_offset %u, str_len %u, area_size %u\n",
				  item_offset, desc->str_len, area_size);
			return -ERANGE;
		}

		item_offset += area_offset;
		if (item_offset >= node->node_size) {
			SSDFS_ERR("item_offset %u >= node_size %u\n",
				  item_offset, node->node_size);
			return -ERANGE;
		}

		item_offset += copied_len;

		err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "item_offset %u, err %d\n",
				  item_offset, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio.desc.folio_index >=
				folio_batch_count(&node->content.batch)) {
			SSDFS_ERR("invalid folio_index: "
				  "index %d, batch_size %u\n",
				  folio.desc.folio_index,
				  folio_batch_count(&node->content.batch));
			return -ERANGE;
		}

		folio.ptr = node->content.batch.folios[folio.desc.folio_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		cur_len = min_t(u32, (u32)desc->str_len - copied_len,
				     (u32)PAGE_SIZE - item_offset);

		err = ssdfs_memcpy_from_folio(buf,
					      copied_len,
					      SSDFS_MAX_NAME_LEN,
					      &folio, cur_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: err %d\n", err);
			return err;
		}

		copied_len += cur_len;
	}

	return 0;
}

/*
 * ssdfs_extract_name() - extract name from the node
 * @node: node object
 * @name: name string descriptor with buffer [in|out]
 *
 * The method is trying to retrieve the name from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - node is corrupted probably.
 */
static
int ssdfs_extract_name(struct ssdfs_btree_node *node,
			struct ssdfs_name_string *name)
{
	u32 hash32_lo, hash32_hi;
	u8 str_len;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !name);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	hash32_lo = le32_to_cpu(name->strings_range.desc.hash_lo);
	hash32_hi = le32_to_cpu(name->right_name.desc.hash_hi);

	name->hash = SSDFS_NAME_HASH(hash32_lo, hash32_hi);

	switch (name->right_name.desc.type) {
	case SSDFS_NAME_SUFFIX:
		switch (name->prefix.desc.type) {
		case SSDFS_NAME_PREFIX:
			/* expected type */
			break;

		default:
			SSDFS_ERR("invalid prefix type %#x\n",
				  name->prefix.desc.type);
			return -ERANGE;
		}

		str_len = name->prefix.desc.str_len;
		if (str_len >= SSDFS_MAX_NAME_LEN) {
			SSDFS_ERR("invalid prefix len %u\n",
				  str_len);
			return -EIO;
		}

		err = ssdfs_extract_string(node, &name->prefix.desc,
					   name->str);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract prefix: err %d\n",
				  err);
			return err;
		}

		name->len = str_len;

		str_len = name->right_name.desc.str_len;
		if ((name->len + str_len) >= SSDFS_MAX_NAME_LEN) {
			SSDFS_ERR("invalid suffix len %u\n",
				  str_len);
			return -EIO;
		}

		err = ssdfs_extract_string(node, &name->right_name.desc,
					   name->str + name->len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract suffix: err %d\n",
				  err);
			return err;
		}

		name->len += str_len;
		break;

	case SSDFS_FULL_NAME:
		str_len = name->right_name.desc.str_len;
		if (str_len >= SSDFS_MAX_NAME_LEN) {
			SSDFS_ERR("invalid suffix len %u\n",
				  str_len);
			return -EIO;
		}

		err = ssdfs_extract_string(node, &name->right_name.desc,
					   name->str);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract suffix: err %d\n",
				  err);
			return err;
		}

		name->len = str_len;
		break;

	default:
		SSDFS_ERR("invalid type %#x\n",
			  name->right_name.desc.type);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_extract_range_by_hash_index() - extract the names for the hash range
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method is trying to extract the names for the hash range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - node contains not all names.
 */
static
int ssdfs_extract_range_by_hash_index(struct ssdfs_btree_node *node,
				      struct ssdfs_btree_search *search)
{
	struct ssdfs_name_string *name;
	u32 found_items;
	u32 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("node_id %u\n", node->node_id);

	SSDFS_DBG("DEBUG SEARCH RESULT NAME:\n");
	ssdfs_debug_btree_search_result_name(search);
	SSDFS_DBG("END DEBUG OUTPUT\n");
#endif /* CONFIG_SSDFS_DEBUG */

	found_items = search->result.name_string_size /
			sizeof(struct ssdfs_name_string);

	if (found_items == 0) {
		SSDFS_ERR("invalid found_items %u\n", found_items);
		return -ERANGE;
	}

	down_read(&node->full_lock);

	for (i = 0; i < found_items; i++) {
		name = &search->result.name[i];

		err = ssdfs_extract_name(node, name);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract name: "
				  "index %u, err %d\n",
				  i, err);
			goto finish_extract_range;
		} else
			search->result.names_in_buffer++;

		if (name->hash < search->request.start.hash ||
		    name->hash > search->request.end.hash) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("hash is out of range: "
				  "hash %llx, start_hash %llx, end_hash %llx\n",
				  name->hash,
				  search->request.start.hash,
				  search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */
			break;
		}
	}

	search->result.state = SSDFS_BTREE_SEARCH_VALID_ITEM;
	search->result.start_index = name->right_name.index;
	search->result.count = found_items;

	name = &search->result.name[search->result.names_in_buffer - 1];
	if (search->request.end.hash > name->hash)
		err = -EAGAIN;

finish_extract_range:
	up_read(&node->full_lock);

	return err;
}

/*
 * ssdfs_shared_dict_btree_node_find_range() - find a range of items into node
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
int ssdfs_shared_dict_btree_node_find_range(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search)
{
	int state;
	u32 area_offset;
	u32 area_size;
	u16 items_count;
	u16 items_capacity;
	u16 vacant_items;
	bool have_enough_space;
	u64 start_hash;
	u64 end_hash;
	u16 index;
	int err = 0, res = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->header_lock);
	state = atomic_read(&node->items_area.state);
	area_offset = node->items_area.offset;
	area_size = node->items_area.area_size;
	items_count = node->items_area.items_count;
	items_capacity = node->items_area.items_capacity;
	start_hash = node->items_area.start_hash;
	end_hash = node->items_area.end_hash;
	up_read(&node->header_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("request (start_hash %#llx, end_hash %#llx), "
		  "items_area (start_hash %#llx, end_hash %#llx)\n",
		  search->request.start.hash, search->request.end.hash,
		  start_hash, end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

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

	vacant_items = items_capacity - items_count;
	have_enough_space = search->request.count <= vacant_items;

	switch (RANGE_WITHOUT_INTERSECTION(search->request.start.hash,
					   search->request.end.hash,
					   start_hash, end_hash)) {
	case 0:
		/* ranges have intersection */
		break;

	case -1: /* range1 < range2 */
		search->result.err = -ENODATA;
		search->result.start_index = 0;
		search->result.count = search->request.count;
		search->result.search_cno =
			ssdfs_current_cno(node->tree->fsi->sb);
		search->result.name_state =
			SSDFS_BTREE_SEARCH_INLINE_BUFFER;
		memset(&search->name, 0, sizeof(struct ssdfs_name_string));
		search->result.name = &search->name;
		search->result.name_string_size =
				sizeof(struct ssdfs_name_string);
		search->result.names_in_buffer = 0;
		search->result.buf_state =
			SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
		search->result.buf = NULL;
		search->result.buf_size = 0;
		search->result.items_in_buffer = 0;

		if (have_enough_space) {
			res = -ENODATA;
			search->result.state =
				SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
			SSDFS_DBG("possible place has been found\n");
		} else {
			search->result.state =
				SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE;
			return -ENODATA;
		}
		break;

	case 1: /* range1 > range2 */
		search->result.err = -ENODATA;
		search->result.start_index = items_count;
		search->result.count = search->request.count;
		search->result.search_cno =
			ssdfs_current_cno(node->tree->fsi->sb);
		search->result.name_state =
			SSDFS_BTREE_SEARCH_INLINE_BUFFER;
		memset(&search->name, 0, sizeof(struct ssdfs_name_string));
		search->result.name = &search->name;
		search->result.name_string_size =
				sizeof(struct ssdfs_name_string);
		search->result.names_in_buffer = 0;
		search->result.buf_state =
			SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
		search->result.buf = NULL;
		search->result.buf_size = 0;
		search->result.items_in_buffer = 0;

		if (have_enough_space) {
			res = -ENODATA;
			search->result.state =
				SSDFS_BTREE_SEARCH_OUT_OF_RANGE;
			SSDFS_DBG("search is out of range\n");
		} else {
			search->result.state =
				SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE;
			return -ENODATA;
		}
		break;

	default:
		BUG();
	}

	if (res != -ENODATA &&
	    !RANGE_HAS_PARTIAL_INTERSECTION(search->request.start.hash,
					    search->request.end.hash,
					    start_hash, end_hash)) {
		SSDFS_ERR("invalid request: "
			  "request (start_hash %llx, end_hash %llx), "
			  "node (start_hash %llx, end_hash %llx)\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  start_hash, end_hash);
		return -ERANGE;
	}

	if (items_count == 0) {
		search->result.state =
			SSDFS_BTREE_SEARCH_OUT_OF_RANGE;

		search->result.err = -ENODATA;
		search->result.start_index = 0;
		search->result.count = search->request.count;
		search->result.search_cno =
			ssdfs_current_cno(node->tree->fsi->sb);
		search->result.name_state = SSDFS_BTREE_SEARCH_INLINE_BUFFER;
		memset(&search->name, 0, sizeof(struct ssdfs_name_string));
		search->result.name = &search->name;
		search->result.name_string_size =
					sizeof(struct ssdfs_name_string);
		search->result.names_in_buffer = 0;
		search->result.buf_state =
			SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
		search->result.buf = NULL;
		search->result.buf_size = 0;
		search->result.items_in_buffer = 0;
		return -ENODATA;
	}

	/* Temporary prepare inline buffer for one name */
	search->result.name_state = SSDFS_BTREE_SEARCH_INLINE_BUFFER;
	search->result.name = &search->name;
	search->result.name_string_size = sizeof(struct ssdfs_name_string);
	search->result.names_in_buffer = 0;

	err = ssdfs_shared_dict_node_find_lookup1_index(node, search,
							&index);
	if (err == -ENODATA) {
		/*
		 * continue logic
		 */
		res = -ENODATA;
		SSDFS_DBG("possible place has been found\n");
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find the lookup1 index: "
			  "start_hash %llx, end_hash %llx, err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(index >= SSDFS_SHDIC_LTBL1_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_shared_dict_node_find_lookup2_index(node, search,
							&index);
	if (err == -ENODATA) {
		/*
		 * Continue to find the hash
		 */
		res = -ENODATA;
		SSDFS_DBG("possible place has been found\n");
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find the lookup2 index: "
			  "start_hash %llx, end_hash %llx, err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		return err;
	} else {
		/*
		 * Lookup1 index defines range of indexes
		 * in lookup2 table. If lookup2 index has been found
		 * then -ENODATA needs to be reset.
		 */
		res = 0;
	}

	err = ssdfs_shared_dict_node_find_hash_index(node, search,
						     &index);
	if (err == -ENODATA) {
		res = -ENODATA;
		search->result.state =
			SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
		search->result.err = -ENODATA;
		search->result.start_index = index;
		search->result.count = search->request.count;
		search->result.search_cno =
			ssdfs_current_cno(node->tree->fsi->sb);
		search->result.buf_state =
			SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
		search->result.buf = NULL;
		search->result.buf_size = 0;
		search->result.items_in_buffer = 0;
		SSDFS_DBG("possible place has been found\n");
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find the hash index: "
			  "start_hash %llx, end_hash %llx, err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		return err;
	}

	err = ssdfs_extract_range_by_hash_index(node, search);
	search->result.search_cno = ssdfs_current_cno(node->tree->fsi->sb);

	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find: "
			  "request (start_hash %#llx, end_hash %#llx), "
			  "items_area (start_hash %#llx, end_hash %#llx)\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  start_hash, end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

		search->result.state =
			SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
		search->result.err = -ENODATA;
		search->result.start_index = index;
		search->result.count = search->request.count;
		search->result.search_cno =
			ssdfs_current_cno(node->tree->fsi->sb);
		search->result.buf_state =
			SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
		search->result.buf = NULL;
		search->result.buf_size = 0;
		search->result.items_in_buffer = 0;

		return err;
	} else if (err == -EAGAIN) {
		search->result.state = SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;

		if (res == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find: "
				  "request (start_hash %#llx, "
				  "end_hash %#llx), "
				  "items_area (start_hash %#llx, "
				  "end_hash %#llx)\n",
				  search->request.start.hash,
				  search->request.end.hash,
				  start_hash, end_hash);
#endif /* CONFIG_SSDFS_DEBUG */
			return res;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("node contains not all requested names: "
				  "node (start_hash %llx, end_hash %llx), "
				  "request (start_hash %llx, end_hash %llx)\n",
				  start_hash, end_hash,
				  search->request.start.hash,
				  search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		}
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to extract range: "
			  "node (start_hash %llx, end_hash %llx), "
			  "request (start_hash %llx, end_hash %llx), "
			  "err %d\n",
			  start_hash, end_hash,
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		ssdfs_debug_btree_node_object(node);
		return err;
	} else {
		if (res == -ENODATA) {
			search->result.state =
				SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find: "
				  "request (start_hash %#llx, "
				  "end_hash %#llx), "
				  "items_area (start_hash %#llx, "
				  "end_hash %#llx)\n",
				  search->request.start.hash,
				  search->request.end.hash,
				  start_hash, end_hash);
#endif /* CONFIG_SSDFS_DEBUG */
			return res;
		}
	}

	search->request.flags &= ~SSDFS_BTREE_SEARCH_INLINE_BUF_HAS_NEW_ITEM;

	return 0;
}

/*
 * ssdfs_shared_dict_btree_node_find_item() - find item into node
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
int ssdfs_shared_dict_btree_node_find_item(struct ssdfs_btree_node *node,
					   struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	if (search->request.count != 1 ||
	    search->request.start.hash != search->request.end.hash) {
		SSDFS_ERR("invalid request state: "
			  "count %d, start_hash %llx, end_hash %llx\n",
			  search->request.count,
			  search->request.start.hash,
			  search->request.end.hash);
		return -ERANGE;
	}

	return ssdfs_shared_dict_btree_node_find_range(node, search);
}

static
int ssdfs_shared_dict_btree_node_allocate_item(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("operation is unavailable\n");
#endif /* CONFIG_SSDFS_DEBUG */
	return -EOPNOTSUPP;
}

static
int ssdfs_shared_dict_btree_node_allocate_range(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("operation is unavailable\n");
#endif /* CONFIG_SSDFS_DEBUG */
	return -EOPNOTSUPP;
}

/*
 * ssdfs_check_items_area() - check items area
 * @node: pointer on node object
 * @area: pointer on items area descriptor [in]
 *
 * This method tries to check the items area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 * %-ENOSPC     - node hasn't free items.
 */
static
int ssdfs_check_items_area(struct ssdfs_btree_node *node,
			   struct ssdfs_btree_node_items_area *area)
{
	u16 free_items;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (area->area_size == 0 ||
	    area->area_size >= node->node_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid area_size %u\n",
			  area->area_size);
		return -EFAULT;
	}

	if ((area->offset + area->area_size) > node->node_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid area: offset %u, "
			  "area_size %u, node_size %u\n",
			  area->offset, area->area_size,
			  node->node_size);
		return -EFAULT;
	}

	if (area->items_capacity == 0 ||
	    area->items_capacity < area->items_count) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid items accounting: "
			  "node_id %u, items_capacity %u, items_count %u\n",
			  node->node_id, area->items_capacity,
			  area->items_count);
		return -EFAULT;
	}

	if (area->min_item_size != SSDFS_DENTRY_INLINE_NAME_MAX_LEN ||
	    area->max_item_size != SSDFS_MAX_NAME_LEN) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("min_item_size %u, max_item_size %u\n",
			  area->min_item_size, area->max_item_size);
		return -EFAULT;
	}

	if (area->free_space > area->area_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("free_space %u > area_size %u\n",
			  area->free_space, area->area_size);
		return -EFAULT;
	}

	free_items = area->items_capacity - area->items_count;
	if (unlikely(free_items < 0)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_WARN("invalid free_items %d\n",
			   free_items);
		return -EFAULT;
	} else if (free_items == 0) {
		SSDFS_DBG("node hasn't free items\n");
		return -ENOSPC;
	}

	if (((u64)free_items * area->min_item_size) > area->free_space) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid free_items: "
			  "free_items %d, min_items_size %u, free_space %u\n",
			  free_items, area->min_item_size, area->free_space);
		return -EFAULT;
	}

	return 0;
}

/*
 * ssdfs_check_lookup2_table_area() - check lookup2 area
 * @node: pointer on node object
 * @area: pointer on lookup2 area descriptor [in]
 *
 * This method tries to check the lookup2 area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_check_lookup2_table_area(struct ssdfs_btree_node *node,
				   struct ssdfs_btree_node_index_area *area)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (area->index_capacity == 0 && area->index_count == 0) {
		if (area->area_size != 0) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("invalid area: offset %u, area_size %u, "
				  "index_size %u, index_count %u, "
				  "index_capacity %u\n",
				  area->offset, area->area_size,
				  area->index_size, area->index_count,
				  area->index_capacity);
			return -EFAULT;
		}
	} else {
		if (area->area_size == 0 ||
		    area->area_size >= node->node_size) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("invalid area: offset %u, area_size %u, "
				  "index_size %u, index_count %u, "
				  "index_capacity %u\n",
				  area->offset, area->area_size,
				  area->index_size, area->index_count,
				  area->index_capacity);
			return -EFAULT;
		}
	}

	if ((area->offset + area->area_size) > node->node_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid area: offset %u, "
			  "area_size %u, node_size %u\n",
			  area->offset, area->area_size,
			  node->node_size);
		return -EFAULT;
	}

	if (area->index_size != sizeof(struct ssdfs_shdict_ltbl2_item)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid index size %u\n",
			  area->index_size);
		return -EFAULT;
	}

	if (area->index_capacity != 0 || area->index_count != 0) {
		if (area->index_capacity == 0 ||
		    area->index_capacity < area->index_count) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("invalid indexes accounting: "
				  "node_id %u, index_capacity %u, "
				  "index_count %u\n",
				  node->node_id, area->index_capacity,
				  area->index_count);
			return -EFAULT;
		}
	}

	if (((u32)area->index_capacity * area->index_size) > area->area_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid index capacity: "
			  "node_id %u, index_capacity %u, "
			  "index_size %u, area_size %u\n",
			  node->node_id, area->index_capacity,
			  area->index_size, area->area_size);
		return -EFAULT;
	}

	return 0;
}

/*
 * ssdfs_check_hash_table_area() - check hash table's area
 * @node: pointer on node object
 * @area: pointer on hash table's area descriptor [in]
 *
 * This method tries to check the hash table's area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_check_hash_table_area(struct ssdfs_btree_node *node,
				struct ssdfs_btree_node_index_area *area)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (area->index_capacity == 0 && area->index_count == 0) {
		if (area->area_size != 0) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("invalid area: offset %u, area_size %u, "
				  "index_size %u, index_count %u, "
				  "index_capacity %u\n",
				  area->offset, area->area_size,
				  area->index_size, area->index_count,
				  area->index_capacity);
			return -EFAULT;
		}
	} else {
		if (area->area_size == 0 ||
		    area->area_size >= node->node_size) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("invalid area: offset %u, area_size %u, "
				  "index_size %u, index_count %u, "
				  "index_capacity %u\n",
				  area->offset, area->area_size,
				  area->index_size, area->index_count,
				  area->index_capacity);
			return -EFAULT;
		}
	}

	if ((area->offset + area->area_size) > node->node_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid area: offset %u, "
			  "area_size %u, node_size %u\n",
			  area->offset, area->area_size,
			  node->node_size);
		return -EFAULT;
	}

	if (area->index_size != sizeof(struct ssdfs_shdict_htbl_item)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid index size %u\n",
			  area->index_size);
		return -EFAULT;
	}

	if (area->index_capacity != 0 || area->index_count != 0) {
		if (area->index_capacity == 0 ||
		    area->index_capacity < area->index_count) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("invalid indexes accounting: "
				  "node_id %u, index_capacity %u, "
				  "index_count %u\n",
				  node->node_id, area->index_capacity,
				  area->index_count);
			return -EFAULT;
		}
	}

	if (((u32)area->index_capacity * area->index_size) > area->area_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid index capacity: "
			  "node_id %u, index_capacity %u, "
			  "index_size %u, area_size %u\n",
			  node->node_id, area->index_capacity,
			  area->index_size, area->area_size);
		return -EFAULT;
	}

	return 0;
}

/*
 * is_ssdfs_left_full_name() - check that left name is full name
 */
static inline
bool is_ssdfs_left_full_name(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	return search->name.left_name.desc.type == SSDFS_FULL_NAME;
}

/*
 * is_ssdfs_right_full_name() - check that right name is full name
 */
static inline
bool is_ssdfs_right_full_name(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	return search->name.right_name.desc.type == SSDFS_FULL_NAME;
}

/*
 * ssdfs_extract_intersection() - extract the intersection of two strings
 * @node: pointer on node object
 * @str1: descriptor of the first string
 * @str2: pointer on the buffer of the second string
 * @str2_len: length of the second string
 * @len: pointer on value of found intersection [out]
 *
 * This method tries to extract the intersection of two strings.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_extract_intersection(struct ssdfs_btree_node *node,
				struct ssdfs_string_descriptor *str1,
				const char *str2, size_t str2_len,
				u16 *len)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	void *kaddr;
	u32 area_offset;
	u32 area_size;
	u32 item_offset;
	size_t full_len, cur_len;
	u32 i;
	u32 processed_len = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !str1 || !str2 || !len);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, str1 %p, str2 %p, str2_len %zu\n",
		  node->node_id, str1, str2, str2_len);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;
	*len = 0;

	down_read(&node->header_lock);
	area_offset = node->items_area.offset;
	area_size = node->items_area.area_size;
	up_read(&node->header_lock);

	if (!str2) {
		SSDFS_ERR("empty str2 pointer\n");
		return -ERANGE;
	}

	if (str1->desc.str_len == 0 || str2_len == 0) {
		SSDFS_ERR("invalid string length: "
			  "str1 %u, str2 %zu\n",
			  str1->desc.str_len,
			  str2_len);
		return -ERANGE;
	}

	full_len = min_t(size_t,
			(size_t)str1->desc.str_len,
			str2_len);

	if (full_len == 0) {
		SSDFS_ERR("full_len == 0\n");
		return -ERANGE;
	}

	while (processed_len < full_len) {
		item_offset = le16_to_cpu(str1->desc.str_offset);
		if ((item_offset + str1->desc.str_len) >= area_size) {
			SSDFS_ERR("item_offset %u, str_len %u, area_size %u\n",
				  item_offset, str1->desc.str_len, area_size);
			return -ERANGE;
		}

		item_offset += area_offset;
		if (item_offset >= node->node_size) {
			SSDFS_ERR("item_offset %u >= node_size %u\n",
				  item_offset, node->node_size);
			return -ERANGE;
		}

		item_offset += processed_len;

		err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "item_offset %u, err %d\n",
				  item_offset, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio.desc.folio_index >=
				folio_batch_count(&node->content.batch)) {
			SSDFS_ERR("invalid folio_index: "
				  "index %d, batch_size %u\n",
				  folio.desc.folio_index,
				  folio_batch_count(&node->content.batch));
			return -ERANGE;
		}

		folio.ptr = node->content.batch.folios[folio.desc.folio_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		cur_len = min_t(u32, (u32)full_len - processed_len,
				     (u32)PAGE_SIZE - item_offset);

		kaddr = kmap_local_folio(folio.ptr, folio.desc.page_in_folio);

		for (i = 0; i < cur_len; i++) {
			const char *symbol1, *symbol2;

			symbol1 = (u8 *)kaddr + item_offset + i;
			symbol2 = str2 + processed_len + i;

			if (*symbol1 == *symbol2)
				*len += 1;
			else
				break;
		}

		kunmap_local(kaddr);

		processed_len += cur_len;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished: len %u\n", *len);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_extract_intersection_with_left_name() - extract the intersection
 * @node: pointer on node object
 * @search: search object
 * @len: pointer on value of found intersection [out]
 *
 * This method tries to extract the intersection of the requested
 * name with the found left name.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_extract_intersection_with_left_name(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search,
					    u16 *len)
{
	u8 type1, type2, type3;
	u16 index1, index2, index3;
	u16 found_len;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search || !len);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	*len = 0;

	switch (search->result.name_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		/* expected states */
		break;

	default:
		SSDFS_ERR("invalid name state %#x\n",
			  search->result.name_state);
		return -ERANGE;
	}

	if (!search->result.name) {
		SSDFS_ERR("invalid name buffer\n");
		return -ERANGE;
	}

	if (search->result.names_in_buffer != 1) {
		SSDFS_ERR("unexpected names_in_buffer %u\n",
			  search->result.names_in_buffer);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("DEBUG SEARCH RESULT NAME:\n");
	ssdfs_debug_btree_search_result_name(search);
	SSDFS_DBG("END DEBUG OUTPUT\n");
#endif /* CONFIG_SSDFS_DEBUG */

	index1 = search->result.name->prefix.index;
	type1 = search->result.name->prefix.desc.type;
	index2 = search->result.name->left_name.index;
	type2 = search->result.name->left_name.desc.type;
	index3 = search->result.name->right_name.index;
	type3 = search->result.name->right_name.desc.type;

	switch (search->result.name->left_name.desc.type) {
	case SSDFS_NAME_PREFIX:
		if (type1 != type2) {
			SSDFS_ERR("type1 %#x != type2 %#x\n",
				  type1, type2);
			return -ERANGE;
		}

		if (index1 != index2) {
			SSDFS_ERR("index1 %u != index2 %u\n",
				  index1, index2);
			return -ERANGE;
		}

		if (type3 != SSDFS_NAME_SUFFIX) {
			SSDFS_ERR("invalid right name's type %#x\n",
				  type3);
			return -ERANGE;
		}

		if ((index2 + 1) != index3) {
			SSDFS_ERR("invalid right name: "
				  "left_name.index %u, right_name.index %u\n",
				  index2, index3);
			return -ERANGE;
		}

		err = ssdfs_extract_intersection(node,
					&search->result.name->left_name,
					search->request.start.name,
					search->request.start.name_len,
					&found_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract intersection: err %d\n",
				  err);
			return err;
		} else if (found_len >= U16_MAX) {
			SSDFS_ERR("invalid found_len %#x\n",
				  found_len);
			return -ERANGE;
		}

		*len = found_len;

		if (found_len == 0)
			goto finish_extraction;

		err = ssdfs_extract_intersection(node,
				&search->result.name->right_name,
				search->request.start.name + found_len,
				search->request.start.name_len - found_len,
				&found_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract intersection: err %d\n",
				  err);
			return err;
		} else if (found_len >= U16_MAX) {
			SSDFS_ERR("invalid found_len %#x\n",
				  found_len);
			return -ERANGE;
		}

		*len += found_len;
		break;

	case SSDFS_NAME_SUFFIX:
		if (type1 != SSDFS_NAME_PREFIX) {
			SSDFS_ERR("unexpected prefix type %#x\n",
				  type1);
			return -ERANGE;
		}

		if (index1 == index2) {
			SSDFS_ERR("index1 %u == index2 %u\n",
				  index1, index2);
			return -ERANGE;
		}

		err = ssdfs_extract_intersection(node,
					&search->result.name->prefix,
					search->request.start.name,
					search->request.start.name_len,
					&found_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract intersection: err %d\n",
				  err);
			return err;
		} else if (found_len >= U16_MAX) {
			SSDFS_ERR("invalid found_len %#x\n",
				  found_len);
			return -ERANGE;
		}

		*len = found_len;

		if (found_len == 0)
			goto finish_extraction;

		err = ssdfs_extract_intersection(node,
				&search->result.name->left_name,
				search->request.start.name + found_len,
				search->request.start.name_len - found_len,
				&found_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract intersection: err %d\n",
				  err);
			return err;
		} else if (found_len >= U16_MAX) {
			SSDFS_ERR("invalid found_len %#x\n",
				  found_len);
			return -ERANGE;
		}

		*len += found_len;
		break;

	case SSDFS_FULL_NAME:
		if (type1 != SSDFS_FULL_NAME) {
			SSDFS_ERR("unexpected prefix type %#x\n",
				  type1);
			return -ERANGE;
		}

		if (index1 != index2) {
			SSDFS_ERR("index1 %u != index2 %u\n",
				  index1, index2);
			return -ERANGE;
		}

		err = ssdfs_extract_intersection(node,
					&search->result.name->left_name,
					search->request.start.name,
					search->request.start.name_len,
					&found_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract intersection: err %d\n",
				  err);
			return err;
		} else if (found_len >= U16_MAX) {
			SSDFS_ERR("invalid found_len %#x\n",
				  found_len);
			return -ERANGE;
		}

		*len = found_len;
		break;

	default:
		SSDFS_ERR("unexpected name type %#x\n",
			  search->result.name->left_name.desc.type);
		return -ERANGE;
	}

finish_extraction:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished: len %u\n", *len);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_extract_intersection_with_right_name() - extract the intersection
 * @node: pointer on node object
 * @search: search object
 * @len: pointer on value of found intersection [out]
 *
 * This method tries to extract the intersection of the requested
 * name with the found right name.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_extract_intersection_with_right_name(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search,
					    u16 *len)
{
	u8 type1, type2, type3;
	u16 index1, index2, index3;
	u16 found_len;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search || !len);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	*len = 0;

	switch (search->result.name_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		/* expected states */
		break;

	default:
		SSDFS_ERR("invalid name state %#x\n",
			  search->result.name_state);
		return -ERANGE;
	}

	if (!search->result.name) {
		SSDFS_ERR("invalid name buffer\n");
		return -ERANGE;
	}

	if (search->result.names_in_buffer != 1) {
		SSDFS_ERR("unexpected names_in_buffer %u\n",
			  search->result.names_in_buffer);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("DEBUG SEARCH RESULT NAME:\n");
	ssdfs_debug_btree_search_result_name(search);
	SSDFS_DBG("END DEBUG OUTPUT\n");
#endif /* CONFIG_SSDFS_DEBUG */

	index1 = search->result.name->prefix.index;
	type1 = search->result.name->prefix.desc.type;
	index2 = search->result.name->left_name.index;
	type2 = search->result.name->left_name.desc.type;
	index3 = search->result.name->right_name.index;
	type3 = search->result.name->right_name.desc.type;

	switch (search->result.name->right_name.desc.type) {
	case SSDFS_NAME_PREFIX:
		err = ssdfs_extract_intersection(node,
					&search->result.name->right_name,
					search->request.start.name,
					search->request.start.name_len,
					&found_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract intersection: err %d\n",
				  err);
			return err;
		} else if (found_len >= U16_MAX) {
			SSDFS_ERR("invalid found_len %#x\n",
				  found_len);
			return -ERANGE;
		}

		*len = found_len;
		break;

	case SSDFS_NAME_SUFFIX:
		if (type2 == SSDFS_NAME_PREFIX) {
			/* the suffix was processed already */
			*len = 0;
			goto finish_extraction;
		}

		if (type2 == SSDFS_NAME_SUFFIX) {
			if (type1 != SSDFS_NAME_PREFIX) {
				SSDFS_ERR("invalid prefix type %#x\n",
					  type1);
				return -ERANGE;
			}

			err = ssdfs_extract_intersection(node,
						&search->result.name->prefix,
						search->request.start.name,
						search->request.start.name_len,
						&found_len);
			if (unlikely(err)) {
				SSDFS_ERR("fail to extract intersection: "
					  "err %d\n", err);
				return err;
			} else if (found_len >= U16_MAX) {
				SSDFS_ERR("invalid found_len %#x\n",
					  found_len);
				return -ERANGE;
			}

			*len = found_len;

			if (found_len == 0)
				goto finish_extraction;

			err = ssdfs_extract_intersection(node,
				&search->result.name->right_name,
				search->request.start.name + found_len,
				search->request.start.name_len - found_len,
				&found_len);
			if (unlikely(err)) {
				SSDFS_ERR("fail to extract intersection: "
					  "err %d\n", err);
				return err;
			} else if (found_len >= U16_MAX) {
				SSDFS_ERR("invalid found_len %#x\n",
					  found_len);
				return -ERANGE;
			}

			*len += found_len;
			goto finish_extraction;
		}

		/* unexpected state */
		return -ERANGE;

	case SSDFS_FULL_NAME:
		err = ssdfs_extract_intersection(node,
					&search->result.name->right_name,
					search->request.start.name,
					search->request.start.name_len,
					&found_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract intersection: err %d\n",
				  err);
			return err;
		} else if (found_len >= U16_MAX) {
			SSDFS_ERR("invalid found_len %#x\n",
				  found_len);
			return -ERANGE;
		}

		*len = found_len;
		break;

	case SSDFS_UNKNOWN_NAME_TYPE:
		*len = 0;
		break;

	default:
		SSDFS_ERR("unexpected name type %#x\n",
			  search->result.name->left_name.desc.type);
		return -ERANGE;
	}

finish_extraction:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished: len %u\n", *len);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * is_free_space_enough() - check that the node has enough free space
 * @node: node object
 * @requested_size: requested size in bytes
 */
static inline
bool is_free_space_enough(struct ssdfs_btree_node *node,
			  size_t requested_size)
{
	u32 free_space;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, requested_size %zu\n",
		  node->node_id, requested_size);
#endif /* CONFIG_SSDFS_DEBUG */

	free_space = node->items_area.free_space;
	return free_space >= requested_size;
}

/*
 * ssdfs_define_item_size() - define average item size
 * @node: node object
 */
static inline
u16 ssdfs_define_item_size(struct ssdfs_btree_node *node)
{
	u32 area_size;
	u32 free_space;
	u32 used_space;
	u16 items_count;
	u8 min_item_size;
	u16 max_item_size;
	u32 item_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	area_size = node->items_area.area_size;
	free_space = node->items_area.free_space;
	item_size = node->items_area.item_size;
	items_count = node->items_area.items_count;
	min_item_size = node->items_area.min_item_size;
	max_item_size = node->items_area.max_item_size;

	used_space = area_size - free_space;

	if (items_count > 0)
		item_size = used_space / items_count;

	if (item_size < min_item_size)
		item_size = min_item_size;
	if (item_size > max_item_size)
		item_size = max_item_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area_size %u, free_space %u, "
		  "used_space %u, item_size %u, "
		  "min_item_size %u, max_item_size %u\n",
		  area_size, free_space, used_space,
		  item_size, min_item_size, max_item_size);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u16)item_size;
}

/*
 * ssdfs_define_items_capacity() - define items capacity
 * @node: node object
 */
static inline
u16 ssdfs_define_items_capacity(struct ssdfs_btree_node *node)
{
	u32 area_size;
	u16 item_size;
	u16 items_count;
	u32 items_capacity;
	u8 min_item_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	area_size = node->items_area.area_size;
	item_size = node->items_area.item_size;
	items_count = node->items_area.items_count;
	min_item_size = node->items_area.min_item_size;

	items_capacity = node->items_area.free_space / item_size;
	if (items_capacity == 0) {
		node->items_area.item_size = min_item_size;
		items_capacity = node->items_area.free_space / item_size;
		if (items_capacity == 0) {
			SSDFS_ERR("unable to resize: "
				  "items_capacity %u\n",
				  items_capacity);
			return U16_MAX;
		}
	}

	items_capacity += items_count;
	if (items_capacity >= U16_MAX) {
		SSDFS_ERR("invalid items_capacity\n");
		return U16_MAX;
	}

	if ((items_capacity * item_size) > area_size)
		items_capacity = area_size / item_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("free_space %u, item_size %u, items_count %u, "
		  "min_item_size %u, items_capacity %u\n",
		  node->items_area.free_space,
		  item_size, items_count, min_item_size,
		  items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	return items_capacity;
}

/*
 * ssdfs_resize_string_area() - resize the strings area
 * @node: pointer on node object
 * @new_offset: new offset in bytes from the node's beginning
 * @new_size: new size of the area in bytes
 *
 * This method tries to resize the strings area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - not enough free space for the resize.
 */
static
int ssdfs_resize_string_area(struct ssdfs_btree_node *node,
			     u32 new_offset, u32 new_size)
{
	u32 area_offset;
	u32 area_size;
	u32 free_space;
	u16 items_count = 0;
	u32 items_capacity = 0;
	u8 min_item_size;
	u16 max_item_size;
	u32 diff;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, new_offset %u, new_size %u\n",
		  node->node_id, new_offset, new_size);
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

	area_offset = node->items_area.offset;
	area_size = node->items_area.area_size;
	free_space = node->items_area.free_space;
	items_count = node->items_area.items_count;
	min_item_size = node->items_area.min_item_size;
	max_item_size = node->items_area.max_item_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area_offset %u, area_size %u, "
		  "free_space %u, items_count %u, "
		  "min_item_size %u, max_item_size %u\n",
		  area_offset, area_size,
		  free_space, items_count,
		  min_item_size, max_item_size);
#endif /* CONFIG_SSDFS_DEBUG */

	if ((new_offset + new_size) > node->node_size) {
		SSDFS_ERR("invalid request: "
			  "new_offset %u, new_size %u, node_size %u\n",
			  new_offset, new_size, node->node_size);
		return -ERANGE;
	}

	if ((area_offset + area_size) > node->node_size) {
		SSDFS_ERR("corrupted area: "
			  "area_offset %u, area_size %u, node_size %u\n",
			  area_offset, area_size, node->node_size);
		return -ERANGE;
	}

	if (area_size < free_space) {
		SSDFS_ERR("corrupted area: "
			  "area_size %u, free_space %u\n",
			  area_size, free_space);
		return -ERANGE;
	}

	node->items_area.item_size = ssdfs_define_item_size(node);

	if (new_offset < area_offset) {
		diff = area_offset - new_offset;

		node->items_area.offset = new_offset;
		node->items_area.area_size += diff;

		err = ssdfs_shift_memory_range_left(node, &node->items_area,
						    diff, area_size,
						    diff);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move area: err %d\n", err);
			return err;
		}

		node->items_area.area_size -= diff;
	} else if (new_offset > area_offset) {
		diff = new_offset - area_offset;

		if ((area_offset + diff) > node->node_size) {
			SSDFS_ERR("fail to shift the area: "
				 "area_offset %u, diff %u, node_size %u\n",
				 area_offset, diff, node->node_size);
			return -ERANGE;
		}

		node->items_area.area_size += diff;

		err = ssdfs_shift_memory_range_right(node, &node->items_area,
						     0, area_size,
						     diff);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move area: err %d\n", err);
			return err;
		}

		node->items_area.offset = new_offset;
		node->items_area.area_size -= diff;
	}

	if (new_size > area_size) {
		/* resize case */

		node->items_area.area_size = new_size;
		node->items_area.free_space += new_size - area_size;

		items_capacity = ssdfs_define_items_capacity(node);
		if (items_capacity >= U16_MAX)
			return -ENOSPC;

		node->items_area.items_capacity = (u16)items_capacity;
	} else if (new_size < area_size) {
		/* shrink case */

		if (free_space < (area_size - new_size)) {
			SSDFS_ERR("unable to shrink: "
				  "free_space %u, area_size %u, new_size %u\n",
				  free_space, area_size, new_size);
			return -ENOSPC;
		}

		node->items_area.area_size = new_size;
		node->items_area.free_space -= area_size - new_size;

		items_capacity = ssdfs_define_items_capacity(node);
		if (items_capacity >= U16_MAX)
			return -ENOSPC;

		node->items_area.items_capacity = (u16)items_capacity;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_count %u, items_capacity %u\n",
		  items_count, items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_resize_hash_table() - resize the hash table's area
 * @node: pointer on node object
 * @new_offset: new offset in bytes from the node's beginning
 * @new_size: new size of the area in bytes
 *
 * This method tries to resize the hash table's area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - not enough free space for the resize.
 */
static
int ssdfs_resize_hash_table(struct ssdfs_btree_node *node,
			    u32 new_offset, u32 new_size)
{
	u32 area_offset;
	u32 area_size;
	u32 items_count;
	u32 items_capacity;
	u8 item_size;
	u32 diff;
#ifdef CONFIG_SSDFS_DEBUG
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	void *kaddr;
	u32 processed_bytes;
	int i;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, new_offset %u, new_size %u\n",
		  node->node_id, new_offset, new_size);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->hash_tbl_area.state)) {
	case SSDFS_BTREE_NODE_HASH_TBL_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid hash table area state %#x\n",
			  atomic_read(&node->hash_tbl_area.state));
		return -ERANGE;
	}

	area_offset = node->hash_tbl_area.offset;
	area_size = node->hash_tbl_area.area_size;
	items_count = node->hash_tbl_area.index_count;
	items_capacity = node->hash_tbl_area.index_capacity;
	item_size = node->hash_tbl_area.index_size;

	if ((new_offset + new_size) > node->node_size) {
		SSDFS_ERR("invalid request: "
			  "new_offset %u, new_size %u, node_size %u\n",
			  new_offset, new_size, node->node_size);
		return -ERANGE;
	}

	if (new_offset != (node->items_area.offset +
					node->items_area.area_size)) {
		SSDFS_ERR("invalid new area start: "
			  "new_offset %u, items_area.offset %u, "
			  "items_area.area_size %u\n",
			  new_offset,
			  node->items_area.offset,
			  node->items_area.area_size);
		return -ERANGE;
	}

	if ((area_offset + area_size) > node->node_size) {
		SSDFS_ERR("corrupted area: "
			  "area_offset %u, area_size %u, node_size %u\n",
			  area_offset, area_size, node->node_size);
		return -ERANGE;
	}

	if (items_count > items_capacity) {
		SSDFS_ERR("corrupted area: "
			  "items_count %u > items_capacity %u\n",
			  items_count, items_capacity);
		return -ERANGE;
	}

	if (item_size != sizeof(struct ssdfs_shdict_htbl_item)) {
		SSDFS_ERR("corrupted area: "
			  "item_size %u\n",
			  item_size);
		return -ERANGE;
	}

	if (new_size % item_size) {
		SSDFS_ERR("unaligned new area size: "
			  "new_size %u, item_size %u\n",
			  new_size, item_size);
		return -ERANGE;
	}

	if (items_count == 0)
		node->hash_tbl_area.offset = new_offset;
	else if (new_offset < area_offset) {
		diff = area_offset - new_offset;

		if (diff % item_size) {
			SSDFS_ERR("unaligned new area offset: "
				  "diff %u, item_size %u\n",
				  diff, item_size);
			return -ERANGE;
		}

		node->hash_tbl_area.offset = new_offset;
		node->hash_tbl_area.area_size += diff;

		err = ssdfs_shift_memory_range_left2(node, &node->hash_tbl_area,
						     diff, area_size,
						     diff);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move area: err %d\n", err);
			return err;
		}

		node->hash_tbl_area.area_size -= diff;
	} else if (new_offset > area_offset) {
		diff = new_offset - area_offset;

		if (diff % item_size) {
			SSDFS_ERR("unaligned new area offset: "
				  "diff %u, item_size %u\n",
				  diff, item_size);
			return -ERANGE;
		}

		if ((area_offset + diff) > node->node_size) {
			SSDFS_ERR("fail to shift the area: "
				 "area_offset %u, diff %u, node_size %u\n",
				 area_offset, diff, node->node_size);
			return -ERANGE;
		}

		node->hash_tbl_area.area_size += diff;

		err = ssdfs_shift_memory_range_right2(node, &node->hash_tbl_area,
						      0, area_size,
						      diff);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move area: err %d\n", err);
			return err;
		}

		node->hash_tbl_area.offset = new_offset;
		node->hash_tbl_area.area_size -= diff;
	}

	if (new_size > area_size) {
		/* resize case */

		node->hash_tbl_area.area_size = new_size;

		items_capacity = new_size / item_size;
		if (items_capacity >= U16_MAX) {
			SSDFS_ERR("invalid items_capacity\n");
			return -ERANGE;
		}

		node->hash_tbl_area.index_capacity = (u16)items_capacity;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index_capacity %u\n",
			  node->hash_tbl_area.index_capacity);
#endif /* CONFIG_SSDFS_DEBUG */
	} else if (new_size < area_size) {
		/* shrink case */

		if ((items_count * item_size) > new_size) {
			SSDFS_ERR("unable to shrink: "
				  "items_count %u, item_size %u, new_size %u\n",
				  items_count, item_size, new_size);
			return -ENOSPC;
		}

		node->hash_tbl_area.area_size = new_size;

		items_capacity = new_size / item_size;

		if (items_capacity >= U16_MAX) {
			SSDFS_ERR("invalid items_capacity\n");
			return -ERANGE;
		}

		if (items_count > items_capacity) {
			SSDFS_ERR("items_count %u > items_capacity %u\n",
				  items_count, items_capacity);
			return -ERANGE;
		}

		node->hash_tbl_area.index_capacity = (u16)items_capacity;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index_capacity %u\n",
			  node->hash_tbl_area.index_capacity);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	area_offset = node->hash_tbl_area.offset;
	area_size = node->hash_tbl_area.area_size;

	if ((area_offset + area_size) > node->node_size) {
		SSDFS_ERR("corrupted area: "
			  "area_offset %u, area_size %u, node_size %u\n",
			  area_offset, area_size, node->node_size);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	fsi = node->tree->fsi;

	err = SSDFS_OFF2FOLIO(fsi->pagesize, area_offset, &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert offset into folio: "
			  "area_offset %u, err %d\n",
			  area_offset, err);
		return err;
	}

	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));

	folio.ptr = node->content.batch.folios[folio.desc.folio_index];

	SSDFS_DBG("area_offset %u, folio_index %d\n",
		  area_offset, folio.desc.folio_index);

	processed_bytes = 0;

	i = 0;
	while (processed_bytes < fsi->pagesize) {
		kaddr = kmap_local_folio(folio.ptr, i);
		SSDFS_DBG("PAGE DUMP: index %u\n", i);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr,
				     PAGE_SIZE);
		SSDFS_DBG("\n");
		kunmap_local(kaddr);

		i++;
		processed_bytes += PAGE_SIZE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_resize_lookup2_table() - resize the lookup2 table's area
 * @node: pointer on node object
 * @new_offset: new offset in bytes from the node's beginning
 * @new_size: new size of the area in bytes
 *
 * This method tries to resize the lookup2 table's area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - not enough free space for the resize.
 */
static
int ssdfs_resize_lookup2_table(struct ssdfs_btree_node *node,
				u32 new_offset, u32 new_size)
{
	u32 area_offset;
	u32 area_size;
	u32 items_count;
	u32 items_capacity;
	u8 item_size;
	u32 diff;
#ifdef CONFIG_SSDFS_DEBUG
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	void *kaddr;
	u32 processed_bytes;
	int i;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, new_offset %u, new_size %u\n",
		  node->node_id, new_offset, new_size);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->lookup_tbl_area.state)) {
	case SSDFS_BTREE_NODE_LOOKUP_TBL_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid lookup2 table area state %#x\n",
			  atomic_read(&node->lookup_tbl_area.state));
		return -ERANGE;
	}

	area_offset = node->lookup_tbl_area.offset;
	area_size = node->lookup_tbl_area.area_size;
	items_count = node->lookup_tbl_area.index_count;
	items_capacity = node->lookup_tbl_area.index_capacity;
	item_size = node->lookup_tbl_area.index_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("BEFORE: area_offset %u, area_size %u, "
		  "items_count %u, items_capacity %u\n",
		  area_offset, area_size,
		  items_count, items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	if ((new_offset + new_size) > node->node_size) {
		SSDFS_ERR("invalid request: "
			  "new_offset %u, new_size %u, node_size %u\n",
			  new_offset, new_size, node->node_size);
		return -ERANGE;
	}

	if (new_offset != (node->hash_tbl_area.offset +
					node->hash_tbl_area.area_size)) {
		SSDFS_ERR("invalid new area start: "
			  "new_offset %u, hash_tbl_area.offset %u, "
			  "hash_tbl_area.area_size %u\n",
			  new_offset,
			  node->hash_tbl_area.offset,
			  node->hash_tbl_area.area_size);
		return -ERANGE;
	}

	if ((area_offset + area_size) > node->node_size) {
		SSDFS_ERR("corrupted area: "
			  "area_offset %u, area_size %u, node_size %u\n",
			  area_offset, area_size, node->node_size);
		return -ERANGE;
	}

	if (items_count > items_capacity) {
		SSDFS_ERR("corrupted area: "
			  "items_count %u > items_capacity %u\n",
			  items_count, items_capacity);
		return -ERANGE;
	}

	if (item_size != sizeof(struct ssdfs_shdict_ltbl2_item)) {
		SSDFS_ERR("corrupted area: "
			  "item_size %u\n",
			  item_size);
		return -ERANGE;
	}

	if (new_size % item_size) {
		SSDFS_ERR("unaligned new area size: "
			  "new_size %u, item_size %u\n",
			  new_size, item_size);
		return -ERANGE;
	}

	if (items_count == 0)
		node->lookup_tbl_area.offset = new_offset;
	else if (new_offset < area_offset) {
		diff = area_offset - new_offset;

		if (diff % item_size) {
			SSDFS_ERR("unaligned new area offset: "
				  "diff %u, item_size %u\n",
				  diff, item_size);
			return -ERANGE;
		}

		node->lookup_tbl_area.offset = new_offset;
		node->lookup_tbl_area.area_size += diff;

		err = ssdfs_shift_memory_range_left2(node,
						     &node->lookup_tbl_area,
						     diff, area_size,
						     diff);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move area: err %d\n", err);
			return err;
		}

		node->lookup_tbl_area.area_size -= diff;
	} else if (new_offset > area_offset) {
		diff = new_offset - area_offset;

		if (diff % item_size) {
			SSDFS_ERR("unaligned new area offset: "
				  "diff %u, item_size %u\n",
				  diff, item_size);
			return -ERANGE;
		}

		if ((area_offset + diff) > node->node_size) {
			SSDFS_ERR("fail to shift the area: "
				 "area_offset %u, diff %u, node_size %u\n",
				 area_offset, diff, node->node_size);
			return -ERANGE;
		}

		node->lookup_tbl_area.area_size += diff;

		err = ssdfs_shift_memory_range_right2(node,
						      &node->lookup_tbl_area,
						      0, area_size,
						      diff);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move area: err %d\n", err);
			return err;
		}

		node->lookup_tbl_area.offset = new_offset;
		node->lookup_tbl_area.area_size -= diff;
	}

	if (new_size > area_size) {
		/* resize case */

		node->lookup_tbl_area.area_size = new_size;

		items_capacity = new_size / item_size;
		if (items_capacity >= U16_MAX) {
			SSDFS_ERR("invalid items_capacity\n");
			return -ERANGE;
		}

		node->lookup_tbl_area.index_capacity = (u16)items_capacity;
	} else if (new_size < area_size) {
		/* shrink case */

		if ((items_count * item_size) > new_size) {
			SSDFS_ERR("unable to shrink: "
				  "items_count %u, item_size %u, new_size %u\n",
				  items_count, item_size, new_size);
			return -ENOSPC;
		}

		node->lookup_tbl_area.area_size = new_size;

		items_capacity = new_size / item_size;

		if (items_capacity >= U16_MAX) {
			SSDFS_ERR("invalid items_capacity\n");
			return -ERANGE;
		}

		if (items_count > items_capacity) {
			SSDFS_ERR("items_count %u > items_capacity %u\n",
				  items_count, items_capacity);
			return -ERANGE;
		}

		node->lookup_tbl_area.index_capacity = (u16)items_capacity;
	}

	area_offset = node->lookup_tbl_area.offset;
	area_size = node->lookup_tbl_area.area_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("AFTER: area_offset %u, area_size %u, "
		  "items_count %u, items_capacity %u\n",
		  area_offset, area_size,
		  node->lookup_tbl_area.index_count,
		  node->lookup_tbl_area.index_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	if ((area_offset + area_size) > node->node_size) {
		SSDFS_ERR("corrupted area: "
			  "area_offset %u, area_size %u, node_size %u\n",
			  area_offset, area_size, node->node_size);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	fsi = node->tree->fsi;

	err = SSDFS_OFF2FOLIO(fsi->pagesize, area_offset, &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert offset into folio: "
			  "area_offset %u, err %d\n",
			  area_offset, err);
		return err;
	}

	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));

	folio.ptr = node->content.batch.folios[folio.desc.folio_index];

	SSDFS_DBG("area_offset %u, folio_index %d\n",
		  area_offset, folio.desc.folio_index);

	processed_bytes = 0;

	i = 0;
	while (processed_bytes < fsi->pagesize) {
		kaddr = kmap_local_folio(folio.ptr, i);
		SSDFS_DBG("PAGE DUMP: index %u\n", i);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr,
				     PAGE_SIZE);
		SSDFS_DBG("\n");
		kunmap_local(kaddr);

		i++;
		processed_bytes += PAGE_SIZE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

static
bool is_ssdfs_resized_node_corrupted(struct ssdfs_btree_node *node)
{
	u32 area_offset;
	u32 area_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	area_offset = node->items_area.offset;
	area_size = node->items_area.area_size;

	if ((area_offset + area_size) != node->hash_tbl_area.offset) {
		SSDFS_ERR("corrupted string area: "
			  "area_offset %u, area_size %u, node_size %u\n",
			  area_offset, area_size, node->node_size);
		return true;
	}

	area_offset = node->hash_tbl_area.offset;
	area_size = node->hash_tbl_area.area_size;

	if ((area_offset + area_size) != node->lookup_tbl_area.offset) {
		SSDFS_ERR("corrupted hash table area: "
			  "area_offset %u, area_size %u, node_size %u\n",
			  area_offset, area_size, node->node_size);
		return true;
	}

	area_offset = node->lookup_tbl_area.offset;
	area_size = node->lookup_tbl_area.area_size;

	if ((area_offset + area_size) > node->node_size) {
		SSDFS_ERR("corrupted area: "
			  "area_offset %u, area_size %u, node_size %u\n",
			  area_offset, area_size, node->node_size);
		return true;
	}

	return false;
}

/*
 * ssdfs_copy_string_from_buffer() - copy string from the buffer into the node
 * @node: pointer on node object
 * @name: pointer on string's buffer
 * @name_len: length of the string in the buffer
 * @str_offset: string's offset in the area
 *
 * This method tries to copy the string from the buffer into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_copy_string_from_buffer(struct ssdfs_btree_node *node,
				  const char *name,
				  size_t name_len,
				  u16 str_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	u32 area_offset;
	u32 area_size;
	u32 item_offset;
	u32 copied_len = 0;
	u32 cur_len;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !name);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, name_len %zu, str_offset %u\n",
		  node->node_id, name_len, str_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	area_offset = node->items_area.offset;
	area_size = node->items_area.area_size;

	if (name_len == 0 || name_len > SSDFS_MAX_NAME_LEN) {
		SSDFS_ERR("invalid string lenght\n");
		return -ERANGE;
	}

	while (copied_len < name_len) {
		item_offset = str_offset;
		if ((item_offset + name_len) >= area_size) {
			SSDFS_ERR("item_offset %u, str_len %zu, area_size %u\n",
				  item_offset, name_len, area_size);
			return -ERANGE;
		}

		item_offset += area_offset;
		if (item_offset >= node->node_size) {
			SSDFS_ERR("item_offset %u >= node_size %u\n",
				  item_offset, node->node_size);
			return -ERANGE;
		}

		item_offset += copied_len;

		err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "item_offset %u, err %d\n",
				  item_offset, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio.desc.folio_index >=
				folio_batch_count(&node->content.batch)) {
			SSDFS_ERR("invalid folio_index: "
				  "index %d, batch_size %u\n",
				  folio.desc.folio_index,
				  folio_batch_count(&node->content.batch));
			return -ERANGE;
		}

		folio.ptr = node->content.batch.folios[folio.desc.folio_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		cur_len = min_t(u32, (u32)name_len - copied_len,
				     (u32)PAGE_SIZE - item_offset);

		err = ssdfs_memcpy_to_folio(&folio,
					    (char *)name, copied_len, name_len,
					    cur_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: err %d\n", err);
			return err;
		}

		copied_len += cur_len;
	};

	return 0;
}

static
int __ssdfs_insert_full_string(struct ssdfs_btree_node *node,
				struct ssdfs_btree_search *search)
{
	struct ssdfs_string_descriptor *left_name, *right_name;
	const char *name;
	u32 area_size;
	u32 free_space;
	u32 used_space;
	size_t name_len;
	u32 left_hash_hi;
	u32 right_hash_hi;
	u32 search_hash_hi;
	u16 str_offset;
	u32 range_len;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!search->result.name) {
		SSDFS_ERR("empty buffer pointer\n");
		return -ERANGE;
	}

	area_size = node->items_area.area_size;
	free_space = node->items_area.free_space;

	if (free_space > area_size) {
		SSDFS_ERR("corrupted area: "
			  "area_size %u, free_space %u\n",
			  area_size, free_space);
		return -ERANGE;
	}

	used_space = area_size - free_space;

	name_len = search->request.start.name_len;

	if (name_len > free_space) {
		SSDFS_ERR("name_len %zu > free_space %u\n",
			  name_len, free_space);
		return -ENOSPC;
	}

	name = search->request.start.name;

	if (!name) {
		SSDFS_ERR("invalid name pointer\n");
		return -ERANGE;
	}

	search_hash_hi = SSDFS_HASH32_HI(search->request.start.hash);
	left_name = &search->result.name->left_name;
	left_hash_hi = le32_to_cpu(left_name->desc.hash_hi);
	right_name = &search->result.name->right_name;
	right_hash_hi = le32_to_cpu(right_name->desc.hash_hi);

	if (search_hash_hi >= U32_MAX || left_hash_hi >= U32_MAX ||
	    right_hash_hi >= U32_MAX) {
		SSDFS_ERR("invalid hash: "
			  "search_hash_hi %#x, left_hash_hi %#x, "
			  "right_hash_hi %#x\n",
			  search_hash_hi, left_hash_hi,
			  right_hash_hi);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("search (start.hash %llx, hash_hi %#x), "
		  "left_hash_hi %#x, right_hash_hi %#x\n",
		  search->request.start.hash,
		  search_hash_hi,
		  left_hash_hi,
		  right_hash_hi);
#endif /* CONFIG_SSDFS_DEBUG */

	if (search_hash_hi < left_hash_hi) {
		str_offset = le16_to_cpu(left_name->desc.str_offset);
		range_len = area_size - free_space - str_offset;

		err = ssdfs_shift_memory_range_right(node,
						     &node->items_area,
						     str_offset,
						     range_len,
						     name_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to shift the range: "
				  "start %u, range %u, "
				  "shift %zu, err %d\n",
				  str_offset, range_len, name_len, err);
			return err;
		}
	} else if (search_hash_hi <= right_hash_hi) {
		str_offset = le16_to_cpu(right_name->desc.str_offset);
		range_len = area_size - free_space - str_offset;

		err = ssdfs_shift_memory_range_right(node,
						     &node->items_area,
						     str_offset,
						     range_len,
						     name_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to shift the range: "
				  "start %u, range %u, "
				  "shift %zu, err %d\n",
				  str_offset, range_len, name_len, err);
			return err;
		}
	} else {
		str_offset = le16_to_cpu(right_name->desc.str_offset);
		str_offset += right_name->desc.str_len;

		if (str_offset < used_space) {
			range_len = area_size - free_space - str_offset;

			err = ssdfs_shift_memory_range_right(node,
							     &node->items_area,
							     str_offset,
							     range_len,
							     name_len);
			if (unlikely(err)) {
				SSDFS_ERR("fail to shift the range: "
					  "start %u, range %u, "
					  "shift %zu, err %d\n",
					  str_offset, range_len,
					  name_len, err);
				return err;
			}
		}
	}

	err = ssdfs_copy_string_from_buffer(node,
					    (char *)name, name_len,
					    str_offset);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy string: "
			  "node_id %u, str_offset %u, "
			  "name_len %zu, err %d\n",
			  node->node_id, str_offset,
			  name_len, err);
		return err;
	}

	if (search->request.start.hash < node->items_area.start_hash)
		node->items_area.start_hash = search->request.start.hash;

	if (node->items_area.end_hash < search->request.start.hash)
		node->items_area.end_hash = search->request.start.hash;

	return 0;
}

static
int ssdfs_add_string_in_empty_node(struct ssdfs_btree_node *node,
				   struct ssdfs_btree_search *search)
{
	const char *name;
	u32 area_size;
	u32 free_space;
	u16 items_count;
	u16 str_offset;
	size_t name_len;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	area_size = node->items_area.area_size;
	free_space = node->items_area.free_space;
	items_count = node->items_area.items_count;

	if (items_count != 0) {
		SSDFS_ERR("node is not empty\n");
		return -EINVAL;
	}

	if (free_space != area_size) {
		SSDFS_ERR("corrupted area: "
			  "free_space %u != area_size %u\n",
			  free_space, area_size);
		return -ERANGE;
	}

	name_len = search->request.start.name_len;

	if (name_len > free_space) {
		SSDFS_ERR("name_len %zu > free_space %u\n",
			  name_len, free_space);
		return -ENOSPC;
	}

	name = search->request.start.name;

	if (!name) {
		SSDFS_ERR("invalid name pointer\n");
		return -ERANGE;
	}

	str_offset = 0;

	err = ssdfs_copy_string_from_buffer(node,
					    (char *)name, name_len,
					    str_offset);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy string: "
			  "node_id %u, str_offset %u, "
			  "name_len %zu, err %d\n",
			  node->node_id, str_offset,
			  name_len, err);
		return err;
	}

	node->items_area.start_hash = search->request.start.hash;
	node->items_area.end_hash = search->request.start.hash;

	return 0;
}

static
int ssdfs_add_string_after_last_name(struct ssdfs_btree_node *node,
				     struct ssdfs_btree_search *search)
{
	struct ssdfs_string_descriptor *left_name;
	const char *name;
	size_t name_len;
	u32 free_space;
	u32 hash32_hi1, hash32_hi2;
	u16 str_offset;
	u16 items_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!search->result.name) {
		SSDFS_ERR("empty buffer pointer\n");
		return -ERANGE;
	}

	left_name = &search->result.name->left_name;
	hash32_hi1 = SSDFS_HASH32_HI(search->request.start.hash);
	hash32_hi2 = le32_to_cpu(left_name->desc.hash_hi);
	items_count = node->items_area.items_count;
	free_space = node->items_area.free_space;

	if ((left_name->index + 1) != items_count) {
		SSDFS_ERR("invalid request: index %u, items_count %u\n",
			  left_name->index, items_count);
		return -ERANGE;
	}

	if (hash32_hi1 <= hash32_hi2) {
		SSDFS_ERR("invalid position: "
			  "name->hash %#x, "
			  "desc.hash %#x\n",
			  hash32_hi1, hash32_hi2);
		return -ERANGE;
	}

	name_len = search->request.start.name_len;

	if (name_len > free_space) {
		SSDFS_ERR("name_len %zu > free_space %u\n",
			  name_len, free_space);
		return -ENOSPC;
	}

	name = search->request.start.name;

	if (!name) {
		SSDFS_ERR("invalid name pointer\n");
		return -ERANGE;
	}

	str_offset = le16_to_cpu(left_name->desc.str_offset);
	str_offset += left_name->desc.str_len;

	err = ssdfs_copy_string_from_buffer(node, (char *)name,
					    name_len, str_offset);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy string: "
			  "node_id %u, str_offset %u, "
			  "name_len %zu, err %d\n",
			  node->node_id, str_offset,
			  name_len, err);
		return err;
	}

	if (search->request.start.hash < node->items_area.start_hash)
		node->items_area.start_hash = search->request.start.hash;

	if (node->items_area.end_hash < search->request.start.hash)
		node->items_area.end_hash = search->request.start.hash;

	return 0;
}

static
int ssdfs_add_string_before_first_name(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
	struct ssdfs_string_descriptor *left_name;
	const char *name;
	size_t name_len;
	u32 area_size;
	u32 free_space;
	u32 hash32_hi1, hash32_hi2;
	u16 str_offset;
	u32 range_len;
	u16 items_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!search->result.name) {
		SSDFS_ERR("empty buffer pointer\n");
		return -ERANGE;
	}

	left_name = &search->result.name->left_name;
	hash32_hi1 = SSDFS_HASH32_HI(search->request.start.hash);
	hash32_hi2 = le32_to_cpu(left_name->desc.hash_hi);
	area_size = node->items_area.area_size;
	items_count = node->items_area.items_count;
	free_space = node->items_area.free_space;

	if (left_name->index != 0) {
		SSDFS_ERR("invalid request: index %u\n",
			  left_name->index);
		return -ERANGE;
	}

	if (hash32_hi1 >= hash32_hi2) {
		SSDFS_ERR("invalid position: "
			  "name->hash %#x, "
			  "desc.hash %#x\n",
			  hash32_hi1,
			  hash32_hi2);
		return -ERANGE;
	}

	name_len = search->request.start.name_len;

	if (name_len > free_space) {
		SSDFS_ERR("name_len %zu > free_space %u\n",
			  name_len, free_space);
		return -ENOSPC;
	}

	name = search->request.start.name;

	if (!name) {
		SSDFS_ERR("invalid name pointer\n");
		return -ERANGE;
	}

	str_offset = 0;
	range_len = area_size - free_space;

	err = ssdfs_shift_memory_range_right(node, &node->items_area,
					     str_offset, range_len,
					     name_len);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shift the range: "
			  "start %u, range %u, "
			  "shift %zu, err %d\n",
			  str_offset, range_len,
			  name_len, err);
		return err;
	}

	err = ssdfs_copy_string_from_buffer(node, (char *)name,
					    name_len, str_offset);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy string: "
			  "node_id %u, str_offset %u, "
			  "name_len %zu, err %d\n",
			  node->node_id, str_offset,
			  name_len, err);
		return err;
	}

	if (search->request.start.hash < node->items_area.start_hash)
		node->items_area.start_hash = search->request.start.hash;

	if (node->items_area.end_hash < search->request.start.hash)
		node->items_area.end_hash = search->request.start.hash;

	return 0;
}

/*
 * ssdfs_insert_full_string() - insert the full string into the node
 * @node: pointer on node object
 * @search: search object
 *
 * This method tries to insert the full name into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - not enough free space for the string.
 */
static
int ssdfs_insert_full_string(struct ssdfs_btree_node *node,
			     struct ssdfs_btree_search *search)
{
	struct ssdfs_string_descriptor *left_name;
	u32 area_size;
	u32 free_space;
	u16 items_count;
	u32 items_capacity;
	size_t name_len;
	u8 min_item_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
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

	area_size = node->items_area.area_size;
	free_space = node->items_area.free_space;
	items_count = node->items_area.items_count;
	min_item_size = node->items_area.min_item_size;

	if (min_item_size != SSDFS_DENTRY_INLINE_NAME_MAX_LEN) {
		SSDFS_ERR("invalid min_item_size %u\n",
			  min_item_size);
		return -ERANGE;
	}

	if (free_space > area_size) {
		SSDFS_ERR("free_space %u > area_size %u\n",
			  free_space, area_size);
		return -ERANGE;
	}

	if (!(search->request.flags &
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE)) {
		SSDFS_ERR("request doesn't contain the hash\n");
		return -ERANGE;
	}

	if (!(search->request.flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME)) {
		SSDFS_ERR("request doesn't contain the name\n");
		return -ERANGE;
	}

	if (search->request.count != 1) {
		SSDFS_ERR("invalid request: "
			  "search->request.count %u\n",
			  search->request.count);
		return -ERANGE;
	}

	name_len = search->request.start.name_len;

	if (name_len > free_space) {
		SSDFS_ERR("name_len %zu > free_space %u\n",
			  name_len, free_space);
		return -ENOSPC;
	}

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
		err = __ssdfs_insert_full_string(node, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert string: "
				  "node_id %u, "
				  "name_len %zu, err %d\n",
				  node->node_id,
				  name_len, err);
			return err;
		}
		break;

	case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
		if (items_count == 0) {
			err = ssdfs_add_string_in_empty_node(node, search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add string: "
					  "node_id %u, err %d\n",
					  node->node_id, err);
				return err;
			}
		} else {
			left_name = &search->result.name->left_name;

			if ((left_name->index + 1) == items_count) {
				err = ssdfs_add_string_after_last_name(node,
									search);
				if (unlikely(err)) {
					SSDFS_ERR("fail to add string: "
						  "err %d\n", err);
					return err;
				}
			} else if (left_name->index == 0) {
				err = ssdfs_add_string_before_first_name(node,
									search);
				if (unlikely(err)) {
					SSDFS_ERR("fail to add string: "
						  "err %d\n", err);
					return err;
				}
			} else {
				SSDFS_ERR("invalid index: "
					  "left_name->index %u\n",
					  left_name->index);
				return -ERANGE;
			}
		}
		break;

	default:
		SSDFS_ERR("unexpected result state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	node->items_area.items_count += 1;
	node->items_area.free_space -= name_len;

	node->items_area.item_size = ssdfs_define_item_size(node);

	items_capacity = ssdfs_define_items_capacity(node);
	if (items_capacity >= U16_MAX) {
		SSDFS_ERR("invalid items_capacity %u\n",
			  items_capacity);
		return -ERANGE;
	}

	node->items_area.items_capacity = (u16)items_capacity;

	return 0;
}

/*
 * __ssdfs_hash_table_insert_descriptor() - insert the hash descriptor
 * @node: node object
 * @search: search object
 * @index: index of the item in the hash table
 * @desc: pointer on the hash descriptor [in]
 *
 * This method tries to insert the hash descriptor into
 * the hash table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - the hash table hasn't vacant items.
 */
static
int __ssdfs_hash_table_insert_descriptor(struct ssdfs_btree_node *node,
					 struct ssdfs_btree_search *search,
					 u16 index,
					 struct ssdfs_shdict_htbl_item *desc)
{
	struct ssdfs_shdict_htbl_item cur_desc;
	u16 items_count;
	u16 items_capacity;
	u8 item_size;
	u16 range_len;
	u16 shift;
	u32 desc_str_offset;
	u8 str_len;
	u32 str_offset;
	u16 i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !desc || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, index %u\n",
		  node->node_id, index);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->hash_tbl_area.state)) {
	case SSDFS_BTREE_NODE_HASH_TBL_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid hash_tbl_area state %#x\n",
			  atomic_read(&node->hash_tbl_area.state));
		return -ERANGE;
	}

	items_count = node->lookup_tbl_area.index_count;

	for (i = 0; i < items_count; i++) {
		struct ssdfs_shdict_ltbl2_item cur_desc;
		u16 cur_index;

		err = ssdfs_get_lookup2_descriptor(node,
						   &node->lookup_tbl_area,
						   i, &cur_desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get lookup2 descriptor: "
				  "index %u, err %d\n",
				  i, err);
			return err;
		}

		cur_index = le16_to_cpu(cur_desc.hash_index);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index %u, cur_index %u\n",
			  index, cur_index);
#endif /* CONFIG_SSDFS_DEBUG */

		if (cur_index >= index) {
			le16_add_cpu(&cur_desc.hash_index, 1);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("correct lookup2_table: "
				  "lookup2_index %d, "
				  "hash_index (old %u, new %u), "
				  "hash_lo %#x\n",
				  i, cur_index,
				  le16_to_cpu(cur_desc.hash_index),
				  le32_to_cpu(cur_desc.hash_lo));
#endif /* CONFIG_SSDFS_DEBUG */

			err = ssdfs_set_lookup2_descriptor(node,
						   &node->lookup_tbl_area,
						   i, &cur_desc);
			if (unlikely(err)) {
				SSDFS_ERR("fail to set lookup2 descriptor: "
					  "index %u, err %d\n",
					  i, err);
				return err;
			}
		}
	}

	ssdfs_mark_lookup2_table_dirty(node);

	items_count = node->hash_tbl_area.index_count;
	items_capacity = node->hash_tbl_area.index_capacity;
	item_size = node->hash_tbl_area.index_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_count %u, items_capacity %u, item_size %u\n",
		  items_count, items_capacity, item_size);
#endif /* CONFIG_SSDFS_DEBUG */

	if (item_size != sizeof(struct ssdfs_shdict_htbl_item)) {
		SSDFS_ERR("corrupted area: "
			  "item_size %u\n",
			  item_size);
		return -ERANGE;
	}

	if (items_count > items_capacity) {
		SSDFS_ERR("items_count %u > items_capacity %u\n",
			  items_count, items_capacity);
		return -ERANGE;
	} else if (items_count == items_capacity) {
		SSDFS_ERR("items_count %u == items_capacity %u\n",
			  items_count, items_capacity);
		return -ENOSPC;
	}

	if (index > items_count) {
		SSDFS_ERR("index %u > items_count %u\n",
			  index, items_count);
		return -ERANGE;
	}

	if (index < items_count) {
		range_len = items_count - index;
		shift = 1;

		err = ssdfs_shift_range_right2(node, &node->hash_tbl_area,
						item_size,
						index, range_len,
						shift);
		if (unlikely(err)) {
			SSDFS_ERR("fail to shift the range: "
				  "index %u, range_len %u, "
				  "shift %u, err %d\n",
				  index, range_len, shift, err);
			return err;
		}
	}

	err = ssdfs_set_hash_descriptor(node, &node->hash_tbl_area,
					index, desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set hash descriptor: "
			  "index %u, err %d\n",
			  index, err);
		return err;
	}

	if (index == 0)
		node->hash_tbl_area.start_hash = search->request.start.hash;

	if (index == items_count)
		node->hash_tbl_area.end_hash = search->request.start.hash;

	node->hash_tbl_area.index_count++;
	items_count = node->hash_tbl_area.index_count;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_count %u, items_capacity %u, item_size %u\n",
		  items_count, items_capacity, item_size);
#endif /* CONFIG_SSDFS_DEBUG */

	desc_str_offset = le16_to_cpu(desc->str_offset);
	str_len = desc->str_len;

	i = index + 1;

	if (i >= items_count)
		goto mark_hash_table_dirty;

	err = ssdfs_get_hash_descriptor(node, &node->hash_tbl_area,
					i, &cur_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash descriptor: "
			  "index %u, err %d\n",
			  i, err);
		return err;
	}

	str_offset = le16_to_cpu(cur_desc.str_offset);

	if (str_offset == (desc_str_offset + str_len)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("no necessity correct string offset: "
			  "str_offset %u, desc_str_offset %u, "
			  "str_len %u\n",
			  str_offset, desc_str_offset, str_len);
#endif /* CONFIG_SSDFS_DEBUG */
		goto mark_hash_table_dirty;
	}

	for (; i < items_count; i++) {
		err = ssdfs_get_hash_descriptor(node, &node->hash_tbl_area,
						i, &cur_desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get hash descriptor: "
				  "index %u, err %d\n",
				  i, err);
			return err;
		}

		str_offset = le16_to_cpu(cur_desc.str_offset);
		str_offset += str_len;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index %u, old str_offset %u, "
			  "new str_offset %u, str_len %u\n",
			  i, le16_to_cpu(cur_desc.str_offset),
			  str_offset, str_len);
#endif /* CONFIG_SSDFS_DEBUG */

		if (str_offset >= U16_MAX) {
			SSDFS_ERR("invalid str_offset %u\n",
				  str_offset);
			return -ERANGE;
		}

		cur_desc.str_offset = cpu_to_le16((u16)str_offset);

		err = ssdfs_set_hash_descriptor(node, &node->hash_tbl_area,
						i, &cur_desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set hash descriptor: "
				  "index %u, err %d\n",
				  i, err);
			return err;
		}
	}

mark_hash_table_dirty:
	ssdfs_mark_hash_table_dirty(node);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search->result.name);
#endif /* CONFIG_SSDFS_DEBUG */

	search->result.name->placement.hash_index = index;

	return 0;
}

/*
 * ssdfs_hash_table_insert_before_left_name() - insert the hash descriptor
 * @node: node object
 * @search: search object
 * @str_len: string length
 * @str_type: string type
 *
 * This method tries to insert the hash descriptor before left name.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - hash table hasn't vacant items.
 * %-EEXIST     - hash table contains the descriptor already.
 */
static inline
int ssdfs_hash_table_insert_before_left_name(struct ssdfs_btree_node *node,
					     struct ssdfs_btree_search *search,
					     u8 str_len, u8 str_type)
{
	struct ssdfs_string_descriptor *left_name;
	struct ssdfs_shdict_htbl_item desc;
	u32 str_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, str_len %u, str_type %#x\n",
		  node->node_id, str_len, str_type);
#endif /* CONFIG_SSDFS_DEBUG */

	left_name = &search->result.name->left_name;

	desc.hash_hi = cpu_to_le32(SSDFS_HASH32_HI(search->request.start.hash));

	str_offset = le16_to_cpu(left_name->desc.str_offset);
	if ((str_offset + str_len) > node->items_area.area_size) {
		SSDFS_ERR("invalid offset: "
			  "str_offset %u, "
			  "area_size %u\n",
			  str_offset,
			  node->items_area.area_size);
		return -ERANGE;
	}

	desc.str_offset = cpu_to_le16((u16)str_offset);

	desc.str_len = str_len;
	desc.type = str_type;

	err = __ssdfs_hash_table_insert_descriptor(node, search,
						   left_name->index,
						   &desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert hash: "
			  "node_id %u, index %u, "
			  "err %d\n",
			  node->node_id, left_name->index, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_hash_table_insert_before_right_name() - insert the hash descriptor
 * @node: node object
 * @search: search object
 * @str_len: string length
 * @str_type: string type
 *
 * This method tries to insert the hash descriptor before right name.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - hash table hasn't vacant items.
 * %-EEXIST     - hash table contains the descriptor already.
 */
static inline
int ssdfs_hash_table_insert_before_right_name(struct ssdfs_btree_node *node,
					      struct ssdfs_btree_search *search,
					      u8 str_len, u8 str_type)
{
	struct ssdfs_string_descriptor *left_name, *right_name;
	struct ssdfs_shdict_htbl_item desc;
	u32 str_offset;
	u16 index;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, str_len %u, str_type %#x\n",
		  node->node_id, str_len, str_type);
#endif /* CONFIG_SSDFS_DEBUG */

	left_name = &search->result.name->left_name;
	right_name = &search->result.name->right_name;

	switch (left_name->desc.type) {
	case SSDFS_NAME_PREFIX:
		switch (right_name->desc.type) {
		case SSDFS_NAME_PREFIX:
		case SSDFS_NAME_SUFFIX:
		case SSDFS_FULL_NAME:
			if (str_type != SSDFS_NAME_SUFFIX) {
				SSDFS_ERR("invalid type: str_type %#x\n",
					  str_type);
				return -ERANGE;
			}
			break;

		default:
			SSDFS_ERR("invalid type: right_name %#x\n",
				  right_name->desc.type);
			return -ERANGE;
		}
		break;

	case SSDFS_NAME_SUFFIX:
		switch (right_name->desc.type) {
		case SSDFS_NAME_PREFIX:
		case SSDFS_NAME_SUFFIX:
		case SSDFS_FULL_NAME:
			/* any str_type is valid */
			break;

		default:
			SSDFS_ERR("invalid type: right_name %#x\n",
				  right_name->desc.type);
			return -ERANGE;
		}
		break;

	case SSDFS_FULL_NAME:
		switch (right_name->desc.type) {
		case SSDFS_NAME_PREFIX:
		case SSDFS_FULL_NAME:
			if (str_type == SSDFS_NAME_SUFFIX) {
				SSDFS_ERR("invalid type: str_type %#x\n",
					  str_type);
				return -ERANGE;
			}
			break;

		default:
			SSDFS_ERR("invalid type: right_name %#x\n",
				  right_name->desc.type);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("invalid type: left_name %#x\n",
			  left_name->desc.type);
		return -ERANGE;
	}

	desc.hash_hi = cpu_to_le32(SSDFS_HASH32_HI(search->request.start.hash));

	str_offset = le16_to_cpu(right_name->desc.str_offset);
	if ((str_offset + str_len) > node->items_area.area_size) {
		SSDFS_ERR("invalid offset: str_offset %u, area_size %u\n",
			  str_offset, node->items_area.area_size);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("right_name: (str_offset %u, str_len %u), "
		  "str_offset %u\n",
		  le16_to_cpu(right_name->desc.str_offset),
		  right_name->desc.str_len,
		  str_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	desc.str_offset = cpu_to_le16((u16)str_offset);

	desc.str_len = str_len;
	desc.type = str_type;

	index = right_name->index;
	err = __ssdfs_hash_table_insert_descriptor(node, search,
						   right_name->index,
						   &desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert hash: "
			  "node_id %u, index %u, err %d\n",
			  node->node_id, index, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_hash_table_insert_after_right_name() - insert the hash descriptor
 * @node: node object
 * @search: search object
 * @str_len: string length
 * @str_type: string type
 *
 * This method tries to insert the hash descriptor after right name.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - hash table hasn't vacant items.
 * %-EEXIST     - hash table contains the descriptor already.
 */
static inline
int ssdfs_hash_table_insert_after_right_name(struct ssdfs_btree_node *node,
					     struct ssdfs_btree_search *search,
					     u8 str_len, u8 str_type)
{
	struct ssdfs_string_descriptor *right_name;
	struct ssdfs_shdict_htbl_item desc;
	u32 str_offset;
	u16 index;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, str_len %u, str_type %#x\n",
		  node->node_id, str_len, str_type);
#endif /* CONFIG_SSDFS_DEBUG */

	right_name = &search->result.name->right_name;

	desc.hash_hi = cpu_to_le32(SSDFS_HASH32_HI(search->request.start.hash));

	str_offset = le16_to_cpu(right_name->desc.str_offset);
	str_offset += right_name->desc.str_len;
	if ((str_offset + str_len) > node->items_area.area_size) {
		SSDFS_ERR("invalid offset: str_offset %u, area_size %u\n",
			  str_offset, node->items_area.area_size);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(str_offset >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	desc.str_offset = cpu_to_le16((u16)str_offset);

	desc.str_len = str_len;
	desc.type = str_type;

	index = right_name->index + 1;
	err = __ssdfs_hash_table_insert_descriptor(node, search, index, &desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert hash: "
			  "node_id %u, index %u, "
			  "err %d\n",
			  node->node_id, index, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_hash_table_insert_into_found_position() - insert the hash descriptor
 * @node: node object
 * @search: search object
 * @str_len: string length
 * @str_type: string type
 *
 * This method tries to insert the hash descriptor into found position.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - hash table hasn't vacant items.
 * %-EEXIST     - hash table contains the descriptor already.
 */
static
int ssdfs_hash_table_insert_into_found_position(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search,
					    u8 str_len, u8 str_type)
{
	struct ssdfs_string_descriptor *left_name, *right_name;
	u32 left_name_hash, right_name_hash, request_hash;
	u16 index1, index2;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, str_len %u, str_type %#x\n",
		  node->node_id, str_len, str_type);
#endif /* CONFIG_SSDFS_DEBUG */

	left_name = &search->result.name->left_name;
	right_name = &search->result.name->right_name;
	request_hash = SSDFS_HASH32_HI(search->request.start.hash);
	left_name_hash = le32_to_cpu(left_name->desc.hash_hi);
	right_name_hash = le32_to_cpu(right_name->desc.hash_hi);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("request_hash %#x, "
		  "left_name_hash %#x, right_name_hash %#x, "
		  "left_name->index %u, right_name->index %u\n",
		  request_hash,
		  left_name_hash,
		  right_name_hash,
		  left_name->index,
		  right_name->index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (left_name_hash > right_name_hash) {
		SSDFS_ERR("invalid hash: left_name %#x, right_name %#x\n",
			  left_name_hash, right_name_hash);
		return -ERANGE;
	}

	if (left_name_hash == right_name_hash) {
		index1 = left_name->index;
		index2 = right_name->index;
	} else {
		index1 = left_name->index + 1;
		index2 = right_name->index;
	}

	if (index1 != index2) {
		SSDFS_ERR("invalid index: index1 %u, index2 %u\n",
			  index1, index2);
		return -ERANGE;
	}

	if (left_name_hash == request_hash) {
		SSDFS_ERR("invalid hash: "
			  "request %#x == left_name %#x\n",
			  request_hash, left_name_hash);
		return -EEXIST;
	} else if (request_hash < left_name_hash) {
		err = ssdfs_hash_table_insert_before_left_name(node,
					    search, str_len, str_type);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert descriptor: "
				  "err %d\n", err);
			return err;
		}
	} else if (left_name_hash < request_hash &&
		   request_hash < right_name_hash) {
		err = ssdfs_hash_table_insert_before_right_name(node,
					    search, str_len, str_type);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert descriptor: "
				  "err %d\n", err);
			return err;
		}
	} else if (request_hash == right_name_hash) {
		SSDFS_ERR("invalid hash: "
			  "request %#x == right_name %#x\n",
			  request_hash, right_name_hash);
		return -EEXIST;
	} else {
		err = ssdfs_hash_table_insert_after_right_name(node,
					    search, str_len, str_type);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert descriptor: "
				  "err %d\n", err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_hash_table_insert_into_empty_table() - insert the hash descriptor
 * @node: node object
 * @search: search object
 * @str_len: string length
 * @str_type: string type
 *
 * This method tries to insert the hash descriptor into empty table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - hash table hasn't vacant items.
 * %-EEXIST     - hash table contains the descriptor already.
 */
static inline
int ssdfs_hash_table_insert_into_empty_table(struct ssdfs_btree_node *node,
					     struct ssdfs_btree_search *search,
					     u8 str_len, u8 str_type)
{
	struct ssdfs_shdict_htbl_item desc;
	u16 items_count;
	u16 index;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, str_len %u, str_type %#x\n",
		  node->node_id, str_len, str_type);
#endif /* CONFIG_SSDFS_DEBUG */

	items_count = node->hash_tbl_area.index_count;

	if (items_count > 0) {
		SSDFS_ERR("hash table is not empty\n");
		return -ERANGE;
	}

	desc.hash_hi = cpu_to_le32(SSDFS_HASH32_HI(search->request.start.hash));
	desc.str_offset = cpu_to_le16(0);

	if (str_len != search->request.start.name_len) {
		SSDFS_ERR("invalid string length: "
			  "str_len %u, name_len %zu\n",
			  str_len, search->request.start.name_len);
		return -ERANGE;
	}

	desc.str_len = str_len;

	if (str_type != SSDFS_FULL_NAME) {
		SSDFS_ERR("invalid str_type %#x\n",
			  str_type);
		return -ERANGE;
	}

	desc.type = str_type;

	index = 0;
	err = __ssdfs_hash_table_insert_descriptor(node, search, index, &desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert hash descriptor: "
			  "node_id %u, index %u, err %d\n",
			  node->node_id, index, err);
		return err;
	}

	node->hash_tbl_area.start_hash = search->request.start.hash;
	node->hash_tbl_area.end_hash = search->request.start.hash;

	return 0;
}

/*
 * ssdfs_hash_table_insert_before_prefix() - insert the hash descriptor
 * @node: node object
 * @search: search object
 * @str_len: string length
 * @str_type: string type
 *
 * This method tries to insert the hash descriptor before prefix.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - hash table hasn't vacant items.
 * %-EEXIST     - hash table contains the descriptor already.
 */
static inline
int ssdfs_hash_table_insert_before_prefix(struct ssdfs_btree_node *node,
					  struct ssdfs_btree_search *search,
					  u8 str_len, u8 str_type)
{
	struct ssdfs_string_descriptor *prefix, *left_name;
	struct ssdfs_shdict_htbl_item desc;
	u16 index, index1, index2;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, str_len %u, str_type %#x\n",
		  node->node_id, str_len, str_type);
#endif /* CONFIG_SSDFS_DEBUG */

	prefix = &search->result.name->prefix;
	left_name = &search->result.name->left_name;

	if (prefix->index != 0) {
		SSDFS_ERR("invalid index: prefix->index %u\n",
			  prefix->index);
		return -ERANGE;
	}

	switch (prefix->desc.type) {
	case SSDFS_NAME_PREFIX:
		index1 = prefix->index + 1;
		index2 = left_name->index;
		if (index1 != index2) {
			SSDFS_ERR("invalid index: "
				  "type %#x, prefix %u, left_name %u\n",
				  prefix->desc.type,
				  prefix->index,
				  left_name->index);
			return -ERANGE;
		}
		break;

	case SSDFS_FULL_NAME:
		index1 = prefix->index;
		index2 = left_name->index;
		if (index1 != index2) {
			SSDFS_ERR("invalid index: "
				  "type %#x, prefix %u, left_name %u\n",
				  prefix->desc.type,
				  prefix->index,
				  left_name->index);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("invalid prefix type %#x\n",
			  prefix->desc.type);
		return -ERANGE;
	}

	switch (str_type) {
	case SSDFS_NAME_PREFIX:
	case SSDFS_FULL_NAME:
		/* expected type */
		break;

	default:
		SSDFS_ERR("invalid type: str_type %#x\n",
			  str_type);
		return -ERANGE;
	}

	desc.hash_hi = cpu_to_le32(SSDFS_HASH32_HI(search->request.start.hash));
	desc.str_offset = cpu_to_le16(0);
	desc.str_len = str_len;
	desc.type = str_type;

	index = prefix->index;
	err = __ssdfs_hash_table_insert_descriptor(node, search, index, &desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert hash: "
			  "node_id %u, index %u, "
			  "err %d\n",
			  node->node_id, index, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_hash_table_insert_after_prefix() - insert the hash descriptor
 * @node: node object
 * @search: search object
 * @str_len: string length
 * @str_type: string type
 *
 * This method tries to insert the hash descriptor after prefix.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - hash table hasn't vacant items.
 * %-EEXIST     - hash table contains the descriptor already.
 */
static inline
int ssdfs_hash_table_insert_after_prefix(struct ssdfs_btree_node *node,
					 struct ssdfs_btree_search *search,
					 u8 str_len, u8 str_type)
{
	struct ssdfs_string_descriptor *prefix, *left_name;
	struct ssdfs_shdict_htbl_item desc;
	u16 index, index1, index2;
	u32 str_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, str_len %u, str_type %#x\n",
		  node->node_id, str_len, str_type);
#endif /* CONFIG_SSDFS_DEBUG */

	prefix = &search->result.name->prefix;
	left_name = &search->result.name->left_name;

	if (prefix->index != 0) {
		SSDFS_ERR("invalid index: "
			  "prefix->index %u\n",
			  prefix->index);
		return -ERANGE;
	}

	switch (prefix->desc.type) {
	case SSDFS_NAME_PREFIX:
		index1 = prefix->index + 1;
		index2 = left_name->index;
		if (index1 != index2) {
			SSDFS_ERR("invalid index: type %#x, "
				  "prefix %u, left_name %u\n",
				  prefix->desc.type,
				  prefix->index,
				  left_name->index);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("invalid prefix type %#x\n",
			  prefix->desc.type);
		return -ERANGE;
	}

	switch (str_type) {
	case SSDFS_NAME_SUFFIX:
		/* expected type */
		break;

	default:
		SSDFS_ERR("invalid type: str_type %#x\n",
			  str_type);
		return -ERANGE;
	}

	desc.hash_hi = cpu_to_le32(SSDFS_HASH32_HI(search->request.start.hash));

	str_offset = le16_to_cpu(prefix->desc.str_offset);
	str_offset += prefix->desc.str_len;

	if (str_offset >= node->items_area.area_size || str_offset >= U16_MAX) {
		SSDFS_ERR("invalid offset: str_offset %u, area_size %u\n",
			  str_offset, node->items_area.area_size);
		return -ERANGE;
	}

	desc.str_offset = cpu_to_le16((u16)str_offset);

	desc.str_len = str_len;
	desc.type = str_type;

	index = left_name->index;
	err = __ssdfs_hash_table_insert_descriptor(node, search, index, &desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert hash: "
			  "node_id %u, index %u, "
			  "err %d\n",
			  node->node_id, index, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_hash_table_insert_after_suffix() - insert the hash descriptor
 * @node: node object
 * @search: search object
 * @str_len: string length
 * @str_type: string type
 *
 * This method tries to insert the hash descriptor after suffix.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - hash table hasn't vacant items.
 * %-EEXIST     - hash table contains the descriptor already.
 */
static inline
int ssdfs_hash_table_insert_after_suffix(struct ssdfs_btree_node *node,
					 struct ssdfs_btree_search *search,
					 u8 str_len, u8 str_type)
{
	struct ssdfs_string_descriptor *left_name;
	struct ssdfs_shdict_htbl_item desc;
	u16 index;
	u16 items_count;
	u32 str_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, str_len %u, str_type %#x\n",
		  node->node_id, str_len, str_type);
#endif /* CONFIG_SSDFS_DEBUG */

	left_name = &search->result.name->left_name;
	items_count = node->hash_tbl_area.index_count;

	if ((left_name->index + 1) != items_count) {
		SSDFS_ERR("invalid index: "
			  "left_name->index %u, items_count %u\n",
			  left_name->index,
			  items_count);
		return -ERANGE;
	}

	desc.hash_hi = cpu_to_le32(SSDFS_HASH32_HI(search->request.start.hash));

	str_offset = le16_to_cpu(left_name->desc.str_offset);
	str_offset += left_name->desc.str_len;

	if (str_offset >= node->items_area.area_size || str_offset >= U16_MAX) {
		SSDFS_ERR("invalid offset: "
			  "str_offset %u, area_size %u\n",
			  str_offset, node->items_area.area_size);
		return -ERANGE;
	}

	desc.str_offset = cpu_to_le16((u16)str_offset);

	if (str_len > search->request.start.name_len) {
		SSDFS_ERR("invalid string length: "
			  "str_len %u, name_len %zu\n",
			str_len, search->request.start.name_len);
		return -ERANGE;
	}

	desc.str_len = str_len;

	switch (str_type) {
	case SSDFS_NAME_PREFIX:
	case SSDFS_NAME_SUFFIX:
	case SSDFS_FULL_NAME:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid str_type %#x\n",
			  str_type);
		return -ERANGE;
	}

	desc.type = str_type;

	index = left_name->index + 1;
	err = __ssdfs_hash_table_insert_descriptor(node, search, index, &desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert descriptor: "
			  "node_id %u, index %u, err %d\n",
			  node->node_id, index,
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_hash_table_add_after_found_position() - insert the hash descriptor
 * @node: node object
 * @search: search object
 * @str_len: string length
 * @str_type: string type
 *
 * This method tries to insert the hash descriptor after found position.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - hash table hasn't vacant items.
 * %-EEXIST     - hash table contains the descriptor already.
 */
static inline
int ssdfs_hash_table_add_after_found_position(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search,
					    u8 str_len, u8 str_type)
{
	struct ssdfs_string_descriptor *prefix, *left_name;
	u32 prefix_hash, left_name_hash, request_hash;
	u16 items_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, str_len %u, str_type %#x\n",
		  node->node_id, str_len, str_type);
#endif /* CONFIG_SSDFS_DEBUG */

	items_count = node->hash_tbl_area.index_count;

	if (items_count <= 1) {
		err = ssdfs_hash_table_insert_into_empty_table(node, search,
								str_len,
								str_type);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert descriptor: "
				  "err %d\n", err);
			return err;
		}
	} else {
		if (!search->result.name) {
			SSDFS_ERR("empty buffer pointer\n");
			return -ERANGE;
		}

		prefix = &search->result.name->prefix;
		left_name = &search->result.name->left_name;
		request_hash = SSDFS_HASH32_HI(search->request.start.hash);
		prefix_hash = le32_to_cpu(prefix->desc.hash_hi);
		left_name_hash = le32_to_cpu(left_name->desc.hash_hi);

		if (prefix_hash > left_name_hash) {
			SSDFS_ERR("prefix %#x > left_name %#x\n",
				  prefix_hash, left_name_hash);
			return -ERANGE;
		}

		if (request_hash < prefix_hash) {
			err = ssdfs_hash_table_insert_before_prefix(node,
								    search,
								    str_len,
								    str_type);
			if (unlikely(err)) {
				SSDFS_ERR("fail to insert descriptor: "
					  "err %d\n", err);
				return err;
			}
		} else if (request_hash == prefix_hash) {
			SSDFS_ERR("invalid hash: "
				  "request %#x == prefix %#x\n",
				  request_hash, prefix_hash);
			return -EEXIST;
		} else if (request_hash > prefix_hash &&
			    request_hash < left_name_hash) {
			err = ssdfs_hash_table_insert_after_prefix(node,
								   search,
								   str_len,
								   str_type);
			if (unlikely(err)) {
				SSDFS_ERR("fail to insert descriptor: "
					  "err %d\n", err);
				return err;
			}
		} else if (request_hash > prefix_hash &&
			   request_hash == left_name_hash) {
			SSDFS_ERR("invalid hash: "
				  "request %#x == left_name %#x\n",
				  request_hash, left_name_hash);
			return -EEXIST;
		} else if (request_hash > left_name_hash) {
			err = ssdfs_hash_table_insert_after_suffix(node,
								   search,
								   str_len,
								   str_type);
			if (unlikely(err)) {
				SSDFS_ERR("fail to insert descriptor: "
					  "err %d\n", err);
				return err;
			}
		} else
			BUG();
	}

	return 0;
}

/*
 * ssdfs_hash_table_insert_descriptor() - insert the hash descriptor
 * @node: node object
 * @search: search object
 * @str_len: string length
 * @str_type: string type
 *
 * This method tries to insert the hash descriptor for the string.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - hash table hasn't vacant items.
 * %-EEXIST     - hash table contains the descriptor already.
 */
static
int ssdfs_hash_table_insert_descriptor(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search,
					u8 str_len, u8 str_type)
{
	u16 items_count;
	u16 items_capacity;
	u16 item_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, str_len %u, str_type %#x\n",
		  node->node_id, str_len, str_type);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->hash_tbl_area.state)) {
	case SSDFS_BTREE_NODE_HASH_TBL_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid hash_tbl_area state %#x\n",
			  atomic_read(&node->hash_tbl_area.state));
		return -ERANGE;
	}

	if (!(search->request.flags &
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE)) {
		SSDFS_ERR("request doesn't contain the hash\n");
		return -ERANGE;
	}

	if (!(search->request.flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME)) {
		SSDFS_ERR("request doesn't contain the name\n");
		return -ERANGE;
	}

	if (search->request.count != 1) {
		SSDFS_ERR("invalid request: "
			  "search->request.count %u\n",
			  search->request.count);
		return -ERANGE;
	}

	items_count = node->hash_tbl_area.index_count;
	items_capacity = node->hash_tbl_area.index_capacity;
	item_size = node->hash_tbl_area.index_size;

	if (items_count == items_capacity) {
		SSDFS_ERR("no vacant items: "
			  "items_count %u, items_capacity %u\n",
			  items_count, items_capacity);
		return -ENOSPC;
	} else if (items_count > items_capacity) {
		SSDFS_ERR("items_count %u > items_capacity %u\n",
			  items_count, items_capacity);
		return -ERANGE;
	}

	if (item_size != sizeof(struct ssdfs_shdict_htbl_item)) {
		SSDFS_ERR("invalid item size %u\n",
			  item_size);
		return -ERANGE;
	}

	if (str_len > SSDFS_MAX_NAME_LEN) {
		SSDFS_ERR("str_len %u > max_name_len %u\n",
			  str_len, SSDFS_MAX_NAME_LEN);
		return -ERANGE;
	}

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
		err = ssdfs_hash_table_insert_into_found_position(node, search,
								  str_len,
								  str_type);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert descriptor: "
				  "err %d\n", err);
			return err;
		}
		break;

	case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
		err = ssdfs_hash_table_add_after_found_position(node, search,
								str_len,
								str_type);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert descriptor: "
				  "err %d\n", err);
			return err;
		}
		break;

	default:
		SSDFS_ERR("unexpected result state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_lookup2_table_inc_str_count() - increment the strings count
 * @node: node object
 * @search: search object
 *
 * This method tries to increment the strings count for
 * the existing descriptor in the lookup2 table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_lookup2_table_inc_str_count(struct ssdfs_btree_node *node,
				      struct ssdfs_btree_search *search)
{
	struct ssdfs_shdict_ltbl2_item read_desc;
	u32 found_hash32;
	u32 req_hash32;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	switch (atomic_read(&node->lookup_tbl_area.state)) {
	case SSDFS_BTREE_NODE_LOOKUP_TBL_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid lookup_tbl_area state %#x\n",
			  atomic_read(&node->lookup_tbl_area.state));
		return -ERANGE;
	}

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(search->request.flags &
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE)) {
		SSDFS_ERR("valid hash is absent in request\n");
		return -ERANGE;
	}

	req_hash32 = SSDFS_HASH32_LO(search->request.start.hash);
	found_hash32 = le32_to_cpu(search->name.strings_range.desc.hash_lo);

	if (found_hash32 < req_hash32) {
		SSDFS_ERR("invalid strings range: "
			  "index %u\n",
			  search->name.strings_range.index);
		return -ERANGE;
	}

	err = ssdfs_get_lookup2_descriptor(node,
					   &node->lookup_tbl_area,
					   search->name.strings_range.index,
					   &read_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract lookup2 item: "
			  "index %u, err %d\n",
			  search->name.strings_range.index,
			  err);
		return err;
	}

	if (found_hash32 != le32_to_cpu(read_desc.hash_lo)) {
		SSDFS_ERR("found_hash %#x != read_hash %#x\n",
			  found_hash32,
			  le32_to_cpu(read_desc.hash_lo));
		return -ERANGE;
	}

	if (le16_to_cpu(read_desc.str_count) >= U16_MAX) {
		SSDFS_ERR("invalid str_count %u\n",
			  le16_to_cpu(read_desc.str_count));
		return -ERANGE;
	}

	read_desc.str_count++;

	err = ssdfs_set_lookup2_descriptor(node,
				&node->lookup_tbl_area,
				search->name.strings_range.index,
				&read_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set lookup2 item: "
			  "index %u, err %d\n",
			  search->name.strings_range.index,
			  err);
		return err;
	}

	ssdfs_mark_lookup2_table_dirty(node);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search->result.name);
#endif /* CONFIG_SSDFS_DEBUG */

	search->result.name->placement.lookup2_index =
				search->name.strings_range.index;

	return 0;
}

/*
 * __ssdfs_lookup2_table_insert_descriptor() - insert a new lookup2 descriptor
 * @node: node object
 * @search: search object
 *
 * This method tries to insert a new descriptor in the lookup2 table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - lookup2 table hasn't vacant items.
 */
static
int __ssdfs_lookup2_table_insert_descriptor(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search)
{
	struct ssdfs_shdict_ltbl2_item desc;
	u16 items_count;
	u16 items_capacity;
	u16 item_size;
	u16 hash_index;
	u16 lookup2_index;
	u16 range_len;
	u16 shift;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	switch (atomic_read(&node->lookup_tbl_area.state)) {
	case SSDFS_BTREE_NODE_LOOKUP_TBL_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid lookup_tbl_area state %#x\n",
			  atomic_read(&node->lookup_tbl_area.state));
		return -ERANGE;
	}

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	items_count = node->lookup_tbl_area.index_count;
	items_capacity = node->lookup_tbl_area.index_capacity;
	item_size = node->lookup_tbl_area.index_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search->result.name);
#endif /* CONFIG_SSDFS_DEBUG */

	hash_index = search->result.name->placement.hash_index;
	lookup2_index = search->name.strings_range.index;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_count %u, items_capacity %u, "
		  "index_size %u, hash_index %u, "
		  "lookup2_index %u\n",
		  items_count, items_capacity,
		  item_size, hash_index,
		  lookup2_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (items_count >= items_capacity) {
		SSDFS_ERR("corrupted node: "
			  "node_id %u, items_count %u, "
			  "items_capacity %u\n",
			  node->node_id, items_count,
			  items_capacity);
		return -ERANGE;
	}

	node->lookup_tbl_area.index_count++;

	desc.hash_lo = cpu_to_le32(SSDFS_HASH32_LO(search->request.start.hash));

	if (lookup2_index < items_count) {
		range_len = items_count - lookup2_index;
		shift = 1;

		err = ssdfs_shift_range_right2(node,
						&node->lookup_tbl_area,
						item_size,
						lookup2_index, range_len,
						shift);
		if (unlikely(err)) {
			SSDFS_ERR("fail to shift the range: "
				  "index %u, range_len %u, "
				  "shift %u, err %d\n",
				  lookup2_index, range_len, shift, err);
			return err;
		}
	} else {
		SSDFS_ERR("invalid index: "
			  "index %u, items_count %u\n",
			  lookup2_index, items_count);
		return -ERANGE;
	}

	if (search->request.start.name_len > SSDFS_MAX_NAME_LEN) {
		SSDFS_ERR("invalid name len %zu\n",
			  search->request.start.name_len);
		return -ERANGE;
	}

	desc.prefix_len = (u8)search->request.start.name_len;
	desc.hash_index = cpu_to_le16(hash_index);
	desc.str_count = cpu_to_le16(1);

	err = ssdfs_set_lookup2_descriptor(node, &node->lookup_tbl_area,
					   lookup2_index, &desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set lookup2 descriptor: "
			  "index %u, err %d\n",
			  lookup2_index, err);
		return err;
	}

	items_count = node->lookup_tbl_area.index_count;

	if (lookup2_index == 0) {
		node->lookup_tbl_area.start_hash =
			SSDFS_NAME_HASH(le32_to_cpu(desc.hash_lo), 0);
	}

	if ((lookup2_index + 1) == items_count) {
		node->lookup_tbl_area.end_hash =
			SSDFS_NAME_HASH(le32_to_cpu(desc.hash_lo), 0);
	}

	ssdfs_mark_lookup2_table_dirty(node);

	search->result.name->placement.lookup2_index = lookup2_index;

	return 0;
}

/*
 * __ssdfs_lookup2_table_add_descriptor() - add a new lookup2 descriptor
 * @node: node object
 * @search: search object
 *
 * This method tries to add a new descriptor in the lookup2 table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - lookup2 table hasn't vacant items.
 */
static
int __ssdfs_lookup2_table_add_descriptor(struct ssdfs_btree_node *node,
					 struct ssdfs_btree_search *search)
{
	struct ssdfs_shdict_ltbl2_item desc;
	u16 items_count;
	u16 items_capacity;
	u16 item_size;
	u16 hash_index;
	u16 lookup2_index;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	switch (atomic_read(&node->lookup_tbl_area.state)) {
	case SSDFS_BTREE_NODE_LOOKUP_TBL_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid lookup_tbl_area state %#x\n",
			  atomic_read(&node->lookup_tbl_area.state));
		return -ERANGE;
	}

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	items_count = node->lookup_tbl_area.index_count;
	items_capacity = node->lookup_tbl_area.index_capacity;
	item_size = node->lookup_tbl_area.index_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search->result.name);
#endif /* CONFIG_SSDFS_DEBUG */

	hash_index = search->result.name->placement.hash_index;
	lookup2_index = items_count;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_count %u, items_capacity %u, "
		  "index_size %u, strings_range.index %u, "
		  "hash_index %u, lookup2_index %u\n",
		  items_count, items_capacity, item_size,
		  search->name.strings_range.index,
		  hash_index, lookup2_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (items_count >= items_capacity) {
		SSDFS_ERR("invalid request: "
			  "items_count %u >= items_capacity %u\n",
			  items_count, items_capacity);
		return -ERANGE;
	}

	desc.hash_lo = cpu_to_le32(SSDFS_HASH32_LO(search->request.start.hash));

	if (search->request.start.name_len > SSDFS_MAX_NAME_LEN) {
		SSDFS_ERR("invalid name len %zu\n",
			  search->request.start.name_len);
		return -ERANGE;
	}

	desc.prefix_len = (u8)search->request.start.name_len;
	desc.hash_index = cpu_to_le16(hash_index);
	desc.str_count = cpu_to_le16(1);

	err = ssdfs_set_lookup2_descriptor(node, &node->lookup_tbl_area,
					   lookup2_index, &desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set lookup2 descriptor: "
			  "index %u, err %d\n",
			  lookup2_index, err);
		return err;
	}

	node->lookup_tbl_area.index_count++;

	node->lookup_tbl_area.end_hash =
			SSDFS_NAME_HASH(le32_to_cpu(desc.hash_lo), 0);

	ssdfs_mark_lookup2_table_dirty(node);

	search->result.name->placement.lookup2_index = lookup2_index;

	return 0;
}

/*
 * ssdfs_lookup2_table_insert_new_descriptor() - add a new lookup2 descriptor
 * @node: node object
 * @search: search object
 *
 * This method tries to insert a new descriptor in the lookup2 table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - lookup2 table hasn't vacant items.
 */
static
int ssdfs_lookup2_table_insert_new_descriptor(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search)
{
	u32 req_hash32;
	u32 found_hash32;
	u16 items_count;
	u16 items_capacity;
	u16 item_size;
	u16 index;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	switch (atomic_read(&node->lookup_tbl_area.state)) {
	case SSDFS_BTREE_NODE_LOOKUP_TBL_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid lookup_tbl_area state %#x\n",
			  atomic_read(&node->lookup_tbl_area.state));
		return -ERANGE;
	}

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	items_count = node->lookup_tbl_area.index_count;
	items_capacity = node->lookup_tbl_area.index_capacity;
	item_size = node->lookup_tbl_area.index_size;
	index = search->name.strings_range.index;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_count %u, items_capacity %u, "
		  "index_size %u, strings_range.index %u\n",
		  items_count, items_capacity,
		  item_size, index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (items_count == items_capacity) {
		SSDFS_ERR("no vacant items: "
			  "items_count %u, items_capacity %u\n",
			  items_count, items_capacity);
		return -ENOSPC;
	} else if (items_count > items_capacity) {
		SSDFS_ERR("items_count %u > items_capacity %u\n",
			  items_count, items_capacity);
		return -ERANGE;
	}

	if (item_size != sizeof(struct ssdfs_shdict_ltbl2_item)) {
		SSDFS_ERR("invalid item size %u\n",
			  item_size);
		return -ERANGE;
	}

	if (index > items_count) {
		SSDFS_ERR("index %u > items_count %u\n",
			  index, items_count);
		return -ERANGE;
	}

	if (!(search->request.flags &
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE)) {
		SSDFS_ERR("valid hash is absent in request\n");
		return -ERANGE;
	}

	req_hash32 = SSDFS_HASH32_LO(search->request.start.hash);
	found_hash32 = le32_to_cpu(search->name.strings_range.desc.hash_lo);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("req_hash32 %#x, found_hash32 %#x, "
		  "search->result.state %#x\n",
		  req_hash32, found_hash32,
		  search->result.state);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
		if (req_hash32 == found_hash32) {
			SSDFS_ERR("invalid hash: "
				  "request %#x == found_hash %#x\n",
				  req_hash32, found_hash32);
			return -EEXIST;
		} else if (req_hash32 < found_hash32) {
			err = __ssdfs_lookup2_table_insert_descriptor(node,
								      search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to insert descriptor: "
					  "err %d\n", err);
				return err;
			}
		} else {
			search->name.strings_range.index++;
			index = search->name.strings_range.index;

			if (index < items_count) {
				err =
				   __ssdfs_lookup2_table_insert_descriptor(node,
									search);
				if (unlikely(err)) {
					SSDFS_ERR("fail to insert descriptor: "
						  "err %d\n", err);
					return err;
				}
			} else {
				err = __ssdfs_lookup2_table_add_descriptor(node,
									search);
				if (unlikely(err)) {
					SSDFS_ERR("fail to add descriptor: "
						  "err %d\n", err);
					return err;
				}
			}
		}
		break;

	case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
		err = __ssdfs_lookup2_table_add_descriptor(node, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add descriptor: "
				  "err %d\n", err);
			return err;
		}
		break;

	default:
		SSDFS_ERR("unexpected result state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_lookup2_table_insert_descriptor() - insert a lookup2 descriptor
 * @node: node object
 * @search: search object
 * @str_type: type of the string
 *
 * This method tries to insert a new descriptor in the lookup2 table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - lookup2 table hasn't vacant items.
 */
static
int ssdfs_lookup2_table_insert_descriptor(struct ssdfs_btree_node *node,
					  struct ssdfs_btree_search *search,
					  u8 str_type)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, str_type %#x\n",
		  node->node_id, str_type);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->lookup_tbl_area.state)) {
	case SSDFS_BTREE_NODE_LOOKUP_TBL_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid lookup_tbl_area state %#x\n",
			  atomic_read(&node->lookup_tbl_area.state));
		return -ERANGE;
	}

	if (!(search->request.flags &
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE)) {
		SSDFS_ERR("request doesn't contain the hash\n");
		return -ERANGE;
	}

	if (search->request.count != 1) {
		SSDFS_ERR("invalid request: "
			  "search->request.count %u\n",
			  search->request.count);
		return -ERANGE;
	}

	switch (str_type) {
	case SSDFS_NAME_PREFIX:
	case SSDFS_FULL_NAME:
		err = ssdfs_lookup2_table_insert_new_descriptor(node,
								search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert new descriptor: "
				  "err %d\n", err);
			return err;
		}
		break;

	case SSDFS_NAME_SUFFIX:
		err = ssdfs_lookup2_table_inc_str_count(node, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to increment strings count: "
				  "err %d\n", err);
			return err;
		}
		break;

	default:
		SSDFS_ERR("invalid str_type %#x\n",
			  str_type);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_lookup1_table_get_range_capacity() - get the capacity for an index
 * @index: lookup1 table's index
 */
static inline
u16 ssdfs_lookup1_table_get_range_capacity(u16 index)
{
	if (index >= SSDFS_SHDIC_LTBL1_SIZE)
		return U16_MAX;

	return lookup1_tbl_range_capacity[index];
}

/*
 * ssdfs_convert_lookup2_to_lookup1_index() - convert lookup2 to lookup1 index
 * @lookup2_index: lookup2 index
 */
static inline
u16 ssdfs_convert_lookup2_to_lookup1_index(u16 lookup2_index)
{
	int cur_index;
	u16 lower_bound, upper_bound;
	u16 range_capacity;
	u16 threshold;
	u16 found_index = U16_MAX;

	threshold = lookup1_tbl_threshold[0];
	range_capacity = lookup1_tbl_range_capacity[0];

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("lookup2_index %u, threshold %u, "
		  "range_capacity %u\n",
		  lookup2_index, threshold, range_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	if (lookup2_index < threshold) {
		/* first index */
		return 0;
	}

	threshold = lookup1_tbl_threshold[SSDFS_SHDIC_LTBL1_SIZE - 1];

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("lookup2_index %u, threshold %u\n",
		  lookup2_index, threshold);
#endif /* CONFIG_SSDFS_DEBUG */

	if (lookup2_index >= threshold) {
		/* last index */
		return SSDFS_SHDIC_LTBL1_SIZE - 1;
	}

	lower_bound = 1;
	upper_bound = SSDFS_SHDIC_LTBL1_SIZE - 2;
	cur_index = SSDFS_SHDIC_LTBL1_SIZE / 2;

	do {
		threshold = lookup1_tbl_threshold[cur_index];
		range_capacity = lookup1_tbl_range_capacity[cur_index];

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("lower_bound %u, upper_bound %u, "
			  "cur_index %u, threshold %u, "
			  "range_capacity %u\n",
			  lower_bound, upper_bound, cur_index,
			  threshold, range_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

		if (lookup2_index >= (threshold - range_capacity) &&
		    lookup2_index < threshold) {
			found_index = cur_index;
			break;
		} else if (lookup2_index < (threshold - range_capacity)) {
			/* correct upper_bound */
			upper_bound = cur_index;
		} else {
			/* correct lower_bound */
			lower_bound = cur_index;
		}

		cur_index = lower_bound + ((upper_bound - lower_bound) / 2);
	} while (lower_bound < upper_bound);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("found_index %u\n",
		  found_index);
#endif /* CONFIG_SSDFS_DEBUG */

	return found_index;
}

/*
 * ssdfs_lookup1_table_modify_descriptor() - modify a lookup1 descriptor
 * @node: node object
 * @search: search object
 *
 * This method tries to modify an existing descriptor in the lookup1 table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_lookup1_table_modify_descriptor(struct ssdfs_btree_node *node,
					  struct ssdfs_btree_search *search)
{
	struct ssdfs_shdict_ltbl1_item *lookup1_tbl;
	struct ssdfs_shdict_ltbl1_item *found_desc;
	struct ssdfs_shdict_ltbl1_item read_desc;
	size_t item_size = sizeof(struct ssdfs_shdict_ltbl1_item);
	u16 items_count;
	u16 items_capacity;
	u16 lookup2_index;
	u16 start_lookup2_index;
	u16 found_index, calculated_index;
	u16 range_len;
	u16 range_capacity;
	u64 hash64;
	u16 i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(search->request.flags &
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE)) {
		SSDFS_ERR("request doesn't contain the hash\n");
		return -ERANGE;
	}

	items_count = le16_to_cpu(node->raw.dict_header.lookup_table1_items);
	items_capacity = SSDFS_SHDIC_LTBL1_SIZE;

	if (items_count > SSDFS_SHDIC_LTBL1_SIZE) {
		SSDFS_ERR("invalid lookup_table1_items %u\n",
			  items_count);
		return -ERANGE;
	}

	switch (search->result.name_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		/* expected states */
		break;

	default:
		SSDFS_ERR("invalid name state %#x\n",
			  search->result.name_state);
		return -ERANGE;
	}

	if (!search->result.name) {
		SSDFS_ERR("invalid name buffer\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search->result.name);
#endif /* CONFIG_SSDFS_DEBUG */

	lookup2_index = search->result.name->placement.lookup2_index;
	calculated_index =
		ssdfs_convert_lookup2_to_lookup1_index(lookup2_index);
	if (calculated_index >= U16_MAX) {
		SSDFS_ERR("invalid lookup1_index: "
			  "lookup2_index %u\n",
			  lookup2_index);
		return -ERANGE;
	}

	lookup1_tbl = node->raw.dict_header.lookup_table1;
	found_index = search->result.name->lookup.index;
	found_desc = &search->result.name->lookup.desc;

	start_lookup2_index = le16_to_cpu(found_desc->start_index);
	if (start_lookup2_index >= U16_MAX) {
		SSDFS_ERR("invalid lookup1 item: "
			  "start_lookup2_index %u\n",
			  start_lookup2_index);
		return -ERANGE;
	}

	range_len = le16_to_cpu(found_desc->range_len);
	if (range_len >= U16_MAX) {
		SSDFS_ERR("invalid lookup1 item: "
			  "range_len %u\n",
			  range_len);
		return -ERANGE;
	}

	range_capacity = lookup1_tbl_range_capacity[calculated_index];

	if (lookup2_index < start_lookup2_index ||
	    lookup2_index > (start_lookup2_index + range_len + 1)) {
		SSDFS_ERR("invalid range: "
			  "lookup2_index %u, start_lookup2_index %u, "
			  "range_len %u\n",
			  lookup2_index,
			  start_lookup2_index,
			  range_len);
		return -ERANGE;
	}

	ssdfs_memcpy(&read_desc, 0, item_size,
		     &lookup1_tbl[calculated_index], 0, item_size,
		     item_size);

	if (calculated_index == found_index) {
		if (memcmp(found_desc, &read_desc, item_size) != 0) {
			SSDFS_ERR("invalid lookup1 descriptors\n");
			return -ERANGE;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("lookup2_index %u, calculated_index %u, "
		  "requested_hash %#x, "
		  "found_hash %#x\n",
		  lookup2_index, calculated_index,
		  SSDFS_HASH32_LO(search->request.start.hash),
		  le32_to_cpu(read_desc.hash_lo));
#endif /* CONFIG_SSDFS_DEBUG */

	hash64 = search->request.start.hash;

	if (SSDFS_HASH32_LO(hash64) < le32_to_cpu(read_desc.hash_lo))
		read_desc.hash_lo = cpu_to_le32(SSDFS_HASH32_LO(hash64));

	ssdfs_memcpy(&lookup1_tbl[calculated_index], 0, item_size,
		     &read_desc, 0, item_size,
		     item_size);

	start_lookup2_index = lookup1_tbl_threshold[calculated_index];

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("calculated_index %u, items_count %u, "
		  "start_lookup2_index %u\n",
		  calculated_index, items_count,
		  start_lookup2_index);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = calculated_index + 1; i < items_capacity; i++) {
		struct ssdfs_shdict_ltbl2_item lookup2_item;
		u16 start_index;
		u16 index_count;

		index_count = node->lookup_tbl_area.index_count;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("lookup2_index_count %u\n",
			  index_count);
#endif /* CONFIG_SSDFS_DEBUG */

		if (index_count <= start_lookup2_index) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("lookup2_index_count %u, "
				  "threshold %u\n",
				  index_count,
				  start_lookup2_index);
#endif /* CONFIG_SSDFS_DEBUG */
			goto set_node_header_dirty;
		}

		if (i < items_count) {
			ssdfs_memcpy(&read_desc, 0, item_size,
				     &lookup1_tbl[i], 0, item_size,
				     item_size);

			start_index = le16_to_cpu(read_desc.start_index);
			if (start_index >= U16_MAX) {
				SSDFS_ERR("invalid lookup1 item: "
					  "start_index %#x\n",
					  start_index);
				return -ERANGE;
			}

			range_len = le16_to_cpu(read_desc.range_len);
			if (range_len >= U16_MAX) {
				SSDFS_ERR("invalid lookup1 item: "
					  "range_len %#x\n",
					  range_len);
				return -ERANGE;
			}

			if ((start_index + range_len) > index_count) {
				SSDFS_ERR("invalid lookup1 item: "
					  "start_index %u, "
					  "range_len %u, "
					  "index_count %u\n",
					  start_index,
					  range_len,
					  index_count);
				return -ERANGE;
			}

			if (start_index != start_lookup2_index) {
				SSDFS_ERR("invalid lookup1 item: "
					  "start_index %u, "
					  "start_lookup2_index %u\n",
					  start_index,
					  start_lookup2_index);
				return -ERANGE;
			}

			err = ssdfs_get_lookup2_descriptor(node,
						&node->lookup_tbl_area,
						start_lookup2_index,
						&lookup2_item);
			if (unlikely(err)) {
				SSDFS_ERR("fail to extract: "
					  "index %u, err %d\n",
					  start_lookup2_index,
					  err);
				return err;
			}

			read_desc.hash_lo = lookup2_item.hash_lo;
			read_desc.start_index =
					cpu_to_le16(start_lookup2_index);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("lookup1_index %u, lookup2_index %u, "
				  "hash_lo %#x, range_len %u\n",
				  i, start_lookup2_index,
				  le32_to_cpu(lookup2_item.hash_lo),
				  range_len);
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_memcpy(&lookup1_tbl[i], 0, item_size,
				     &read_desc, 0, item_size,
				     item_size);
		} else {
			err = ssdfs_get_lookup2_descriptor(node,
						&node->lookup_tbl_area,
						start_lookup2_index,
						&lookup2_item);
			if (unlikely(err)) {
				SSDFS_ERR("fail to extract: "
					  "index %u, err %d\n",
					  start_lookup2_index,
					  err);
				return err;
			}

			read_desc.hash_lo = lookup2_item.hash_lo;
			read_desc.start_index =
					cpu_to_le16(start_lookup2_index);
			read_desc.range_len = cpu_to_le16(0);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("lookup1_index %u, lookup2_index %u, "
				  "hash_lo %#x, range_len %u\n",
				  i, start_lookup2_index,
				  le32_to_cpu(lookup2_item.hash_lo),
				  le16_to_cpu(read_desc.range_len));
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_memcpy(&lookup1_tbl[i], 0, item_size,
				     &read_desc, 0, item_size,
				     item_size);

			le16_add_cpu(&node->raw.dict_header.lookup_table1_items,
				     1);
		}

		start_lookup2_index = lookup1_tbl_threshold[i];
	}

set_node_header_dirty:
	items_count = le16_to_cpu(node->raw.dict_header.lookup_table1_items);

	ssdfs_memcpy(&read_desc, 0, item_size,
		     &lookup1_tbl[items_count - 1], 0, item_size,
		     item_size);

	le16_add_cpu(&read_desc.range_len, 1);

	ssdfs_memcpy(&lookup1_tbl[items_count - 1], 0, item_size,
		     &read_desc, 0, item_size,
		     item_size);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_count %u, range_len %u\n",
		  items_count,
		  le16_to_cpu(read_desc.range_len));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_set_node_header_dirty(node,
					  node->items_area.items_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set header dirty: err %d\n",
			  err);
		return err;
	}

	search->result.name->placement.lookup1_index = calculated_index;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("LOOKUP1 TABLE DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     lookup1_tbl,
			     sizeof(struct ssdfs_shdict_ltbl1_item) *
				SSDFS_SHDIC_LTBL1_SIZE);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_lookup1_table_add_descriptor() - add a lookup1 descriptor in the table
 * @node: node object
 * @search: search object
 *
 * This method tries to add a new descriptor in the lookup1 table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_lookup1_table_add_descriptor(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
	struct ssdfs_shdict_ltbl1_item *lookup1_tbl;
	struct ssdfs_shdict_ltbl1_item read_desc;
	size_t item_size = sizeof(struct ssdfs_shdict_ltbl1_item);
	u16 items_count;
	u16 lookup2_index = 0;
	u16 calculated_index = 0;
	u16 start_index;
	u16 range_len;
	u16 range_capacity = 0;
	u64 hash64;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(search->request.flags &
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE)) {
		SSDFS_ERR("request doesn't contain the hash\n");
		return -ERANGE;
	}

	items_count = le16_to_cpu(node->raw.dict_header.lookup_table1_items);

	if (items_count > SSDFS_SHDIC_LTBL1_SIZE) {
		SSDFS_ERR("invalid lookup_table1_items %u\n",
			  items_count);
		return -ERANGE;
	}

	switch (search->result.name_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		/* expected states */
		break;

	default:
		SSDFS_ERR("invalid name state %#x\n",
			  search->result.name_state);
		return -ERANGE;
	}

	if (!search->result.name) {
		SSDFS_ERR("invalid name buffer\n");
		return -ERANGE;
	}

	lookup1_tbl = node->raw.dict_header.lookup_table1;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search->result.name);
#endif /* CONFIG_SSDFS_DEBUG */

	if (items_count == 0) {
		calculated_index = 0;
	} else {
		lookup2_index = search->result.name->placement.lookup2_index;
		calculated_index =
			ssdfs_convert_lookup2_to_lookup1_index(lookup2_index);
		if (calculated_index >= U16_MAX) {
			SSDFS_ERR("invalid lookup1_index: "
				  "lookup2_index %u\n",
				  lookup2_index);
			return -ERANGE;
		}

		range_capacity = lookup1_tbl_range_capacity[calculated_index];
	}

	if (calculated_index == items_count) {
		hash64 = search->request.start.hash;
		read_desc.hash_lo = cpu_to_le32(SSDFS_HASH32_LO(hash64));
		read_desc.start_index = cpu_to_le16(lookup2_index);
		read_desc.range_len = cpu_to_le16(1);

		ssdfs_memcpy(&lookup1_tbl[calculated_index], 0, item_size,
			     &read_desc, 0, item_size,
			     item_size);

		le16_add_cpu(&node->raw.dict_header.lookup_table1_items, 1);
	} else {
		ssdfs_memcpy(&read_desc, 0, item_size,
			     &lookup1_tbl[calculated_index], 0, item_size,
			     item_size);

		start_index = le16_to_cpu(read_desc.start_index);
		if (start_index >= U16_MAX) {
			SSDFS_ERR("invalid lookup1 item: "
				  "start_index %#x\n",
				  start_index);
			return -ERANGE;
		}

		range_len = le16_to_cpu(read_desc.range_len);
		if (range_len >= U16_MAX) {
			SSDFS_ERR("invalid lookup1 item: "
				  "range_len %#x\n",
				  range_len);
			return -ERANGE;
		}

		if (lookup2_index < start_index ||
		    lookup2_index > (start_index + range_len + 1)) {
			SSDFS_ERR("invalid range: "
				  "lookup2_index %u, start_index %u, "
				  "range_len %u\n",
				  lookup2_index,
				  start_index,
				  range_len);
			return -ERANGE;
		}

		if (range_len == range_capacity) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to add into lookup1 table: "
				  "range_len %u, range_capacity %u\n",
				  range_len, range_capacity);
#endif /* CONFIG_SSDFS_DEBUG */
			return -ENOSPC;
		}

		if (range_len > range_capacity) {
			SSDFS_ERR("corrupted lookup1 table: "
				  "range_len %u, range_capacity %u\n",
				  range_len, range_capacity);
			return -ERANGE;
		}

		if (start_index == lookup2_index) {
			hash64 = search->request.start.hash;
			read_desc.hash_lo =
				cpu_to_le32(SSDFS_HASH32_LO(hash64));
		}

		le16_add_cpu(&read_desc.range_len, 1);

		ssdfs_memcpy(&lookup1_tbl[calculated_index], 0, item_size,
			     &read_desc, 0, item_size,
			     item_size);
	}

	err = ssdfs_set_node_header_dirty(node,
					  node->items_area.items_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set header dirty: err %d\n",
			  err);
		return err;
	}

	search->result.name->placement.lookup1_index = calculated_index;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("LOOKUP1 TABLE DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     lookup1_tbl,
			     sizeof(struct ssdfs_shdict_ltbl1_item) *
				SSDFS_SHDIC_LTBL1_SIZE);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_lookup1_table_insert_descriptor() - insert a lookup1 descriptor
 * @node: node object
 * @search: search object
 *
 * This method tries to insert a new descriptor in the lookup1 table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_lookup1_table_insert_descriptor(struct ssdfs_btree_node *node,
					  struct ssdfs_btree_search *search,
					  u8 str_type)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));
	BUG_ON(!search->result.name);

	SSDFS_DBG("node_id %u, str_type %#x\n",
		  node->node_id, str_type);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (str_type) {
	case SSDFS_NAME_PREFIX:
	case SSDFS_FULL_NAME:
		if (!search->result.name) {
			SSDFS_ERR("invalid name buffer\n");
			return -ERANGE;
		}

		err = ssdfs_lookup1_table_add_descriptor(node, search);
		if (err == -ENOSPC) {
			err = ssdfs_lookup1_table_modify_descriptor(node,
								    search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to modify the lookup1 table: "
					  "err %d\n", err);
				return err;
			}
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to add lookup1 descriptor: "
				  "err %d\n", err);
			return err;
		}
		break;

	case SSDFS_NAME_SUFFIX:
		/*
		 * No record was added into lookup2 table for the suffix.
		 * Do nothing.
		 */
		break;

	default:
		SSDFS_ERR("invalid str_type %#x\n",
			  str_type);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_check_node_consistency() - check a node's consistency
 * @node: node object
 *
 * This method tries to check a node's consistency.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_check_node_consistency(struct ssdfs_btree_node *node)
{
	size_t hdr_size = sizeof(struct ssdfs_shared_dictionary_node_header);
	u16 index_area_size;
	u16 str_area_offset;
	u16 str_area_bytes;
	u16 hash_tbl_offset;
	u16 hash_tbl_size;
	u16 lookup_tbl2_offset;
	u16 lookup_tbl2_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_check_items_area(node, &node->items_area);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("items area is corrupted: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	err = ssdfs_check_lookup2_table_area(node, &node->lookup_tbl_area);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("lookup2 table area is corrupted: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	err = ssdfs_check_hash_table_area(node, &node->hash_tbl_area);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("hash table area is corrupted: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	index_area_size = node->index_area.area_size;
	str_area_offset = node->items_area.offset;
	str_area_bytes = node->items_area.area_size;
	hash_tbl_offset = node->hash_tbl_area.offset;
	hash_tbl_size = node->hash_tbl_area.area_size;
	lookup_tbl2_offset = node->lookup_tbl_area.offset;
	lookup_tbl2_size = node->lookup_tbl_area.area_size;

	if (str_area_offset != (hdr_size + index_area_size)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted strings area: "
			  "str_area_offset %u, hdr_size %zu, "
			  "index_area_size %u\n",
			  str_area_offset,
			  hdr_size,
			  index_area_size);
		return -ERANGE;
	}

	if (hash_tbl_offset != (str_area_offset + str_area_bytes)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted hash table: "
			  "hash_tbl_offset %u, str_area_offset %u, "
			  "str_area_bytes %u\n",
			  hash_tbl_offset,
			  str_area_offset,
			  str_area_bytes);
		return -ERANGE;
	}

	if (lookup_tbl2_offset != (hash_tbl_offset + hash_tbl_size)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted lookup table: "
			  "lookup_tbl2_offset %u, hash_tbl_offset %u, "
			  "hash_tbl_size %u\n",
			  lookup_tbl2_offset,
			  hash_tbl_offset,
			  hash_tbl_size);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_add_full_name() - add a full name into the node
 * @node: node object
 * @search: search object
 *
 * This method tries to insert a full name into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - node hasn't enough free space.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_add_full_name(struct ssdfs_btree_node *node,
			struct ssdfs_btree_search *search)
{
	size_t hdesc_size = sizeof(struct ssdfs_shdict_htbl_item);
	size_t l2desc_size = sizeof(struct ssdfs_shdict_ltbl2_item);
	size_t str_len;
	size_t requested_size;
	u32 area_offset;
	u32 area_size;
	u32 free_space;
	u32 threshold;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(search->request.flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME)) {
		SSDFS_ERR("request doesn't contain valid name\n");
		return -ERANGE;
	}

	if (!search->request.start.name) {
		SSDFS_ERR("empty name pointer\n");
		return -ERANGE;
	}

	str_len = search->request.start.name_len;

	if (str_len > SSDFS_MAX_NAME_LEN) {
		SSDFS_ERR("invalid str_len %zu\n", str_len);
		return -ERANGE;
	}

	requested_size = str_len + l2desc_size + hdesc_size;

	down_write(&node->header_lock);

	if (!is_free_space_enough(node, requested_size)) {
		err = -ENOSPC;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u hasn't enough free space: "
			  "requested_size %zu\n",
			  node->node_id, requested_size);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_add_full_name;
	}

	area_offset = node->items_area.offset;
	area_size = node->items_area.area_size;
	free_space = node->items_area.free_space;

	if (free_space < requested_size) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted items area: free_space %u\n",
			  free_space);
		goto finish_add_full_name;
	}

	if (area_size < free_space) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted items area: "
			  "area_size %u, free_space %u\n",
			  area_size, free_space);
		goto finish_add_full_name;
	}

	area_size -= l2desc_size + hdesc_size;

	err = ssdfs_resize_string_area(node, area_offset, area_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shrink the string area: "
			  "area_offset %u, area_size %u, err %d\n",
			  area_offset, area_size, err);
		goto check_node_consistency;
	}

	threshold = area_offset + area_size;

	area_offset = node->hash_tbl_area.offset;
	area_size = node->hash_tbl_area.area_size;

	if (area_offset <= (l2desc_size + hdesc_size)) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted area: "
			  "area_offset %u\n",
			  area_offset);
		goto finish_add_full_name;
	}

	if (threshold != (area_offset - (l2desc_size + hdesc_size))) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted area: "
			  "threshold %u, area_offset %u\n",
			  threshold, area_offset);
		goto finish_add_full_name;
	}

	area_offset -= l2desc_size + hdesc_size;
	area_size += hdesc_size;

	err = ssdfs_resize_hash_table(node, area_offset, area_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to resize hash table: "
			  "area_offset %u, area_size %u, err %d\n",
			  area_offset, area_size, err);
		goto check_node_consistency;
	}

	threshold = area_offset + area_size;

	area_offset = node->lookup_tbl_area.offset;
	area_size = node->lookup_tbl_area.area_size;

	if (area_offset <= l2desc_size) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted area: "
			  "area_offset %u\n",
			  area_offset);
		goto finish_add_full_name;
	}

	if (threshold != (area_offset - l2desc_size)) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted area: "
			  "threshold %u, area_offset %u\n",
			  threshold, area_offset);
		goto finish_add_full_name;
	}

	area_offset -= l2desc_size;
	area_size += l2desc_size;

	err = ssdfs_resize_lookup2_table(node, area_offset, area_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to resize lookup2 table: "
			  "area_offset %u, area_size %u, err %d\n",
			  area_offset, area_size, err);
		goto check_node_consistency;
	}

	if (is_ssdfs_resized_node_corrupted(node)) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("node %u has been corrupted during resize\n",
			  node->node_id);
		goto finish_add_full_name;
	}

	err = ssdfs_insert_full_string(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert the full string: err %d\n", err);
		goto check_node_consistency;
	}

	err = ssdfs_hash_table_insert_descriptor(node, search,
						 (u8)str_len,
						 SSDFS_FULL_NAME);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert hash descriptor: err %d\n", err);
		goto check_node_consistency;
	}

	err = ssdfs_lookup2_table_insert_descriptor(node, search,
						    SSDFS_FULL_NAME);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert lookup2 descriptor: err %d\n", err);
		goto check_node_consistency;
	}

	err = ssdfs_lookup1_table_insert_descriptor(node, search,
						    SSDFS_FULL_NAME);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert lookup1 descriptor: err %d\n", err);
		goto check_node_consistency;
	}

check_node_consistency:
	err = ssdfs_check_node_consistency(node);
	if (unlikely(err)) {
		SSDFS_ERR("node %u is corrupted: err %d\n",
			  node->node_id, err);
		goto finish_add_full_name;
	}

	atomic_set(&node->state, SSDFS_BTREE_NODE_DIRTY);

finish_add_full_name:
	up_write(&node->header_lock);

	return err;
}

#define SSDFS_LOWER_PREFIX_THRESHOLD	(SSDFS_DENTRY_INLINE_NAME_MAX_LEN / 2)
#define SSDFS_DEFAULT_PREFIX_LEN	(SSDFS_DENTRY_INLINE_NAME_MAX_LEN)

/*
 * ssdfs_create_prefix_for_left_name() - create the prefix for left name
 * @node: node object
 * @search: search object
 * @prefix_len: length of the prefix
 *
 * This method tries to create the prefix for left name in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EOPNOTSUPP - unable to create the prefix.
 * %-ENOSPC     - node hasn't enough free space.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_create_prefix_for_left_name(struct ssdfs_btree_node *node,
				      struct ssdfs_btree_search *search,
				      u16 prefix_len)
{
	struct ssdfs_string_descriptor *prefix, *left_name, *right_name;
	struct ssdfs_strings_range_descriptor *strings_range;
	struct ssdfs_shdict_htbl_item read_hdesc;
	struct ssdfs_shdict_ltbl2_item read_ldesc;
	size_t hdesc_size = sizeof(struct ssdfs_shdict_htbl_item);
	size_t l2desc_size = sizeof(struct ssdfs_shdict_ltbl2_item);
	size_t str_len;
	size_t requested_size;
	u32 area_offset;
	u32 area_size;
	u32 free_space;
	u32 threshold;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, prefix_len %u\n",
		  node->node_id, prefix_len);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->result.name_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		/* expected states */
		break;

	default:
		SSDFS_ERR("invalid name state %#x\n",
			  search->result.name_state);
		return -ERANGE;
	}

	if (!search->result.name) {
		SSDFS_ERR("invalid name buffer\n");
		return -ERANGE;
	}

	prefix = &search->result.name->prefix;
	left_name = &search->result.name->left_name;
	right_name = &search->result.name->right_name;
	strings_range = &search->result.name->strings_range;

	switch (prefix->desc.type) {
	case SSDFS_FULL_NAME:
		/* expected type */
		break;

	case SSDFS_NAME_PREFIX:
		SSDFS_ERR("unsupported type %#x\n",
			  prefix->desc.type);
		return -EOPNOTSUPP;

	default:
		SSDFS_ERR("invalid type %#x\n",
			  prefix->desc.type);
		return -ERANGE;
	}

	switch (left_name->desc.type) {
	case SSDFS_FULL_NAME:
		/* expected type */
		break;

	default:
		SSDFS_ERR("invalid type %#x\n",
			  left_name->desc.type);
		return -ERANGE;
	}

	if (prefix->index != left_name->index) {
		SSDFS_ERR("prefix->index %u != left_name->index %u\n",
			  prefix->index,
			  left_name->index);
		return -ERANGE;
	}

	if (!(search->request.flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME)) {
		SSDFS_ERR("request doesn't contain valid name\n");
		return -ERANGE;
	}

	if (!search->request.start.name) {
		SSDFS_ERR("empty name pointer\n");
		return -ERANGE;
	}

	str_len = search->request.start.name_len;

	if (str_len > SSDFS_MAX_NAME_LEN) {
		SSDFS_ERR("invalid str_len %zu\n", str_len);
		return -ERANGE;
	}

	if (prefix_len > str_len) {
		SSDFS_ERR("prefix_len %u > str_len %zu\n",
			  prefix_len, str_len);
		return -ERANGE;
	}

	requested_size = hdesc_size;

	down_write(&node->header_lock);

	if (!is_free_space_enough(node, requested_size)) {
		err = -ENOSPC;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u hasn't enough free space: "
			  "requested_size %zu\n",
			  node->node_id, requested_size);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_create_left_prefix;
	}

	area_offset = node->items_area.offset;
	area_size = node->items_area.area_size;
	free_space = node->items_area.free_space;

	if (free_space < requested_size) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted items area: free_space %u\n",
			  free_space);
		goto finish_create_left_prefix;
	}

	if (area_size < free_space) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted items area: "
			  "area_size %u, free_space %u\n",
			  area_size, free_space);
		goto finish_create_left_prefix;
	}

	area_size -= hdesc_size;

	err = ssdfs_resize_string_area(node, area_offset, area_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shrink the string area: "
			  "area_offset %u, area_size %u, err %d\n",
			  area_offset, area_size, err);
		goto check_node_consistency;
	}

	threshold = area_offset + area_size;

	area_offset = node->hash_tbl_area.offset;
	area_size = node->hash_tbl_area.area_size;

	if (area_offset < requested_size) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted area: "
			  "area_offset %u\n",
			  area_offset);
		goto finish_create_left_prefix;
	}

	if (threshold != (area_offset - requested_size)) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted area: "
			  "threshold %u, area_offset %u\n",
			  threshold, area_offset);
		goto finish_create_left_prefix;
	}

	area_offset -= hdesc_size;
	area_size += hdesc_size;

	err = ssdfs_resize_hash_table(node, area_offset, area_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to resize hash table: "
			  "area_offset %u, area_size %u, err %d\n",
			  area_offset, area_size, err);
		goto check_node_consistency;
	}

	threshold = area_offset + area_size;
	area_offset = node->lookup_tbl_area.offset;

	if (threshold != area_offset) {
		err = -ERANGE;
		SSDFS_ERR("threshold %u != area_offset %u\n",
			  threshold, area_offset);
		goto check_node_consistency;
	}

	if (is_ssdfs_resized_node_corrupted(node)) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("node %u has been corrupted during resize\n",
			  node->node_id);
		goto check_node_consistency;
	}

	err = ssdfs_get_hash_descriptor(node, &node->hash_tbl_area,
					prefix->index, &read_hdesc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash descriptor: "
			  "index %u, err %d\n",
			  prefix->index, err);
		goto check_node_consistency;
	}

	if (memcmp(&read_hdesc, &prefix->desc, hdesc_size) != 0) {
		err = -ERANGE;
		SSDFS_ERR("corrupted node: "
			  "different hash descriptors: "
			  "index %u\n", prefix->index);
		goto check_node_consistency;
	}

	str_len = read_hdesc.str_len;
	read_hdesc.str_len = (u8)prefix_len;
	read_hdesc.type = SSDFS_NAME_PREFIX;

	err = ssdfs_set_hash_descriptor(node, &node->hash_tbl_area,
					prefix->index, &read_hdesc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set hash descriptor: "
			  "index %u, err %d\n",
			  prefix->index, err);
		goto check_node_consistency;
	}

	ssdfs_mark_hash_table_dirty(node);

	ssdfs_memcpy(&prefix->desc, 0, hdesc_size,
		     &read_hdesc, 0, hdesc_size,
		     hdesc_size);

	le16_add_cpu(&read_hdesc.str_offset, prefix_len);
	read_hdesc.str_len = (u8)(str_len - prefix_len);
	read_hdesc.type = SSDFS_NAME_SUFFIX;

	if (left_name->index == right_name->index) {
		left_name->index = prefix->index + 1;
		right_name->index = left_name->index;
	} else {
		left_name->index = prefix->index + 1;
		right_name->index = left_name->index + 1;
	}

	err = __ssdfs_hash_table_insert_descriptor(node, search,
						   left_name->index,
						   &read_hdesc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert hash descriptor: err %d\n", err);
		goto check_node_consistency;
	}

	err = ssdfs_get_hash_descriptor(node, &node->hash_tbl_area,
					left_name->index, &read_hdesc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash descriptor: "
			  "index %u, err %d\n",
			  left_name->index, err);
		goto check_node_consistency;
	}

	ssdfs_memcpy(&left_name->desc, 0, hdesc_size,
		     &read_hdesc, 0, hdesc_size,
		     hdesc_size);

	if (left_name->index == right_name->index) {
		ssdfs_memcpy(&right_name->desc, 0, hdesc_size,
			     &read_hdesc, 0, hdesc_size,
			     hdesc_size);
	}

	err = ssdfs_get_lookup2_descriptor(node,
					   &node->lookup_tbl_area,
					   strings_range->index,
					   &read_ldesc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract lookup2 item: "
			  "index %u, err %d\n",
			  search->name.strings_range.index,
			  err);
		goto check_node_consistency;
	}

	if (memcmp(&read_ldesc, &strings_range->desc, l2desc_size) != 0) {
		err = -ERANGE;
		SSDFS_ERR("corrupted node: "
			  "different lookup2 descriptors: "
			  "index %u\n",
			  strings_range->index);
		goto check_node_consistency;
	}

	read_ldesc.prefix_len = (u8)prefix_len;

	if (read_ldesc.str_count != 1) {
		err = -ERANGE;
		SSDFS_ERR("invalid str_count %u\n",
			  read_ldesc.str_count);
		goto check_node_consistency;
	}

	/* Prefix needs to be accounted as string too */
	read_ldesc.str_count++;

	err = ssdfs_set_lookup2_descriptor(node,
					   &node->lookup_tbl_area,
					   strings_range->index,
					   &read_ldesc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set lookup2 item: "
			  "index %u, err %d\n",
			  strings_range->index, err);
		goto check_node_consistency;
	}

	ssdfs_mark_lookup2_table_dirty(node);

	ssdfs_memcpy(&strings_range->desc, 0, l2desc_size,
		     &read_ldesc, 0, l2desc_size,
		     l2desc_size);

check_node_consistency:
	err = ssdfs_check_node_consistency(node);
	if (unlikely(err)) {
		SSDFS_ERR("node %u is corrupted: err %d\n",
			  node->node_id, err);
		goto finish_create_left_prefix;
	}

	atomic_set(&node->state, SSDFS_BTREE_NODE_DIRTY);

finish_create_left_prefix:
	up_write(&node->header_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("DEBUG SEARCH RESULT NAME:\n");
	ssdfs_debug_btree_search_result_name(search);
	SSDFS_DBG("END DEBUG OUTPUT\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_create_prefix_for_right_name() - create the prefix for right name
 * @node: node object
 * @search: search object
 * @prefix_len: length of the prefix
 *
 * This method tries to create the prefix for left name in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EOPNOTSUPP - unable to create the prefix.
 * %-ENOSPC     - node hasn't enough free space.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_create_prefix_for_right_name(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search,
					u16 prefix_len)
{
	struct ssdfs_string_descriptor *prefix, *left_name, *right_name;
	struct ssdfs_strings_range_descriptor *strings_range;
	struct ssdfs_shdict_htbl_item read_hdesc;
	struct ssdfs_shdict_ltbl2_item read_ldesc;
	size_t hdesc_size = sizeof(struct ssdfs_shdict_htbl_item);
	size_t l2desc_size = sizeof(struct ssdfs_shdict_ltbl2_item);
	size_t str_len;
	u32 hash_hi;
	u16 str_offset;
	size_t requested_size;
	u32 area_offset;
	u32 area_size;
	u32 free_space;
	u32 threshold;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, prefix_len %u\n",
		  node->node_id, prefix_len);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->result.name_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		/* expected states */
		break;

	default:
		SSDFS_ERR("invalid name state %#x\n",
			  search->result.name_state);
		return -ERANGE;
	}

	if (!search->result.name) {
		SSDFS_ERR("invalid name buffer\n");
		return -ERANGE;
	}

	prefix = &search->result.name->prefix;
	left_name = &search->result.name->left_name;
	right_name = &search->result.name->right_name;
	strings_range = &search->result.name->strings_range;

	switch (right_name->desc.type) {
	case SSDFS_FULL_NAME:
		/* expected type */
		break;

	case SSDFS_NAME_PREFIX:
		SSDFS_ERR("unsupported type %#x\n",
			  right_name->desc.type);
		return -EOPNOTSUPP;

	default:
		SSDFS_ERR("invalid type %#x\n",
			  right_name->desc.type);
		return -ERANGE;
	}

	if (!(search->request.flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME)) {
		SSDFS_ERR("request doesn't contain valid name\n");
		return -ERANGE;
	}

	if (!search->request.start.name) {
		SSDFS_ERR("empty name pointer\n");
		return -ERANGE;
	}

	str_len = search->request.start.name_len;

	if (str_len > SSDFS_MAX_NAME_LEN) {
		SSDFS_ERR("invalid str_len %zu\n", str_len);
		return -ERANGE;
	}

	if (prefix_len > str_len) {
		SSDFS_ERR("prefix_len %u > str_len %zu\n",
			  prefix_len, str_len);
		return -ERANGE;
	}

	requested_size = hdesc_size;

	down_write(&node->header_lock);

	if (!is_free_space_enough(node, requested_size)) {
		err = -ENOSPC;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u hasn't enough free space: "
			  "requested_size %zu\n",
			  node->node_id, requested_size);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_create_right_prefix;
	}

	area_offset = node->items_area.offset;
	area_size = node->items_area.area_size;
	free_space = node->items_area.free_space;

	if (free_space < requested_size) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted items area: free_space %u\n",
			  free_space);
		goto finish_create_right_prefix;
	}

	if (area_size < free_space) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted items area: "
			  "area_size %u, free_space %u\n",
			  area_size, free_space);
		goto finish_create_right_prefix;
	}

	area_size -= hdesc_size;

	err = ssdfs_resize_string_area(node, area_offset, area_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shrink the string area: "
			  "area_offset %u, area_size %u, err %d\n",
			  area_offset, area_size, err);
		goto check_node_consistency;
	}

	threshold = area_offset + area_size;

	area_offset = node->hash_tbl_area.offset;
	area_size = node->hash_tbl_area.area_size;

	if (area_offset < requested_size) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted area: "
			  "area_offset %u\n",
			  area_offset);
		goto finish_create_right_prefix;
	}

	if (threshold != (area_offset - requested_size)) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted area: "
			  "threshold %u, area_offset %u\n",
			  threshold, area_offset);
		goto finish_create_right_prefix;
	}

	area_offset -= hdesc_size;
	area_size += hdesc_size;

	err = ssdfs_resize_hash_table(node, area_offset, area_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to resize hash table: "
			  "area_offset %u, area_size %u, err %d\n",
			  area_offset, area_size, err);
		goto check_node_consistency;
	}

	threshold = area_offset + area_size;
	area_offset = node->lookup_tbl_area.offset;

	if (threshold != area_offset) {
		err = -ERANGE;
		SSDFS_ERR("threshold %u != area_offset %u\n",
			  threshold, area_offset);
		goto check_node_consistency;
	}

	if (is_ssdfs_resized_node_corrupted(node)) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("node %u has been corrupted during resize\n",
			  node->node_id);
		goto check_node_consistency;
	}

	err = ssdfs_get_hash_descriptor(node, &node->hash_tbl_area,
					right_name->index, &read_hdesc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash descriptor: "
			  "index %u, err %d\n",
			  right_name->index, err);
		goto check_node_consistency;
	}

	if (memcmp(&read_hdesc, &right_name->desc, hdesc_size) != 0) {
		err = -ERANGE;
		SSDFS_ERR("corrupted node: "
			  "different hash descriptors: "
			  "index %u\n",
			  right_name->index);
		goto check_node_consistency;
	}

	str_len = read_hdesc.str_len;
	hash_hi = le32_to_cpu(read_hdesc.hash_hi);
	str_offset = le16_to_cpu(read_hdesc.str_offset);
	read_hdesc.str_len = (u8)prefix_len;
	read_hdesc.type = SSDFS_NAME_PREFIX;

	err = ssdfs_set_hash_descriptor(node, &node->hash_tbl_area,
					right_name->index, &read_hdesc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set hash descriptor: "
			  "index %u, err %d\n",
			  right_name->index, err);
		goto check_node_consistency;
	}

	ssdfs_mark_hash_table_dirty(node);

	ssdfs_memcpy(&prefix->desc, 0, hdesc_size,
		     &read_hdesc, 0, hdesc_size,
		     hdesc_size);
	prefix->index = right_name->index;
	ssdfs_memcpy(&left_name->desc, 0, hdesc_size,
		     &read_hdesc, 0, hdesc_size,
		     hdesc_size);
	left_name->index = right_name->index;

	read_hdesc.hash_hi = cpu_to_le32(hash_hi);
	read_hdesc.str_offset = cpu_to_le16(str_offset + prefix_len);
	read_hdesc.str_len = (u8)(str_len - prefix_len);
	read_hdesc.type = SSDFS_NAME_SUFFIX;

	err = __ssdfs_hash_table_insert_descriptor(node, search,
						   right_name->index + 1,
						   &read_hdesc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert hash descriptor: "
			  "index %u, err %d\n",
			  right_name->index + 1, err);
		goto check_node_consistency;
	}

	ssdfs_memcpy(&right_name->desc, 0, hdesc_size,
		     &read_hdesc, 0, hdesc_size,
		     hdesc_size);
	right_name->index++;

	err = ssdfs_get_lookup2_descriptor(node,
					   &node->lookup_tbl_area,
					   strings_range->index + 1,
					   &read_ldesc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract lookup2 item: "
			  "index %u, err %d\n",
			  strings_range->index + 1,
			  err);
		goto check_node_consistency;
	}

	if (le16_to_cpu(read_ldesc.hash_index) != prefix->index) {
		err = -ERANGE;
		SSDFS_ERR("hash_index %u != prefix->index %u\n",
			  le16_to_cpu(read_ldesc.hash_index),
			  prefix->index);
		goto check_node_consistency;
	}

	if (read_ldesc.str_count != 1) {
		err = -ERANGE;
		SSDFS_ERR("invalid str_count %u\n",
			  read_ldesc.str_count);
		goto check_node_consistency;
	}

	read_ldesc.prefix_len = (u8)prefix_len;

	/* Prefix needs to be accounted as string too */
	read_ldesc.str_count++;

	err = ssdfs_set_lookup2_descriptor(node,
					   &node->lookup_tbl_area,
					   strings_range->index + 1,
					   &read_ldesc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set lookup2 item: "
			  "index %u, err %d\n",
			  strings_range->index + 1, err);
		goto check_node_consistency;
	}

	ssdfs_mark_lookup2_table_dirty(node);

	ssdfs_memcpy(&strings_range->desc, 0, l2desc_size,
		     &read_ldesc, 0, l2desc_size,
		     l2desc_size);
	strings_range->index++;

check_node_consistency:
	err = ssdfs_check_node_consistency(node);
	if (unlikely(err)) {
		SSDFS_ERR("node %u is corrupted: err %d\n",
			  node->node_id, err);
		goto finish_create_right_prefix;
	}

	atomic_set(&node->state, SSDFS_BTREE_NODE_DIRTY);

finish_create_right_prefix:
	up_write(&node->header_lock);

	return err;
}

/*
 * __ssdfs_insert_suffix() - insert a name's suffix in the node
 * @node: node object
 * @search: search object
 * @prefix_len: length of the prefix
 *
 * This method tries to insert a name's suffix in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - node hasn't enough free space.
 * %-EFAULT     - node is corrupted.
 */
static
int __ssdfs_insert_suffix(struct ssdfs_btree_node *node,
			  struct ssdfs_btree_search *search,
			  u16 prefix_len)
{
	struct ssdfs_string_descriptor *prefix, *left_name, *right_name;
	const char *name;
	struct ssdfs_shdict_htbl_item read_hdesc;
	u32 area_size;
	u32 free_space;
	u16 items_count;
	u32 items_capacity;
	size_t name_len, suffix_len;
	u16 str_offset;
	u32 insert_hash32_hi;
	u32 prefix_hash32_hi;
	u32 lname_hash32_hi;
	u32 rname_hash32_hi;
	u32 range_len;
	u8 min_item_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
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

	area_size = node->items_area.area_size;
	free_space = node->items_area.free_space;
	items_count = node->items_area.items_count;
	min_item_size = node->items_area.min_item_size;

	if (min_item_size != SSDFS_DENTRY_INLINE_NAME_MAX_LEN) {
		SSDFS_ERR("invalid min_item_size %u\n",
			  min_item_size);
		return -ERANGE;
	}

	if (free_space > area_size) {
		SSDFS_ERR("free_space %u > area_size %u\n",
			  free_space, area_size);
		return -ERANGE;
	}

	if (!(search->request.flags &
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE)) {
		SSDFS_ERR("request doesn't contain the hash\n");
		return -ERANGE;
	}

	if (!(search->request.flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME)) {
		SSDFS_ERR("request doesn't contain the name\n");
		return -ERANGE;
	}

	if (search->request.count != 1) {
		SSDFS_ERR("invalid request: "
			  "search->request.count %u\n",
			  search->request.count);
		return -ERANGE;
	}

	if (!search->result.name) {
		SSDFS_ERR("empty name descriptor\n");
		return -ERANGE;
	}

	prefix = &search->result.name->prefix;
	left_name = &search->result.name->left_name;
	right_name = &search->result.name->right_name;

	if (prefix->desc.str_len != prefix_len) {
		SSDFS_ERR("desc.str_len %u != prefix_len %u\n",
			  prefix->desc.str_len,
			  prefix_len);
		return -ERANGE;
	}

	name_len = search->request.start.name_len;

	if (prefix_len >= name_len) {
		SSDFS_ERR("prefix_len %u >= name_len %zu\n",
			  prefix_len, name_len);
		return -ERANGE;
	}

	suffix_len = name_len - prefix_len;

	if (suffix_len > free_space) {
		SSDFS_ERR("suffix_len %zu > free_space %u\n",
			  suffix_len, free_space);
		return -ENOSPC;
	}

	name = search->request.start.name;

	if (!name) {
		SSDFS_ERR("invalid name pointer\n");
		return -ERANGE;
	}

	switch (prefix->desc.type) {
	case SSDFS_NAME_PREFIX:
		/* expected type */
		break;

	default:
		SSDFS_ERR("unexpected left_name type %#x\n",
			  left_name->desc.type);
		return -ERANGE;
	}

	insert_hash32_hi = SSDFS_HASH32_HI(search->request.start.hash);
	rname_hash32_hi = le32_to_cpu(right_name->desc.hash_hi);
	lname_hash32_hi = le32_to_cpu(left_name->desc.hash_hi);

	switch (right_name->desc.type) {
	case SSDFS_FULL_NAME:
	case SSDFS_NAME_PREFIX:
		if (insert_hash32_hi >= rname_hash32_hi) {
			SSDFS_ERR("invalid position: "
				  "name->hash %#x, "
				  "desc.hash %#x\n",
				  insert_hash32_hi,
				  rname_hash32_hi);
			return -ERANGE;
		}
		break;

	case SSDFS_NAME_SUFFIX:
		if (left_name->index <= right_name->index) {
			if (insert_hash32_hi == rname_hash32_hi) {
				SSDFS_ERR("invalid position: "
					  "name->hash %#x, "
					  "desc.hash %#x\n",
					  insert_hash32_hi,
					  rname_hash32_hi);
				return -ERANGE;
			}
		} else {
			SSDFS_ERR("corrupted node: "
				  "left_name->index %u, "
				  "right_name->index %u\n",
				  left_name->index,
				  right_name->index);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("unexpected right_name type %#x\n",
			  right_name->desc.type);
		return -ERANGE;
	}

	switch (left_name->desc.type) {
	case SSDFS_NAME_PREFIX:
	case SSDFS_NAME_SUFFIX:
		if (insert_hash32_hi == lname_hash32_hi) {
			SSDFS_ERR("invalid position: "
				  "name->hash %#x, "
				  "desc.hash %#x\n",
				  insert_hash32_hi,
				  lname_hash32_hi);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("unexpected left_name type %#x\n",
			  left_name->desc.type);
		return -ERANGE;
	}

	if (insert_hash32_hi > rname_hash32_hi) {
		/* insert after right suffix */
		str_offset = le16_to_cpu(right_name->desc.str_offset);
		str_offset += right_name->desc.str_len;
	} else if (insert_hash32_hi > lname_hash32_hi) {
		/* insert after left suffix */
		str_offset = le16_to_cpu(left_name->desc.str_offset);
		str_offset += left_name->desc.str_len;
	} else if (insert_hash32_hi < lname_hash32_hi) {
		/* insert before left suffix */
		str_offset = le16_to_cpu(left_name->desc.str_offset);
	} else
		BUG();

	range_len = area_size - free_space - str_offset;

	if (range_len > 0) {
		err = ssdfs_shift_memory_range_right(node, &node->items_area,
						     str_offset, range_len,
						     suffix_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to shift the range: "
				  "start %u, range %u, "
				  "shift %zu, err %d\n",
				  str_offset, range_len, suffix_len, err);
			return err;
		}
	}

	err = ssdfs_copy_string_from_buffer(node,
					    name + prefix_len,
					    suffix_len,
					    str_offset);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy string: "
			  "node_id %u, str_offset %u, "
			  "suffix_len %zu, err %d\n",
			  node->node_id, str_offset,
			  suffix_len, err);
		return err;
	}

	prefix_hash32_hi = le32_to_cpu(prefix->desc.hash_hi);

	if (insert_hash32_hi < prefix_hash32_hi) {
		err = ssdfs_get_hash_descriptor(node, &node->hash_tbl_area,
						prefix->index, &read_hdesc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get hash descriptor: "
				  "index %u, err %d\n",
				  prefix->index, err);
			return err;
		}

		read_hdesc.hash_hi = cpu_to_le32(insert_hash32_hi);

		err = ssdfs_set_hash_descriptor(node, &node->hash_tbl_area,
						prefix->index, &read_hdesc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set hash descriptor: "
				  "index %u, err %d\n",
				  prefix->index, err);
			return err;
		}

		ssdfs_mark_hash_table_dirty(node);
	}

	node->items_area.items_count += 1;
	node->items_area.free_space -= suffix_len;

	node->items_area.item_size = ssdfs_define_item_size(node);

	items_capacity = ssdfs_define_items_capacity(node);
	if (items_capacity >= U16_MAX) {
		SSDFS_ERR("invalid items_capacity %u\n",
			  items_capacity);
		return -ERANGE;
	}

	node->items_area.items_capacity = (u16)items_capacity;

	if (search->request.start.hash < node->items_area.start_hash)
		node->items_area.start_hash = search->request.start.hash;

	if (node->items_area.end_hash < search->request.start.hash)
		node->items_area.end_hash = search->request.start.hash;

	return 0;
}

/*
 * ssdfs_insert_suffix() - insert a name's suffix in the node
 * @node: node object
 * @search: search object
 * @prefix_len: length of the prefix
 *
 * This method tries to insert a name's suffix in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - node hasn't enough free space.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_insert_suffix(struct ssdfs_btree_node *node,
			struct ssdfs_btree_search *search,
			u16 prefix_len)
{
	size_t hdesc_size = sizeof(struct ssdfs_shdict_htbl_item);
	size_t str_len;
	size_t requested_size;
	u32 area_offset;
	u32 area_size;
	u32 free_space;
	u32 threshold;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	str_len = search->request.start.name_len;
	requested_size = (str_len - prefix_len) + hdesc_size;

	if (!is_free_space_enough(node, requested_size)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u hasn't enough free space: "
			  "requested_size %zu\n",
			  node->node_id, requested_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOSPC;
	}

	area_offset = node->items_area.offset;
	area_size = node->items_area.area_size;
	free_space = node->items_area.free_space;

	if (free_space < requested_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted items area: free_space %u\n",
			  free_space);
		return -ERANGE;
	}

	if (area_size < free_space) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted items area: "
			  "area_size %u, free_space %u\n",
			  area_size, free_space);
		return -ERANGE;
	}

	area_size -= hdesc_size;

	err = ssdfs_resize_string_area(node, area_offset, area_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shrink the string area: "
			  "area_offset %u, area_size %u, err %d\n",
			  area_offset, area_size, err);
		return err;
	}

	threshold = area_offset + area_size;

	area_offset = node->hash_tbl_area.offset;
	area_size = node->hash_tbl_area.area_size;

	if (area_offset <= hdesc_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted area: "
			  "area_offset %u\n",
			  area_offset);
		return -ERANGE;
	}

	if (threshold != (area_offset - hdesc_size)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted area: "
			  "threshold %u, area_offset %u\n",
			  threshold, area_offset);
		return -ERANGE;
	}

	area_offset -= hdesc_size;
	area_size += hdesc_size;

	err = ssdfs_resize_hash_table(node, area_offset, area_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to resize hash table: "
			  "area_offset %u, area_size %u, err %d\n",
			  area_offset, area_size, err);
		return err;
	}

	threshold = area_offset + area_size;
	area_offset = node->lookup_tbl_area.offset;

	if (threshold != area_offset) {
		SSDFS_ERR("threshold %u != area_offset %u\n",
			  threshold, area_offset);
		return -ERANGE;
	}

	if (is_ssdfs_resized_node_corrupted(node)) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("node %u has been corrupted during resize\n",
			  node->node_id);
		return err;
	}

	err = __ssdfs_insert_suffix(node, search, prefix_len);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert suffix: err %d\n",
			  err);
		return err;
	}

	err = ssdfs_hash_table_insert_descriptor(node, search,
						 (u8)(str_len - prefix_len),
						 SSDFS_NAME_SUFFIX);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert hash descriptor: err %d\n", err);
		return err;
	}

	err = ssdfs_lookup2_table_inc_str_count(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to increase str_count: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_insert_suffix_into_left_range() - insert a name's suffix in left range
 * @node: node object
 * @search: search object
 * @prefix_len: length of the prefix
 *
 * This method tries to insert a name's suffix in the left range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EOPNOTSUPP - unable to insert the name's suffix.
 * %-ENOSPC     - node hasn't enough free space.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_insert_suffix_into_left_range(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search,
					u16 prefix_len)
{
	struct ssdfs_string_descriptor *prefix, *left_name;
	struct ssdfs_strings_range_descriptor *strings_range;
	struct ssdfs_shdict_ltbl2_item *ltbl2_item;
	size_t str_len;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(search->request.flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME)) {
		SSDFS_ERR("request doesn't contain valid name\n");
		return -ERANGE;
	}

	if (!search->request.start.name) {
		SSDFS_ERR("empty name pointer\n");
		return -ERANGE;
	}

	str_len = search->request.start.name_len;

	if (str_len > SSDFS_MAX_NAME_LEN) {
		SSDFS_ERR("invalid str_len %zu\n", str_len);
		return -ERANGE;
	}

	switch (search->result.name_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		/* expected states */
		break;

	default:
		SSDFS_ERR("invalid name state %#x\n",
			  search->result.name_state);
		return -ERANGE;
	}

	if (!search->result.name) {
		SSDFS_ERR("invalid name buffer\n");
		return -ERANGE;
	}

	strings_range = &search->result.name->strings_range;
	ltbl2_item = &strings_range->desc;

	prefix = &search->result.name->prefix;
	left_name = &search->result.name->left_name;

	switch (prefix->desc.type) {
	case SSDFS_NAME_PREFIX:
		/* expected type */
		break;

	default:
		SSDFS_ERR("invalid type %#x\n",
			  prefix->desc.type);
		return -ERANGE;
	}

	switch (left_name->desc.type) {
	case SSDFS_NAME_SUFFIX:
		/* expected type */
		break;

	default:
		SSDFS_ERR("invalid type %#x\n",
			  left_name->desc.type);
		return -ERANGE;
	}

	if (le16_to_cpu(ltbl2_item->hash_index) != prefix->index) {
		SSDFS_ERR("corrupted search result: "
			  "ltbl2_item->hash_index %u, "
			  "prefix->index %u\n",
			  le16_to_cpu(ltbl2_item->hash_index),
			  prefix->index);
		return -ERANGE;
	}

	if (prefix->index > left_name->index) {
		SSDFS_ERR("corrupted search result: "
			  "prefix->index %u, "
			  "left_name->index %u\n",
			  prefix->index, left_name->index);
		return -ERANGE;
	}

	if (left_name->index >= (prefix->index + ltbl2_item->str_count)) {
		SSDFS_ERR("corrupted search result: "
			  "left_name->index %u, "
			  "prefix->index %u, "
			  "ltbl2_item->str_count %u\n",
			  left_name->index, prefix->index,
			  ltbl2_item->str_count);
		return -ERANGE;
	}

	if (prefix_len > str_len) {
		SSDFS_ERR("prefix_len %u > str_len %zu\n",
			  prefix_len, str_len);
		return -ERANGE;
	}

	if (prefix_len != prefix->desc.str_len) {
		SSDFS_ERR("prefix_len %u != prefix->desc.str_len %u\n",
			  prefix_len,
			  prefix->desc.str_len);
		return -ERANGE;
	}

	down_write(&node->header_lock);

	err = ssdfs_insert_suffix(node, search, prefix_len);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert name's suffix: err %d\n",
			  err);
		if (atomic_read(&node->state) == SSDFS_BTREE_NODE_CORRUPTED)
			goto finish_insert_left_suffix;
		else
			goto check_node_consistency;
	}

check_node_consistency:
	err = ssdfs_check_node_consistency(node);
	if (unlikely(err)) {
		SSDFS_ERR("node %u is corrupted: err %d\n",
			  node->node_id, err);
		goto finish_insert_left_suffix;
	}

	atomic_set(&node->state, SSDFS_BTREE_NODE_DIRTY);

finish_insert_left_suffix:
	up_write(&node->header_lock);

	return err;
}

/*
 * ssdfs_insert_suffix_into_right_range() - insert a suffix into right range
 * @node: node object
 * @search: search object
 * @prefix_len: length of the prefix
 *
 * This method tries to insert a name's suffix into the right range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EOPNOTSUPP - unable to insert the name's suffix.
 * %-ENOSPC     - node hasn't enough free space.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_insert_suffix_into_right_range(struct ssdfs_btree_node *node,
					 struct ssdfs_btree_search *search,
					 u16 prefix_len)
{
	struct ssdfs_string_descriptor *prefix, *left_name, *right_name;
	struct ssdfs_strings_range_descriptor *strings_range;
	struct ssdfs_shdict_ltbl2_item *ltbl2_item;
	size_t str_len;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(search->request.flags & SSDFS_BTREE_SEARCH_HAS_VALID_NAME)) {
		SSDFS_ERR("request doesn't contain valid name\n");
		return -ERANGE;
	}

	if (!search->request.start.name) {
		SSDFS_ERR("empty name pointer\n");
		return -ERANGE;
	}

	str_len = search->request.start.name_len;

	if (str_len > SSDFS_MAX_NAME_LEN) {
		SSDFS_ERR("invalid str_len %zu\n", str_len);
		return -ERANGE;
	}

	switch (search->result.name_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		/* expected states */
		break;

	default:
		SSDFS_ERR("invalid name state %#x\n",
			  search->result.name_state);
		return -ERANGE;
	}

	if (!search->result.name) {
		SSDFS_ERR("invalid name buffer\n");
		return -ERANGE;
	}

	strings_range = &search->result.name->strings_range;
	ltbl2_item = &strings_range->desc;

	prefix = &search->result.name->prefix;
	left_name = &search->result.name->left_name;
	right_name = &search->result.name->right_name;

	switch (prefix->desc.type) {
	case SSDFS_NAME_PREFIX:
		/* expected type */
		break;

	default:
		SSDFS_ERR("invalid type %#x\n",
			  prefix->desc.type);
		return -ERANGE;
	}

	switch (left_name->desc.type) {
	case SSDFS_NAME_SUFFIX:
		/* expected type */
		break;

	default:
		SSDFS_ERR("invalid type %#x\n",
			  left_name->desc.type);
		return -ERANGE;
	}

	switch (right_name->desc.type) {
	case SSDFS_NAME_SUFFIX:
		/* expected type */
		break;

	default:
		SSDFS_ERR("invalid type %#x\n",
			  right_name->desc.type);
		return -ERANGE;
	}

	if (le16_to_cpu(ltbl2_item->hash_index) != prefix->index) {
		SSDFS_ERR("corrupted search result: "
			  "ltbl2_item->hash_index %u, "
			  "prefix->index %u\n",
			  le16_to_cpu(ltbl2_item->hash_index),
			  prefix->index);
		return -ERANGE;
	}

	if (prefix->index > left_name->index) {
		SSDFS_ERR("corrupted search result: "
			  "prefix->index %u, "
			  "left_name->index %u\n",
			  prefix->index, left_name->index);
		return -ERANGE;
	}

	if (left_name->index > right_name->index) {
		SSDFS_ERR("corrupted search result: "
			  "left_name->index %u, "
			  "right_name->index %u\n",
			  left_name->index, right_name->index);
		return -ERANGE;
	}

	if (left_name->index >= (prefix->index + ltbl2_item->str_count)) {
		SSDFS_ERR("corrupted search result: "
			  "left_name->index %u, "
			  "prefix->index %u, "
			  "ltbl2_item->str_count %u\n",
			  left_name->index, prefix->index,
			  ltbl2_item->str_count);
		return -ERANGE;
	}

	if (right_name->index >= (prefix->index + ltbl2_item->str_count)) {
		SSDFS_ERR("corrupted search result: "
			  "right_name->index %u, "
			  "prefix->index %u, "
			  "ltbl2_item->str_count %u\n",
			  right_name->index, prefix->index,
			  ltbl2_item->str_count);
		return -ERANGE;
	}

	if (prefix_len > str_len) {
		SSDFS_ERR("prefix_len %u > str_len %zu\n",
			  prefix_len, str_len);
		return -ERANGE;
	}

	if (prefix_len != prefix->desc.str_len) {
		SSDFS_ERR("prefix_len %u != prefix->desc.str_len %u\n",
			  prefix_len,
			  prefix->desc.str_len);
		return -ERANGE;
	}

	down_write(&node->header_lock);

	err = ssdfs_insert_suffix(node, search, prefix_len);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert name's suffix: err %d\n",
			  err);
		if (atomic_read(&node->state) == SSDFS_BTREE_NODE_CORRUPTED)
			goto finish_insert_right_suffix;
		else
			goto check_node_consistency;
	}

check_node_consistency:
	err = ssdfs_check_node_consistency(node);
	if (unlikely(err)) {
		SSDFS_ERR("node %u is corrupted: err %d\n",
			  node->node_id, err);
		goto finish_insert_right_suffix;
	}

	atomic_set(&node->state, SSDFS_BTREE_NODE_DIRTY);

finish_insert_right_suffix:
	up_write(&node->header_lock);

	return err;
}

/*
 * ssdfs_correct_search_result_for_full_name() - correct search result
 * @node: node object
 * @search: search object
 *
 * This method tries to correct a search result for the case
 * of full name.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_correct_search_result_for_full_name(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search)
{
	struct ssdfs_string_descriptor *left_name, *right_name;
	struct ssdfs_strings_range_descriptor *strings_range;
	struct ssdfs_shdict_ltbl2_item *ltbl2_item;
	struct ssdfs_shdict_search_key key = {0};
	u32 index;
	u32 hash_hi32;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	left_name = &search->result.name->left_name;
	right_name = &search->result.name->right_name;
	strings_range = &search->result.name->strings_range;
	ltbl2_item = &strings_range->desc;

	switch (left_name->desc.type) {
	case SSDFS_NAME_SUFFIX:
		/* continue logic */
		break;

	default:
		/* nothing should be done */
		return 0;
	}

	index = le16_to_cpu(ltbl2_item->hash_index);
	index += ltbl2_item->str_count - 1;

	err = ssdfs_get_hash_table_search_key(node, index, &key);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash item: "
			  "node_id %u, index %u, err %d\n",
			  node->node_id, index, err);
		return err;
	}

	/* simulate presence of name with lesser hash */
	hash_hi32 = SSDFS_HASH32_HI(search->request.start.hash) - 1;

	left_name->index = index;
	ssdfs_memcpy(&left_name->desc,
		     0, sizeof(struct ssdfs_shdict_htbl_item),
		     &key,
		     0, sizeof(struct ssdfs_shdict_search_key),
		     sizeof(struct ssdfs_shdict_htbl_item));
	left_name->desc.hash_hi = cpu_to_le32(hash_hi32);

	right_name->index = index;
	ssdfs_memcpy(&right_name->desc,
		     0, sizeof(struct ssdfs_shdict_htbl_item),
		     &key,
		     0, sizeof(struct ssdfs_shdict_search_key),
		     sizeof(struct ssdfs_shdict_htbl_item));
	right_name->desc.hash_hi = cpu_to_le32(hash_hi32);

	return 0;
}

/*
 * __ssdfs_shared_dict_btree_node_insert_item() - insert an item into the node
 * @node: node object
 * @search: search object
 *
 * This method tries to insert an item into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EOPNOTSUPP - unable to insert the name's suffix.
 * %-ENOSPC     - node hasn't enough free space.
 * %-EFAULT     - node is corrupted.
 */
static
int __ssdfs_shared_dict_btree_node_insert_item(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node_items_area items_area;
	struct ssdfs_btree_node_index_area lookup_tbl_area;
	struct ssdfs_btree_node_index_area hash_tbl_area;
	size_t hdr_size = sizeof(struct ssdfs_shared_dictionary_node_header);
	u16 index_area_size;
	u16 str_area_offset;
	u16 str_area_bytes;
	u16 hash_tbl_offset;
	u16 hash_tbl_size;
	u16 lookup_tbl2_offset;
	u16 lookup_tbl2_size;
	u16 left_len, right_len;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
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

	switch (atomic_read(&node->lookup_tbl_area.state)) {
	case SSDFS_BTREE_NODE_LOOKUP_TBL_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid lookup_tbl_area state %#x\n",
			  atomic_read(&node->lookup_tbl_area.state));
		return -ERANGE;
	}

	switch (atomic_read(&node->hash_tbl_area.state)) {
	case SSDFS_BTREE_NODE_HASH_TBL_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid hash_tbl_area state %#x\n",
			  atomic_read(&node->hash_tbl_area.state));
		return -ERANGE;
	}

	down_write(&node->full_lock);

	down_read(&node->header_lock);
	index_area_size = node->index_area.area_size;
	ssdfs_memcpy(&items_area,
		     0, sizeof(struct ssdfs_btree_node_items_area),
		     &node->items_area,
		     0, sizeof(struct ssdfs_btree_node_items_area),
		     sizeof(struct ssdfs_btree_node_items_area));
	ssdfs_memcpy(&lookup_tbl_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     &node->lookup_tbl_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     sizeof(struct ssdfs_btree_node_index_area));
	ssdfs_memcpy(&hash_tbl_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     &node->hash_tbl_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     sizeof(struct ssdfs_btree_node_index_area));
	up_read(&node->header_lock);

	err = ssdfs_check_items_area(node, &items_area);
	if (unlikely(err)) {
		SSDFS_ERR("items area is corrupted: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		goto finish_insert_item;
	}

	err = ssdfs_check_lookup2_table_area(node, &lookup_tbl_area);
	if (unlikely(err)) {
		SSDFS_ERR("lookup2 table area is corrupted: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		goto finish_insert_item;
	}

	err = ssdfs_check_hash_table_area(node, &hash_tbl_area);
	if (unlikely(err)) {
		SSDFS_ERR("hash table area is corrupted: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		goto finish_insert_item;
	}

	str_area_offset = items_area.offset;
	str_area_bytes = items_area.area_size;
	hash_tbl_offset = hash_tbl_area.offset;
	hash_tbl_size = hash_tbl_area.area_size;
	lookup_tbl2_offset = lookup_tbl_area.offset;
	lookup_tbl2_size = lookup_tbl_area.area_size;

	if (str_area_offset != (hdr_size + index_area_size)) {
		err = -EIO;
		SSDFS_ERR("corrupted strings area: "
			  "str_area_offset %u, hdr_size %zu, "
			  "index_area_size %u\n",
			  str_area_offset,
			  hdr_size,
			  index_area_size);
		goto finish_insert_item;
	}

	if (hash_tbl_offset != (str_area_offset + str_area_bytes)) {
		err = -EIO;
		SSDFS_ERR("corrupted hash table: "
			  "hash_tbl_offset %u, str_area_offset %u, "
			  "str_area_bytes %u\n",
			  hash_tbl_offset,
			  str_area_offset,
			  str_area_bytes);
		goto finish_insert_item;
	}

	if (lookup_tbl2_offset != (hash_tbl_offset + hash_tbl_size)) {
		err = -EIO;
		SSDFS_ERR("corrupted lookup table: "
			  "lookup_tbl2_offset %u, hash_tbl_offset %u, "
			  "hash_tbl_size %u\n",
			  lookup_tbl2_offset,
			  hash_tbl_offset,
			  hash_tbl_size);
		goto finish_insert_item;
	}

	if (items_area.items_count == 0) {
		err = ssdfs_add_full_name(node, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add the full name: "
				  "node_id %u, err %d\n",
				  node->node_id, err);
			goto finish_insert_item;
		}
	} else {
		err = ssdfs_extract_intersection_with_left_name(node,
								search,
								&left_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract intersection: "
				  "err %d\n", err);
			goto finish_insert_item;
		}

		err = ssdfs_extract_intersection_with_right_name(node,
								search,
								&right_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract intersection: "
				  "err %d\n", err);
			goto finish_insert_item;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("left_len %u, right_len %u\n",
			  left_len, right_len);
#endif /* CONFIG_SSDFS_DEBUG */

		if (left_len < SSDFS_LOWER_PREFIX_THRESHOLD &&
		    right_len < SSDFS_LOWER_PREFIX_THRESHOLD) {
			err = ssdfs_correct_search_result_for_full_name(node,
									search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to correct search result: "
					  "err %d\n", err);
				goto finish_insert_item;
			}

			err = ssdfs_add_full_name(node, search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add the full name: "
					  "node_id %u, err %d\n",
					  node->node_id, err);
				goto finish_insert_item;
			}
		} else if (left_len >= right_len) {
			if (left_len > SSDFS_DEFAULT_PREFIX_LEN)
				left_len = SSDFS_DEFAULT_PREFIX_LEN;

			if (is_ssdfs_left_full_name(search)) {
				err = ssdfs_create_prefix_for_left_name(node,
								    search,
								    left_len);
				if (err == -EOPNOTSUPP) {
					err = ssdfs_add_full_name(node, search);
					if (unlikely(err)) {
						SSDFS_ERR("fail to add name: "
							  "node_id %u, "
							  "err %d\n",
							  node->node_id,
							  err);
					}

					goto finish_insert_item;
				} else if (unlikely(err)) {
					SSDFS_ERR("fail to create prefix: "
						  "len %u, err %d\n",
						  left_len, err);
					goto finish_insert_item;
				}
			}

			err = ssdfs_insert_suffix_into_left_range(node,
								  search,
								  left_len);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add suffix into range: "
					  "err %d\n", err);
				goto finish_insert_item;
			}
		} else {
			if (right_len > SSDFS_DEFAULT_PREFIX_LEN)
				right_len = SSDFS_DEFAULT_PREFIX_LEN;

			if (is_ssdfs_right_full_name(search)) {
				err = ssdfs_create_prefix_for_right_name(node,
								    search,
								    right_len);
				if (err == -EOPNOTSUPP) {
					err = ssdfs_add_full_name(node, search);
					if (unlikely(err)) {
						SSDFS_ERR("fail to add name: "
							  "node_id %u, "
							  "err %d\n",
							  node->node_id,
							  err);
					}

					goto finish_insert_item;
				} else if (unlikely(err)) {
					SSDFS_ERR("fail to create prefix: "
						  "len %u, err %d\n",
						  right_len, err);
					goto finish_insert_item;
				}
			}

			err = ssdfs_insert_suffix_into_right_range(node,
								   search,
								   right_len);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add suffix into range: "
					  "err %d\n", err);
				goto finish_insert_item;
			}
		}
	}

finish_insert_item:
	up_write(&node->full_lock);

	return err;
}

/*
 * ssdfs_shared_dict_btree_node_insert_item() - insert item in the node
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
 * %-ENOSPC     - node hasn't free space.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_shared_dict_btree_node_insert_item(struct ssdfs_btree_node *node,
					     struct ssdfs_btree_search *search)
{
	int state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

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
		 * Node doesn't contain an item.
		 */
	} else if (search->result.err) {
		SSDFS_WARN("invalid search result: err %d\n",
			   search->result.err);
		return search->result.err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.count != 1);
	BUG_ON(!(search->request.flags &
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE));
	BUG_ON(!(search->request.flags &
			SSDFS_BTREE_SEARCH_HAS_VALID_NAME));
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&node->items_area.state);
	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  state);
		return -ERANGE;
	}

	err = __ssdfs_shared_dict_btree_node_insert_item(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert item: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	ssdfs_debug_btree_node_object(node);

	return 0;
}

/*
 * ssdfs_shared_dict_btree_node_insert_range() - insert a range into the node
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to insert a range of items into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - node hasn't free space.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_shared_dict_btree_node_insert_range(struct ssdfs_btree_node *node,
					      struct ssdfs_btree_search *search)
{
	struct ssdfs_name_string *cur_name;
	u32 request_flags;
	int state;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

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

	state = atomic_read(&node->items_area.state);
	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  state);
		return -ERANGE;
	}

	switch (search->result.name_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
		if (search->result.names_in_buffer != 1) {
			SSDFS_ERR("inconsistent search result: "
				  "names_in_buffer %u\n",
				  search->result.names_in_buffer);
			return -ERANGE;
		}
		break;

	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		if (search->result.names_in_buffer < 1) {
			SSDFS_ERR("inconsistent search result: "
				  "names_in_buffer %u\n",
				  search->result.names_in_buffer);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("invalid search result state %#x\n",
			  search->result.name_state);
		return -ERANGE;
	}

	if (!search->result.name) {
		SSDFS_ERR("invalid buffer pointer\n");
		return -ERANGE;
	}

	request_flags = search->request.flags;

	if (search->request.count != search->result.names_in_buffer) {
		if (request_flags & SSDFS_BTREE_SEARCH_HAS_VALID_COUNT) {
			SSDFS_ERR("count %u != names_in_buffer %u\n",
				  search->request.count,
				  search->result.names_in_buffer);
			return -ERANGE;
		} else {
			search->request.count = search->result.names_in_buffer;
			search->request.flags |=
				SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
		}
	}

	cur_name = &search->result.name[search->result.names_in_buffer - 1];
	search->request.end.name = cur_name->str;
	search->request.end.name_len = cur_name->len;
	search->request.end.hash = cur_name->hash;

	for (i = 0; i < search->result.names_in_buffer; i++) {
		cur_name = &search->result.name[i];

		search->request.start.name = cur_name->str;
		search->request.start.name_len = cur_name->len;
		search->request.start.hash = cur_name->hash;

		search->request.flags |=
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE;
		search->request.flags |=
			SSDFS_BTREE_SEARCH_HAS_VALID_NAME;
		search->request.flags |=
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;

		err = __ssdfs_shared_dict_btree_node_insert_item(node, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert item: "
				  "node_id %u, index %d, err %d\n",
				  node->node_id, i, err);
			return err;
		}

		search->request.count--;
	}

	ssdfs_debug_btree_node_object(node);

	return 0;
}

static
int ssdfs_shared_dict_btree_node_change_item(struct ssdfs_btree_node *node,
					     struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("operation is unavailable\n");
#endif /* CONFIG_SSDFS_DEBUG */
	return -EOPNOTSUPP;
}

#define SSDFS_HTBL_DESC(ptr) \
	((struct ssdfs_shdict_htbl_item *)(ptr))
#define SSDFS_LTBL2_DESC(ptr) \
	((struct ssdfs_shdict_ltbl2_item *)(ptr))

/*
 * is_lookup1_position_correct() - check that lookup1 position is correct
 * @node: pointer on node object
 * @search: search object
 *
 * This method tries to check that requested position
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
static inline
int is_lookup1_position_correct(struct ssdfs_btree_node *node,
				struct ssdfs_btree_search *search)
{
	struct ssdfs_lookup_descriptor *lookup;
	struct ssdfs_shdict_search_key req_key, found_key;
	size_t key_size = sizeof(struct ssdfs_shdict_search_key);
	int err, res;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	lookup = &search->result.name->lookup;
	ssdfs_memcpy(&req_key, 0, key_size,
		     &lookup->desc, 0, key_size,
		     key_size);

	err = ssdfs_get_lookup1_table_search_key(node, lookup->index,
						 &found_key);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get lookup1 key: "
			  "index %u, err %d\n",
			  lookup->index, err);
		return SSDFS_CHECK_POSITION_FAILURE;
	}

	res = ssdfs_hash32_lo_compare(&req_key, &found_key);
	if (res == 0)
		return SSDFS_CORRECT_POSITION;
	else if (res < 0)
		return SSDFS_SEARCH_RIGHT_DIRECTION;
	else
		return SSDFS_SEARCH_LEFT_DIRECTION;
}

/*
 * is_lookup2_position_correct() - check that lookup2 position is correct
 * @node: pointer on node object
 * @search: search object
 *
 * This method tries to check that requested position
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
static inline
int is_lookup2_position_correct(struct ssdfs_btree_node *node,
				struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node_index_area *lookup_tbl_area;
	struct ssdfs_strings_range_descriptor *strings_range;
	struct ssdfs_shdict_search_key req_key, found_key;
	size_t key_size = sizeof(struct ssdfs_shdict_search_key);
	int err, res;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	lookup_tbl_area = &node->lookup_tbl_area;

	strings_range = &search->result.name->strings_range;
	ssdfs_memcpy(&req_key, 0, key_size,
		     &strings_range->desc, 0, key_size,
		     key_size);

	err = ssdfs_get_lookup2_descriptor(node, lookup_tbl_area,
					   strings_range->index,
					   SSDFS_LTBL2_DESC(&found_key));
	if (unlikely(err)) {
		SSDFS_ERR("fail to get lookup2 key: "
			  "index %u, err %d\n",
			  strings_range->index, err);
		return SSDFS_CHECK_POSITION_FAILURE;
	}

	res = ssdfs_hash32_lo_compare(&req_key, &found_key);
	if (res == 0)
		return SSDFS_CORRECT_POSITION;
	else if (res < 0)
		return SSDFS_SEARCH_RIGHT_DIRECTION;
	else
		return SSDFS_SEARCH_LEFT_DIRECTION;
}

/*
 * is_hash_position_correct() - check that hash position is correct
 * @node: pointer on node object
 * @search: search object
 *
 * This method tries to check that requested position
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
static inline
int is_hash_position_correct(struct ssdfs_btree_node *node,
			     struct ssdfs_btree_search *search,
			     u16 item_index)
{
	struct ssdfs_btree_node_index_area *hash_tbl_area;
	struct ssdfs_shdict_search_key req_key = { .name = {0}, .range = {0} };
	struct ssdfs_shdict_search_key found_key = { .name = {0}, .range = {0} };
	int err, res;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	hash_tbl_area = &node->hash_tbl_area;

	err = ssdfs_convert_hash64_to_hash32_hi(search, &req_key);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert hash64: err %d\n",
			  err);
		return SSDFS_CHECK_POSITION_FAILURE;
	}

	err = ssdfs_get_hash_descriptor(node, hash_tbl_area,
					item_index,
					SSDFS_HTBL_DESC(&found_key));
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash descriptor: "
			  "index %u, err %d\n",
			  item_index, err);
		return SSDFS_CHECK_POSITION_FAILURE;
	}

	res = ssdfs_hash32_hi_compare(&req_key, &found_key);
	if (res == 0)
		return SSDFS_CORRECT_POSITION;
	else if (res < 0)
		return SSDFS_SEARCH_RIGHT_DIRECTION;
	else
		return SSDFS_SEARCH_LEFT_DIRECTION;
}

/*
 * is_requested_position_correct() - check that requested position is correct
 * @node: pointer on node object
 * @search: search object
 *
 * This method tries to check that requested position
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
				  struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node_items_area *items_area;
	struct ssdfs_btree_node_index_area *hash_tbl_area;
	struct ssdfs_btree_node_index_area *lookup_tbl_area;
	u16 item_index;
	u16 items_count, items_capacity;
	int direction = SSDFS_CHECK_POSITION_FAILURE;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, search->result.start_index);
#endif /* CONFIG_SSDFS_DEBUG */

	items_area = &node->items_area;
	hash_tbl_area = &node->hash_tbl_area;
	lookup_tbl_area = &node->lookup_tbl_area;

	items_count = items_area->items_count;
	items_capacity = items_area->items_capacity;

	item_index = search->result.start_index;
	if ((item_index + search->request.count) >= items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, count %u\n",
			  item_index, search->request.count);
		return SSDFS_CHECK_POSITION_FAILURE;
	}

	if (item_index >= items_count) {
		if (items_count == 0)
			item_index = items_count;
		else
			item_index = items_count - 1;

		search->result.start_index = item_index;
	}


	switch (search->result.name_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		/* expected states */
		break;

	default:
		SSDFS_ERR("invalid name state %#x\n",
			  search->result.name_state);
		return SSDFS_CHECK_POSITION_FAILURE;
	}

	if (!search->result.name) {
		SSDFS_ERR("invalid name buffer\n");
		return SSDFS_CHECK_POSITION_FAILURE;
	}

	direction = is_lookup1_position_correct(node, search);

	switch (direction) {
	case SSDFS_CHECK_POSITION_FAILURE:
	case SSDFS_SEARCH_LEFT_DIRECTION:
	case SSDFS_SEARCH_RIGHT_DIRECTION:
		return direction;

	default:
		/* continue the check */
		break;
	}

	direction = is_lookup2_position_correct(node, search);

	switch (direction) {
	case SSDFS_CHECK_POSITION_FAILURE:
	case SSDFS_SEARCH_LEFT_DIRECTION:
	case SSDFS_SEARCH_RIGHT_DIRECTION:
		return direction;

	default:
		/* continue the check */
		break;
	}

	return is_hash_position_correct(node, search, item_index);
}

/*
 * ssdfs_find_lookup1_position_from_left() - find a correct position from left
 * @node: node object
 * @search: search object
 *
 * This method tries to find the correct position from the left
 * for a lookup1 index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - the requested position is out of the node.
 * %-ENOENT     - possible place is found.
 */
static
int ssdfs_find_lookup1_position_from_left(struct ssdfs_btree_node *node,
					  struct ssdfs_btree_search *search)
{
	struct ssdfs_lookup_descriptor *lookup;
	struct ssdfs_shdict_search_key req_key, found_key;
	size_t key_size = sizeof(struct ssdfs_shdict_search_key);
	int i;
	int res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	lookup = &search->result.name->lookup;
	ssdfs_memcpy(&req_key, 0, key_size,
		     &lookup->desc, 0, key_size,
		     key_size);
	memset(&found_key, 0xFF, key_size);

	if (lookup->index == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find a new index: "
			  "lookup->index %u\n",
			  lookup->index);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	for (i = lookup->index - 1; i >= 0; i--) {
		err = ssdfs_get_lookup1_table_search_key(node, i, &found_key);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get lookup1 key: "
				  "index %d, err %d\n",
				  i, err);
			return err;
		}

		res = ssdfs_hash32_lo_compare(&req_key, &found_key);
		if (res == 0) {
			lookup->index = i;
			return 0;
		} else if (res > 0) {
			lookup->index = i;
			return -ENOENT;
		}
	}

	lookup->index = 0;
	return -ENODATA;
}

/*
 * ssdfs_find_lookup2_position_from_left() - find a correct position from left
 * @node: node object
 * @search: search object
 *
 * This method tries to find the correct position from the left
 * for a lookup2 index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - the requested position is out of the node.
 * %-ENOENT     - possible place is found.
 */
static
int ssdfs_find_lookup2_position_from_left(struct ssdfs_btree_node *node,
					  struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node_index_area *lookup_tbl_area;
	struct ssdfs_strings_range_descriptor *strings_range;
	struct ssdfs_shdict_search_key req_key = { .name = {0}, .range = {0} };
	struct ssdfs_shdict_search_key found_key = { .name = {0}, .range = {0} };
	size_t key_size = sizeof(struct ssdfs_shdict_search_key);
	int i;
	int res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	lookup_tbl_area = &node->lookup_tbl_area;

	strings_range = &search->result.name->strings_range;
	ssdfs_memcpy(&req_key, 0, key_size,
		     &strings_range->desc, 0, key_size,
		     key_size);

	if (strings_range->index == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find a new index: "
			  "strings_range->index %u\n",
			  strings_range->index);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	for (i = strings_range->index - 1; i >= 0; i--) {
		err = ssdfs_get_lookup2_descriptor(node, lookup_tbl_area, i,
						SSDFS_LTBL2_DESC(&found_key));
		if (unlikely(err)) {
			SSDFS_ERR("fail to get lookup2 key: "
				  "index %u, err %d\n",
				  i, err);
			return err;
		}

		res = ssdfs_hash32_lo_compare(&req_key, &found_key);
		if (res == 0) {
			strings_range->index = i;
			return 0;
		} else if (res > 0) {
			strings_range->index = i;
			return -ENOENT;
		}
	}

	strings_range->index = 0;
	return -ENODATA;
}

/*
 * ssdfs_find_hash_position_from_left() - find a correct position from left
 * @node: node object
 * @item_index: starting item index
 * @search: search object
 *
 * This method tries to find the correct position from the left
 * for a hash index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - the requested position is out of the node.
 * %-ENOENT     - possible place is found.
 */
static
int ssdfs_find_hash_position_from_left(struct ssdfs_btree_node *node,
					int item_index,
					struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node_index_area *hash_tbl_area;
	struct ssdfs_strings_range_descriptor *strings_range;
	struct ssdfs_shdict_search_key req_key = { .name = {0}, .range = {0} };
	struct ssdfs_shdict_search_key found_key = { .name = {0}, .range = {0} };
	u16 lower_bound;
	int i;
	int res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	hash_tbl_area = &node->hash_tbl_area;
	strings_range = &search->result.name->strings_range;

	lower_bound = le16_to_cpu(strings_range->desc.hash_index);

	if (item_index <= 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find a new index: "
			  "item_index %d\n",
			  item_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	if (item_index <= lower_bound) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("item_index %d <= lower_bound %u\n",
			  item_index, lower_bound);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	err = ssdfs_convert_hash64_to_hash32_hi(search, &req_key);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert hash64: err %d\n",
			  err);
		return err;
	}

	for (i = item_index - 1; i >= lower_bound; i--) {
		err = ssdfs_get_hash_descriptor(node, hash_tbl_area, i,
						SSDFS_HTBL_DESC(&found_key));
		if (unlikely(err)) {
			SSDFS_ERR("fail to get hash descriptor: "
				  "index %u, err %d\n",
				  i, err);
			return err;
		}

		res = ssdfs_hash32_hi_compare(&req_key, &found_key);
		if (res == 0) {
			search->result.name->right_name.index = i;
			return 0;
		} else if (res > 0) {
			search->result.name->right_name.index = i;
			return -ENOENT;
		}
	}

	search->result.name->right_name.index = lower_bound;
	return -ENODATA;
}

/*
 * ssdfs_find_correct_position_from_left() - find position from the left
 * @node: pointer on node object
 * @search: search object
 *
 * This method tries to find a correct position of the name
 * from the left side of names' sequence in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_find_correct_position_from_left(struct ssdfs_btree_node *node,
					  struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node_items_area *items_area;
	int item_index;
	u16 items_count, items_capacity;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, search->result.start_index);
#endif /* CONFIG_SSDFS_DEBUG */

	items_area = &node->items_area;
	items_count = items_area->items_count;
	items_capacity = items_area->items_capacity;

	item_index = search->result.start_index;
	if ((item_index + search->request.count) >= items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %d, count %u\n",
			  item_index, search->request.count);
		return -ERANGE;
	}

	if (item_index >= items_count) {
		if (items_count == 0)
			item_index = items_count;
		else
			item_index = items_count - 1;

		search->result.start_index = (u16)item_index;
	}

	if (item_index == 0)
		return 0;

	switch (search->result.name_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		/* expected states */
		break;

	default:
		SSDFS_ERR("invalid name state %#x\n",
			  search->result.name_state);
		return -ERANGE;
	}

	if (!search->result.name) {
		SSDFS_ERR("invalid name buffer\n");
		return -ERANGE;
	}

	switch (is_lookup1_position_correct(node, search)) {
	case SSDFS_CORRECT_POSITION:
		/* check the lookup2 table */
		break;

	case SSDFS_SEARCH_LEFT_DIRECTION:
		return ssdfs_find_lookup1_position_from_left(node, search);

	default:
		SSDFS_ERR("invalid direction\n");
		return -ERANGE;
	}

	switch (is_lookup2_position_correct(node, search)) {
	case SSDFS_CORRECT_POSITION:
		/* check the hash table */
		break;

	case SSDFS_SEARCH_LEFT_DIRECTION:
		return ssdfs_find_lookup2_position_from_left(node, search);

	default:
		SSDFS_ERR("invalid direction\n");
		return -ERANGE;
	}

	switch (is_hash_position_correct(node, search, item_index)) {
	case SSDFS_SEARCH_LEFT_DIRECTION:
		/* find hash position */
		break;

	default:
		SSDFS_ERR("invalid direction\n");
		return -ERANGE;
	}

	return ssdfs_find_hash_position_from_left(node, item_index, search);
}

/*
 * ssdfs_find_lookup1_position_from_right() - find a correct position from right
 * @node: node object
 * @search: search object
 *
 * This method tries to find the correct position from the right
 * for a lookup1 index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - the requested position is out of the node.
 * %-ENOENT     - possible place is found.
 */
static
int ssdfs_find_lookup1_position_from_right(struct ssdfs_btree_node *node,
					   struct ssdfs_btree_search *search)
{
	struct ssdfs_lookup_descriptor *lookup;
	struct ssdfs_shdict_search_key req_key = { .name = {0}, .range = {0} };
	struct ssdfs_shdict_search_key found_key = { .name = {0}, .range = {0} };
	size_t key_size = sizeof(struct ssdfs_shdict_search_key);
	u16 table_size;
	int i;
	int res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	lookup = &search->result.name->lookup;
	table_size = le16_to_cpu(node->raw.dict_header.lookup_table1_items);

	ssdfs_memcpy(&req_key, 0, key_size,
		     &lookup->desc, 0, key_size,
		     key_size);

	if (lookup->index >= table_size) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find a new index: "
			  "lookup->index %u, table_size %u\n",
			  lookup->index, table_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	for (i = lookup->index; i < table_size; i++) {
		err = ssdfs_get_lookup1_table_search_key(node, i, &found_key);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get lookup1 key: "
				  "index %d, err %d\n",
				  i, err);
			return err;
		}

		res = ssdfs_hash32_lo_compare(&req_key, &found_key);
		if (res == 0) {
			lookup->index = i;
			return 0;
		} else if (res < 0) {
			lookup->index = i - 1;
			return -ENOENT;
		}
	}

	lookup->index = table_size - 1;
	return -ENODATA;
}

/*
 * ssdfs_find_lookup2_position_from_right() - find a correct position from right
 * @node: node object
 * @search: search object
 *
 * This method tries to find the correct position from the right
 * for a lookup2 index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - the requested position is out of the node.
 * %-ENOENT     - possible place is found.
 */
static
int ssdfs_find_lookup2_position_from_right(struct ssdfs_btree_node *node,
					   struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node_index_area *lookup_tbl_area;
	struct ssdfs_strings_range_descriptor *strings_range;
	struct ssdfs_shdict_search_key req_key, found_key;
	size_t key_size = sizeof(struct ssdfs_shdict_search_key);
	u16 table_size;
	int i;
	int res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	lookup_tbl_area = &node->lookup_tbl_area;
	table_size = lookup_tbl_area->index_count;

	strings_range = &search->result.name->strings_range;
	ssdfs_memcpy(&req_key, 0, key_size,
		     &strings_range->desc, 0, key_size,
		     key_size);

	if (strings_range->index >= table_size) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find a new index: "
			  "strings_range->index %u, table_size %u\n",
			  strings_range->index, table_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	for (i = strings_range->index; i < table_size; i++) {
		err = ssdfs_get_lookup2_descriptor(node, lookup_tbl_area, i,
						SSDFS_LTBL2_DESC(&found_key));
		if (unlikely(err)) {
			SSDFS_ERR("fail to get lookup2 key: "
				  "index %u, err %d\n",
				  i, err);
			return err;
		}

		res = ssdfs_hash32_lo_compare(&req_key, &found_key);
		if (res == 0) {
			strings_range->index = i;
			return 0;
		} else if (res < 0) {
			strings_range->index = i - 1;
			return -ENOENT;
		}
	}

	strings_range->index = table_size - 1;
	return -ENODATA;
}

/*
 * ssdfs_find_hash_position_from_right() - find a correct position from right
 * @node: node object
 * @search: search object
 *
 * This method tries to find the correct position from the right
 * for a hash index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - the requested position is out of the node.
 * %-ENOENT     - possible place is found.
 */
static
int ssdfs_find_hash_position_from_right(struct ssdfs_btree_node *node,
					int item_index,
					struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node_index_area *hash_tbl_area;
	struct ssdfs_strings_range_descriptor *strings_range;
	struct ssdfs_shdict_search_key req_key = { .name = {0}, .range = {0} };
	struct ssdfs_shdict_search_key found_key = { .name = {0}, .range = {0} };
	u16 table_size;
	u16 upper_bound;
	int i;
	int res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	hash_tbl_area = &node->hash_tbl_area;
	strings_range = &search->result.name->strings_range;

	table_size = hash_tbl_area->index_count;

	upper_bound = le16_to_cpu(strings_range->desc.hash_index);
	upper_bound += strings_range->desc.str_count;

	if (item_index >= table_size) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find a new index: "
			  "item_index %u, table_size %u\n",
			  item_index, table_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	if (upper_bound > table_size) {
		SSDFS_ERR("upper_bound %u > table_size %u\n",
			  upper_bound, table_size);
		return -ERANGE;
	}

	if (item_index >= upper_bound) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("item_index %d >= upper_bound %u\n",
			  item_index, upper_bound);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	err = ssdfs_convert_hash64_to_hash32_hi(search, &req_key);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert hash64: err %d\n",
			  err);
		return err;
	}

	for (i = item_index; i < upper_bound; i++) {
		err = ssdfs_get_hash_descriptor(node, hash_tbl_area, i,
						SSDFS_HTBL_DESC(&found_key));
		if (unlikely(err)) {
			SSDFS_ERR("fail to get hash descriptor: "
				  "index %u, err %d\n",
				  i, err);
			return err;
		}

		res = ssdfs_hash32_hi_compare(&req_key, &found_key);
		if (res == 0) {
			search->result.name->right_name.index = i;
			return 0;
		} else if (res < 0) {
			search->result.name->right_name.index = i - 1;
			return -ENOENT;
		}
	}

	search->result.name->right_name.index = upper_bound - 1;
	return -ENODATA;
}

/*
 * ssdfs_find_correct_position_from_right() - find position from the right
 * @node: pointer on node object
 * @search: search object
 *
 * This method tries to find a correct position of the name
 * from the right side of names' sequence in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_find_correct_position_from_right(struct ssdfs_btree_node *node,
					   struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node_items_area *items_area;
	int item_index;
	u16 items_count, items_capacity;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, search->result.start_index);
#endif /* CONFIG_SSDFS_DEBUG */

	items_area = &node->items_area;
	items_count = items_area->items_count;
	items_capacity = items_area->items_capacity;

	item_index = search->result.start_index;
	if ((item_index + search->request.count) >= items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %d, count %u\n",
			  item_index, search->request.count);
		return -ERANGE;
	}

	if (item_index >= items_count) {
		if (items_count == 0)
			item_index = items_count;
		else
			item_index = items_count - 1;

		search->result.start_index = (u16)item_index;
	}


	switch (search->result.name_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		/* expected states */
		break;

	default:
		SSDFS_ERR("invalid name state %#x\n",
			  search->result.name_state);
		return -ERANGE;
	}

	if (!search->result.name) {
		SSDFS_ERR("invalid name buffer\n");
		return -ERANGE;
	}

	switch (is_lookup1_position_correct(node, search)) {
	case SSDFS_CORRECT_POSITION:
		/* check the lookup2 table */
		break;

	case SSDFS_SEARCH_RIGHT_DIRECTION:
		return ssdfs_find_lookup1_position_from_right(node, search);

	default:
		SSDFS_ERR("invalid direction\n");
		return -ERANGE;
	}

	switch (is_lookup2_position_correct(node, search)) {
	case SSDFS_CORRECT_POSITION:
		/* check the hash table */
		break;

	case SSDFS_SEARCH_RIGHT_DIRECTION:
		return ssdfs_find_lookup2_position_from_right(node, search);

	default:
		SSDFS_ERR("invalid direction\n");
		return -ERANGE;
	}

	switch (is_hash_position_correct(node, search, item_index)) {
	case SSDFS_SEARCH_RIGHT_DIRECTION:
		/* find hash position */
		break;

	default:
		SSDFS_ERR("invalid direction\n");
		return -ERANGE;
	}

	return ssdfs_find_hash_position_from_right(node, item_index, search);
}

/*
 * __ssdfs_invalidate_items_area() - invalidate the items area
 * @node: pointer on node object
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
				  u16 start_index, u16 range_len,
				  struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node *parent = NULL;
	struct ssdfs_shared_dictionary_node_header *hdr;
	struct ssdfs_btree_node_items_area *items_area;
	struct ssdfs_btree_node_index_area *ltbl_area;
	struct ssdfs_btree_node_index_area *htbl_area;
	bool is_hybrid = false;
	bool has_index_area = false;
	bool index_area_empty = false;
	bool items_area_empty = false;
	int parent_type = SSDFS_BTREE_LEAF_NODE;
	spinlock_t *lock;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, start_index %u, range_len %u\n",
		  node->node_id, start_index, range_len);
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

	items_area = &node->items_area;

	switch (atomic_read(&node->lookup_tbl_area.state)) {
	case SSDFS_BTREE_NODE_LOOKUP_TBL_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid lookup_tbl_area state %#x\n",
			  atomic_read(&node->lookup_tbl_area.state));
		return -ERANGE;
	}

	ltbl_area = &node->lookup_tbl_area;

	switch (atomic_read(&node->hash_tbl_area.state)) {
	case SSDFS_BTREE_NODE_HASH_TBL_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid hash_tbl_area state %#x\n",
			  atomic_read(&node->hash_tbl_area.state));
		return -ERANGE;
	}

	htbl_area = &node->hash_tbl_area;

	if (((u32)start_index + range_len) > items_area->items_count) {
		SSDFS_ERR("start_index %u, range_len %u, items_count %u\n",
			  start_index, range_len,
			  items_area->items_count);
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

	if (items_area->items_count == range_len) {
		items_area_empty = true;

		items_area->items_count = 0;
		items_area->free_space = items_area->area_size;
		items_area->items_capacity =
			items_area->free_space / items_area->min_item_size;
		items_area->start_hash = U64_MAX;
		items_area->end_hash = U64_MAX;

		htbl_area->index_count = 0;
		htbl_area->index_capacity =
			htbl_area->area_size / htbl_area->index_size;
		htbl_area->start_hash = U64_MAX;
		htbl_area->end_hash = U64_MAX;

		ltbl_area->index_count = 0;
		ltbl_area->index_capacity =
			ltbl_area->area_size / ltbl_area->index_size;
		ltbl_area->start_hash = U64_MAX;
		ltbl_area->end_hash = U64_MAX;

		hdr = &node->raw.dict_header;
		hdr->lookup_table1_items = cpu_to_le16(0);
		memset(hdr->lookup_table1, 0xFF,
			sizeof(struct ssdfs_shdict_ltbl1_item) *
			SSDFS_SHDIC_LTBL1_SIZE);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("LOOKUP1 TABLE DUMP\n");
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     hdr->lookup_table1,
				     sizeof(struct ssdfs_shdict_ltbl1_item) *
					SSDFS_SHDIC_LTBL1_SIZE);
		SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */
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
			lock = &parent->descriptor_lock;
			spin_lock(lock);
			parent = parent->parent_node;
			spin_unlock(lock);
			lock = NULL;

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
					struct ssdfs_btree_search *search)
{
	u16 items_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, search %p\n",
		  node->node_id, search);
#endif /* CONFIG_SSDFS_DEBUG */

	items_count = node->items_area.items_count;
	return __ssdfs_invalidate_items_area(node, 0, items_count, search);
}

/*
 * ssdfs_invalidate_items_area_partially() - invalidate the items area
 * @node: pointer on node object
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
					  u16 start_index, u16 range_len,
					  struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, start_index %u, range_len %u\n",
		  node->node_id, start_index, range_len);
#endif /* CONFIG_SSDFS_DEBUG */

	return __ssdfs_invalidate_items_area(node,
					     start_index, range_len,
					     search);
}

/*
 * ssdfs_shift_strings_range_left() - shift the strings range to the left
 * @node: pointer on node object
 * @start_hindex: starting hash index
 * @end_hindex: ending hash index
 * @deleted_space: pointer on the value of deleted space size [in|out]
 *
 * The method tries to shift the strings range to the left.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_shift_strings_range_left(struct ssdfs_btree_node *node,
				   u16 start_hindex, u16 end_hindex,
				   u32 *deleted_space)
{
	struct ssdfs_shdict_htbl_item hash_desc;
	u16 start_offset;
	u32 selected_space, shift;
	u16 deleted_range;
	bool need_to_shift = true;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !deleted_space);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, start_hindex %u, end_hindex %u\n",
		  node->node_id, start_hindex, end_hindex);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_get_hash_descriptor(node, &node->hash_tbl_area,
					end_hindex,
					&hash_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash descriptor: "
			  "index %u, err %d\n",
			  end_hindex, err);
		return err;
	}

	start_offset = le16_to_cpu(hash_desc.str_offset);

	err = ssdfs_get_hash_descriptor(node, &node->hash_tbl_area,
					start_hindex,
					&hash_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash descriptor: "
			  "index %u, err %d\n",
			  start_hindex, err);
		return err;
	}

	if (le16_to_cpu(hash_desc.str_offset) >= start_offset) {
		SSDFS_ERR("start_offset1 %u >= start_offset2 %u\n",
			  le16_to_cpu(hash_desc.str_offset),
			  start_offset);
		return -ERANGE;
	}

	shift = start_offset - le16_to_cpu(hash_desc.str_offset);

	err = ssdfs_get_hash_descriptor(node, &node->hash_tbl_area,
					node->hash_tbl_area.index_count - 1,
					&hash_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash descriptor: "
			  "index %u, err %d\n",
			  node->hash_tbl_area.index_count - 1,
			  err);
		return err;
	}

	selected_space = le16_to_cpu(hash_desc.str_offset);
	selected_space += hash_desc.str_len;

	if (start_offset >= selected_space) {
		SSDFS_ERR("start_offset1 %u >= start_offset2 %u\n",
			  start_offset, selected_space);
		return -ERANGE;
	}

	selected_space -= start_offset;

	if ((end_hindex + 1) >= node->hash_tbl_area.index_count)
		need_to_shift = false;
	else
		need_to_shift = true;

	if (need_to_shift) {
		err = ssdfs_shift_memory_range_left(node, &node->items_area,
						    start_offset,
						    selected_space,
						    shift);
		if (unlikely(err)) {
			SSDFS_ERR("fail to shift memory range: "
				  "node_id %u, start_offset %u, "
				  "selected_space %u, shift %u, err %d\n",
				  node->node_id, start_offset,
				  selected_space, shift, err);
			return err;
		}
	}

	node->items_area.free_space += selected_space;

	if (node->items_area.free_space > node->items_area.area_size) {
		SSDFS_ERR("free_space %u > area_size %u\n",
			  node->items_area.free_space,
			  node->items_area.area_size);
		return -ERANGE;
	}

	deleted_range = end_hindex - start_hindex;

	if (deleted_range >= node->items_area.items_count) {
		SSDFS_ERR("deleted_range %u >= items_count %u\n",
			  deleted_range,
			  node->items_area.items_count);
		return -ERANGE;
	}

	node->items_area.items_count -= deleted_range;
	*deleted_space += selected_space;

	err = ssdfs_get_hash_descriptor(node, &node->hash_tbl_area,
					0,
					&hash_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash descriptor: "
			  "index %u, err %d\n",
			  0, err);
		return err;
	}

	node->items_area.start_hash =
		SSDFS_NAME_HASH(0, le32_to_cpu(hash_desc.hash_hi));

	err = ssdfs_get_hash_descriptor(node, &node->hash_tbl_area,
					node->items_area.items_count - 1,
					&hash_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash descriptor: "
			  "index %u, err %d\n",
			  node->items_area.items_count - 1,
			  err);
		return err;
	}

	node->items_area.end_hash =
		SSDFS_NAME_HASH(0, le32_to_cpu(hash_desc.hash_hi));

	set_ssdfs_btree_node_dirty(node);

	return 0;
}

/*
 * ssdfs_shift_hash_table_range_left() - shift the hash range to the left
 * @node: pointer on node object
 * @start_hindex: starting hash index
 * @end_hindex: ending hash index
 * @deleted_bytes: pointer on the value of deleted bytes [in|out]
 *
 * The method tries to shift the hash range to the left.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_shift_hash_table_range_left(struct ssdfs_btree_node *node,
				      u16 start_hindex, u16 end_hindex,
				      u32 deleted_bytes)
{
	struct ssdfs_shdict_htbl_item hash_desc;
	size_t hdesc_size = sizeof(struct ssdfs_shdict_htbl_item);
	u16 deleted_range;
	u16 selected_range;
	u16 str_offset;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, start_hindex %u, "
		  "end_hindex %u, deleted_bytes %u\n",
		  node->node_id, start_hindex,
		  end_hindex, deleted_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	if (start_hindex >= end_hindex) {
		SSDFS_ERR("start_hindex %u >= end_hindex %u\n",
			  start_hindex, end_hindex);
	}

	deleted_range = end_hindex - start_hindex;

	if (deleted_range >= node->hash_tbl_area.index_count) {
		SSDFS_ERR("deleted_range %u >= items_count %u\n",
			  deleted_range,
			  node->hash_tbl_area.index_count);
		return -ERANGE;
	}

	if ((end_hindex + 1) >= node->hash_tbl_area.index_count)
		goto correct_hash_tbl_header;

	selected_range = node->hash_tbl_area.index_count - end_hindex;

	err = ssdfs_shift_range_left2(node, &node->hash_tbl_area,
					hdesc_size,
					end_hindex,
					selected_range,
					deleted_range);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shift the hash range: "
			  "node_id %u, start_index %u, "
			  "range_len %u, shift %u, err %d\n",
			  node->node_id, end_hindex,
			  selected_range, deleted_range, err);
		return err;
	}

	for (i = end_hindex; i < node->hash_tbl_area.index_count; i++) {
		err = ssdfs_get_hash_descriptor(node,
						&node->hash_tbl_area,
						i,
						&hash_desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get hash descriptor: "
				  "index %d, err %d\n",
				  i, err);
			return err;
		}

		str_offset = le16_to_cpu(hash_desc.str_offset);

		if (str_offset <= deleted_bytes) {
			SSDFS_ERR("str_offset %u <= deleted_bytes %u\n",
				  str_offset, deleted_bytes);
			return -ERANGE;
		}

		str_offset -= (u16)deleted_bytes;
		hash_desc.str_offset = cpu_to_le16(str_offset);

		err = ssdfs_set_hash_descriptor(node,
						&node->hash_tbl_area,
						i,
						&hash_desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set hash descriptor: "
				  "index %d, err %d\n",
				  i, err);
			return err;
		}
	}

correct_hash_tbl_header:
	node->hash_tbl_area.index_count -= deleted_range;

	err = ssdfs_get_hash_descriptor(node, &node->hash_tbl_area,
					0,
					&hash_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash descriptor: "
			  "index %u, err %d\n",
			  0, err);
		return err;
	}

	node->hash_tbl_area.start_hash =
		SSDFS_NAME_HASH(0, le32_to_cpu(hash_desc.hash_hi));

	err = ssdfs_get_hash_descriptor(node, &node->hash_tbl_area,
					node->hash_tbl_area.index_count - 1,
					&hash_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash descriptor: "
			  "index %u, err %d\n",
			  node->hash_tbl_area.index_count - 1,
			  err);
		return err;
	}

	node->hash_tbl_area.end_hash =
		SSDFS_NAME_HASH(0, le32_to_cpu(hash_desc.hash_hi));

	ssdfs_mark_hash_table_dirty(node);

	return 0;
}

/*
 * ssdfs_shorten_strings_range() - remove suffixes from the range
 * @node: pointer on node object
 * @range: strings range
 * @start_hindex: starting hash index
 * @deleted_space: pointer on the value of deleted bytes [in|out]
 *
 * The method tries to remove suffixes from the range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_shorten_strings_range(struct ssdfs_btree_node *node,
				struct ssdfs_strings_range_descriptor *range,
				u16 start_hindex,
				u32 *deleted_space)
{
	u16 hash_index, str_count;
	u32 selected_space;
	u16 deleted_range;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !range || !deleted_space);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, start_hindex %u\n",
		  node->node_id, start_hindex);
#endif /* CONFIG_SSDFS_DEBUG */

	hash_index = le16_to_cpu(range->desc.hash_index);
	if (hash_index >= U16_MAX) {
		SSDFS_ERR("invalid hash_index %#x\n",
			  hash_index);
		return -ERANGE;
	}

	str_count = range->desc.str_count;
	if (str_count >= U8_MAX || str_count == 0) {
		SSDFS_ERR("invalid str_count %u\n",
			  str_count);
		return -ERANGE;
	}

	selected_space = 0;

	err = ssdfs_shift_strings_range_left(node,
					     hash_index + 1,
					     start_hindex,
					     &selected_space);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shift the strings range: "
			  "start_hindex %u, end_hindex %u, err %d\n",
			  hash_index + 1, start_hindex, err);
		return err;
	}

	deleted_range = start_hindex - (hash_index + 1);

	if (deleted_range >= node->items_area.items_count) {
		SSDFS_ERR("deleted_range %u >= items_count %u\n",
			  deleted_range,
			  node->items_area.items_count);
		return -ERANGE;
	}

	err = ssdfs_shift_hash_table_range_left(node, hash_index + 1,
						start_hindex,
						selected_space);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shift the hash table: "
			  "start_hindex %u, end_hindex %u, "
			  "moved_bytes %u, err %d\n",
			  hash_index + 1,
			  start_hindex,
			  selected_space,
			  err);
		return err;
	}

	if (deleted_range >= range->desc.str_count) {
		SSDFS_ERR("deleted_range %u >= str_count %u\n",
			  deleted_range,
			  range->desc.str_count);
		return -ERANGE;
	}

	range->desc.str_count -= (u8)deleted_range;

	err = ssdfs_set_lookup2_descriptor(node,
					   &node->lookup_tbl_area,
					   range->index,
					   &range->desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set lookup2 item: "
			  "index %u, err %d\n",
			  range->index, err);
		return err;
	}

	deleted_space += selected_space;

	return 0;
}

/*
 * ssdfs_shift_lookup2_table_range_left() - shift the lookup2 table's range left
 * @node: pointer on node object
 * @start_l2index: starting lookup2 index
 * @end_l2index: ending lookup2 index
 *
 * The method tries to shift the lookup2 table's range to the left.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_shift_lookup2_table_range_left(struct ssdfs_btree_node *node,
					 u16 start_l2index,
					 u16 end_l2index)
{
	struct ssdfs_shdict_ltbl2_item l2desc;
	size_t l2desc_size = sizeof(struct ssdfs_shdict_ltbl2_item);
	u16 deleted_range;
	u16 selected_range;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, start_l2index %u, end_l2index %u\n",
		  node->node_id, start_l2index, end_l2index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (start_l2index >= end_l2index) {
		SSDFS_ERR("start_l2index %u >= end_l2index %u\n",
			  start_l2index, end_l2index);
	}

	deleted_range = end_l2index - start_l2index;

	if (deleted_range >= node->lookup_tbl_area.index_count) {
		SSDFS_ERR("deleted_range %u >= items_count %u\n",
			  deleted_range,
			  node->lookup_tbl_area.index_count);
		return -ERANGE;
	}

	if ((end_l2index + 1) >= node->lookup_tbl_area.index_count)
		goto correct_lookup2_tbl_header;

	selected_range = node->lookup_tbl_area.index_count - end_l2index;

	err = ssdfs_shift_range_left2(node, &node->lookup_tbl_area,
					l2desc_size,
					end_l2index,
					selected_range,
					deleted_range);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shift the lookup2 range: "
			  "node_id %u, start_index %u, "
			  "range_len %u, shift %u, err %d\n",
			  node->node_id, end_l2index,
			  selected_range, deleted_range, err);
		return err;
	}

correct_lookup2_tbl_header:
	node->lookup_tbl_area.index_count -= deleted_range;

	err = ssdfs_get_lookup2_descriptor(node,
					   &node->lookup_tbl_area,
					   0,
					   &l2desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get lookup2 descriptor: "
			  "index %u, err %d\n",
			  0, err);
		return err;
	}

	node->lookup_tbl_area.start_hash =
		SSDFS_NAME_HASH(le32_to_cpu(l2desc.hash_lo), 0);

	err = ssdfs_get_lookup2_descriptor(node, &node->lookup_tbl_area,
					node->lookup_tbl_area.index_count - 1,
					&l2desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get lookup2 descriptor: "
			  "index %u, err %d\n",
			  node->lookup_tbl_area.index_count - 1, err);
		return err;
	}

	node->lookup_tbl_area.end_hash =
		SSDFS_NAME_HASH(le32_to_cpu(l2desc.hash_lo), 0);

	ssdfs_mark_lookup2_table_dirty(node);

	return 0;
}

/*
 * ssdfs_save_found_l1desc() - save the found lookup1 descriptor
 * @range: strings range
 * @found: found search key
 * @found_index: found index
 * @lookup: lookup1 descriptor [out]
 */
static inline
int ssdfs_save_found_l1desc(struct ssdfs_strings_range_descriptor *range,
			    struct ssdfs_shdict_search_key *found,
			    u16 found_index,
			    struct ssdfs_lookup_descriptor *lookup)
{
	size_t key_size = sizeof(struct ssdfs_shdict_search_key);
	u16 start_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!range || !found || !lookup);
#endif /* CONFIG_SSDFS_DEBUG */

	start_index = le16_to_cpu(found->range.start_index);

	if (range->index != start_index) {
		SSDFS_ERR("range->index %u != start_index %u\n",
			  range->index, start_index);
		return -ERANGE;
	}

	ssdfs_memcpy(&lookup->desc, 0, key_size,
		     &found, 0, key_size,
		     key_size);
	lookup->index = found_index;

	return 0;
}

/*
 * __ssdfs_find_l1desc_for_l2desc() - find lookup1 for lookup2 descriptor
 * @node: node object
 * @range: strings range
 * @lookup: lookup1 descriptor [out]
 *
 * This method tries to find the lookup1 descriptor
 * for lookup2 descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to find a lookup1 descriptor.
 */
static
int __ssdfs_find_l1desc_for_l2desc(struct ssdfs_btree_node *node,
				   struct ssdfs_strings_range_descriptor *range,
				   struct ssdfs_lookup_descriptor *lookup)
{
	struct ssdfs_shdict_search_key lower_bound, upper_bound;
	int index, lower_index, upper_index;
	size_t key_size = sizeof(struct ssdfs_shdict_search_key);
	size_t desc_size = sizeof(struct ssdfs_shdict_ltbl1_item);
	u32 hash_lo1, hash_lo2;
	u16 table_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !range || !lookup);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	hash_lo1 = le32_to_cpu(range->desc.hash_lo);

	if (hash_lo1 >= U32_MAX) {
		SSDFS_ERR("invalid hash_lo %#x\n",
			  hash_lo1);
		return -ERANGE;
	}

	if (range->index >= U16_MAX) {
		SSDFS_ERR("invalid lookup1 index %u\n",
			  range->index);
		return -ERANGE;
	}

	memset(&lookup->desc, 0xFF, desc_size);
	lookup->index = U16_MAX;

	table_size = le16_to_cpu(node->raw.dict_header.lookup_table1_items);

	if (table_size == 0) {
		SSDFS_DBG("lookup1 table is empty\n");
		return -ENODATA;
	}

	if (table_size > SSDFS_SHDIC_LTBL1_SIZE) {
		SSDFS_ERR("invalid table_size %u\n",
			  table_size);
		return -ERANGE;
	}

	lower_index = 0;
	err = ssdfs_get_lookup1_table_search_key(node, lower_index,
						 &lower_bound);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get key: index %u, err %d\n",
			  lower_index, err);
		return err;
	}

	if (!is_ssdfs_hash32_lo_valid(&lower_bound))
		return -ENODATA;

	hash_lo2 = le32_to_cpu(lower_bound.name.hash_lo);

	if (hash_lo1 < hash_lo2) {
		ssdfs_memcpy(&lookup->desc, 0, key_size,
			     &lower_bound, 0, key_size,
			     key_size);
		lookup->index = (u16)lower_index;
		return -ENODATA;
	} else if (hash_lo1 == hash_lo2) {
		err = ssdfs_save_found_l1desc(range, &lower_bound,
						(u16)lower_index,
						lookup);
		if (unlikely(err)) {
			SSDFS_ERR("fail to save l1desc: "
				  "index %u, err %d\n",
				  lower_index, err);
			return err;
		} else
			return 0;
	} else {
		ssdfs_memcpy(&lookup->desc, 0, key_size,
			     &lower_bound, 0, key_size,
			     key_size);
		lookup->index = (u16)lower_index;
	}

	upper_index = table_size - 1;
	err = ssdfs_get_lookup1_table_search_key(node, upper_index,
						 &upper_bound);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get key: index %u, err %d\n",
			  upper_index, err);
		return err;
	}

	if (!is_ssdfs_hash32_lo_valid(&upper_bound)) {
		/*
		 * continue to search
		 */
	} else {
		hash_lo2 = le32_to_cpu(upper_bound.name.hash_lo);

		if (hash_lo1 >= hash_lo2) {
			err = ssdfs_save_found_l1desc(range, &upper_bound,
							(u16)upper_index,
							lookup);
			if (unlikely(err)) {
				SSDFS_ERR("fail to save l1desc: "
					  "index %u, err %d\n",
					  upper_index, err);
				return err;
			} else
				return 0;
		}
	}

	do {
		int diff = upper_index - lower_index;

		index = diff / 2;

		err = ssdfs_get_lookup1_table_search_key(node, index,
							 &lower_bound);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get key: index %u, err %d\n",
				  index, err);
			return err;
		}

		err = ssdfs_get_lookup1_table_search_key(node, index + 1,
							 &upper_bound);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get key: index %u, err %d\n",
				  index + 1, err);
			return err;
		}

		if (!is_ssdfs_hash32_lo_valid(&lower_bound))
			upper_index = index;
		else {
			hash_lo2 = le32_to_cpu(lower_bound.name.hash_lo);

			if (hash_lo1 < hash_lo2)
				upper_index = index;
			else if (hash_lo1 == hash_lo2) {
				err = ssdfs_save_found_l1desc(range,
							      &lower_bound,
							      (u16)index,
							      lookup);
				if (unlikely(err)) {
					SSDFS_ERR("fail to save l1desc: "
						  "index %u, err %d\n",
						  index, err);
					return err;
				} else
					return 0;
			} else {
				if (!is_ssdfs_hash32_lo_valid(&upper_bound))
					upper_index = index;
				else {
					hash_lo2 =
					  le32_to_cpu(upper_bound.name.hash_lo);

					if (hash_lo1 < hash_lo2)
						lower_index = index;
					else if (hash_lo1 == hash_lo2) {
						err =
						  ssdfs_save_found_l1desc(range,
								 &upper_bound,
								 (u16)index + 1,
								 lookup);
						if (unlikely(err))
							return err;
						else
							return 0;
					} else
						lower_index = index;
				}
			}
		}
	} while (lower_index <= upper_index);

	if (lower_index != upper_index) {
		SSDFS_ERR("lower_index %d != upper_index %d\n",
			  lower_index, upper_index);
		return -ERANGE;
	}

	ssdfs_memcpy(&lookup->desc, 0, key_size,
		     &lower_bound, 0, key_size,
		     key_size);
	lookup->index = (u16)lower_index;

	return 0;
}

/*
 * ssdfs_find_l1desc_for_l2desc() - find lookup1 for lookup2 descriptor
 * @node: node object
 * @name: name string's descriptor
 * @lookup: lookup1 descriptor [out]
 *
 * This method tries to find the lookup1 descriptor
 * for lookup2 descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to find a lookup1 descriptor.
 */
static
int ssdfs_find_l1desc_for_l2desc(struct ssdfs_btree_node *node,
				 struct ssdfs_name_string *name,
				 struct ssdfs_lookup_descriptor *lookup)
{
	struct ssdfs_strings_range_descriptor *range;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !name || !lookup);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	range = &name->strings_range;
	return __ssdfs_find_l1desc_for_l2desc(node, range, lookup);
}

/*
 * ssdfs_shift_lookup1_table_range_left() - shift the lookup1 table's range left
 * @node: pointer on node object
 * @lower_l2bound: lower bound of strings range
 * @upper_l2bound: upper bound of strings range
 *
 * The method tries to shift the lookup1 table's range to the left.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_shift_lookup1_table_range_left(struct ssdfs_btree_node *node,
			struct ssdfs_strings_range_descriptor *lower_l2bound,
			struct ssdfs_strings_range_descriptor *upper_l2bound)
{
	struct ssdfs_shdict_ltbl1_item *lookup_table;
	int array_size;
	size_t l1desc_size = sizeof(struct ssdfs_shdict_ltbl1_item);
	struct ssdfs_lookup_descriptor lower_l1bound;
	struct ssdfs_lookup_descriptor upper_l1bound;
	u16 start_index1, start_index2;
	u16 range_len1, range_len2;
	u16 start_selected_index;
	u16 end_selected_index;
	u16 deleted_range = 0;
	u16 selected_range = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !lower_l2bound || !upper_l2bound);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	lookup_table = node->raw.dict_header.lookup_table1;
	array_size = le16_to_cpu(node->raw.dict_header.lookup_table1_items);

	err = __ssdfs_find_l1desc_for_l2desc(node, lower_l2bound,
					     &lower_l1bound);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find lookup1 descriptor: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	start_index1 = le16_to_cpu(lower_l1bound.desc.start_index);
	range_len1 = le16_to_cpu(lower_l1bound.desc.range_len);

	if (start_index1 >= U16_MAX || range_len1 >= U16_MAX) {
		SSDFS_ERR("invalid lookup1 descriptor: "
			  "start_index %u, range_len %u\n",
			  start_index1, range_len1);
		return -ERANGE;
	}

	err = __ssdfs_find_l1desc_for_l2desc(node, upper_l2bound,
					     &upper_l1bound);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find lookup1 descriptor: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	start_index2 = le16_to_cpu(upper_l1bound.desc.start_index);
	range_len2 = le16_to_cpu(upper_l1bound.desc.range_len);

	if (start_index2 >= U16_MAX || range_len2 >= U16_MAX) {
		SSDFS_ERR("invalid lookup1 descriptor: "
			  "start_index %u, range_len %u\n",
			  start_index2, range_len2);
		return -ERANGE;
	}

	start_selected_index = start_index1 + 1;
	end_selected_index = start_index2;

	if (lower_l2bound->index < start_index1 ||
	    lower_l2bound->index >= (start_index1 + range_len1)) {
		SSDFS_ERR("invalid lookup2 index: "
			  "lookup2 index %u, found index %u, range_len %u\n",
			  lower_l2bound->index, start_index1, range_len1);
		return -ERANGE;
	} else if (lower_l2bound->index == start_index1) {
		/* remove the whole index */
		start_selected_index = start_index1;
	} else {
		lower_l1bound.desc.range_len =
			cpu_to_le16(lower_l2bound->index - start_index1);

		if (lower_l1bound.index >= array_size) {
			SSDFS_ERR("index %u >= array_size %d\n",
				  lower_l1bound.index, array_size);
			return -ERANGE;
		}

		ssdfs_memcpy(&lookup_table[lower_l1bound.index],
			     0, l1desc_size,
			     &lower_l1bound.desc,
			     0, l1desc_size,
			     l1desc_size);
	}

	if (upper_l2bound->index < start_index2 ||
	    upper_l2bound->index >= (start_index2 + range_len2)) {
		SSDFS_ERR("invalid lookup2 index: "
			  "lookup2 index %u, found index %u, range_len %u\n",
			  upper_l2bound->index, start_index2, range_len2);
		return -ERANGE;
	} else if (upper_l2bound->index == start_index2) {
		/*
		 * leave the lookup1 descriptor unchanged
		 */
	} else {
		upper_l1bound.desc.range_len =
			cpu_to_le16(upper_l2bound->index - start_index2);

		if (upper_l1bound.index >= array_size) {
			SSDFS_ERR("index %u >= array_size %d\n",
				  upper_l1bound.index, array_size);
			return -ERANGE;
		}

		ssdfs_memcpy(&lookup_table[upper_l1bound.index],
			     0, l1desc_size,
			     &upper_l1bound.desc,
			     0, l1desc_size,
			     l1desc_size);
	}

	if (start_selected_index > end_selected_index) {
		SSDFS_ERR("start_selected_index %u > end_selected_index %u\n",
			  start_selected_index, end_selected_index);
		return -ERANGE;
	}

	deleted_range = end_selected_index - start_selected_index;

	if (deleted_range == 0)
		goto finish_shift_lookup1_table_range;

	if (end_selected_index >= array_size) {
		SSDFS_ERR("end_selected_index %u >= array_size %u\n",
			  end_selected_index, array_size);
		return -ERANGE;
	}

	selected_range = array_size - end_selected_index;

	memmove(&lookup_table[start_selected_index],
		&lookup_table[end_selected_index],
		selected_range * l1desc_size);

	array_size -= deleted_range;
	node->raw.dict_header.lookup_table1_items = cpu_to_le16(array_size);

finish_shift_lookup1_table_range:
	err = ssdfs_set_node_header_dirty(node,
					  node->items_area.items_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set header dirty: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_hash_index_compare() - compare the hash index with the range
 * @hash_index: index of the hash
 * @desc: lookup2 descriptor
 *
 * -1 - hash_index is outside the range (lesser)
 *  0 - hash_index is inside the range
 *  1 - hash_index is outside the range (greater)
 */
static inline
int ssdfs_hash_index_compare(u16 hash_index,
			     struct ssdfs_shdict_ltbl2_item *desc)
{
	u16 range_start, range_end;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
#endif /* CONFIG_SSDFS_DEBUG */

	range_start = le16_to_cpu(desc->hash_index);
	range_end = range_start + desc->str_count;

	if (hash_index < range_start)
		return -1;
	else if (hash_index >= range_start && hash_index < range_end)
		return 0;
	else
		return 1;
}

/*
 * __ssdfs_find_l2desc_for_hdesc() - find lookup2 descriptor for hash descriptor
 * @node: node object
 * @area: lookup2 area's descriptor
 * @hash_index: index of the hash
 * @range: pointer on found strings range [out]
 *
 * This method tries to find the lookup2 descriptor for hash descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to find a lookup2 descriptor.
 */
static
int __ssdfs_find_l2desc_for_hdesc(struct ssdfs_btree_node *node,
				  struct ssdfs_btree_node_index_area *area,
				  u16 hash_index,
				  struct ssdfs_strings_range_descriptor *range)
{
	struct ssdfs_shdict_search_key lower_bound, upper_bound;
	int index, lower_index, upper_index;
	size_t key_size = sizeof(struct ssdfs_shdict_search_key);
	size_t desc_size = sizeof(struct ssdfs_shdict_ltbl2_item);
	u16 table_size;
	int res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !range);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, hash_index %u\n",
		  node->node_id, hash_index);
#endif /* CONFIG_SSDFS_DEBUG */

	table_size = area->index_count;

	memset(&range->desc, 0xFF, desc_size);
	range->index = U16_MAX;

	lower_index = 0;
	err = ssdfs_get_lookup2_table_search_key(node, lower_index,
						 &lower_bound);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get key: index %u, err %d\n",
			  lower_index, err);
		return err;
	}

	if (!is_ssdfs_hash32_lo_valid(&lower_bound))
		return -ENODATA;

	res = ssdfs_hash_index_compare(hash_index,
					SSDFS_LTBL2_DESC(&lower_bound));
	if (res < 0) {
		ssdfs_memcpy(&range->desc, 0, key_size,
			     &lower_bound, 0, key_size,
			     key_size);
		range->index = (u16)lower_index;
		return -ENODATA;
	} else if (res == 0) {
		ssdfs_memcpy(&range->desc, 0, key_size,
			     &lower_bound, 0, key_size,
			     key_size);
		range->index = (u16)lower_index;
		return 0;
	}

	upper_index = table_size - 1;
	err = ssdfs_get_lookup2_table_search_key(node, upper_index,
						 &upper_bound);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get key: index %u, err %d\n",
			  upper_index, err);
		return err;
	}

	if (!is_ssdfs_hash32_lo_valid(&upper_bound)) {
		/*
		 * continue to search
		 */
	} else {
		res = ssdfs_hash_index_compare(hash_index,
					SSDFS_LTBL2_DESC(&upper_bound));
		if (res == 0) {
			ssdfs_memcpy(&range->desc, 0, key_size,
				     &upper_bound, 0, key_size,
				     key_size);
			range->index = (u16)upper_index;
			return 0;
		} else if (res > 0) {
			ssdfs_memcpy(&range->desc, 0, key_size,
				     &upper_bound, 0, key_size,
				     key_size);
			range->index = (u16)upper_index;
			return -ENODATA;
		}
	}

	do {
		int diff = upper_index - lower_index;

		index = diff / 2;

		err = ssdfs_get_lookup2_table_search_key(node, index,
							 &lower_bound);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get key: index %u, err %d\n",
				  index, err);
			return err;
		}

		err = ssdfs_get_lookup2_table_search_key(node, index + 1,
							 &upper_bound);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get key: index %u, err %d\n",
				  index + 1, err);
			return err;
		}

		if (!is_ssdfs_hash32_lo_valid(&lower_bound))
			upper_index = index;
		else {
			res = ssdfs_hash_index_compare(hash_index,
					SSDFS_LTBL2_DESC(&lower_bound));
			if (res < 0)
				upper_index = index;
			else if (res == 0) {
				ssdfs_memcpy(&range->desc, 0, key_size,
					     &lower_bound, 0, key_size,
					     key_size);
				range->index = (u16)index;
				return 0;
			} else {
				if (!is_ssdfs_hash32_lo_valid(&upper_bound))
					upper_index = index;
				else {
					res =
					    ssdfs_hash_index_compare(hash_index,
						SSDFS_LTBL2_DESC(&upper_bound));
					if (res < 0) {
						lower_index = index;
					} else if (res == 0) {
						ssdfs_memcpy(&range->desc,
							     0, key_size,
							     &upper_bound,
							     0, key_size,
							     key_size);
						range->index = (u16)index + 1;
						return 0;
					} else
						lower_index = index;
				}
			}
		}
	} while (lower_index <= upper_index);

	if (lower_index != upper_index) {
		SSDFS_ERR("lower_index %d != upper_index %d\n",
			  lower_index, upper_index);
		return -ERANGE;
	}

	ssdfs_memcpy(&range->desc, 0, key_size,
		     &lower_bound, 0, key_size,
		     key_size);
	range->index = (u16)lower_index;

	return 0;
}

/*
 * ssdfs_find_l2desc_for_hdesc() - find lookup2 descriptor for hash descriptor
 * @node: node object
 * @area: lookup2 area's descriptor
 * @name: name's string descriptor
 * @range: pointer on found strings range [out]
 *
 * This method tries to find the lookup2 descriptor for hash descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to find a lookup2 descriptor.
 */
static
int ssdfs_find_l2desc_for_hdesc(struct ssdfs_btree_node *node,
				struct ssdfs_btree_node_index_area *area,
				struct ssdfs_name_string *name,
				struct ssdfs_strings_range_descriptor *range)
{
	u16 hash_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !name || !range);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	hash_index = name->right_name.index;
	return __ssdfs_find_l2desc_for_hdesc(node, area, hash_index, range);
}

/*
 * ssdfs_remove_strings_range() - remove the strings range
 * @node: pointer on node object
 * @item_index: starting item index
 * @range_len: number of items for deletion
 * @deleted_space: pointer on the value of deleted bytes [in|out]
 *
 * The method tries to remove the strings range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_remove_strings_range(struct ssdfs_btree_node *node,
				u16 item_index, u16 range_len,
				u32 *deleted_space)
{
	struct ssdfs_strings_range_descriptor lower_bound;
	struct ssdfs_strings_range_descriptor upper_bound;
	u16 start_hindex, end_hindex;
	u16 start_l2index, end_l2index;
	u16 hash_index, str_count;
	u32 selected_space;
	bool need_to_shift = false;
	u16 items_capacity, items_count;
	u32 area_offset, area_size;
	u32 diff_range = 0;
	u32 diff_offset = 0;
	u32 diff_size = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !deleted_space);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, item_index %u, range_len %u\n",
		  node->node_id, item_index, range_len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (range_len == 0) {
		SSDFS_ERR("range_len == 0\n");
		return -ERANGE;
	}

	*deleted_space = 0;
	start_hindex = item_index;
	end_hindex = item_index + range_len;

	err = __ssdfs_find_l2desc_for_hdesc(node, &node->lookup_tbl_area,
					    start_hindex, &lower_bound);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find lookup2 descriptor: "
			  "node_id %u, item_index %u, err %d\n",
			  node->node_id, start_hindex, err);
		return err;
	}

	err = __ssdfs_find_l2desc_for_hdesc(node, &node->lookup_tbl_area,
					    end_hindex, &upper_bound);
	if (err == -ENODATA) {
		end_hindex--;
		err = __ssdfs_find_l2desc_for_hdesc(node,
						    &node->lookup_tbl_area,
						    end_hindex, &upper_bound);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to find lookup2 descriptor: "
			  "node_id %u, hash_index %u, err %d\n",
			  node->node_id, end_hindex, err);
		return err;
	}

	hash_index = le16_to_cpu(upper_bound.desc.hash_index);
	if (hash_index >= U16_MAX) {
		SSDFS_ERR("invalid hash_index %#x\n",
			  hash_index);
		return -ERANGE;
	}

	str_count = upper_bound.desc.str_count;
	if (str_count >= U8_MAX) {
		SSDFS_ERR("invalid str_count %u\n",
			  str_count);
		return -ERANGE;
	}

	if (end_hindex == hash_index) {
		if ((item_index + range_len) == end_hindex) {
			/*
			 * This item is out of the range.
			 * It will be moved later.
			 */
		} else if (str_count == 1) {
			/*
			 * This item is in the range.
			 * But it's the latest item.
			 * Do nothing.
			 */
		} else {
			SSDFS_ERR("invalid case: "
				  "end_hindex %u, hash_index %u, "
				  "str_count %u\n",
				  end_hindex, hash_index, str_count);
			return -ERANGE;
		}
	} else if (end_hindex > hash_index &&
		   end_hindex < (hash_index + str_count - 1)) {
		err = ssdfs_shorten_strings_range(node,
						  &upper_bound,
						  end_hindex,
						  deleted_space);
		if (unlikely(err)) {
			SSDFS_ERR("fail to shorten strings range: "
				  "node_id %u, start_hindex %u, err %d\n",
				  node->node_id,
				  end_hindex,
				  err);
			return err;
		}

		end_hindex = hash_index;
	} else if (end_hindex == (hash_index + str_count - 1)) {
		if ((end_hindex + 1) != node->items_area.items_count) {
			SSDFS_ERR("detected not latest range: "
				  "end_hindex %u, strings_count %u\n",
				  end_hindex,
				  node->items_area.items_count);
			return -ERANGE;
		}
	} else {
		SSDFS_ERR("end_hindex %u, hash_index %u, str_count %u\n",
			  end_hindex, hash_index, str_count);
		return -ERANGE;
	}

	hash_index = le16_to_cpu(lower_bound.desc.hash_index);
	if (hash_index >= U16_MAX) {
		SSDFS_ERR("invalid hash_index %#x\n",
			  hash_index);
		return -ERANGE;
	}

	str_count = lower_bound.desc.str_count;
	if (str_count >= U8_MAX || str_count == 0) {
		SSDFS_ERR("invalid str_count %u\n",
			  str_count);
		return -ERANGE;
	}

	if (start_hindex == hash_index) {
		/*
		 * The whole range will be deleted.
		 */
	} else if (start_hindex > hash_index &&
		   start_hindex < (hash_index + str_count - 1)) {
		err = ssdfs_shorten_strings_range(node,
						  &lower_bound,
						  start_hindex,
						  deleted_space);
		if (unlikely(err)) {
			SSDFS_ERR("fail to shorten strings range: "
				  "node_id %u, start_hindex %u, err %d\n",
				  node->node_id,
				  end_hindex,
				  err);
			return err;
		}

		start_hindex = hash_index + str_count;
	} else {
		SSDFS_ERR("start_hindex %u, hash_index %u, str_count %u\n",
			  start_hindex, hash_index, str_count);
		return -ERANGE;
	}

	if (start_hindex == end_hindex)
		return 0;

	if (end_hindex < node->items_area.items_count)
		need_to_shift = true;

	selected_space = 0;

	err = ssdfs_shift_strings_range_left(node,
					     start_hindex,
					     end_hindex,
					     &selected_space);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shift the strings range: "
			  "start_hindex %u, end_hindex %u, err %d\n",
			  start_hindex, end_hindex, err);
		return err;
	}

	*deleted_space += selected_space;

	err = ssdfs_shift_hash_table_range_left(node,
						start_hindex,
						end_hindex,
						selected_space);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shift the hash table: "
			  "start_hindex %u, end_hindex %u, "
			  "moved_bytes %u, err %d\n",
			  start_hindex,
			  end_hindex,
			  selected_space,
			  err);
		return err;
	}

	if (le16_to_cpu(lower_bound.desc.hash_index) == item_index)
		start_l2index = lower_bound.index + 1;
	else
		start_l2index = lower_bound.index;

	end_l2index = upper_bound.index;

	err = ssdfs_shift_lookup2_table_range_left(node,
						   start_l2index,
						   end_l2index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shift lookup2 table's range: "
			  "node_id %u, start_l2index %u, "
			  "end_l2index %u, err %d\n",
			  node->node_id, start_l2index,
			  end_l2index, err);
		return err;
	}

	err = ssdfs_shift_lookup1_table_range_left(node,
						   &lower_bound,
						   &upper_bound);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shift lookup1 table's range: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	items_count = node->lookup_tbl_area.index_count;
	items_capacity = node->lookup_tbl_area.index_capacity;

	if (items_count < items_capacity) {
		diff_range = items_capacity - items_count;
		diff_size = diff_range * sizeof(struct ssdfs_shdict_ltbl2_item);
		diff_offset += diff_size;
	}

	if (diff_offset > 0 || diff_size > 0) {
		area_offset = node->lookup_tbl_area.offset;
		area_size = node->lookup_tbl_area.area_size;

		if (diff_size > area_size) {
			SSDFS_ERR("diff %u > area_size %u\n",
				  diff_size, area_size);
			return -ERANGE;
		}

		area_offset += diff_offset;
		area_size -= diff_size;

		err = ssdfs_resize_lookup2_table(node, area_offset, area_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to resize lookup2 table: "
				  "area_offset %u, area_size %u, err %d\n",
				  area_offset, area_size, err);
			return err;
		}
	}

	items_count = node->hash_tbl_area.index_count;
	items_capacity = node->hash_tbl_area.index_capacity;

	if (items_count < items_capacity) {
		diff_range = items_capacity - items_count;
		diff_size = diff_range * sizeof(struct ssdfs_shdict_htbl_item);
		diff_offset += diff_size;
	}

	if (diff_offset > 0 || diff_size > 0) {
		area_offset = node->hash_tbl_area.offset;
		area_size = node->hash_tbl_area.area_size;

		if (diff_size > area_size) {
			SSDFS_ERR("diff %u > area_size %u\n",
				  diff_size, area_size);
			return -ERANGE;
		}

		area_offset += diff_offset;
		area_size -= diff_size;

		err = ssdfs_resize_hash_table(node, area_offset, area_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to resize hash table: "
				  "area_offset %u, area_size %u, err %d\n",
				  area_offset, area_size, err);
			return err;
		}
	}

	if (diff_offset > 0) {
		area_offset = node->items_area.offset;
		area_size = node->items_area.area_size;

		area_offset += diff_offset;

		err = ssdfs_resize_string_area(node, area_offset, area_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to resize the string area: "
				  "area_offset %u, area_size %u, err %d\n",
				  area_offset, area_size, err);
			return err;
		}
	}

	*deleted_space += diff_offset;
	return 0;
}

/*
 * __ssdfs_shared_dict_btree_node_delete_range() - delete a range of items
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
int __ssdfs_shared_dict_btree_node_delete_range(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node_items_area items_area;
	struct ssdfs_btree_node_index_area lookup_tbl_area;
	struct ssdfs_btree_node_index_area hash_tbl_area;
	u16 item_index;
	u16 range_len = 0;
	int direction;
	u32 deleted_space;
	u16 names_count = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

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

	down_read(&node->header_lock);
	ssdfs_memcpy(&items_area,
		     0, sizeof(struct ssdfs_btree_node_items_area),
		     &node->items_area,
		     0, sizeof(struct ssdfs_btree_node_items_area),
		     sizeof(struct ssdfs_btree_node_items_area));
	up_read(&node->header_lock);

	err = ssdfs_check_items_area(node, &items_area);
	if (unlikely(err)) {
		atomic_set(&node->state,
			   SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("items area is corrupted: err %d\n",
			  err);
		return err;
	}

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
	down_write(&node->header_lock);

	ssdfs_memcpy(&lookup_tbl_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     &node->lookup_tbl_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     sizeof(struct ssdfs_btree_node_index_area));
	ssdfs_memcpy(&hash_tbl_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     &node->hash_tbl_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     sizeof(struct ssdfs_btree_node_index_area));

	err = ssdfs_check_lookup2_table_area(node, &lookup_tbl_area);
	if (unlikely(err)) {
		atomic_set(&node->state,
			   SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("lookup2 table area is corrupted\n");
		goto finish_delete_range;
	}

	err = ssdfs_check_hash_table_area(node, &hash_tbl_area);
	if (unlikely(err)) {
		atomic_set(&node->state,
			   SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("hash table area is corrupted\n");
		goto finish_delete_range;
	}

	direction = is_requested_position_correct(node, search);
	switch (direction) {
	case SSDFS_CORRECT_POSITION:
		/* do nothing */
		break;

	case SSDFS_SEARCH_LEFT_DIRECTION:
		err = ssdfs_find_correct_position_from_left(node, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the correct position: "
				  "err %d\n",
				  err);
			goto finish_delete_range;
		}
		break;

	case SSDFS_SEARCH_RIGHT_DIRECTION:
		err = ssdfs_find_correct_position_from_right(node, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the correct position: "
				  "err %d\n",
				  err);
			goto finish_delete_range;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("fail to check requested position\n");
		goto finish_delete_range;
	}

	item_index = search->result.start_index;

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_DELETE_ITEM:
		if ((item_index + range_len) > node->items_area.items_count) {
			err = -ERANGE;
			SSDFS_ERR("invalid items_count: "
				  "item_index %u, items_count %u, "
				  "items_count %u\n",
				  item_index, range_len,
				  node->items_area.items_count);
			goto finish_delete_range;
		}
		break;

	case SSDFS_BTREE_SEARCH_DELETE_RANGE:
	case SSDFS_BTREE_SEARCH_DELETE_ALL:
		/* request can be distributed between several nodes */
		range_len = min_t(unsigned int, range_len,
				  node->items_area.items_count - item_index);
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node_id %u, item_index %u, "
			  "request.count %u, items_count %u\n",
			  node->node_id, item_index,
			  search->request.count,
			  node->items_area.items_count);
#endif /* CONFIG_SSDFS_DEBUG */
		break;

	default:
		BUG();
	}

	if (range_len == node->items_area.items_count) {
		/* items area is empty */
		err = ssdfs_invalidate_whole_items_area(node, search);
	} else {
		err = ssdfs_invalidate_items_area_partially(node,
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
					node->items_area.items_capacity);
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
					node->items_area.items_capacity);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set header dirty: err %d\n",
				  err);
		}
		goto finish_delete_range;

	default:
		BUG();
	}

	err = ssdfs_remove_strings_range(node, item_index, range_len,
					 &deleted_space);
	if (unlikely(err)) {
		SSDFS_ERR("fail to remove strings range: "
			  "item_index %u, range_len %u, err %d\n",
			  item_index, range_len, err);
		goto finish_delete_range;
	}

	err = ssdfs_check_node_consistency(node);
	if (unlikely(err)) {
		SSDFS_ERR("node %u is corrupted: err %d\n",
			  node->node_id, err);
		goto finish_delete_range;
	}

	set_ssdfs_btree_node_dirty(node);

	names_count = node->items_area.items_count;

finish_delete_range:
	up_write(&node->header_lock);
	up_write(&node->full_lock);

	if (unlikely(err))
		return err;

	if (names_count == 0)
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
 * ssdfs_shared_dict_btree_node_delete_item() - delete an item from node
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
int ssdfs_shared_dict_btree_node_delete_item(struct ssdfs_btree_node *node,
					     struct ssdfs_btree_search *search)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	BUG_ON(search->result.count != 1);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_shared_dict_btree_node_delete_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete the name: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_shared_dict_btree_node_delete_range() - delete range of items from node
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
int ssdfs_shared_dict_btree_node_delete_range(struct ssdfs_btree_node *node,
					      struct ssdfs_btree_search *search)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_shared_dict_btree_node_delete_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete the range: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_prepare_prefix_for_name() - prepare a prefix for the name
 * @node: node object
 * @lookup2_area: lookup2 area's descriptor
 * @hash_area: hash area's descriptor
 * @name: name's string descriptor
 * @range: pointer on found strings range [out]
 *
 * This method tries to prepare a prefix for the name.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_prepare_prefix_for_name(struct ssdfs_btree_node *node,
			struct ssdfs_btree_node_index_area *lookup2_area,
			struct ssdfs_btree_node_index_area *hash_area,
			struct ssdfs_name_string *name,
			struct ssdfs_strings_range_descriptor *range)
{
	u16 hash_index, prefix_index;
	u16 table_size;
	int res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !lookup2_area || !hash_area || !name || !range);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	hash_index = name->right_name.index;
	table_size = lookup2_area->index_count;

do_hash_index_compare:
	res = ssdfs_hash_index_compare(hash_index, &range->desc);
	if (res < 0) {
		SSDFS_ERR("invalid strings_range: "
			  "hash_index %u, range (start %u, str_count %u)\n",
			  hash_index,
			  le16_to_cpu(range->desc.hash_index),
			  range->desc.str_count);
		return -ERANGE;
	} else if (res > 0) {
		range->index++;

		if (range->index >= table_size) {
			SSDFS_ERR("range->index %u >= table_size %u\n",
				  range->index, table_size);
			return -ERANGE;
		}

		err = ssdfs_get_lookup2_table_search_key(node, range->index,
				(struct ssdfs_shdict_search_key *)&range->desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get lookup2 descriptor: "
				  "index %u, err %d\n",
				  range->index, err);
			return err;
		} else
			goto do_hash_index_compare;
	}

	prefix_index = le16_to_cpu(range->desc.hash_index);
	err = ssdfs_get_hash_descriptor(node, hash_area,
					prefix_index,
					&name->prefix.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash descriptor: "
			  "index %u, err %d\n",
			  prefix_index, err);
		return err;
	}

	switch (name->prefix.desc.type) {
	case SSDFS_NAME_PREFIX:
	case SSDFS_FULL_NAME:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid descriptor type %#x\n",
			  name->prefix.desc.type);
		return -ERANGE;
	}

	name->prefix.index = prefix_index;
	ssdfs_memcpy(&name->strings_range,
		     0, sizeof(struct ssdfs_strings_range_descriptor),
		     range,
		     0, sizeof(struct ssdfs_strings_range_descriptor),
		     sizeof(struct ssdfs_strings_range_descriptor));

	return 0;
}

/*
 * ssdfs_lookup2_index_compare() - compare lookup2 index with lookup1 descriptor
 * @lookup2_index: lookup2 index
 * @desc: lookup1 descriptor
 *
 * This method compares the lookup2 index with the range of indexes
 * that is contained in the lookup1 descriptor.
 *
 * RETURN:
 * -1 - lookup2_index is outside the range (lesser)
 *  0 - lookup2_index is inside the range
 *  1 - lookup2_index is outside the range (greater)
 */
static inline
int ssdfs_lookup2_index_compare(u16 lookup2_index,
				struct ssdfs_shdict_ltbl1_item *desc)
{
	u16 range_start, range_end;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
#endif /* CONFIG_SSDFS_DEBUG */

	range_start = le16_to_cpu(desc->start_index);
	range_end = range_start + le16_to_cpu(desc->range_len);

	if (lookup2_index < range_start)
		return -1;
	else if (lookup2_index >= range_start && lookup2_index < range_end)
		return 0;
	else
		return 1;
}

/*
 * ssdfs_prepare_lookup1_for_name() - prepare the lookup1 descriptor for a name
 * @node: pointer on node object
 * @name: pointer on name string descriptor
 * @lookup: pointer on lookup1 descriptor [out]
 *
 * This method tries to prepare the lookup1 descriptor for the name.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - lookup1 table is empty.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_prepare_lookup1_for_name(struct ssdfs_btree_node *node,
				   struct ssdfs_name_string *name,
				   struct ssdfs_lookup_descriptor *lookup)
{
	u16 lookup2_index;
	u16 table_size;
	int res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !name || !lookup);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	table_size = le16_to_cpu(node->raw.dict_header.lookup_table1_items);

	if (table_size == 0) {
		SSDFS_DBG("lookup1 table is empty\n");
		return -ENODATA;
	}

	if (table_size > SSDFS_SHDIC_LTBL1_SIZE) {
		SSDFS_ERR("invalid table_size %u\n",
			  table_size);
		return -ERANGE;
	}

	lookup2_index = name->strings_range.index;

	if (lookup2_index >= U16_MAX) {
		SSDFS_ERR("invalid lookup2 index\n");
		return -ERANGE;
	}

do_lookup2_index_compare:
	res = ssdfs_lookup2_index_compare(lookup2_index, &lookup->desc);
	if (res < 0) {
		SSDFS_ERR("invalid lookup: "
			  "lookup2_index %u, "
			  "range (start_index %u, range_len %u)\n",
			  lookup2_index,
			  le16_to_cpu(lookup->desc.start_index),
			  le16_to_cpu(lookup->desc.range_len));
		return -ERANGE;
	} else if (res > 0) {
		lookup->index++;

		if (lookup->index >= table_size) {
			SSDFS_ERR("lookup->index %u >= table_size %u\n",
				  lookup->index, table_size);
			return -ERANGE;
		}

		err = ssdfs_get_lookup1_table_search_key(node, lookup->index,
			    (struct ssdfs_shdict_search_key *)&lookup->desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get lookup1 descriptor: "
				  "index %u, err %d\n",
				  lookup->index, err);
			return err;
		} else
			goto do_lookup2_index_compare;
	}

	ssdfs_memcpy(&name->lookup,
		     0, sizeof(struct ssdfs_lookup_descriptor),
		     lookup,
		     0, sizeof(struct ssdfs_lookup_descriptor),
		     sizeof(struct ssdfs_lookup_descriptor));

	return 0;
}

/*
 * ssdfs_shared_dict_btree_node_extract_range() - extract range of items from node
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
int ssdfs_shared_dict_btree_node_extract_range(struct ssdfs_btree_node *node,
					    u16 start_index, u16 count,
					    struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node_items_area items_area;
	struct ssdfs_btree_node_index_area lookup_tbl_area;
	struct ssdfs_btree_node_index_area hash_tbl_area;
	struct ssdfs_shdict_htbl_item hash_desc;
	size_t hdesc_size = sizeof(struct ssdfs_shdict_htbl_item);
	struct ssdfs_strings_range_descriptor strings_range;
	struct ssdfs_lookup_descriptor lookup;
	struct ssdfs_name_string *name;
	size_t name_string_size = sizeof(struct ssdfs_name_string);
	size_t buf_size;
	u16 hash_index, name_index;
	u16 found_names = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_index %u, count %u, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  start_index, count,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
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
	ssdfs_memcpy(&items_area,
		     0, sizeof(struct ssdfs_btree_node_items_area),
		     &node->items_area,
		     0, sizeof(struct ssdfs_btree_node_items_area),
		     sizeof(struct ssdfs_btree_node_items_area));
	ssdfs_memcpy(&lookup_tbl_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     &node->lookup_tbl_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     sizeof(struct ssdfs_btree_node_index_area));
	ssdfs_memcpy(&hash_tbl_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     &node->hash_tbl_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     sizeof(struct ssdfs_btree_node_index_area));
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

	if (count == 0) {
		SSDFS_ERR("empty request\n");
		return -ERANGE;
	}

	if (start_index >= items_area.items_count) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start_index %u >= items_count %u\n",
			  start_index, items_area.items_count);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	if ((start_index + count) > items_area.items_count)
		count = items_area.items_count - start_index;

	buf_size = name_string_size * count;

	switch (search->result.name_state) {
	case SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE:
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
		if (count == 1) {
			search->result.name = &search->name;
			search->result.name_state =
					SSDFS_BTREE_SEARCH_INLINE_BUFFER;
			search->result.name_string_size = buf_size;
			search->result.names_in_buffer = 0;
		} else {
			err = ssdfs_btree_search_alloc_result_name(search,
								   buf_size);
			if (unlikely(err)) {
				SSDFS_ERR("fail to allocate buffer\n");
				return err;
			}
		}
		break;

	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		if (count == 1) {
			ssdfs_btree_search_free_result_name(search);

			search->result.name = &search->name;
			search->result.name_state =
					SSDFS_BTREE_SEARCH_INLINE_BUFFER;
			search->result.name_string_size = buf_size;
			search->result.names_in_buffer = 0;
		} else {
			search->result.name = krealloc(search->result.name,
						      buf_size, GFP_KERNEL);
			if (!search->result.name) {
				SSDFS_ERR("fail to allocate buffer\n");
				return -ENOMEM;
			}
			search->result.name_state =
					SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER;
			search->result.name_string_size = buf_size;
			search->result.names_in_buffer = 0;
		}
		break;

	default:
		SSDFS_ERR("invalid name_state %#x\n",
			  search->result.name_state);
		return -ERANGE;
	}

	down_read(&node->full_lock);

	hash_index = start_index;
	name_index = 0;
	for (; hash_index < count; hash_index++) {
		name = &search->result.name[name_index];

		err = ssdfs_get_hash_descriptor(node, &hash_tbl_area,
						hash_index, &hash_desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get hash descriptor: "
				  "index %u, err %d\n",
				  hash_index, err);
			goto finish_extract_range;
		}

		switch (hash_desc.type) {
		case SSDFS_NAME_PREFIX:
			/* skip the prefix */
			continue;

		case SSDFS_NAME_SUFFIX:
		case SSDFS_FULL_NAME:
			ssdfs_memcpy(&name->right_name.desc, 0, hdesc_size,
				     &hash_desc, 0, hdesc_size,
				     hdesc_size);
			name->right_name.index = hash_index;
			name_index++;
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid hash descriptor: "
				  "type %#x\n",
				  hash_desc.type);
			goto finish_extract_range;
		}
	}

	found_names = name_index;

	if (found_names == 0) {
		err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("no names were found: "
			  "start_index %u, count %u\n",
			  start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_extract_range;
	}

	name = &search->result.name[0];
	err = ssdfs_find_l2desc_for_hdesc(node, &lookup_tbl_area,
					  name, &strings_range);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find lookup2 descriptor: "
			  "err %d\n", err);
		goto finish_extract_range;
	}

	for (name_index = 0; name_index < found_names; name_index++) {
		name = &search->result.name[name_index];

		err = ssdfs_prepare_prefix_for_name(node,
						    &lookup_tbl_area,
						    &hash_tbl_area,
						    name, &strings_range);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare prefix for name: "
				  "index %u, err %d\n",
				  name_index, err);
			goto finish_extract_range;
		}
	}

	down_read(&node->header_lock);

	name = &search->result.name[0];
	err = ssdfs_find_l1desc_for_l2desc(node, name, &lookup);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find lookup1 descriptor: "
			  "err %d\n", err);
		goto finish_header_processing;
	}

	for (name_index = 0; name_index < found_names; name_index++) {
		name = &search->result.name[name_index];

		err = ssdfs_prepare_lookup1_for_name(node, name, &lookup);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare lookup1 for name: "
				  "index %u, err %d\n",
				  name_index, err);
			goto finish_header_processing;
		}
	}

finish_header_processing:
	up_read(&node->header_lock);

	if (unlikely(err))
		goto finish_extract_range;

	for (name_index = 0; name_index < found_names; name_index++) {
		name = &search->result.name[name_index];

		err = ssdfs_extract_name(node, name);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the name: "
				  "index %u, err %d\n",
				  name_index, err);
			goto finish_extract_range;
		} else
			search->result.names_in_buffer++;
	}

finish_extract_range:
	up_read(&node->full_lock);

	if (err == -ENODATA) {
		/*
		 * do nothing
		 */
	} else if (unlikely(err)) {
		search->result.state = SSDFS_BTREE_SEARCH_FAILURE;
		search->result.err = err;
	}

	return err;
}

/*
 * ssdfs_shared_dict_btree_resize_items_area() - resize items area of the node
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
int ssdfs_shared_dict_btree_resize_items_area(struct ssdfs_btree_node *node,
						u32 new_size)
{
	size_t hdr_size = sizeof(struct ssdfs_shared_dictionary_node_header);
	u32 area_offset;
	u32 area_size;
	u32 free_space;
	u32 diff;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u, new_size %u\n",
		  node->node_id, new_size);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_CORRUPTED:
		SSDFS_WARN("node %u is corrupted\n",
			   node->node_id);
		return -EFAULT;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	down_write(&node->full_lock);
	down_write(&node->header_lock);
	down_write(&node->bmap_array.lock);

	area_offset = node->items_area.offset;
	area_size = node->items_area.area_size;
	free_space = node->items_area.free_space;

	if (area_size < free_space) {
		err = -EFAULT;
		SSDFS_ERR("area_size %u < free_space %u\n",
			  area_size, free_space);
		goto finish_area_resize;
	}

	if ((area_size - free_space) > new_size) {
		err = -ERANGE;
		SSDFS_ERR("fail to resize items area: "
			  "area_size %u, free_space %u, new_size %u\n",
			  area_size, free_space, new_size);
		goto finish_area_resize;
	}

	if (area_size < new_size) {
		diff = new_size - area_size;

		if (area_offset <= diff) {
			err = -ERANGE;
			SSDFS_ERR("area_offset %u <= diff %u\n",
				  area_offset, diff);
			goto finish_area_resize;
		}

		area_offset -= diff;

		if (area_offset < hdr_size) {
			err = -ERANGE;
			SSDFS_ERR("area_offset %u < hdr_size %zu\n",
				  area_offset, hdr_size);
			goto finish_area_resize;
		}

		area_size += diff;
	} else if (area_size > new_size) {
		diff = area_size - new_size;
		area_offset += diff;
		area_size -= diff;
	} else {
		err = 0;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("area_size %u == new_size %u\n",
			  area_size, new_size);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_area_resize;
	}

	err = ssdfs_resize_string_area(node, area_offset, area_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to resize the items area: "
			  "node_id %u, area_offset %u, "
			  "area_size %u, err %d\n",
			  node->node_id, area_offset,
			  area_size, err);
		goto finish_area_resize;
	}

	if (is_ssdfs_resized_node_corrupted(node)) {
		err = -ERANGE;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("node %u has been corrupted during resize\n",
			  node->node_id);
		goto finish_area_resize;
	}

	atomic_set(&node->state, SSDFS_BTREE_NODE_DIRTY);

finish_area_resize:
	up_write(&node->bmap_array.lock);
	up_write(&node->header_lock);
	up_write(&node->full_lock);

	return err;
}

void ssdfs_debug_shdict_btree_object(struct ssdfs_shared_dict_btree_info *tree)
{
#ifdef CONFIG_SSDFS_DEBUG
	struct list_head *this, *next;
	struct ssdfs_btree_index *index;
	struct ssdfs_raw_extent *extent;

	BUG_ON(!tree);

	SSDFS_DBG("SHARED DICTIONARY: state %#x, is_locked %d, "
		  "read_reqs %d\n",
		  atomic_read(&tree->state),
		  rwsem_is_locked(&tree->lock),
		  atomic_read(&tree->read_reqs));

	ssdfs_debug_btree_object(&tree->generic_tree);

	if (!list_empty_careful(&tree->requests.queue.list)) {
		SSDFS_DBG("NAME REQUESTS:\n");

		list_for_each_safe(this, next, &tree->requests.queue.list) {
			struct ssdfs_name_info *ni;

			ni = list_entry(this, struct ssdfs_name_info, list);

			if (ni) {
				switch (ni->type) {
				case SSDFS_NAME_ADD:
				case SSDFS_NAME_CHANGE:
				case SSDFS_NAME_DELETE:
					SSDFS_DBG("NAME: op_type %#x, "
						  "hash %llx, len %zu\n",
						   ni->type,
						   ni->desc.name.hash,
						   ni->desc.name.len);

					SSDFS_DBG("STRING DUMP:\n");
					print_hex_dump_bytes("",
							DUMP_PREFIX_OFFSET,
							ni->desc.name.str_buf,
							SSDFS_MAX_NAME_LEN);
					SSDFS_DBG("\n");
					break;

				case SSDFS_INIT_SHDICT_NODE:
					index = &ni->desc.index;
					extent = &index->extent;
					SSDFS_DBG("NODE_INDEX: hash %llx, "
						  "seg_id %llu, "
						  "logical_blk %u, "
						  "len %u\n",
					    le64_to_cpu(index->hash),
					    le64_to_cpu(extent->seg_id),
					    le32_to_cpu(extent->logical_blk),
					    le32_to_cpu(extent->len));
					break;

				default:
					/* do nothing */
					break;
				}
			}
		}

		SSDFS_DBG("\n");
	}

	SSDFS_DBG("WAIT_QUEUE: is_active %d\n",
		  waitqueue_active(&tree->wait_queue));
#endif /* CONFIG_SSDFS_DEBUG */
}

void ssdfs_debug_btree_search_result_name(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	struct ssdfs_shdict_ltbl2_item *ltbl2_item;
	size_t item_size;
	size_t count;
	int i;

	BUG_ON(!search);

	SSDFS_DBG("REQUEST: type %#x, flags %#x, count %u, "
		  "START: name %p, name_len %zu, hash %#llx, ino %llu, "
		  "END: name %p, name_len %zu, hash %#llx, ino %llu\n",
		  search->request.type,
		  search->request.flags,
		  search->request.count,
		  search->request.start.name,
		  search->request.start.name_len,
		  search->request.start.hash,
		  search->request.start.ino,
		  search->request.end.name,
		  search->request.end.name_len,
		  search->request.end.hash,
		  search->request.end.ino);

	SSDFS_DBG("RESULT: state %#x, err %d, start_index %u, count %u, "
		  "search_cno %llu\n",
		  search->result.state,
		  search->result.err,
		  search->result.start_index,
		  search->result.count,
		  search->result.search_cno);

	SSDFS_DBG("NAME: name_state %#x, name %p, "
		  "name_string_size %zu, names_in_buffer %u\n",
		  search->result.name_state,
		  search->result.name,
		  search->result.name_string_size,
		  search->result.names_in_buffer);

	SSDFS_DBG("LOOKUP: index %u, hash_lo %#x, "
		  "start_index %u, range_len %u\n",
		  search->name.lookup.index,
		  le32_to_cpu(search->name.lookup.desc.hash_lo),
		  le16_to_cpu(search->name.lookup.desc.start_index),
		  le16_to_cpu(search->name.lookup.desc.range_len));

	ltbl2_item = &search->name.strings_range.desc;
	SSDFS_DBG("STRINGS_RANGE: index %u, hash_lo %#x, "
		  "prefix_len %u, str_count %u, "
		  "hash_index %u\n",
		  search->name.strings_range.index,
		  le32_to_cpu(ltbl2_item->hash_lo),
		  ltbl2_item->prefix_len,
		  ltbl2_item->str_count,
		  le16_to_cpu(ltbl2_item->hash_index));

	SSDFS_DBG("PREFIX: index %u, hash_hi %#x, "
		  "str_offset %u, str_len %u, type %#x\n",
		  search->name.prefix.index,
		  le32_to_cpu(search->name.prefix.desc.hash_hi),
		  le16_to_cpu(search->name.prefix.desc.str_offset),
		  search->name.prefix.desc.str_len,
		  search->name.prefix.desc.type);

	SSDFS_DBG("LEFT_NAME: index %u, hash_hi %#x, "
		  "str_offset %u, str_len %u, type %#x\n",
		  search->name.left_name.index,
		  le32_to_cpu(search->name.left_name.desc.hash_hi),
		  le16_to_cpu(search->name.left_name.desc.str_offset),
		  search->name.left_name.desc.str_len,
		  search->name.left_name.desc.type);

	SSDFS_DBG("RIGHT_NAME: index %u, hash_hi %#x, "
		  "str_offset %u, str_len %u, type %#x\n",
		  search->name.right_name.index,
		  le32_to_cpu(search->name.right_name.desc.hash_hi),
		  le16_to_cpu(search->name.right_name.desc.str_offset),
		  search->name.right_name.desc.str_len,
		  search->name.right_name.desc.type);

	if (search->result.name) {
		count = search->result.names_in_buffer;

		if (count > 0)
			item_size = search->result.name_string_size / count;
		else
			item_size = 0;

		for (i = 0; i < search->result.names_in_buffer; i++) {
			struct ssdfs_name_string *name;
			u8 *addr;

			addr = (u8 *)search->result.name + (i * item_size);
			name = (struct ssdfs_name_string *)addr;

			SSDFS_DBG("NAME: index %d, hash %#llx, str_len %zu\n",
				  i, name->hash, name->len);

			SSDFS_DBG("LOOKUP: index %u, hash_lo %#x, "
				  "start_index %u, range_len %u\n",
				  name->lookup.index,
				  le32_to_cpu(name->lookup.desc.hash_lo),
				  le16_to_cpu(name->lookup.desc.start_index),
				  le16_to_cpu(name->lookup.desc.range_len));

			ltbl2_item = &name->strings_range.desc;
			SSDFS_DBG("STRINGS_RANGE: index %u, hash_lo %#x, "
				  "prefix_len %u, str_count %u, "
				  "hash_index %u\n",
				  name->strings_range.index,
				  le32_to_cpu(ltbl2_item->hash_lo),
				  ltbl2_item->prefix_len,
				  ltbl2_item->str_count,
				  le16_to_cpu(ltbl2_item->hash_index));

			SSDFS_DBG("PREFIX: index %u, hash_hi %#x, "
				  "str_offset %u, str_len %u, type %#x\n",
				  name->prefix.index,
				  le32_to_cpu(name->prefix.desc.hash_hi),
				  le16_to_cpu(name->prefix.desc.str_offset),
				  name->prefix.desc.str_len,
				  name->prefix.desc.type);

			SSDFS_DBG("LEFT_NAME: index %u, hash_hi %#x, "
				  "str_offset %u, str_len %u, type %#x\n",
				  name->left_name.index,
				  le32_to_cpu(name->left_name.desc.hash_hi),
				  le16_to_cpu(name->left_name.desc.str_offset),
				  name->left_name.desc.str_len,
				  name->left_name.desc.type);

			SSDFS_DBG("RIGHT_NAME: index %u, hash_hi %#x, "
				  "str_offset %u, str_len %u, type %#x\n",
				  name->right_name.index,
				  le32_to_cpu(name->right_name.desc.hash_hi),
				  le16_to_cpu(name->right_name.desc.str_offset),
				  name->right_name.desc.str_len,
				  name->right_name.desc.type);

			SSDFS_DBG("RAW STRING DUMP: index %d\n",
				  i);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
						name->str,
						name->len);
			SSDFS_DBG("\n");
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */
}

const struct ssdfs_btree_descriptor_operations
				ssdfs_shared_dict_btree_desc_ops = {
	.init		= ssdfs_shared_dict_btree_desc_init,
	.flush		= ssdfs_shared_dict_btree_desc_flush,
};

const struct ssdfs_btree_operations ssdfs_shared_dict_btree_ops = {
	.create_root_node	= ssdfs_shared_dict_btree_create_root_node,
	.create_node		= ssdfs_shared_dict_btree_create_node,
	.init_node		= ssdfs_shared_dict_btree_init_node,
	.destroy_node		= ssdfs_shared_dict_btree_destroy_node,
	.add_node		= ssdfs_shared_dict_btree_add_node,
	.delete_node		= ssdfs_shared_dict_btree_delete_node,
	.pre_flush_root_node	= ssdfs_shared_dict_btree_pre_flush_root_node,
	.flush_root_node	= ssdfs_shared_dict_btree_flush_root_node,
	.pre_flush_node		= ssdfs_shared_dict_btree_pre_flush_node,
	.flush_node		= ssdfs_shared_dict_btree_flush_node,
};

const struct ssdfs_btree_node_operations ssdfs_shared_dict_btree_node_ops = {
	.find_item		= ssdfs_shared_dict_btree_node_find_item,
	.find_range		= ssdfs_shared_dict_btree_node_find_range,
	.extract_range		= ssdfs_shared_dict_btree_node_extract_range,
	.allocate_item		= ssdfs_shared_dict_btree_node_allocate_item,
	.allocate_range		= ssdfs_shared_dict_btree_node_allocate_range,
	.insert_item		= ssdfs_shared_dict_btree_node_insert_item,
	.insert_range		= ssdfs_shared_dict_btree_node_insert_range,
	.change_item		= ssdfs_shared_dict_btree_node_change_item,
	.delete_item		= ssdfs_shared_dict_btree_node_delete_item,
	.delete_range		= ssdfs_shared_dict_btree_node_delete_range,
	.resize_items_area	= ssdfs_shared_dict_btree_resize_items_area,
};
