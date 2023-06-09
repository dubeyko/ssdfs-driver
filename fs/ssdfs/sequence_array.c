// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/sequence_array.c - sequence array implementation.
 *
 * Copyright (c) 2019-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "page_vector.h"
#include "ssdfs.h"
#include "sequence_array.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_seq_arr_page_leaks;
atomic64_t ssdfs_seq_arr_memory_leaks;
atomic64_t ssdfs_seq_arr_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_seq_arr_cache_leaks_increment(void *kaddr)
 * void ssdfs_seq_arr_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_seq_arr_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_seq_arr_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_seq_arr_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_seq_arr_kfree(void *kaddr)
 * struct page *ssdfs_seq_arr_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_seq_arr_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_seq_arr_free_page(struct page *page)
 * void ssdfs_seq_arr_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(seq_arr)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(seq_arr)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_seq_arr_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_seq_arr_page_leaks, 0);
	atomic64_set(&ssdfs_seq_arr_memory_leaks, 0);
	atomic64_set(&ssdfs_seq_arr_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_seq_arr_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_seq_arr_page_leaks) != 0) {
		SSDFS_ERR("SEQUENCE ARRAY: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_seq_arr_page_leaks));
	}

	if (atomic64_read(&ssdfs_seq_arr_memory_leaks) != 0) {
		SSDFS_ERR("SEQUENCE ARRAY: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_seq_arr_memory_leaks));
	}

	if (atomic64_read(&ssdfs_seq_arr_cache_leaks) != 0) {
		SSDFS_ERR("SEQUENCE ARRAY: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_seq_arr_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * ssdfs_create_sequence_array() - create sequence array
 * @revert_threshold: threshold of rollbacking to zero
 *
 * This method tries to allocate memory and to create
 * the sequence array.
 *
 * RETURN:
 * [success] - pointer on created sequence array
 * [failure] - error code:
 *
 * %-EINVAL  - invalid input.
 * %-ENOMEM  - fail to allocate memory.
 */
struct ssdfs_sequence_array *
ssdfs_create_sequence_array(unsigned long revert_threshold)
{
	struct ssdfs_sequence_array *ptr;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("revert_threshold %lu\n", revert_threshold);
#endif /* CONFIG_SSDFS_DEBUG */

	if (revert_threshold == 0) {
		SSDFS_ERR("invalid revert_threshold %lu\n",
			  revert_threshold);
		return ERR_PTR(-EINVAL);
	}

	ptr = ssdfs_seq_arr_kmalloc(sizeof(struct ssdfs_sequence_array),
				    GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate memory\n");
		return ERR_PTR(-ENOMEM);
	}

	ptr->revert_threshold = revert_threshold;
	spin_lock_init(&ptr->lock);
	ptr->last_allocated_id = SSDFS_SEQUENCE_ARRAY_INVALID_ID;
	INIT_RADIX_TREE(&ptr->map, GFP_ATOMIC);

	return ptr;
}

/*
 * ssdfs_destroy_sequence_array() - destroy sequence array
 * @array: pointer on sequence array object
 * @free_item: pointer on function that can free item
 *
 * This method tries to delete all items from the radix tree,
 * to free memory of every item and to free the memory of
 * sequence array itself.
 */
void ssdfs_destroy_sequence_array(struct ssdfs_sequence_array *array,
				  ssdfs_free_item free_item)
{
	struct radix_tree_iter iter;
	void __rcu **slot;
	void *item_ptr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !free_item);

	SSDFS_DBG("array %p\n", array);
#endif /* CONFIG_SSDFS_DEBUG */

	rcu_read_lock();
	spin_lock(&array->lock);
	radix_tree_for_each_slot(slot, &array->map, &iter, 0) {
		item_ptr = rcu_dereference_raw(*slot);

		spin_unlock(&array->lock);
		rcu_read_unlock();

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index %llu, ptr %p\n",
			  (u64)iter.index, item_ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		if (!item_ptr) {
			SSDFS_WARN("empty node pointer: "
				   "index %llu\n",
				   (u64)iter.index);
		} else {
			free_item(item_ptr);
		}

		rcu_read_lock();
		spin_lock(&array->lock);

		radix_tree_iter_delete(&array->map, &iter, slot);
	}
	array->last_allocated_id = SSDFS_SEQUENCE_ARRAY_INVALID_ID;
	spin_unlock(&array->lock);
	rcu_read_unlock();

	ssdfs_seq_arr_kfree(array);
}

/*
 * ssdfs_sequence_array_init_item() - initialize the array by item
 * @array: pointer on sequence array object
 * @id: ID of inserting item
 * @item: pointer on inserting item
 *
 * This method tries to initialize the array by item.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL  - invalid input.
 */
int ssdfs_sequence_array_init_item(struct ssdfs_sequence_array *array,
				   unsigned long id, void *item)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !item);

	SSDFS_DBG("array %p, id %lu, item %p\n",
		  array, id, item);
#endif /* CONFIG_SSDFS_DEBUG */

	if (id > array->revert_threshold) {
		SSDFS_ERR("invalid input: "
			  "id %lu, revert_threshold %lu\n",
			  id, array->revert_threshold);
		return -EINVAL;
	}

	err = radix_tree_preload(GFP_NOFS);
	if (unlikely(err)) {
		SSDFS_ERR("fail to preload radix tree: err %d\n",
			  err);
		return err;
	}

	spin_lock(&array->lock);
	err = radix_tree_insert(&array->map, id, item);
	spin_unlock(&array->lock);

	radix_tree_preload_end();

	if (unlikely(err)) {
		SSDFS_ERR("fail to add item into radix tree: "
			  "id %llu, item %p, err %d\n",
			  (u64)id, item, err);
		return err;
	}

	spin_lock(&array->lock);
	if (array->last_allocated_id == SSDFS_SEQUENCE_ARRAY_INVALID_ID)
		array->last_allocated_id = id;
	spin_unlock(&array->lock);

	return 0;
}

/*
 * ssdfs_sequence_array_add_item() - add new item into array
 * @array: pointer on sequence array object
 * @item: pointer on adding item
 * @id: pointer on ID value [out]
 *
 * This method tries to add a new item into the array.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE  - internal error.
 */
int ssdfs_sequence_array_add_item(struct ssdfs_sequence_array *array,
				  void *item, unsigned long *id)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !item || !id);

	SSDFS_DBG("array %p, item %p, id %p\n",
		  array, item, id);
#endif /* CONFIG_SSDFS_DEBUG */

	*id = SSDFS_SEQUENCE_ARRAY_INVALID_ID;

	err = radix_tree_preload(GFP_NOFS);
	if (unlikely(err)) {
		SSDFS_ERR("fail to preload radix tree: err %d\n",
			  err);
		return err;
	}

	spin_lock(&array->lock);

	if (array->last_allocated_id == SSDFS_SEQUENCE_ARRAY_INVALID_ID) {
		*id = 0;
		array->last_allocated_id = 0;
	} else {
		if ((array->last_allocated_id + 1) > array->revert_threshold) {
			*id = 0;
			array->last_allocated_id = 0;
		} else {
			array->last_allocated_id++;
			*id = array->last_allocated_id;
		}
	}

	if (*id > array->revert_threshold) {
		err = -ERANGE;
		goto finish_add_item;
	}

	err = radix_tree_insert(&array->map, *id, item);
	if (!err) {
		radix_tree_tag_set(&array->map, *id,
				   SSDFS_SEQUENCE_ITEM_DIRTY_TAG);
	}

finish_add_item:
	spin_unlock(&array->lock);

	radix_tree_preload_end();

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("id %lu\n", *id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (unlikely(err)) {
		SSDFS_ERR("fail to add item into radix tree: "
			  "id %llu, last_allocated_id %lu, "
			  "item %p, err %d\n",
			  (u64)*id, array->last_allocated_id,
			  item, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_sequence_array_get_item() - retrieve item from array
 * @array: pointer on sequence array object
 * @id: ID value
 *
 * This method tries to retrieve the pointer on an item
 * with @id value.
 *
 * RETURN:
 * [success] - pointer on existing item.
 * [failure] - error code:
 *
 * %-ENOENT  - item is absent.
 */
void *ssdfs_sequence_array_get_item(struct ssdfs_sequence_array *array,
				    unsigned long id)
{
	void *item_ptr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, id %lu\n",
		  array, id);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&array->lock);
	item_ptr = radix_tree_lookup(&array->map, id);
	spin_unlock(&array->lock);

	if (!item_ptr) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find the item: id %llu\n",
			  (u64)id);
#endif /* CONFIG_SSDFS_DEBUG */
		return ERR_PTR(-ENOENT);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("item_ptr %p\n", item_ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	return item_ptr;
}

/*
 * ssdfs_sequence_array_apply_for_all() - apply action for all items
 * @array: pointer on sequence array object
 * @apply_action: pointer on method that needs to be applied
 *
 * This method tries to apply some action on all items..
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE  - internal error.
 */
int ssdfs_sequence_array_apply_for_all(struct ssdfs_sequence_array *array,
					ssdfs_apply_action apply_action)
{
	struct radix_tree_iter iter;
	void **slot;
	void *item_ptr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !apply_action);

	SSDFS_DBG("array %p\n", array);
#endif /* CONFIG_SSDFS_DEBUG */

	rcu_read_lock();

	spin_lock(&array->lock);
	radix_tree_for_each_slot(slot, &array->map, &iter, 0) {
		item_ptr = radix_tree_deref_slot(slot);
		if (unlikely(!item_ptr)) {
			SSDFS_WARN("empty item ptr: id %llu\n",
				   (u64)iter.index);
			continue;
		}
		spin_unlock(&array->lock);

		rcu_read_unlock();

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("id %llu, item_ptr %p\n",
			  (u64)iter.index, item_ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		err = apply_action(item_ptr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to apply action: "
				  "id %llu, err %d\n",
				  (u64)iter.index,  err);
			goto finish_apply_to_all;
		}

		rcu_read_lock();

		spin_lock(&array->lock);
	}
	spin_unlock(&array->lock);

	rcu_read_unlock();

finish_apply_to_all:
	if (unlikely(err)) {
		SSDFS_ERR("fail to apply action for all items: "
			  "err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_sequence_array_change_state() - change item's state
 * @array: pointer on sequence array object
 * @id: ID value
 * @old_tag: old tag value
 * @new_tag: new tag value
 * @change_state: pointer on method of changing item's state
 * @old_state: old item's state value
 * @new_state: new item's state value
 *
 * This method tries to change an item's state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE  - internal error.
 * %-ENOENT  - item is absent.
 */
int ssdfs_sequence_array_change_state(struct ssdfs_sequence_array *array,
					unsigned long id,
					int old_tag, int new_tag,
					ssdfs_change_item_state change_state,
					int old_state, int new_state)
{
	void *item_ptr = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !change_state);

	SSDFS_DBG("array %p, id %lu, "
		  "old_tag %#x, new_tag %#x, "
		  "old_state %#x, new_state %#x\n",
		  array, id, old_tag, new_tag,
		  old_state, new_state);
#endif /* CONFIG_SSDFS_DEBUG */

	if (old_tag > SSDFS_SEQUENCE_MAX_TAGS ||
	    old_tag < SSDFS_SEQUENCE_ITEM_DIRTY_TAG) {
		SSDFS_ERR("invalid tag: old_tag %#x\n",
			  old_tag);
		return -EINVAL;
	}

	if (new_tag > SSDFS_SEQUENCE_MAX_TAGS ||
	    new_tag < SSDFS_SEQUENCE_ITEM_DIRTY_TAG) {
		SSDFS_ERR("invalid tag: new_tag %#x\n",
			  new_tag);
		return -EINVAL;
	}

	rcu_read_lock();

	spin_lock(&array->lock);
	item_ptr = radix_tree_lookup(&array->map, id);
	if (!item_ptr)
		err = -ENOENT;
	spin_unlock(&array->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to find item id %llu\n",
			  (u64)id);
		goto finish_change_state;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("id %llu, item_ptr %p\n",
		  (u64)id, item_ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	err = change_state(item_ptr, old_state, new_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change state: "
			  "id %llu, old_state %#x, "
			  "new_state %#x, err %d\n",
			  (u64)id, old_state, new_state, err);
		goto finish_change_state;
	}

	spin_lock(&array->lock);
	if (old_tag >= SSDFS_SEQUENCE_MAX_TAGS) {
		if (new_tag == SSDFS_SEQUENCE_ITEM_DIRTY_TAG) {
			radix_tree_tag_set(&array->map, id,
					SSDFS_SEQUENCE_ITEM_DIRTY_TAG);
		} else {
			radix_tree_tag_clear(&array->map, id,
					SSDFS_SEQUENCE_ITEM_DIRTY_TAG);
		}
	} else if (new_tag >= SSDFS_SEQUENCE_MAX_TAGS) {
		radix_tree_tag_clear(&array->map, id,
					SSDFS_SEQUENCE_ITEM_DIRTY_TAG);
	} else {
		radix_tree_tag_set(&array->map, id,
					SSDFS_SEQUENCE_ITEM_DIRTY_TAG);
	}
	spin_unlock(&array->lock);

finish_change_state:
	rcu_read_unlock();

	return err;
}

/*
 * ssdfs_sequence_array_change_all_tagged_states() - change state of tagged items
 * @array: pointer on sequence array object
 * @new_tag: new tag value
 * @change_state: pointer on method of changing item's state
 * @old_state: old item's state value
 * @new_state: new item's state value
 * @found_items: pointer on count of found items [out]
 *
 * This method tries to change the state of all tagged items.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE  - internal error.
 */
static int
ssdfs_sequence_array_change_all_tagged_states(struct ssdfs_sequence_array *ptr,
					   int new_tag,
					   ssdfs_change_item_state change_state,
					   int old_state, int new_state,
					   unsigned long *found_items)
{
	struct radix_tree_iter iter;
	void **slot;
	void *item_ptr;
	int tag = SSDFS_SEQUENCE_ITEM_DIRTY_TAG;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !change_state || !found_items);

	SSDFS_DBG("array %p, new_tag %#x, "
		  "old_state %#x, new_state %#x\n",
		  ptr, new_tag, old_state, new_state);

	if (new_tag > SSDFS_SEQUENCE_MAX_TAGS ||
	    new_tag < SSDFS_SEQUENCE_ITEM_DIRTY_TAG) {
		SSDFS_ERR("invalid tag: new_tag %#x\n",
			  new_tag);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	*found_items = 0;

	rcu_read_lock();

	spin_lock(&ptr->lock);
	radix_tree_for_each_tagged(slot, &ptr->map, &iter, 0, tag) {
		item_ptr = radix_tree_deref_slot(slot);
		if (unlikely(!item_ptr)) {
			SSDFS_WARN("empty item ptr: id %llu\n",
				   (u64)iter.index);
			radix_tree_tag_clear(&ptr->map, iter.index, tag);
			continue;
		}
		spin_unlock(&ptr->lock);

		rcu_read_unlock();

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index %llu, next_index %llu, "
			  "tags %#lx, item_ptr %p\n",
			  (u64)iter.index, (u64)iter.next_index,
			  iter.tags, item_ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		err = change_state(item_ptr, old_state, new_state);
		if (err == -ENOENT) {
			SSDFS_DBG("unable to change state: "
				  "id %llu, old_state %#x, "
				  "new_state %#x\n",
				  (u64)iter.index, old_state,
				  new_state);
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to change state: "
				  "id %llu, old_state %#x, "
				  "new_state %#x, err %d\n",
				  (u64)iter.index, old_state,
				  new_state, err);
			goto finish_change_all_states;
		} else
			(*found_items)++;

		rcu_read_lock();

		if (err == -ENOENT) {
			err = 0;
			continue;
		}

		spin_lock(&ptr->lock);
		if (new_tag >= SSDFS_SEQUENCE_MAX_TAGS)
			radix_tree_tag_clear(&ptr->map, iter.index, tag);
		else
			radix_tree_tag_set(&ptr->map, iter.index, tag);
	}
	spin_unlock(&ptr->lock);

	rcu_read_unlock();

finish_change_all_states:
	if (*found_items == 0) {
		SSDFS_DBG("unable to change all items' state: "
			  "found_items %lu\n",
			  *found_items);
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to change all items' state\n");
		return err;
	} else {
		SSDFS_DBG("found_items %lu\n",
			  *found_items);
	}

	return 0;
}

/*
 * __ssdfs_sequence_array_change_all_states() - change state of all items
 * @array: pointer on sequence array object
 * @new_tag: new tag value
 * @change_state: pointer on method of changing item's state
 * @old_state: old item's state value
 * @new_state: new item's state value
 * @found_items: pointer on count of found items [out]
 *
 * This method tries to change the state of all items.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE  - internal error.
 */
static
int __ssdfs_sequence_array_change_all_states(struct ssdfs_sequence_array *ptr,
					   int new_tag,
					   ssdfs_change_item_state change_state,
					   int old_state, int new_state,
					   unsigned long *found_items)
{
	struct radix_tree_iter iter;
	void **slot;
	void *item_ptr;
	int tag = SSDFS_SEQUENCE_ITEM_DIRTY_TAG;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !change_state || !found_items);

	SSDFS_DBG("array %p, new_tag %#x, "
		  "old_state %#x, new_state %#x\n",
		  ptr, new_tag, old_state, new_state);

	if (new_tag > SSDFS_SEQUENCE_MAX_TAGS ||
	    new_tag < SSDFS_SEQUENCE_ITEM_DIRTY_TAG) {
		SSDFS_ERR("invalid tag: new_tag %#x\n",
			  new_tag);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	*found_items = 0;

	rcu_read_lock();

	spin_lock(&ptr->lock);
	radix_tree_for_each_slot(slot, &ptr->map, &iter, 0) {
		item_ptr = radix_tree_deref_slot(slot);
		if (unlikely(!item_ptr)) {
			SSDFS_WARN("empty item ptr: id %llu\n",
				   (u64)iter.index);
			radix_tree_tag_clear(&ptr->map, iter.index, tag);
			continue;
		}
		spin_unlock(&ptr->lock);

		rcu_read_unlock();

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index %llu, next_index %llu, "
			  "tags %#lx, item_ptr %p\n",
			  (u64)iter.index, (u64)iter.next_index,
			  iter.tags, item_ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		err = change_state(item_ptr, old_state, new_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change state: "
				  "id %llu, old_state %#x, "
				  "new_state %#x, err %d\n",
				  (u64)iter.index, old_state,
				  new_state, err);
			goto finish_change_all_states;
		}

		(*found_items)++;

		rcu_read_lock();

		spin_lock(&ptr->lock);
		if (new_tag >= SSDFS_SEQUENCE_MAX_TAGS)
			radix_tree_tag_clear(&ptr->map, iter.index, tag);
		else
			radix_tree_tag_set(&ptr->map, iter.index, tag);
	}
	spin_unlock(&ptr->lock);

	rcu_read_unlock();

finish_change_all_states:
	if (*found_items == 0) {
		SSDFS_DBG("unable to change all items' state: "
			  "found_items %lu\n",
			  *found_items);
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to change all items' state\n");
		return err;
	} else {
		SSDFS_DBG("found_items %lu\n",
			  *found_items);
	}

	return 0;
}

/*
 * ssdfs_sequence_array_change_all_states() - change state of all tagged items
 * @array: pointer on sequence array object
 * @old_tag: old tag value
 * @new_tag: new tag value
 * @change_state: pointer on method of changing item's state
 * @old_state: old item's state value
 * @new_state: new item's state value
 * @found_items: pointer on count of found items [out]
 *
 * This method tries to change the state of all tagged items.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE  - internal error.
 */
int ssdfs_sequence_array_change_all_states(struct ssdfs_sequence_array *ptr,
					   int old_tag, int new_tag,
					   ssdfs_change_item_state change_state,
					   int old_state, int new_state,
					   unsigned long *found_items)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !change_state || !found_items);

	SSDFS_DBG("array %p, "
		  "old_tag %#x, new_tag %#x, "
		  "old_state %#x, new_state %#x\n",
		  ptr, old_tag, new_tag,
		  old_state, new_state);
#endif /* CONFIG_SSDFS_DEBUG */

	if (old_tag > SSDFS_SEQUENCE_MAX_TAGS ||
	    old_tag < SSDFS_SEQUENCE_ITEM_DIRTY_TAG) {
		SSDFS_ERR("invalid tag: old_tag %#x\n",
			  old_tag);
		return -EINVAL;
	}

	if (new_tag > SSDFS_SEQUENCE_MAX_TAGS ||
	    new_tag < SSDFS_SEQUENCE_ITEM_DIRTY_TAG) {
		SSDFS_ERR("invalid tag: new_tag %#x\n",
			  new_tag);
		return -EINVAL;
	}

	if (old_tag >= SSDFS_SEQUENCE_MAX_TAGS) {
		err = __ssdfs_sequence_array_change_all_states(ptr,
								new_tag,
								change_state,
								old_state,
								new_state,
								found_items);
	} else {
		err = ssdfs_sequence_array_change_all_tagged_states(ptr,
								    new_tag,
								    change_state,
								    old_state,
								    new_state,
								    found_items);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to change all states: "
			  "old_tag %#x, new_tag %#x, err %d\n",
			  old_tag, new_tag, err);
		return err;
	}

	return 0;
}

/*
 * has_ssdfs_sequence_array_state() - check that any item is tagged
 * @array: pointer on sequence array object
 * @tag: checking tag
 *
 * This method tries to check that any item is tagged.
 */
bool has_ssdfs_sequence_array_state(struct ssdfs_sequence_array *array,
				    int tag)
{
	bool res;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("array %p, tag %#x\n", array, tag);
#endif /* CONFIG_SSDFS_DEBUG */

	if (tag >= SSDFS_SEQUENCE_MAX_TAGS) {
		SSDFS_ERR("invalid tag %#x\n", tag);
		return false;
	}

	spin_lock(&array->lock);
	res = radix_tree_tagged(&array->map, tag);
	spin_unlock(&array->lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("res %#x\n", res);
#endif /* CONFIG_SSDFS_DEBUG */

	return res;
}
