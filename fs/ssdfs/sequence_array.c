//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/sequence_array.c - sequence array implementation.
 *
 * Copyright (c) 2019-2020 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include "ssdfs.h"
#include "sequence_array.h"

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

	SSDFS_DBG("revert_threshold %lu\n", revert_threshold);

	if (revert_threshold == 0) {
		SSDFS_ERR("invalid revert_threshold %lu\n",
			  revert_threshold);
		return ERR_PTR(-EINVAL);
	}

	ptr = kmalloc(sizeof(struct ssdfs_sequence_array), GFP_KERNEL);
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
	void **slot;
	void *item_ptr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !free_item);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p\n", array);

	spin_lock(&array->lock);
	radix_tree_for_each_slot(slot, &array->map, &iter, 0) {
		item_ptr = radix_tree_delete(&array->map, iter.index);

		spin_unlock(&array->lock);
		if (!item_ptr) {
			SSDFS_WARN("empty node pointer: "
				   "index %llu\n",
				   (u64)iter.index);
		} else {
			free_item(item_ptr);
		}
		spin_lock(&array->lock);
	}
	array->last_allocated_id = SSDFS_SEQUENCE_ARRAY_INVALID_ID;
	spin_unlock(&array->lock);

	kfree(array);
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, id %lu, item %p\n",
		  array, id, item);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, item %p, id %p\n",
		  array, item, id);

	*id = SSDFS_SEQUENCE_ARRAY_INVALID_ID;

	err = radix_tree_preload(GFP_NOFS);
	if (unlikely(err)) {
		SSDFS_ERR("fail to preload radix tree: err %d\n",
			  err);
		return err;
	}

	spin_lock(&array->lock);

	if (array->last_allocated_id == SSDFS_SEQUENCE_ARRAY_INVALID_ID) {
		err = -ERANGE;
		goto finish_add_item;
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

finish_add_item:
	spin_unlock(&array->lock);

	radix_tree_preload_end();

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, id %lu\n",
		  array, id);

	spin_lock(&array->lock);
	item_ptr = radix_tree_lookup(&array->map, id);
	spin_unlock(&array->lock);

	if (!item_ptr) {
		SSDFS_DBG("unable to find the item: id %llu\n",
			  (u64)id);
		return ERR_PTR(-ENOENT);
	}

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p\n", array);

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
	int res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array || !change_state);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, id %lu, "
		  "old_tag %#x, new_tag %#x, "
		  "old_state %#x, new_state %#x\n",
		  array, id, old_tag, new_tag,
		  old_state, new_state);

	rcu_read_lock();

	spin_lock(&array->lock);
	item_ptr = radix_tree_lookup(&array->map, id);
	if (item_ptr) {
		if (old_tag != SSDFS_SEQUENCE_ITEM_NO_TAG) {
			res = radix_tree_tag_get(&array->map, id, old_tag);
			if (res != 1)
				err = -ERANGE;
		}
	} else
		err = -ENOENT;
	spin_unlock(&array->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to find item id %llu with tag %#x\n",
			  (u64)id, old_tag);
		goto finish_change_state;
	}

	err = change_state(item_ptr, old_state, new_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change state: "
			  "id %llu, old_state %#x, "
			  "new_state %#x, err %d\n",
			  (u64)id, old_state, new_state, err);
		goto finish_change_state;
	}

	spin_lock(&array->lock);
	item_ptr = radix_tree_tag_set(&array->map, id, new_tag);
	if (old_tag != SSDFS_SEQUENCE_ITEM_NO_TAG)
		radix_tree_tag_clear(&array->map, id, old_tag);
	spin_unlock(&array->lock);

finish_change_state:
	rcu_read_unlock();

	return err;
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
	struct radix_tree_iter iter;
	void **slot;
	void *item_ptr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !change_state || !found_items);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p, "
		  "old_tag %#x, new_tag %#x, "
		  "old_state %#x, new_state %#x\n",
		  ptr, old_tag, new_tag,
		  old_state, new_state);

	*found_items = 0;

	rcu_read_lock();

	spin_lock(&ptr->lock);
	radix_tree_for_each_tagged(slot, &ptr->map, &iter, 0, old_tag) {
		item_ptr = radix_tree_deref_slot(slot);
		if (unlikely(!item_ptr)) {
			SSDFS_WARN("empty item ptr: id %llu\n",
				   (u64)iter.index);
			radix_tree_tag_clear(&ptr->map, iter.index, old_tag);
			continue;
		}
		spin_unlock(&ptr->lock);

		rcu_read_unlock();

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
		radix_tree_tag_set(&ptr->map, iter.index, new_tag);
		radix_tree_tag_clear(&ptr->map, iter.index, old_tag);
	}
	spin_unlock(&ptr->lock);

	rcu_read_unlock();

finish_change_all_states:
	if (*found_items == 0 || err) {
		SSDFS_ERR("fail to change all items' state\n");
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("array %p\n", array);

	spin_lock(&array->lock);
	res = radix_tree_tagged(&array->map, tag);
	spin_unlock(&array->lock);

	return res;
}
