/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/sequence_array.h - sequence array's declarations.
 *
 * Copyright (c) 2019-2024 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_SEQUENCE_ARRAY_H
#define _SSDFS_SEQUENCE_ARRAY_H

#define SSDFS_SEQUENCE_ARRAY_INVALID_ID		ULONG_MAX

/*
 * Number of tags cannot be bigger than RADIX_TREE_MAX_TAGS
 */
#define SSDFS_SEQUENCE_ITEM_DIRTY_TAG		XA_MARK_0
#define SSDFS_SEQUENCE_MAX_TAGS			RADIX_TREE_MAX_TAGS

/*
 * struct ssdfs_sequence_array - sequence of pointers on items
 * @revert_threshold: threshold of reverting the ID numbers' sequence
 * @lock: exclusive lock
 * @last_allocated_id: the latest ID was allocated
 * @map: pointers' radix tree
 *
 * The sequence array is specialized structure that has goal
 * to provide access to items via pointers on the basis of
 * ID numbers. It means that every item has dedicated ID but
 * sequence array could contain only some portion of existing
 * items. Initialization phase has goal to add some limited
 * number of existing items into the sequence array.
 * The ID number could be reverted from some maximum number
 * (threshold) to zero value.
 */
struct ssdfs_sequence_array {
	unsigned long revert_threshold;

	spinlock_t lock;
	unsigned long last_allocated_id;
	struct radix_tree_root map;
};

/* function prototype */
typedef void (*ssdfs_free_item)(void *item);
typedef int (*ssdfs_apply_action)(void *item);
typedef int (*ssdfs_change_item_state)(void *item,
					int old_state,
					int new_state);
typedef int (*ssdfs_search_action)(void *item,
				   unsigned long id,
				   void *search_condition);
typedef int (*ssdfs_pre_delete_action)(void *item,
					u64 peb_id);

/*
 * Inline functions
 */
static inline
bool is_ssdfs_sequence_array_last_id_invalid(struct ssdfs_sequence_array *ptr)
{
	bool is_invalid = false;

	spin_lock(&ptr->lock);
	is_invalid = ptr->last_allocated_id == SSDFS_SEQUENCE_ARRAY_INVALID_ID;
	spin_unlock(&ptr->lock);

	return is_invalid;
}

static inline
unsigned long ssdfs_sequence_array_last_id(struct ssdfs_sequence_array *array)
{
	unsigned long last_id = ULONG_MAX;

	spin_lock(&array->lock);
	last_id = array->last_allocated_id;
	spin_unlock(&array->lock);

	return last_id;
}

static inline
void ssdfs_sequence_array_set_last_id(struct ssdfs_sequence_array *array,
				      unsigned long id)
{
	spin_lock(&array->lock);
	array->last_allocated_id = id;
	spin_unlock(&array->lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("set last id %lu\n", id);
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * Sequence array API
 */
struct ssdfs_sequence_array *
ssdfs_create_sequence_array(unsigned long revert_threshold);
void ssdfs_destroy_sequence_array(struct ssdfs_sequence_array *array,
				  ssdfs_free_item free_item);
int ssdfs_sequence_array_init_item(struct ssdfs_sequence_array *array,
				   unsigned long id, void *item);
int ssdfs_sequence_array_add_item(struct ssdfs_sequence_array *array,
				  void *item, unsigned long *id);
int ssdfs_sequence_array_delete_item(struct ssdfs_sequence_array *array,
					unsigned long id,
					ssdfs_free_item free_item);
void *ssdfs_sequence_array_get_item(struct ssdfs_sequence_array *array,
				    unsigned long id);
int ssdfs_sequence_array_search(struct ssdfs_sequence_array *array,
				ssdfs_search_action search_action,
				ssdfs_free_item free_item,
				void *search_condition);
int ssdfs_sequence_array_apply_for_all(struct ssdfs_sequence_array *array,
					ssdfs_apply_action apply_action);
int ssdfs_sequence_array_change_state(struct ssdfs_sequence_array *array,
					unsigned long id,
					int old_tag, int new_tag,
					ssdfs_change_item_state change_state,
					int old_state, int new_state);
int ssdfs_sequence_array_change_all_states(struct ssdfs_sequence_array *ptr,
					   int old_tag, int new_tag,
					   ssdfs_change_item_state change_state,
					   int old_state, int new_state,
					   unsigned long *found_items);
int ssdfs_sequence_array_pre_delete_all(struct ssdfs_sequence_array *array,
					ssdfs_pre_delete_action pre_delete,
					u64 peb_id);
bool has_ssdfs_sequence_array_state(struct ssdfs_sequence_array *array,
				    int tag);

#endif /* _SSDFS_SEQUENCE_ARRAY_H */
