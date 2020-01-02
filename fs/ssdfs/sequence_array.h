//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/sequence_array.h - sequence array's declarations.
 *
 * Copyright (c) 2019-2020 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_SEQUENCE_ARRAY_H
#define _SSDFS_SEQUENCE_ARRAY_H

#define SSDFS_SEQUENCE_ARRAY_INVALID_ID		ULONG_MAX

#define SSDFS_SEQUENCE_ITEM_NO_TAG		0
#define SSDFS_SEQUENCE_ITEM_DIRTY_TAG		1
#define SSDFS_SEQUENCE_ITEM_UNDER_COMMIT_TAG	2
#define SSDFS_SEQUENCE_ITEM_COMMITED_TAG	3

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

/*
 * Inline functions
 */
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
}

static inline
bool is_ssdfs_sequence_array_last_id_invalid(struct ssdfs_sequence_array *ptr)
{
	bool is_invalid = false;

	spin_lock(&ptr->lock);
	is_invalid = ptr->last_allocated_id == SSDFS_SEQUENCE_ARRAY_INVALID_ID;
	spin_unlock(&ptr->lock);

	return is_invalid;
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
void *ssdfs_sequence_array_get_item(struct ssdfs_sequence_array *array,
				    unsigned long id);
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
bool has_ssdfs_sequence_array_state(struct ssdfs_sequence_array *array,
				    int tag);

#endif /* _SSDFS_SEQUENCE_ARRAY_H */
