//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/common_bitmap.h - shared declarations for all bitmaps.
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

#ifndef _SSDFS_COMMON_BITMAP_H
#define _SSDFS_COMMON_BITMAP_H

#define SSDFS_ITEMS_PER_BYTE(item_bits) ({ \
	BUG_ON(item_bits > BITS_PER_BYTE); \
	BITS_PER_BYTE / item_bits; \
})

#define SSDFS_ITEMS_PER_LONG(item_bits) ({ \
	BUG_ON(item_bits > BITS_PER_BYTE); \
	BITS_PER_LONG / item_bits; \
})

#define ALIGNED_START_ITEM(item, state_bits) ({ \
	u64 aligned_start; \
	aligned_start = (item >> state_bits) << state_bits; \
	aligned_start; \
})

#define ALIGNED_END_ITEM(item, state_bits) ({ \
	u64 aligned_end; \
	aligned_end = item + SSDFS_ITEMS_PER_BYTE(state_bits) - 1; \
	aligned_end >>= state_bits; \
	aligned_end <<= state_bits; \
	aligned_end; \
})

typedef bool (*byte_check_func)(u8 *value, int state);
typedef u8 (*byte_op_func)(u8 *value, int state, u8 start_off, u8 state_bits,
			   int state_mask);

/*
 * FIRST_STATE_IN_BYTE() - determine first item's offset for requested state
 * @value: pointer on analysed byte
 * @state: requested state
 * @start_off: starting item's offset for analysis beginning
 * @state_bits: bits per state
 * @state_mask: mask of a bitmap's state
 *
 * This function tries to determine an item with @state in
 * @value starting from @start_off.
 *
 * RETURN:
 * [success] - found item's offset.
 * [failure] - BITS_PER_BYTE.
 */
static inline
u8 FIRST_STATE_IN_BYTE(u8 *value, int state,
			u8 start_offset, u8 state_bits,
			int state_mask)
{
	u8 i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!value);
	BUG_ON(state_bits > BITS_PER_BYTE);
	BUG_ON((state_bits % 2) != 0);
	BUG_ON(start_offset > SSDFS_ITEMS_PER_BYTE(state_bits));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("value %#x, state %#x, "
		  "start_offset %u, state_bits %u\n",
		  *value, state, start_offset, state_bits);

	i = start_offset * state_bits;
	for (; i < BITS_PER_BYTE; i += state_bits) {
		if (((*value >> i) & state_mask) == state) {
			SSDFS_DBG("found bit %u, found item %u\n",
				  i, i / state_bits);
			return i / state_bits;
		}
	}

	return SSDFS_ITEMS_PER_BYTE(state_bits);
}

/*
 * FIRST_MASK_IN_BYTE() - determine first item's offset for requested mask
 * @value: pointer on analysed byte
 * @mask: requested mask
 * @start_offset: starting item's offset for analysis beginning
 * @state_bits: bits per state
 * @state_mask: mask of a bitmap's state
 *
 * This function tries to determine an item for @mask in
 * @value starting from @start_off.
 *
 * RETURN:
 * [success] - found item's offset.
 * [failure] - BITS_PER_BYTE.
 */
static inline
u8 FIRST_MASK_IN_BYTE(u8 *value, int mask,
		      u8 start_offset, u8 state_bits,
		      int state_mask)
{
	u8 i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!value);
	BUG_ON(state_bits > BITS_PER_BYTE);
	BUG_ON((state_bits % 2) != 0);
	BUG_ON(start_offset > SSDFS_ITEMS_PER_BYTE(state_bits));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("value %#x, mask %#x, "
		  "start_offset %u, state_bits %u\n",
		  *value, mask, start_offset, state_bits);

	i = start_offset * state_bits;
	for (; i < BITS_PER_BYTE; i += state_bits) {
		if (((*value >> i) & state_mask) & mask) {
			SSDFS_DBG("found bit %u, found item %u\n",
				  i, i / state_bits);
			return i / state_bits;
		}
	}

	return SSDFS_ITEMS_PER_BYTE(state_bits);
}

/*
 * FIND_FIRST_ITEM_IN_BYTE() - find item in byte value
 * @value: pointer on analysed byte
 * @state: requested state or mask
 * @state_bits: bits per state
 * @state_mask: mask of a bitmap's state
 * @start_offset: starting item's offset for search
 * @check: pointer on check function
 * @op: pointer on concrete operation function
 * @found_offset: pointer on found item's offset into byte for state [out]
 *
 * This function tries to find in byte items with @state starting from
 * @start_offset.
 *
 * RETURN:
 * [success] - @found_offset contains found items' offset into byte.
 * [failure] - error code:
 *
 * %-ENODATA    - analyzed @value doesn't contain any item for @state.
 */
static inline
int FIND_FIRST_ITEM_IN_BYTE(u8 *value, int state, u8 state_bits,
			    int state_mask,
			    u8 start_offset, byte_check_func check,
			    byte_op_func op, u8 *found_offset)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!value || !found_offset || !check || !op);
	BUG_ON(state_bits > BITS_PER_BYTE);
	BUG_ON((state_bits % 2) != 0);
	BUG_ON(start_offset > SSDFS_ITEMS_PER_BYTE(state_bits));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("value %#x, state %#x, state_bits %u, "
		  "start_offset %u, found_offset %p\n",
		  *value, state, state_bits,
		  start_offset, found_offset);

	*found_offset = U8_MAX;

	if (check(value, state)) {
		u8 offset = op(value, state, start_offset, state_bits,
				state_mask);

		if (offset < SSDFS_ITEMS_PER_BYTE(state_bits)) {
			*found_offset = offset;

			SSDFS_DBG("item's offset %u for state %#x\n",
				  *found_offset, state);

			return 0;
		}
	}

	return -ENODATA;
}

/*
 * ssdfs_find_first_dirty_fragment() - find first dirty fragment
 * @addr: start address
 * @max_fragment: upper bound for search
 * @found_addr: found address with dirty fragments [out]
 *
 * This method tries to find address of first found bitmap's
 * part that contains dirty fragments.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA     - nothing found.
 */
static inline
int ssdfs_find_first_dirty_fragment(unsigned long *addr,
				    unsigned long max_fragment,
				    unsigned long **found_addr)
{
	unsigned long found;

	SSDFS_DBG("addr %p, max_fragment %lu, found_addr %p\n",
		  addr, max_fragment, found_addr);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!addr || !found_addr);
#endif /* CONFIG_SSDFS_DEBUG */

	found = find_first_bit(addr, max_fragment);

	if (found >= max_fragment) {
		SSDFS_DBG("unable to find fragment: "
			  "found %lu, max_fragment %lu\n",
			  found, max_fragment);
		return -ENODATA;
	}

	*found_addr = (unsigned long *)((u8 *)addr + (found / BITS_PER_BYTE));

	return 0;
}

/*
 * ssdfs_clear_dirty_state() - clear all dirty states for address
 * @addr: pointer on unsigned long value
 */
static inline
int ssdfs_clear_dirty_state(unsigned long *addr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!addr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("addr %p\n", addr);

	memset(addr, 0, sizeof(unsigned long));
	return 0;
}

#endif /* _SSDFS_COMMON_BITMAP_H */
