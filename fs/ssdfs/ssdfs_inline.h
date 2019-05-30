//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 *  SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ssdfs_inline.h - inline functions and macros.
 *
 * Copyright (c) 2019 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_INLINE_H
#define _SSDFS_INLINE_H

#define SSDFS_CRIT(fmt, ...) \
	pr_crit("pid %d:%s:%d %s(): " fmt, \
		 current->pid, __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#define SSDFS_ERR(fmt, ...) \
	pr_err("pid %d:%s:%d %s(): " fmt, \
		 current->pid, __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#define SSDFS_WARN(fmt, ...) \
	do { \
		pr_warn("pid %d:%s:%d %s(): " fmt, \
			current->pid, __FILE__, __LINE__, \
			__func__, ##__VA_ARGS__); \
		dump_stack(); \
	} while (0)

#define SSDFS_NOTICE(fmt, ...) \
	pr_notice(fmt, ##__VA_ARGS__)

#define SSDFS_INFO(fmt, ...) \
	pr_info(fmt, ##__VA_ARGS__)

#ifdef CONFIG_SSDFS_DEBUG

#define SSDFS_DBG(fmt, ...) \
	pr_debug("pid %d:%s:%d %s(): " fmt, \
		 current->pid, __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#else /* CONFIG_SSDFS_DEBUG */

#define SSDFS_DBG(fmt, ...) \
	no_printk(KERN_DEBUG fmt, ##__VA_ARGS__)

#endif /* CONFIG_SSDFS_DEBUG */

#endif /* _SSDFS_INLINE_H */
