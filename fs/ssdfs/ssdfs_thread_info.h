//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ssdfs_thread_info.h - thread declarations.
 *
 * Copyright (c) 2019-2020 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_THREAD_INFO_H
#define _SSDFS_THREAD_INFO_H

/*
 * struct ssdfs_thread_info - thread info
 * @task: task descriptor
 * @wait: wait queue
 * @full_stop: ending of thread's activity
 */
struct ssdfs_thread_info {
	struct task_struct *task;
	struct wait_queue_entry wait;
	struct completion full_stop;
};

/* function prototype */
typedef int (*ssdfs_threadfn)(void *data);

/*
 * struct ssdfs_thread_descriptor - thread descriptor
 * @threadfn: thread's function
 * @fmt: thread's name format
 */
struct ssdfs_thread_descriptor {
	ssdfs_threadfn threadfn;
	const char *fmt;
};

#endif /* _SSDFS_THREAD_INFO_H */
