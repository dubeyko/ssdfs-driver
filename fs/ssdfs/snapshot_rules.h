//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/snapshot_rules.h - snapshot rule declarations.
 *
 * Copyright (c) 2021-2022 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_SNAPSHOT_RULES_H
#define _SSDFS_SNAPSHOT_RULES_H

/*
 * struct ssdfs_snapshot_rules_list - snapshot rules list descriptor
 * @lock: snapshot rules list's lock
 * @list: snapshot rules list
 */
struct ssdfs_snapshot_rules_list {
	spinlock_t lock;
	struct list_head list;
};

/*
 * Snapshot rules list API
 */
void ssdfs_snapshot_rules_list_init(struct ssdfs_snapshot_rules_list *rl);
bool is_ssdfs_snapshot_rules_list_empty(struct ssdfs_snapshot_rules_list *rl);
void ssdfs_snapshot_rules_list_add_tail(struct ssdfs_snapshot_rules_list *rl,
					struct ssdfs_snapshot_rule_item *ri);
void ssdfs_snapshot_rules_list_add_head(struct ssdfs_snapshot_rules_list *rl,
					struct ssdfs_snapshot_rule_item *ri);
void ssdfs_snapshot_rules_list_remove_all(struct ssdfs_snapshot_rules_list *rl);

/*
 * Snapshot rule's API
 */
struct ssdfs_snapshot_rule_item *ssdfs_snapshot_rule_alloc(void);
void ssdfs_snapshot_rule_free(struct ssdfs_snapshot_rule_item *ri);

struct page *ssdfs_snapshot_rules_add_pagevec_page(struct pagevec *pvec);
void ssdfs_snapshot_rules_pagevec_release(struct pagevec *pvec);

int ssdfs_process_snapshot_rules(struct ssdfs_fs_info *fsi);
int ssdfs_modify_snapshot_rule(struct ssdfs_fs_info *fsi,
				struct ssdfs_snapshot_request *snr);
int ssdfs_remove_snapshot_rule(struct ssdfs_snapshot_subsystem *snapshots,
				struct ssdfs_snapshot_request *snr);

#endif /* _SSDFS_SNAPSHOT_RULES_H */
