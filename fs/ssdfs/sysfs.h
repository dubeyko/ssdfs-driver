/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/sysfs.h - declaration of attributes are exported in sysfs.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2024 Viacheslav Dubeyko <slava@dubeyko.com>
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

#ifndef _SSDFS_SYSFS_H
#define _SSDFS_SYSFS_H

#include <linux/sysfs.h>

struct ssdfs_feature_attr {
	struct attribute attr;
	ssize_t (*show)(struct kobject *, struct attribute *,
			char *);
	ssize_t (*store)(struct kobject *, struct attribute *,
			 const char *, size_t);
};

struct ssdfs_dev_attr {
	struct attribute attr;
	ssize_t (*show)(struct ssdfs_dev_attr *, struct ssdfs_fs_info *,
			char *);
	ssize_t (*store)(struct ssdfs_dev_attr *, struct ssdfs_fs_info *,
			 const char *, size_t);
};

struct ssdfs_segments_attr {
	struct attribute attr;
	ssize_t (*show)(struct ssdfs_segments_attr *, struct ssdfs_fs_info *,
			char *);
	ssize_t (*store)(struct ssdfs_segments_attr *, struct ssdfs_fs_info *,
			 const char *, size_t);
};

struct ssdfs_seg_attr {
	struct attribute attr;
	ssize_t (*show)(struct ssdfs_seg_attr *, struct ssdfs_segment_info *,
			char *);
	ssize_t (*store)(struct ssdfs_seg_attr *, struct ssdfs_segment_info *,
			 const char *, size_t);
};

struct ssdfs_pebs_attr {
	struct attribute attr;
	ssize_t (*show)(struct ssdfs_pebs_attr *, struct ssdfs_segment_info *,
			char *);
	ssize_t (*store)(struct ssdfs_pebs_attr *, struct ssdfs_segment_info *,
			 const char *, size_t);
};

struct ssdfs_peb_attr {
	struct attribute attr;
	ssize_t (*show)(struct ssdfs_peb_attr *, struct ssdfs_peb_container *,
			char *);
	ssize_t (*store)(struct ssdfs_peb_attr *, struct ssdfs_peb_container *,
			 const char *, size_t);
};

struct ssdfs_segbmap_attr {
	struct attribute attr;
	ssize_t (*show)(struct ssdfs_segbmap_attr *, struct ssdfs_fs_info *,
			char *);
	ssize_t (*store)(struct ssdfs_segbmap_attr *, struct ssdfs_fs_info *,
			 const char *, size_t);
};

struct ssdfs_maptbl_attr {
	struct attribute attr;
	ssize_t (*show)(struct ssdfs_maptbl_attr *, struct ssdfs_fs_info *,
			char *);
	ssize_t (*store)(struct ssdfs_maptbl_attr *, struct ssdfs_fs_info *,
			 const char *, size_t);
};

#define SSDFS_ATTR(type, name, mode, show, store) \
	static struct ssdfs_##type##_attr ssdfs_##type##_attr_##name = \
		__ATTR(name, mode, show, store)

#define SSDFS_FEATURE_INFO_ATTR(name) \
	SSDFS_ATTR(feature, name, 0444, NULL, NULL)
#define SSDFS_FEATURE_RO_ATTR(name) \
	SSDFS_ATTR(feature, name, 0444, ssdfs_feature_##name##_show, NULL)

#define SSDFS_DEV_INFO_ATTR(name) \
	SSDFS_ATTR(dev, name, 0444, NULL, NULL)
#define SSDFS_DEV_RO_ATTR(name) \
	SSDFS_ATTR(dev, name, 0444, ssdfs_dev_##name##_show, NULL)
#define SSDFS_DEV_RW_ATTR(name) \
	SSDFS_ATTR(dev, name, 0644, \
		    ssdfs_dev_##name##_show, ssdfs_dev_##name##_store)

#define SSDFS_SEGMENTS_INFO_ATTR(name) \
	SSDFS_ATTR(segments, name, 0444, NULL, NULL)
#define SSDFS_SEGMENTS_RO_ATTR(name) \
	SSDFS_ATTR(segments, name, 0444, ssdfs_segments_##name##_show, NULL)
#define SSDFS_SEGMENTS_RW_ATTR(name) \
	SSDFS_ATTR(segments, name, 0644, \
		    ssdfs_segments_##name##_show, ssdfs_segments_##name##_store)

#define SSDFS_SEG_INFO_ATTR(name) \
	SSDFS_ATTR(seg, name, 0444, NULL, NULL)
#define SSDFS_SEG_RO_ATTR(name) \
	SSDFS_ATTR(seg, name, 0444, ssdfs_seg_##name##_show, NULL)
#define SSDFS_SEG_RW_ATTR(name) \
	SSDFS_ATTR(seg, name, 0644, \
		    ssdfs_seg_##name##_show, ssdfs_seg_##name##_store)

#define SSDFS_PEBS_INFO_ATTR(name) \
	SSDFS_ATTR(pebs, name, 0444, NULL, NULL)
#define SSDFS_PEBS_RO_ATTR(name) \
	SSDFS_ATTR(pebs, name, 0444, ssdfs_pebs_##name##_show, NULL)
#define SSDFS_PEBS_RW_ATTR(name) \
	SSDFS_ATTR(pebs, name, 0644, \
		    ssdfs_pebs_##name##_show, ssdfs_pebs_##name##_store)

#define SSDFS_PEB_INFO_ATTR(name) \
	SSDFS_ATTR(peb, name, 0444, NULL, NULL)
#define SSDFS_PEB_RO_ATTR(name) \
	SSDFS_ATTR(peb, name, 0444, ssdfs_peb_##name##_show, NULL)
#define SSDFS_PEB_RW_ATTR(name) \
	SSDFS_ATTR(peb, name, 0644, \
		    ssdfs_peb_##name##_show, ssdfs_peb_##name##_store)

#define SSDFS_SEGBMAP_INFO_ATTR(name) \
	SSDFS_ATTR(segbmap, name, 0444, NULL, NULL)
#define SSDFS_SEGBMAP_RO_ATTR(name) \
	SSDFS_ATTR(segbmap, name, 0444, ssdfs_segbmap_##name##_show, NULL)
#define SSDFS_SEGBMAP_RW_ATTR(name) \
	SSDFS_ATTR(segbmap, name, 0644, \
		    ssdfs_segbmap_##name##_show, ssdfs_segbmap_##name##_store)

#define SSDFS_MAPTBL_INFO_ATTR(name) \
	SSDFS_ATTR(maptbl, name, 0444, NULL, NULL)
#define SSDFS_MAPTBL_RO_ATTR(name) \
	SSDFS_ATTR(maptbl, name, 0444, ssdfs_maptbl_##name##_show, NULL)
#define SSDFS_MAPTBL_RW_ATTR(name) \
	SSDFS_ATTR(maptbl, name, 0644, \
		    ssdfs_maptbl_##name##_show, ssdfs_maptbl_##name##_store)

#define SSDFS_FEATURE_ATTR_LIST(name) \
	(&ssdfs_feature_attr_##name.attr)
#define SSDFS_DEV_ATTR_LIST(name) \
	(&ssdfs_dev_attr_##name.attr)
#define SSDFS_SEGMENTS_ATTR_LIST(name) \
	(&ssdfs_segments_attr_##name.attr)
#define SSDFS_SEG_ATTR_LIST(name) \
	(&ssdfs_seg_attr_##name.attr)
#define SSDFS_PEBS_ATTR_LIST(name) \
	(&ssdfs_pebs_attr_##name.attr)
#define SSDFS_PEB_ATTR_LIST(name) \
	(&ssdfs_peb_attr_##name.attr)
#define SSDFS_SEGBMAP_ATTR_LIST(name) \
	(&ssdfs_segbmap_attr_##name.attr)
#define SSDFS_MAPTBL_ATTR_LIST(name) \
	(&ssdfs_maptbl_attr_##name.attr)

#endif /* _SSDFS_SYSFS_H */
