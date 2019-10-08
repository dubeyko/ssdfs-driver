#
# SPDX-License-Identifier: BSD-3-Clause-Clear
# Makefile for the Linux SSD-oriented File System  (SSDFS)
#
#

obj-$(CONFIG_SSDFS)			+= ssdfs.o

#ccflags-$(CONFIG_SSDFS_DEBUG)		+= -DDEBUG

ssdfs-y	:= super.o fs_error.o recovery.o options.o \
		page_array.o \
		volume_header.o log_footer.o \
		block_bitmap.o block_bitmap_tables.o \
		peb_block_bitmap.o segment_block_bitmap.o \
		sequence_array.o offset_translation_table.o \
		request_queue.o readwrite.o  \
		peb.o peb_gc_thread.o peb_read_thread.o peb_flush_thread.o \
		peb_container.o \
		segment.o segment_tree.o current_segment.o \
		segment_bitmap.o segment_bitmap_tables.o \
		peb_mapping_queue.o \
		peb_mapping_table.o peb_mapping_table_thread.o \
		peb_mapping_table_cache.o peb_migration_scheme.o \
		btree_search.o btree_node.o btree_hierarchy.o btree.o \
		extents_queue.o extents_tree.o \
		shared_extents_tree.o shared_extents_tree_thread.o \
		inodes_tree.o dentries_tree.o \
		shared_dictionary.o shared_dictionary_thread.o \
		xattr_tree.o \
		inode.o file.o dir.o ioctl.o \
		sysfs.o \
		xattr.o xattr_user.o xattr_trusted.o \
		compression.o

ssdfs-$(CONFIG_SSDFS_POSIX_ACL)		+= acl.o
ssdfs-$(CONFIG_SSDFS_SECURITY)		+= xattr_security.o
ssdfs-$(CONFIG_SSDFS_ZLIB)		+= compr_zlib.o
ssdfs-$(CONFIG_SSDFS_LZO)		+= compr_lzo.o
ssdfs-$(CONFIG_SSDFS_MTD_DEVICE)	+= dev_mtd.o
ssdfs-$(CONFIG_SSDFS_BLOCK_DEVICE)	+= dev_bdev.o
