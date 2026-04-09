// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (C) 2025 Micron Technology, Inc.  All rights reserved.
 */

#ifndef FAMFS_FUSED_H
#define FAMFS_FUSED_H

#include <assert.h>
#include <linux/uuid.h>
#include "famfs_fused_icache.h"

enum {
	CACHE_NEVER,
	CACHE_NORMAL,
	CACHE_ALWAYS,
};

#define FAMFS_UUID_CHECK_INTERVAL 10 /* seconds */

struct famfs_ctx {
	int debug;
	int flock;
	int xattr;
	char *source;
	char *daxdev;
	int max_daxdevs;
	struct famfs_daxdev *daxdev_table;
	double timeout;
	int cache;
	int timeout_set;
	int pass_yaml; /* pass the shadow yaml through */
	int readdirplus;
	struct famfs_icache icache;
	uuid_le fs_uuid;              /* filesystem UUID from superblock */
	int uuid_valid;               /* set to 1 after UUID is read at startup */
};

#endif /* FAMFS_FUSED_H */
