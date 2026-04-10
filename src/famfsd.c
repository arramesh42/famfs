/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2023-2025 Micron Technology, Inc.  All rights reserved.
 *
 * famfsd - Filesystem UUID validation daemon for famfs
 *
 * This daemon monitors a mounted famfs filesystem and validates that the
 * underlying storage has not been reformatted by another host. If a UUID
 * mismatch is detected, the daemon logs an error and unmounts the filesystem.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <linux/limits.h>
#include <linux/uuid.h>
#include <uuid/uuid.h>

#include "famfs_lib.h"
#include "famfs_lib_internal.h"
#include "famfs_meta.h"

#define FAMFSD_VERSION "1.0.0"
#define POLL_INTERVAL_SEC 5
#define UUID_CHECK_RELPATH ".meta/.uuid_check"
#define SB_FILE_RELPATH ".meta/.superblock"

/* Global for signal handling */
static volatile sig_atomic_t g_running = 1;

static void signal_handler(int sig)
{
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		g_running = 0;
		break;
	}
}

static int setup_signal_handlers(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGTERM, &sa, NULL) < 0)
		return -1;
	if (sigaction(SIGINT, &sa, NULL) < 0)
		return -1;

	/* Ignore SIGPIPE */
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL) < 0)
		return -1;

	return 0;
}

/**
 * read_superblock_uuids() - Read UUIDs from the superblock
 *
 * @mpt:             Mount point path
 * @fs_uuid_out:     Output buffer for the filesystem UUID (optional, can be NULL)
 * @system_uuid_out: Output buffer for the system UUID (optional, can be NULL)
 *
 * Returns 0 on success, negative on error
 */
static int read_superblock_uuids(const char *mpt, uuid_le *fs_uuid_out,
				 uuid_le *system_uuid_out)
{
	char sb_path[PATH_MAX];
	struct famfs_superblock *sb;
	size_t sb_size;
	int rc;

	snprintf(sb_path, PATH_MAX, "%s/%s", mpt, SB_FILE_RELPATH);

	sb = (struct famfs_superblock *)famfs_mmap_whole_file(
		sb_path, 1 /* read_only */, &sb_size);
	if (!sb) {
		syslog(LOG_ERR, "famfsd: failed to mmap superblock at %s",
		       sb_path);
		return -ENOENT;
	}

	if (sb_size != FAMFS_SUPERBLOCK_SIZE) {
		syslog(LOG_ERR, "famfsd: bad superblock size=%zu (expected %d)",
		       sb_size, FAMFS_SUPERBLOCK_SIZE);
		munmap(sb, sb_size);
		return -EINVAL;
	}

	/* Verify superblock magic */
	if (sb->ts_magic != FAMFS_SUPER_MAGIC) {
		syslog(LOG_ERR, "famfsd: invalid superblock magic");
		munmap(sb, sb_size);
		return -EINVAL;
	}

	if (fs_uuid_out)
		memcpy(fs_uuid_out, &sb->ts_uuid, sizeof(uuid_le));

	if (system_uuid_out)
		memcpy(system_uuid_out, &sb->ts_system_uuid, sizeof(uuid_le));

	rc = munmap(sb, sb_size);
	if (rc)
		syslog(LOG_WARNING, "famfsd: failed to munmap superblock");

	return 0;
}

/**
 * check_is_owner() - Check if this system is the filesystem owner
 *
 * @mpt: Mount point path
 *
 * Returns 1 if owner, 0 if client (including when superblock can't be read)
 *
 * Note: If we cannot read or validate the superblock, we assume we are
 * not the owner. This handles the case where the filesystem has been
 * reformatted by another host - clients should exit gracefully rather
 * than attempt UUID monitoring on a filesystem they don't own.
 */
static int check_is_owner(const char *mpt)
{
	uuid_le sb_system_uuid, my_system_uuid;
	int rc;

	/* Get the system UUID from the superblock (owner's UUID) */
	rc = read_superblock_uuids(mpt, NULL, &sb_system_uuid);
	if (rc < 0) {
		/*
		 * Cannot read superblock - this can happen if:
		 * 1. The filesystem was reformatted by another host
		 * 2. The superblock is invalid or corrupted
		 * In either case, we are not the owner of this filesystem.
		 */
		return 0;
	}

	/* Get this system's UUID */
	rc = famfs_get_system_uuid(&my_system_uuid);
	if (rc < 0) {
		/*
		 * Cannot determine our own system UUID - we cannot
		 * confirm ownership, so assume we are a client.
		 */
		return 0;
	}

	/* Compare: if they match, we are the owner */
	if (memcmp(&sb_system_uuid, &my_system_uuid, sizeof(uuid_le)) == 0)
		return 1;

	return 0;
}

/**
 * read_uuid_from_check_file() - Read the expected UUID from the check file
 *
 * @shadow_path: Path to the shadow root directory
 * @uuid_out:    Output buffer for the UUID
 *
 * Returns 0 on success, negative on error
 */
static int read_uuid_from_check_file(const char *shadow_path, uuid_le *uuid_out)
{
	char check_path[PATH_MAX];
	FILE *fp;
	char uuid_str[48];
	uuid_t local_uuid;

	snprintf(check_path, PATH_MAX, "%s/%s", shadow_path, UUID_CHECK_RELPATH);

	fp = fopen(check_path, "r");
	if (!fp) {
		syslog(LOG_ERR, "famfsd: cannot open uuid check file: %s (%s)",
		       check_path, strerror(errno));
		return -errno;
	}

	if (fgets(uuid_str, sizeof(uuid_str), fp) == NULL) {
		syslog(LOG_ERR, "famfsd: cannot read uuid from check file");
		fclose(fp);
		return -EIO;
	}
	fclose(fp);

	/* Remove trailing newline if present */
	uuid_str[strcspn(uuid_str, "\n")] = '\0';

	/* Parse UUID string back to uuid_le */
	if (uuid_parse(uuid_str, local_uuid) < 0) {
		syslog(LOG_ERR, "famfsd: invalid UUID format in check file: %s",
		       uuid_str);
		return -EINVAL;
	}

	memcpy(uuid_out, local_uuid, sizeof(uuid_le));
	return 0;
}

/**
 * uuid_to_string() - Convert a uuid_le to string
 *
 * @uuid: Input UUID
 * @buf:  Output buffer (must be at least 37 bytes)
 */
static void uuid_to_string(const uuid_le *uuid, char *buf)
{
	uuid_t local_uuid;

	memcpy(&local_uuid, uuid, sizeof(local_uuid));
	uuid_unparse(local_uuid, buf);
}

/**
 * famfsd_main_loop() - Main monitoring loop
 *
 * @mpt:         Mount point to monitor
 * @shadow_path: Path to shadow root directory
 *
 * Returns 0 on normal shutdown, 1 on UUID mismatch, negative on error
 */
static int famfsd_main_loop(const char *mpt, const char *shadow_path)
{
	uuid_le expected_uuid, current_uuid;
	char exp_str[37], cur_str[37];
	int rc;

	/* Read the expected UUID from check file */
	rc = read_uuid_from_check_file(shadow_path, &expected_uuid);
	if (rc < 0) {
		syslog(LOG_ERR, "famfsd: failed to read expected UUID");
		return rc;
	}

	uuid_to_string(&expected_uuid, exp_str);
	syslog(LOG_NOTICE, "famfsd: monitoring %s (uuid=%s)", mpt, exp_str);

	while (g_running) {
		sleep(POLL_INTERVAL_SEC);

		if (!g_running)
			break;

		/* Read current UUID from superblock */
		rc = read_superblock_uuids(mpt, &current_uuid, NULL);
		if (rc < 0) {
			/* May be a transient error, log and continue */
			syslog(LOG_WARNING,
			       "famfsd: failed to read current UUID (rc=%d)",
			       rc);
			continue;
		}

		/* Compare UUIDs */
		if (memcmp(&expected_uuid, &current_uuid, sizeof(uuid_le)) != 0) {
			uuid_to_string(&current_uuid, cur_str);

			syslog(LOG_CRIT,
			       "famfsd: UUID MISMATCH DETECTED!");
			syslog(LOG_CRIT,
			       "famfsd:   expected: %s", exp_str);
			syslog(LOG_CRIT,
			       "famfsd:   current:  %s", cur_str);
			syslog(LOG_CRIT,
			       "famfsd: Storage may have been reformatted by another host!");
			syslog(LOG_CRIT,
			       "famfsd: Initiating unmount of %s", mpt);

			/* Initiate unmount */
			rc = famfs_umount(mpt);
			if (rc != 0) {
				syslog(LOG_ERR,
				       "famfsd: unmount failed: %s",
				       strerror(errno));
			} else {
				syslog(LOG_NOTICE,
				       "famfsd: unmount successful");
			}

			/* Exit with error code regardless of unmount success */
			return 1;
		}
	}

	syslog(LOG_NOTICE, "famfsd: shutting down gracefully");
	return 0;
}

static void usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [OPTIONS] <mount_point>\n", progname);
	fprintf(stderr, "\n");
	fprintf(stderr, "Monitor a famfs mount for UUID changes and unmount if detected.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -f, --foreground   Run in foreground (don't daemonize)\n");
	fprintf(stderr, "  -v, --verbose      Verbose output\n");
	fprintf(stderr, "  -h, --help         Show this help message\n");
	fprintf(stderr, "  -V, --version      Show version\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Exit codes:\n");
	fprintf(stderr, "  0  Normal shutdown (signal received)\n");
	fprintf(stderr, "  1  UUID mismatch detected (filesystem unmounted)\n");
	fprintf(stderr, "  2  Startup error\n");
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"foreground", no_argument, 0, 'f'},
		{"verbose",    no_argument, 0, 'v'},
		{"help",       no_argument, 0, 'h'},
		{"version",    no_argument, 0, 'V'},
		{0, 0, 0, 0}
	};
	int foreground = 0;
	int verbose = 0;
	const char *mpt;
	char shadow_path[PATH_MAX] = {0};
	int rc;
	int opt;

	while ((opt = getopt_long(argc, argv, "fvhV", long_options, NULL)) != -1) {
		switch (opt) {
		case 'f':
			foreground = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		case 'V':
			printf("famfsd version %s\n", FAMFSD_VERSION);
			return 0;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: mount point required\n");
		usage(argv[0]);
		return 2;
	}

	mpt = argv[optind];

	/* Verify mount point is a valid famfs mount */
	if (!famfs_path_is_mount_pt(mpt, NULL, shadow_path)) {
		fprintf(stderr, "Error: %s is not a famfs mount point\n", mpt);
		return 2;
	}

	if (verbose)
		printf("famfsd: shadow path is %s\n", shadow_path);

	/* Check if this system is the filesystem owner.
	 * Clients (including nodes where we can't read the superblock due to
	 * filesystem reformatting by another host) exit gracefully here.
	 */
	if (!check_is_owner(mpt)) {
		/* This is a client, not the owner - UUID monitoring not needed */
		if (verbose)
			printf("famfsd: this system is a client, not the owner; "
			       "UUID monitoring not required\n");
		return 0;
	}

	if (verbose)
		printf("famfsd: this system is the filesystem owner\n");

	/* Setup signal handlers */
	if (setup_signal_handlers() < 0) {
		fprintf(stderr, "Error: failed to setup signal handlers\n");
		return 2;
	}

	/* Open syslog */
	openlog("famfsd", LOG_PID | LOG_CONS, LOG_DAEMON);

	/* Daemonize if not foreground */
	if (!foreground) {
		if (daemon(0, 0) < 0) {
			syslog(LOG_ERR, "famfsd: failed to daemonize: %s",
			       strerror(errno));
			closelog();
			return 2;
		}
	}

	syslog(LOG_NOTICE, "famfsd: started for mount point %s (pid=%d)",
	       mpt, getpid());

	rc = famfsd_main_loop(mpt, shadow_path);

	closelog();
	return rc;
}
