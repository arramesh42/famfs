// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (C) 2023-2025 Micron Technology, Inc.  All rights reserved.
 *
 * famfsd - Famfs superblock consistency checker daemon
 *
 * This daemon periodically monitors the famfs superblock to detect if another
 * host has overwritten it. If a superblock mismatch (especially fs_uuid) is
 * detected, the daemon logs an error and initiates an unmount of the filesystem.
 *
 * The daemon works on both famfs-owner (MASTER) and famfs-client nodes.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <linux/limits.h>
#include <getopt.h>
#include <time.h>

#include "famfs_lib.h"
#include "famfs_meta.h"
#include "famfs_log.h"

#define SUPERBLOCK_CHECK_FILE ".meta/.superblock_check"
#define SB_FILE_PATH ".meta/.superblock"
#define DEFAULT_CHECK_INTERVAL 10  /* seconds */

/* Global flag for graceful shutdown */
static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_mismatch_detected = 0;

/* Configuration structure */
struct famfsd_config {
	char mount_point[PATH_MAX];
	char shadow_path[PATH_MAX];
	int check_interval;
	int verbose;
	int foreground;
};

/**
 * Signal handler for graceful shutdown
 */
static void
signal_handler(int sig)
{
	famfs_log(FAMFS_LOG_DEBUG, "%s: received signal %d\n", __func__, sig);
	if (sig == SIGTERM || sig == SIGINT) {
		g_running = 0;
	}
}

/**
 * Print usage information
 */
static void
usage(const char *progname)
{
	fprintf(stderr,
		"Usage: %s [options] <mount_point>\n"
		"\n"
		"Famfs superblock consistency checker daemon.\n"
		"Monitors the superblock for changes that might indicate another host\n"
		"has overwritten the filesystem.\n"
		"\n"
		"Options:\n"
		"  -i, --interval <sec>  Check interval in seconds (default: %d)\n"
		"  -f, --foreground      Run in foreground (don't daemonize)\n"
		"  -v, --verbose         Verbose output\n"
		"  -h, --help            Show this help message\n"
		"\n"
		"The daemon will automatically stop if a superblock mismatch is detected.\n",
		progname, DEFAULT_CHECK_INTERVAL);
}

/**
 * Read the saved superblock from the shadow filesystem
 */
static int
read_saved_superblock(
	const char *shadow_root,
	struct famfs_superblock *sb_out)
{
	char check_path[PATH_MAX];
	int fd;
	ssize_t bytes_read;

	snprintf(check_path, sizeof(check_path), "%s/%s",
		 shadow_root, SUPERBLOCK_CHECK_FILE);

	famfs_log(FAMFS_LOG_DEBUG, "%s: reading saved superblock from %s\n",
		  __func__, check_path);

	fd = open(check_path, O_RDONLY);
	if (fd < 0) {
		famfs_log(FAMFS_LOG_ERR, "%s: failed to open %s (errno=%d: %s)\n",
			  __func__, check_path, errno, strerror(errno));
		return -errno;
	}

	bytes_read = read(fd, sb_out, sizeof(struct famfs_superblock));
	close(fd);

	if (bytes_read != sizeof(struct famfs_superblock)) {
		famfs_log(FAMFS_LOG_ERR, "%s: short read from %s "
			  "(read=%zd, expected=%zu)\n",
			  __func__, check_path, bytes_read,
			  sizeof(struct famfs_superblock));
		return -EIO;
	}

	famfs_log(FAMFS_LOG_DEBUG, "%s: successfully read saved superblock\n",
		  __func__);
	return 0;
}

/**
 * Read the current superblock from the mount point
 */
static int
read_current_superblock(
	const char *mount_point,
	struct famfs_superblock *sb_out)
{
	char sb_path[PATH_MAX];
	struct famfs_superblock *sb_mapped;
	size_t sb_size;

	snprintf(sb_path, sizeof(sb_path), "%s/%s", mount_point, SB_FILE_PATH);

	famfs_log(FAMFS_LOG_DEBUG, "%s: reading current superblock from %s\n",
		  __func__, sb_path);

	sb_mapped = (struct famfs_superblock *)famfs_mmap_whole_file(
		sb_path, 1 /* read_only */, &sb_size);

	if (!sb_mapped) {
		famfs_log(FAMFS_LOG_ERR, "%s: failed to mmap superblock at %s\n",
			  __func__, sb_path);
		return -EIO;
	}

	if (sb_size < sizeof(struct famfs_superblock)) {
		famfs_log(FAMFS_LOG_ERR, "%s: superblock file too small "
			  "(size=%zu, expected=%zu)\n",
			  __func__, sb_size, sizeof(struct famfs_superblock));
		munmap(sb_mapped, sb_size);
		return -EINVAL;
	}

	/* Copy the superblock data */
	memcpy(sb_out, sb_mapped, sizeof(struct famfs_superblock));

	munmap(sb_mapped, sb_size);

	famfs_log(FAMFS_LOG_DEBUG, "%s: successfully read current superblock\n",
		  __func__);
	return 0;
}

/**
 * Compare two UUIDs
 * Returns 0 if equal, non-zero if different
 */
static int
famfsd_uuid_compare(const uuid_le *uuid1, const uuid_le *uuid2)
{
	return memcmp(uuid1, uuid2, sizeof(uuid_le));
}

/**
 * Print UUID to log
 */
static void
log_uuid(const char *prefix, const uuid_le *uuid, enum famfs_log_level level)
{
	famfs_log(level, "%s: %02x%02x%02x%02x-%02x%02x-%02x%02x-"
		  "%02x%02x-%02x%02x%02x%02x%02x%02x\n",
		  prefix,
		  uuid->b[0], uuid->b[1], uuid->b[2], uuid->b[3],
		  uuid->b[4], uuid->b[5], uuid->b[6], uuid->b[7],
		  uuid->b[8], uuid->b[9], uuid->b[10], uuid->b[11],
		  uuid->b[12], uuid->b[13], uuid->b[14], uuid->b[15]);
}

/**
 * Compare superblocks and check for fs_uuid mismatch
 */
static int
compare_superblocks(
	const struct famfs_superblock *saved_sb,
	const struct famfs_superblock *current_sb,
	int verbose)
{
	int mismatch = 0;

	famfs_log(FAMFS_LOG_DEBUG, "%s: comparing superblocks\n", __func__);

	/* Check magic number first */
	if (saved_sb->ts_magic != current_sb->ts_magic) {
		famfs_log(FAMFS_LOG_ERR,
			  "%s: SUPERBLOCK MAGIC MISMATCH! "
			  "saved=0x%llx, current=0x%llx\n",
			  __func__,
			  (unsigned long long)saved_sb->ts_magic,
			  (unsigned long long)current_sb->ts_magic);
		mismatch = 1;
	}

	/* Check fs_uuid - this is the critical check */
	if (famfsd_uuid_compare(&saved_sb->ts_uuid, &current_sb->ts_uuid) != 0) {
		famfs_log(FAMFS_LOG_ERR,
			  "%s: *** FILESYSTEM UUID MISMATCH DETECTED! ***\n",
			  __func__);
		famfs_log(FAMFS_LOG_ERR,
			  "%s: Another host may have overwritten the filesystem!\n",
			  __func__);
		log_uuid("saved fs_uuid", &saved_sb->ts_uuid, FAMFS_LOG_ERR);
		log_uuid("current fs_uuid", &current_sb->ts_uuid, FAMFS_LOG_ERR);
		mismatch = 1;
	} else {
		famfs_log(FAMFS_LOG_DEBUG, "%s: fs_uuid matches\n", __func__);
	}

	/* Also check version for informational purposes */
	if (saved_sb->ts_version != current_sb->ts_version) {
		famfs_log(FAMFS_LOG_WARNING,
			  "%s: version mismatch: saved=%llu, current=%llu\n",
			  __func__,
			  (unsigned long long)saved_sb->ts_version,
			  (unsigned long long)current_sb->ts_version);
		/* Version mismatch alone is suspicious but might not be fatal */
		if (!mismatch) {
			famfs_log(FAMFS_LOG_WARNING,
				  "%s: version changed but UUID matches - "
				  "this is unusual\n", __func__);
		}
	}

	/* Check CRC */
	if (saved_sb->ts_crc != current_sb->ts_crc) {
		famfs_log(FAMFS_LOG_DEBUG,
			  "%s: CRC changed: saved=0x%llx, current=0x%llx\n",
			  __func__,
			  (unsigned long long)saved_sb->ts_crc,
			  (unsigned long long)current_sb->ts_crc);
		/* CRC change without UUID change is logged but not fatal */
	}

	if (verbose && !mismatch) {
		famfs_log(FAMFS_LOG_DEBUG, "%s: superblock check passed\n",
			  __func__);
	}

	return mismatch;
}

/**
 * Perform the superblock consistency check
 */
static int
check_superblock_consistency(
	const struct famfsd_config *cfg,
	struct famfs_superblock *saved_sb)
{
	struct famfs_superblock current_sb;
	int rc;

	famfs_log(FAMFS_LOG_DEBUG, "%s: performing superblock check\n", __func__);

	/* Read current superblock from mount point */
	rc = read_current_superblock(cfg->mount_point, &current_sb);
	if (rc) {
		famfs_log(FAMFS_LOG_ERR,
			  "%s: failed to read current superblock (rc=%d)\n",
			  __func__, rc);
		/* If we can't read the superblock, the filesystem might be gone */
		return rc;
	}

	/* Compare with saved superblock */
	if (compare_superblocks(saved_sb, &current_sb, cfg->verbose)) {
		famfs_log(FAMFS_LOG_ERR,
			  "%s: *** SUPERBLOCK MISMATCH DETECTED! ***\n",
			  __func__);
		return -EINVAL;
	}

	famfs_log(FAMFS_LOG_DEBUG, "%s: superblock check passed\n", __func__);
	return 0;
}

/**
 * Perform unmount of the filesystem
 */
static int
do_unmount(const char *mount_point)
{
	int rc;

	famfs_log(FAMFS_LOG_ERR,
		  "%s: initiating unmount of %s due to superblock mismatch\n",
		  __func__, mount_point);

	fprintf(stderr,
		"famfsd: CRITICAL - Superblock mismatch detected!\n"
		"famfsd: Another host may have overwritten the filesystem.\n"
		"famfsd: Initiating unmount of %s\n", mount_point);

	rc = famfs_umount(mount_point);
	if (rc) {
		famfs_log(FAMFS_LOG_ERR,
			  "%s: umount failed for %s (errno=%d: %s)\n",
			  __func__, mount_point, errno, strerror(errno));
		fprintf(stderr, "famfsd: WARNING - umount failed (errno=%d)\n",
			errno);
		return rc;
	}

	famfs_log(FAMFS_LOG_NOTICE,
		  "%s: successfully unmounted %s\n", __func__, mount_point);
	fprintf(stderr, "famfsd: Successfully unmounted %s\n", mount_point);

	return 0;
}

/**
 * Get shadow path from mount point via xattr
 */
static int
get_shadow_path(const char *mount_point, char *shadow_out, size_t shadow_size)
{
	char *shadow_root;
	int rc;

	famfs_log(FAMFS_LOG_DEBUG, "%s: getting shadow path for %s\n",
		  __func__, mount_point);

	rc = famfs_get_shadow_from_xattr(mount_point, shadow_out, shadow_size);
	if (rc) {
		famfs_log(FAMFS_LOG_ERR,
			  "%s: failed to get shadow path from xattr (rc=%d)\n",
			  __func__, rc);
		return rc;
	}

	famfs_log(FAMFS_LOG_DEBUG, "%s: shadow path: %s\n", __func__, shadow_out);

	/* Get the shadow root (append /root if needed) */
	shadow_root = famfs_get_shadow_root(shadow_out, 0);
	if (!shadow_root) {
		famfs_log(FAMFS_LOG_ERR, "%s: failed to get shadow root\n",
			  __func__);
		return -EINVAL;
	}

	strncpy(shadow_out, shadow_root, shadow_size - 1);
	shadow_out[shadow_size - 1] = '\0';
	free(shadow_root);

	famfs_log(FAMFS_LOG_DEBUG, "%s: shadow root: %s\n", __func__, shadow_out);
	return 0;
}

/**
 * Daemonize the process
 */
static int
daemonize(void)
{
	pid_t pid;

	famfs_log(FAMFS_LOG_DEBUG, "%s: daemonizing\n", __func__);

	pid = fork();
	if (pid < 0) {
		famfs_log(FAMFS_LOG_ERR, "%s: fork failed (errno=%d)\n",
			  __func__, errno);
		return -1;
	}

	if (pid > 0) {
		/* Parent exits */
		exit(0);
	}

	/* Child continues */
	if (setsid() < 0) {
		famfs_log(FAMFS_LOG_ERR, "%s: setsid failed (errno=%d)\n",
			  __func__, errno);
		return -1;
	}

	/* Second fork to prevent acquiring a controlling terminal */
	pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (pid > 0) {
		exit(0);
	}

	/* Close standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	/* Redirect stdin/stdout/stderr to /dev/null */
	open("/dev/null", O_RDONLY);  /* stdin */
	open("/dev/null", O_WRONLY);  /* stdout */
	open("/dev/null", O_WRONLY);  /* stderr */

	famfs_log(FAMFS_LOG_DEBUG, "%s: daemonized successfully (pid=%d)\n",
		  __func__, getpid());
	return 0;
}

/**
 * Main daemon loop
 */
static int
daemon_loop(struct famfsd_config *cfg)
{
	struct famfs_superblock saved_sb;
	int rc;
	int check_count = 0;

	famfs_log(FAMFS_LOG_DEBUG, "%s: starting daemon loop\n", __func__);
	famfs_log(FAMFS_LOG_DEBUG, "%s: mount_point=%s\n",
		  __func__, cfg->mount_point);
	famfs_log(FAMFS_LOG_DEBUG, "%s: shadow_path=%s\n",
		  __func__, cfg->shadow_path);
	famfs_log(FAMFS_LOG_DEBUG, "%s: check_interval=%d seconds\n",
		  __func__, cfg->check_interval);

	/* Read the saved superblock once at startup */
	rc = read_saved_superblock(cfg->shadow_path, &saved_sb);
	if (rc) {
		famfs_log(FAMFS_LOG_ERR,
			  "%s: failed to read saved superblock (rc=%d)\n",
			  __func__, rc);
		famfs_log(FAMFS_LOG_ERR,
			  "%s: cannot proceed without saved superblock - "
			  "was the filesystem mounted properly?\n", __func__);
		return rc;
	}

	famfs_log(FAMFS_LOG_NOTICE,
		  "%s: famfsd started, monitoring %s (interval=%ds)\n",
		  __func__, cfg->mount_point, cfg->check_interval);
	log_uuid("monitoring fs_uuid", &saved_sb.ts_uuid, FAMFS_LOG_NOTICE);

	/* Main monitoring loop */
	while (g_running) {
		check_count++;
		famfs_log(FAMFS_LOG_DEBUG, "%s: check #%d starting\n",
			  __func__, check_count);

		rc = check_superblock_consistency(cfg, &saved_sb);
		if (rc) {
			famfs_log(FAMFS_LOG_ERR,
				  "%s: superblock consistency check failed!\n",
				  __func__);
			g_mismatch_detected = 1;
			g_running = 0;
			break;
		}

		famfs_log(FAMFS_LOG_DEBUG, "%s: check #%d passed, sleeping %d seconds\n",
			  __func__, check_count, cfg->check_interval);

		/* Sleep for the check interval */
		sleep(cfg->check_interval);
	}

	/* Handle mismatch if detected */
	if (g_mismatch_detected) {
		famfs_log(FAMFS_LOG_ERR,
			  "%s: mismatch detected - initiating unmount\n",
			  __func__);
		rc = do_unmount(cfg->mount_point);
		if (rc) {
			famfs_log(FAMFS_LOG_ERR,
				  "%s: unmount failed - manual intervention required!\n",
				  __func__);
		}
		famfs_log(FAMFS_LOG_NOTICE,
			  "%s: famfsd stopping due to mismatch detection\n",
			  __func__);
		return -EINVAL;
	}

	famfs_log(FAMFS_LOG_NOTICE, "%s: famfsd stopping (signal received)\n",
		  __func__);
	return 0;
}

int
main(int argc, char *argv[])
{
	struct famfsd_config cfg = {
		.check_interval = DEFAULT_CHECK_INTERVAL,
		.verbose = 0,
		.foreground = 0,
	};
	int rc;
	int opt;

	static struct option long_options[] = {
		{"interval",   required_argument, 0, 'i'},
		{"foreground", no_argument,       0, 'f'},
		{"verbose",    no_argument,       0, 'v'},
		{"help",       no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	/* Enable syslog for the daemon */
	famfs_log_enable_syslog("famfs", LOG_PID, LOG_DAEMON);
	famfs_log_set_level(FAMFS_LOG_DEBUG);  /* Enable debug logging */

	famfs_log(FAMFS_LOG_DEBUG, "%s: famfsd starting\n", __func__);

	while ((opt = getopt_long(argc, argv, "i:fvh", long_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			cfg.check_interval = atoi(optarg);
			if (cfg.check_interval < 1) {
				fprintf(stderr,
					"Error: interval must be at least 1 second\n");
				exit(1);
			}
			famfs_log(FAMFS_LOG_DEBUG, "%s: check interval set to %d\n",
				  __func__, cfg.check_interval);
			break;
		case 'f':
			cfg.foreground = 1;
			famfs_log(FAMFS_LOG_DEBUG, "%s: running in foreground\n",
				  __func__);
			break;
		case 'v':
			cfg.verbose = 1;
			famfs_log(FAMFS_LOG_DEBUG, "%s: verbose mode enabled\n",
				  __func__);
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: mount point required\n");
		usage(argv[0]);
		exit(1);
	}

	/* Get mount point */
	strncpy(cfg.mount_point, argv[optind], sizeof(cfg.mount_point) - 1);
	cfg.mount_point[sizeof(cfg.mount_point) - 1] = '\0';

	famfs_log(FAMFS_LOG_DEBUG, "%s: mount_point=%s\n",
		  __func__, cfg.mount_point);

	/* Get shadow path from mount point */
	rc = get_shadow_path(cfg.mount_point, cfg.shadow_path,
			     sizeof(cfg.shadow_path));
	if (rc) {
		fprintf(stderr,
			"Error: failed to get shadow path for %s\n",
			cfg.mount_point);
		famfs_log(FAMFS_LOG_ERR,
			  "%s: failed to get shadow path (rc=%d)\n",
			  __func__, rc);
		exit(1);
	}

	famfs_log(FAMFS_LOG_DEBUG, "%s: shadow_path=%s\n",
		  __func__, cfg.shadow_path);

	/* Set up signal handlers */
	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGHUP, SIG_IGN);

	famfs_log(FAMFS_LOG_DEBUG, "%s: signal handlers installed\n", __func__);

	/* Daemonize if not running in foreground */
	if (!cfg.foreground) {
		famfs_log(FAMFS_LOG_DEBUG, "%s: daemonizing process\n", __func__);
		if (daemonize() < 0) {
			fprintf(stderr, "Error: failed to daemonize\n");
			exit(1);
		}
	}

	famfs_log(FAMFS_LOG_NOTICE,
		  "%s: famfsd pid=%d monitoring %s\n",
		  __func__, getpid(), cfg.mount_point);

	/* Run the daemon loop */
	rc = daemon_loop(&cfg);

	famfs_log(FAMFS_LOG_NOTICE, "%s: famfsd exiting (rc=%d)\n", __func__, rc);

	famfs_log_close_syslog();

	return (rc == 0) ? 0 : 1;
}
