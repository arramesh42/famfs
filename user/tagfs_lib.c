// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>
#include <errno.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <linux/types.h>
#include <stddef.h>
#include <sys/mman.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <linux/uuid.h> /* Our preferred UUID format */
#include <uuid/uuid.h>  /* for uuid_generate / libuuid */
#include <libgen.h>
#include <assert.h>
#include <sys/param.h> /* MIN()/MAX() */

#include "tagfs.h"
#include "tagfs_ioctl.h"
#include "tagfs_meta.h"

#include "tagfs_lib.h"
#include "bitmap.h"

void
make_bit_string(u8 byte, char *str)
{
	str[0] = (byte & 0x80) ? '1':'0';
	str[1] = (byte & 0x40) ? '1':'0';
	str[2] = (byte & 0x20) ? '1':'0';
	str[3] = (byte & 0x10) ? '1':'0';
	str[4] = (byte & 0x08) ? '1':'0';
	str[5] = (byte & 0x04) ? '1':'0';
	str[6] = (byte & 0x02) ? '1':'0';
	str[7] = (byte & 0x01) ? '1':'0';
	str[8] = 0;
}

void
mu_print_bitmap(u8 *bitmap, int num_bits)
{
	int i, val;

	mu_bitmap_foreach(bitmap, num_bits, i, val) {
		if (!(i%64))
			printf("\n%4d: ", i);

		printf("%d", val);
	}
	printf("\n");
}


void
tagfs_uuidgen(uuid_le *uuid)
{
	uuid_t local_uuid;

	uuid_generate(local_uuid);
	memcpy(uuid, &local_uuid, sizeof(local_uuid));
}

void
tagfs_print_uuid(const uuid_le *uuid)
{
	uuid_t local_uuid;
	char uuid_str[37];

	memcpy(&local_uuid, uuid, sizeof(local_uuid));
	uuid_unparse(local_uuid, uuid_str);

	printf("%s\n", uuid_str);

}

int
tagfs_get_device_size(const char       *fname,
		      size_t           *size,
		      enum extent_type *type)
{
	char spath[PATH_MAX];
	char *basename;
	FILE *sfile;
	u_int64_t size_i;
	struct stat st;
	int rc;
	int is_blk = 0;

	rc = stat(fname, &st);
	if (rc < 0) {
		fprintf(stderr, "%s: failed to stat file %s (%s)\n",
			__func__, fname, strerror(errno));
		return -errno;
	}

	basename = strrchr(fname, '/');
	switch (st.st_mode & S_IFMT) {
	case S_IFBLK:
		is_blk = 1;
		snprintf(spath, PATH_MAX, "/sys/class/block%s/size", basename);
		break;
	case S_IFCHR:
		snprintf(spath, PATH_MAX, "/sys/dev/char/%d:%d/size",
			 major(st.st_rdev), minor(st.st_rdev));
		break;
	default:
		fprintf(stderr, "invalid dax device %s\n", fname);
		return -EINVAL;
	}

	printf("%s: getting daxdev size from file %s\n", __func__, spath);
	sfile = fopen(spath, "r");
	if (!sfile) {
		fprintf(stderr, "%s: fopen on %s failed (%s)\n",
			__func__, spath, strerror(errno));
		return -EINVAL;
	}

	rc = fscanf(sfile, "%lu", &size_i);
	if (rc < 0) {
		fprintf(stderr, "%s: fscanf on %s failed (%s)\n",
			__func__, spath, strerror(errno));
		fclose(sfile);
		return -EINVAL;
	}

	fclose(sfile);

	if (is_blk)
		size_i *= 512; /* blkdev size is in 512b blocks */

	printf("%s: size=%ld\n", __func__, size_i);
	*size = (size_t)size_i;
	return 0;
}

/**
 * tagfs_fsck_scan()
 *
 * * Print info from the superblock
 * * Print log stats
 * * build the log bitmap (which scans the log) and check for errors
 */
int
tagfs_fsck_scan(
	const struct tagfs_superblock *sb,
	const struct tagfs_log        *logp,
	int                            verbose)
{
	size_t total_log_size;
	size_t effective_log_size;
	int i;
	u64 errors = 0;
	u8 *bitmap;
	u64 alloc_total, size_total;

	effective_log_size = sizeof(*logp) +
		(logp->tagfs_log_next_index * sizeof(struct tagfs_log_entry));

	/*
	 * Print superblock info
	 */
	printf("Tagfs Superblock:\n");
	printf("  UUID:   ");
	tagfs_print_uuid(&sb->ts_uuid);
	printf("  sizeof superblock: %ld\n", sizeof(struct tagfs_superblock));
	printf("  num_daxdevs:              %d\n", sb->ts_num_daxdevs);
	for (i = 0; i < sb->ts_num_daxdevs; i++) {
		if (i == 0)
			printf("  primary: ");
		else
			printf("         %d: ", i);

		printf("%s   %ld\n",
		       sb->ts_devlist[i].dd_daxdev, sb->ts_devlist[i].dd_size);
	}

	/*
	 * print log info
	 */
	printf("\nLog stats:\n");
	printf("  # of log entriesi in use: %lld of %lld\n",
	       logp->tagfs_log_next_index, logp->tagfs_log_last_index + 1);
	printf("  Log size in use:          %ld\n", effective_log_size);

	/*
	 * Build the log bitmap to scan for errors
	 */
	bitmap = tagfs_build_bitmap(logp,  sb->ts_devlist[0].dd_size, NULL, &errors,
				    &size_total, &alloc_total, 0);
	if (errors)
		printf("ERROR: %lld ALLOCATION COLLISIONS FOUND\n", errors);
	else {
		float space_amp = (float)alloc_total / (float)size_total;

		printf("  No allocation errors found\n");
		printf("  alloc_total=%lld size_total=%lld space_amplification=%.2f\n",
		       alloc_total, size_total, space_amp);
	}

	free(bitmap);

	if (verbose) {
		printf("log_offset:        %lld\n", sb->ts_log_offset);
		printf("log_len:           %lld\n", sb->ts_log_len);

		printf("sizeof(log header) %ld\n", sizeof(struct tagfs_log));
		printf("sizeof(log_entry)  %ld\n", sizeof(struct tagfs_log_entry));

		printf("last_log_index:    %lld\n", logp->tagfs_log_last_index);
		total_log_size = sizeof(struct tagfs_log)
			+ (sizeof(struct tagfs_log_entry) * (1 + logp->tagfs_log_last_index));
		printf("full log size:     %ld\n", total_log_size);
		printf("TAGFS_LOG_LEN:     %d\n", TAGFS_LOG_LEN);
		printf("Remainder:         %ld\n", TAGFS_LOG_LEN - total_log_size);
		printf("\nfc: %ld\n", sizeof(struct tagfs_file_creation));
		printf("fa:   %ld\n", sizeof(struct tagfs_file_access));
	}
	return errors;
}

/**
 * tagfs_mmap_superblock_and_log_raw()
 *
 * This function SHOULD ONLY BE CALLED BY FSCK AND MKMETA
 *
 * The superblock and log are mapped directly from a device. Other apps should map
 * them from their meta files!
 *
 * @devname   - dax device name
 * @sbp
 * @logp
 * @read_only - map sb and log read-only
 */
int
tagfs_mmap_superblock_and_log_raw(const char *devname,
				  struct tagfs_superblock **sbp,
				  struct tagfs_log **logp,
				  int read_only)
{
	int fd = 0;
	void *sb_buf;
	int rc = 0;
	int openmode = (read_only) ? O_RDONLY : O_RDWR;
	int mapmode  = (read_only) ? PROT_READ : PROT_READ | PROT_WRITE;

	fd = open(devname, openmode, 0);
	if (fd < 0) {
		fprintf(stderr, "%s: open %s failed; rc %d errno %d\n",
			__func__, devname, rc, errno);
		rc = -1;
		goto err_out;
	}

	/* Map superblock and log in one call */
	sb_buf = mmap(0, TAGFS_SUPERBLOCK_SIZE + TAGFS_LOG_LEN, mapmode, MAP_SHARED, fd, 0);
	if (sb_buf == MAP_FAILED) {
		fprintf(stderr, "Failed to mmap superblock and log from %s\n", devname);
		rc = -1;
		goto err_out;
	}
	*sbp = (struct tagfs_superblock *)sb_buf;

	*logp = (struct tagfs_log *)((u64)sb_buf + TAGFS_SUPERBLOCK_SIZE);
	close(fd);
	return 0;

err_out:
	if (sb_buf)
		munmap(sb_buf, TAGFS_SUPERBLOCK_SIZE);

	if (fd)
		close(fd);
	return rc;
}

int
tagfs_check_super(const struct tagfs_superblock *sb)
{
	if (!sb)
		return -1;
	if (sb->ts_magic != TAGFS_SUPER_MAGIC)
		return -1;
	/* TODO: check crc, etc. */
	return 0;
}

#define XLEN 256

/**
 * tagfs_get_mpt_by_dev()
 *
 * @mtdev = the primary dax device for a tagfs file system.
 *
 * This function determines the mount point by parsing /proc/mounts to find the mount point
 * from a dax device name.
 */
static char *
tagfs_get_mpt_by_dev(const char *mtdev)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	int rc;
	char *answer = NULL;

	fp = fopen("/proc/mounts", "r");
	if (fp == NULL)
		return NULL;

	while ((read = getline(&line, &len, fp)) != -1) {
		char dev[XLEN];
		char mpt[XLEN];
		char fstype[XLEN];
		char args[XLEN];
		int  x0, x1;
		char *xmpt = NULL;

		if (strstr(line, "tagfs")) {
			rc = sscanf(line, "%s %s %s %s %d %d",
				    dev, mpt, fstype, args, &x0, &x1);
			if (rc <= 0)
				goto out;

			xmpt = realpath(mpt, NULL);
			if (!xmpt) {
				fprintf(stderr, "realpath(%s) errno %d\n", mpt, errno);
				continue;
			}
			if (strcmp(dev, mtdev) == 0) {
				answer = strdup(xmpt);
				free(xmpt);
				free(line);
				return answer;
			}
		}
		if (xmpt)
			free(xmpt);

	}

out:
	fclose(fp);
	if (line)
		free(line);
	return NULL;
}

/**
 * tagfs_ext_to_simple_ext()
 *
 * Convert a struct tagfs_extent list to struct tagfs_simple_extent.
 * The output list comes from malloc() and must be freed by the caller after use.
 */
struct tagfs_simple_extent *
tagfs_ext_to_simple_ext(
	struct tagfs_extent *te_list,
	size_t               ext_count)
{
	struct tagfs_simple_extent *se = calloc(ext_count, sizeof(*se));
	int i;

	assert(te_list);
	if (!se)
		return NULL;

	for (i = 0; i < ext_count; i++) {
		se[i].tagfs_extent_offset = te_list[i].offset;
		se[i].tagfs_extent_len    = te_list[i].len;
	}
	return se;
}

/**
 * tagfs_file_map_create()
 *
 * This function allocates free space in a tagfs file system and associates it
 * with a file.
 *
 * @path
 * @fd           - file descriptor for the file whose map will be created (already open)
 * @size
 * @nextents
 * @extent_list
 */
int
tagfs_file_map_create(
	const char                 *path,
	int                         fd,
	size_t                      size,
	int                         nextents,
	struct tagfs_simple_extent *ext_list,
	enum tagfs_file_type        type)
{
	struct tagfs_ioc_map filemap;
	struct tagfs_extent *ext;
	int rc;

	assert(fd > 0);

	ext = calloc(nextents, sizeof(struct tagfs_extent));
	if (!ext)
		return -ENOMEM;

	filemap.file_type      = type;
	filemap.file_size      = size;
	filemap.extent_type    = FSDAX_EXTENT;
	filemap.ext_list_count = nextents;
	filemap.ext_list       = (struct tagfs_extent *)ext_list;

#if 0
	for (i = 0; i < nextents; i++) {
		ext[i].offset = ext_list[i].tagfs_extent_offset;
		ext[i].len    = ext_list[i].tagfs_extent_len;
	}
#endif
	rc = ioctl(fd, TAGFSIOC_MAP_CREATE, &filemap);
	if (rc)
		fprintf(stderr, "%s: failed MAP_CREATE for file %s (errno %d)\n",
			__func__, path, errno);

	free(ext);
	return rc;
}

/**
 * tagfs_mkmeta()
 *
 * @devname - primary device for a tagfs file system
 */
int
tagfs_mkmeta(const char *devname)
{
	struct stat st = {0};
	int rc, sbfd, logfd;
	char *mpt = NULL;
	char dirpath[PATH_MAX];
	char sb_file[PATH_MAX];
	char log_file[PATH_MAX];
	struct tagfs_superblock *sb;
	struct tagfs_log *logp;
	struct tagfs_simple_extent ext;

	dirpath[0] = 0;

	/* Get mount point path */
	mpt = tagfs_get_mpt_by_dev(devname);
	if (!mpt) {
		fprintf(stderr, "%s: unable to resolve mount pt from dev %s\n", __func__, devname);
		return -1;
	}
	printf("mpt: %s\n", mpt);
	strncat(dirpath, mpt,     PATH_MAX - 1);
	strncat(dirpath, "/",     PATH_MAX - 1);
	strncat(dirpath, ".meta", PATH_MAX - 1);
	free(mpt);
	mpt = NULL;

	/* Create the meta directory */
	if (stat(dirpath, &st) == -1) {
		rc = mkdir(dirpath, 0700);
		if (rc)
			fprintf(stderr, "%s: error creating directory %s\n",
				__func__, dirpath);
	}

	/* Create the superblock file */
	strncpy(sb_file, dirpath, PATH_MAX - 1);
	strncpy(log_file, dirpath, PATH_MAX - 1);

	strncat(sb_file, "/.superblock", PATH_MAX - 1);
	strncat(log_file, "/.log", PATH_MAX - 1);

	/* Check if superblock file already exists, and cleanup of bad */
	rc = stat(sb_file, &st);
	if (rc == 0) {
		if ((st.st_mode & S_IFMT) == S_IFREG) {
			/* Superblock file exists */
			if (st.st_size != TAGFS_SUPERBLOCK_SIZE) {
				fprintf(stderr, "%s: unlinking bad superblock file\n",
					__func__);
				unlink(sb_file);
			}
		} else {
			fprintf(stderr,
				"%s: non-regular file found where superblock expected\n",
				__func__);
			return -EINVAL;
		}
	}

	rc = tagfs_mmap_superblock_and_log_raw(devname, &sb, &logp, 1);
	if (rc) {
		fprintf(stderr, "%s: superblock/log accessfailed\n", __func__);
		return -1;
	}

	if (tagfs_check_super(sb)) {
		fprintf(stderr, "%s: no valid superblock on device %s\n", __func__, devname);
		return -1;
	}

	/* Create and allocate Superblock file */
	sbfd = open(sb_file, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
	if (sbfd < 0) {
		fprintf(stderr, "%s: failed to create file %s\n", __func__, sb_file);
		return -1;
	}

	ext.tagfs_extent_offset = 0;
	ext.tagfs_extent_len    = TAGFS_SUPERBLOCK_SIZE;
	rc = tagfs_file_map_create(sb_file, sbfd, TAGFS_SUPERBLOCK_SIZE, 1, &ext,
				   TAGFS_SUPERBLOCK);
	if (rc)
		return -1;

	/* Check if log file already exists, and cleanup of bad */
	rc = stat(log_file, &st);
	if (rc == 0) {
		if ((st.st_mode & S_IFMT) == S_IFREG) {
			/* Log file exists; is it the right size? */
			if (st.st_size != sb->ts_log_len) {
				fprintf(stderr, "%s: unlinking bad log file\n", __func__);
				unlink(log_file);
			}
		} else {
			fprintf(stderr,
				"%s: non-regular file found where superblock expected\n",
				__func__);
			return -EINVAL;
		}
	}

	/* Create and allocate log file */
	logfd = open(log_file, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
	if (logfd < 0) {
		fprintf(stderr, "%s: failed to create file %s\n", __func__, log_file);
		return -1;
	}

	ext.tagfs_extent_offset = sb->ts_log_offset;
	ext.tagfs_extent_len    = sb->ts_log_len;
	rc = tagfs_file_map_create(log_file, logfd, sb->ts_log_len, 1, &ext, TAGFS_LOG);
	if (rc)
		return -1;

	close(sbfd);
	close(logfd);
	return 0;
}

/**
 * mmap_whole_file()
 *
 * @fname
 * @read_only - mmap will be read-only if true
 * @size      - size will be stored if this pointer is non-NULL
 */
void *
mmap_whole_file(
	const char *fname,
	int         read_only,
	size_t     *sizep)
{
	struct stat st;
	void *addr;
	int rc, fd;
	int openmode = (read_only) ? O_RDONLY : O_RDWR;
	int mapmode  = (read_only) ? PROT_READ : PROT_READ | PROT_WRITE;

	rc = stat(fname, &st);
	if (rc < 0) {
		fprintf(stderr, "%s: failed to stat file %s (%s)\n",
			__func__, fname, strerror(errno));
		return NULL;
	}
	if ((st.st_mode & S_IFMT) != S_IFREG) {
		fprintf(stderr, "%s: error %s is not a regular file\n", __func__, fname);
		return NULL;
	}
	if (sizep)
		*sizep = st.st_size;

	fd = open(fname, openmode, 0);
	if (fd < 0) {
		fprintf(stderr, "open %s failed; rc %d errno %d\n", fname, rc, errno);
		rc = -1;
		return NULL;
	}

	addr = mmap(0, st.st_size, mapmode, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "Failed to mmap file %s\n", fname);
		rc = -1;
		close(fd);
		return NULL;
	}
	return addr;
}

struct tagfs_superblock *
mmap_superblock_file_read_only(const char *mpt)
{
	char sb_path[PATH_MAX];

	memset(sb_path, 0, PATH_MAX);

	strncat(sb_path, mpt,     PATH_MAX - 1);
	strncat(sb_path, "/", PATH_MAX - 1);
	strncat(sb_path, SB_FILE_RELPATH, PATH_MAX - 1);

	return mmap_whole_file(sb_path, 1 /* superblock file always read-only */, NULL);
}

#if 0
static struct tagfs_log *
__mmap_log_file(const char *mpt,
		int read_only)
{
	char log_path[PATH_MAX];

	memset(log_path, 0, PATH_MAX);

	strncat(log_path, mpt,     PATH_MAX - 1);
	strncat(log_path, "/", PATH_MAX - 1);
	strncat(log_path, LOG_FILE_RELPATH, PATH_MAX - 1);

	return mmap_whole_file(log_path, read_only, NULL);
}

static struct tagfs_log *
mmap_log_file_read_only(const char *mpt)
{
	return __mmap_log_file(mpt, 1);
}

static struct tagfs_log *
mmap_log_file_writable(const char *mpt)
{
	return __mmap_log_file(mpt, 0);
}
#endif

/******/

static inline int
tagfs_log_full(const struct tagfs_log *logp)
{
	return (logp->tagfs_log_next_index > logp->tagfs_log_last_index);
}

static inline int
tagfs_log_entry_fc_path_is_relative(const struct tagfs_file_creation *fc)
{
	return ((strlen((char *)fc->tagfs_relpath) >= 1)
		&& (fc->tagfs_relpath[0] != '/'));
}

static inline int
tagfs_log_entry_md_path_is_relative(const struct tagfs_mkdir *md)
{
	return ((strlen((char *)md->tagfs_relpath) >= 1)
		&& (md->tagfs_relpath[0] != '/'));
}

int
tagfs_logplay(
	const struct tagfs_log *logp,
	const char             *mpt,
	int                     dry_run)
{
	int nlog = 0;
	int i, j;
	int rc;


	if (tagfs_log_full(logp)) {
		fprintf(stderr, "%s: log is empty (mpt=%s)\n",
			__func__, mpt);
		return -1;
	}

	printf("%s: log contains %lld entries\n", __func__, logp->tagfs_log_next_index);
	for (i = 0; i < logp->tagfs_log_next_index; i++) {
		struct tagfs_log_entry le = logp->entries[i];

		nlog++;
		switch (le.tagfs_log_entry_type) {
		case TAGFS_LOG_FILE: {
			const struct tagfs_file_creation *fc = &le.tagfs_fc;
			struct tagfs_simple_extent *el;
			char fullpath[PATH_MAX];
			char rpath[PATH_MAX];
			struct stat st;
			int skip_file = 0;
			int fd;

			printf("%s: %d file=%s size=%lld\n", __func__, i,
			       fc->tagfs_relpath, fc->tagfs_fc_size);

			if (!tagfs_log_entry_fc_path_is_relative(fc)) {
				fprintf(stderr,
					"%s: ignoring log entry; path is not relative\n",
					__func__);
				skip_file++;
			}

			/* The only file that should have an extent with offset 0
			 * is the superblock, which is not in the log. Check for files with
			 * null offset...
			 */
			for (j = 0; j < fc->tagfs_nextents; j++) {
				const struct tagfs_simple_extent *se = &fc->tagfs_ext_list[j].se;

				if (se->tagfs_extent_offset == 0) {
					fprintf(stderr,
						"%s: ERROR file %s has extent with 0 offset\n",
						__func__, fc->tagfs_relpath);
					skip_file++;
				}
			}

			if (skip_file)
				continue;

			/* tagfs_mkdirs(mpt, fc->tagfs_relpath); */

			snprintf(fullpath, PATH_MAX - 1, "%s/%s", mpt, fc->tagfs_relpath);
			realpath(fullpath, rpath);
			if (dry_run)
				continue;

			rc = stat(rpath, &st);
			if (!rc) {
				fprintf(stderr, "%s: File (%s) already exists\n",
					__func__, rpath);
				continue;
			}
			printf("%s: creating file %s mode %o\n",
			       __func__, fc->tagfs_relpath, fc->fc_mode);
			fd = tagfs_file_create(rpath, fc->fc_mode,
					       fc->fc_uid, fc->fc_gid);
			if (fd < 0) {
				fprintf(stderr,
					"%s: unable to create destfile (%s)\n",
					__func__, fc->tagfs_relpath);

				unlink(rpath);
				continue;
			}

			/* Build extent list of tagfs_simple_extent; the log entry has a
			 * different kind of extent list...
			 */
			el = calloc(fc->tagfs_nextents, sizeof(*el));
			for (j = 0; j < fc->tagfs_nextents; j++) {
				const struct tagfs_log_extent *tle = &fc->tagfs_ext_list[j];

				el[j].tagfs_extent_offset = tle[j].se.tagfs_extent_offset;
				el[j].tagfs_extent_len    = tle[j].se.tagfs_extent_len;
			}
			tagfs_file_map_create(rpath, fd, fc->tagfs_fc_size,
					      fc->tagfs_nextents, el, TAGFS_REG);
			close(fd);
			free(el);
			break;
		}
		case TAGFS_LOG_MKDIR: {
			const struct tagfs_mkdir *md = &le.tagfs_md;
			char fullpath[PATH_MAX];
			char rpath[PATH_MAX];
			int skip_dir = 0;
			struct stat st;

			printf("%s: %d mkdir=%s\n", __func__, i, md->tagfs_relpath);

			if (!tagfs_log_entry_md_path_is_relative(md)) {
				fprintf(stderr,
					"%s: ignoring log mkdir entry; path is not relative\n",
					__func__);
				skip_dir++;
			}

			if (skip_dir)
				continue;

			snprintf(fullpath, PATH_MAX - 1, "%s/%s", mpt, md->tagfs_relpath);
			realpath(fullpath, rpath);
			if (dry_run)
				continue;

			rc = stat(rpath, &st);
			if (!rc) {
				switch (st.st_mode & S_IFMT) {
				case S_IFDIR:
					fprintf(stderr, "%s: directory (%s) already exists\n",
						__func__, rpath);
					break;

				case S_IFREG:
					fprintf(stderr,
						"%s: file (%s) exists where dir should be\n",
						__func__, rpath);
					break;

				default:
					fprintf(stderr,
						"%s: something (%s) exists where dir should be\n",
						__func__, rpath);
					break;
				}
				continue;
			}

			printf("%s: creating directory %s\n", __func__, md->tagfs_relpath);
			rc = tagfs_dir_create(mpt, (char *)md->tagfs_relpath, md->fc_mode,
					      md->fc_uid, md->fc_gid);
			if (rc) {
				fprintf(stderr,
					"%s: error: unable to create directory (%s)\n",
					__func__, md->tagfs_relpath);
			}

			break;
		}
		case TAGFS_LOG_ACCESS:
		default:
			printf("%s: invalid log entry\n", __func__);
			break;
		}
	}
	printf("%s: processed %d log entries\n", __func__, nlog);
	return 0;
}

/**
 * tagfs_append_log()
 *
 * @logp - pointer to struct tagfs_log in memory media
 * @e    - pointer to log entry in memory
 *
 * NOTE: this function is not re-entrant. Must hold a lock or mutex when calling this
 * function if there is any chance of re-entrancy.
 */
int
tagfs_append_log(struct tagfs_log       *logp,
		 struct tagfs_log_entry *e)
{
	/* XXX This function is not re-entrant */
	if (!logp || !e)
		return -EINVAL;

	if (logp->tagfs_log_magic != TAGFS_LOG_MAGIC) {
		fprintf(stderr, "Log has invalid magic number\n");
		return -EINVAL;
	}

	if (logp->tagfs_log_next_index >= logp->tagfs_log_last_index) {
		fprintf(stderr, "log is full\n");
		return -E2BIG;
	}

	e->tagfs_log_entry_seqnum = logp->tagfs_log_next_seqnum;
	memcpy(&logp->entries[logp->tagfs_log_next_index], e, sizeof(*e));

	logp->tagfs_log_next_seqnum++;
	logp->tagfs_log_next_index++;
	return 0;
}

#if 0
/* TODO */
int
tagfs_validate_fullpath(const char *fullpath)
{
}
#endif

/**
 * tagfs_relpath_from_fullpath()
 *
 * Returns a pointer to the relpath. This pointer points within the fullpath string
 *
 * @mpt - mount point string (rationalized by realpath())
 * @fullpath
 */
char *
tagfs_relpath_from_fullpath(
	const char *mpt,
	char       *fullpath)
{
	char *relpath;

	assert(mpt);
	assert(fullpath);
	assert(strlen(fullpath) > strlen(mpt));

	if (strstr(fullpath, mpt) != fullpath) {
		/* mpt path should be a substring starting at the beginning of fullpath*/
		fprintf(stderr, "%s: failed to get relpath from mpt=%s fullpath=%s\n",
			__func__, mpt, fullpath);
		return NULL;
	}

	/* This assumes relpath() removed any duplicate '/' characters: */
	relpath = &fullpath[strlen(mpt) + 1];
	printf("%s: mpt=%s, fullpath=%s relpath=%s\n", __func__, mpt, fullpath, relpath);
	return relpath;
}

/**
 * tagfs_log_file_creation()
 */
/* TODO: UI would be cleaner if this accepted a fullpath and the mpt, and did the
 * conversion itself. Then pretty much all calls would use the same stuff.
 */
int
tagfs_log_file_creation(
	struct tagfs_log           *logp,
	u64                         nextents,
	struct tagfs_simple_extent *ext_list,
	const char                 *relpath,
	mode_t                      mode,
	uid_t                       uid,
	gid_t                       gid,
	size_t                      size)
{
	struct tagfs_log_entry le = {0};
	struct tagfs_file_creation *fc = &le.tagfs_fc;
	int i;

	assert(logp);
	assert(ext_list);
	assert(nextents >= 1);
	assert(relpath[0] != '/');

	if (tagfs_log_full(logp)) {
		fprintf(stderr, "%s: log full\n", __func__);
		return -ENOMEM;
	}

	//le.tagfs_log_entry_seqnum = logp->tagfs_log_next_seqnum++; /* XXX mem ordering */
	le.tagfs_log_entry_type = TAGFS_LOG_FILE;

	fc->tagfs_fc_size = size;
	fc->tagfs_nextents = nextents;
	fc->tagfs_fc_flags = TAGFS_FC_ALL_HOSTS_RW; /* XXX hard coded access for now */

	strncpy((char *)fc->tagfs_relpath, relpath, TAGFS_MAX_PATHLEN - 1);

	fc->fc_mode = mode;
	fc->fc_uid  = uid;
	fc->fc_gid  = gid;

	/* Copy extents into log entry */
	for (i = 0; i < nextents; i++) {
		struct tagfs_log_extent *ext = &fc->tagfs_ext_list[i];

		ext->tagfs_extent_type = TAGFS_EXT_SIMPLE;
		ext->se.tagfs_extent_offset = ext_list[i].tagfs_extent_offset;
		ext->se.tagfs_extent_len    = ext_list[i].tagfs_extent_len;
	}

	return tagfs_append_log(logp, &le);
}

/**
 * tagfs_log_dir_creation()
 */
/* TODO: UI would be cleaner if this accepted a fullpath and the mpt, and did the
 * conversion itself. Then pretty much all calls would use the same stuff.
 */
int
tagfs_log_dir_creation(
	struct tagfs_log           *logp,
	const char                 *relpath,
	mode_t                      mode,
	uid_t                       uid,
	gid_t                       gid)
{
	struct tagfs_log_entry le = {0};
	struct tagfs_mkdir *md = &le.tagfs_md;

	assert(logp);
	assert(relpath[0] != '/');

	if (tagfs_log_full(logp)) {
		fprintf(stderr, "%s: log full\n", __func__);
		return -ENOMEM;
	}

	le.tagfs_log_entry_type = TAGFS_LOG_MKDIR;

	strncpy((char *)md->tagfs_relpath, relpath, TAGFS_MAX_PATHLEN - 1);

	md->fc_mode = mode;
	md->fc_uid  = uid;
	md->fc_gid  = gid;

	return tagfs_append_log(logp, &le);
}

/**
 * __open_relpath()
 *
 * @path       - any path within a tagfs file system (from mount pt on down)
 * @relpath    - the relative path to open (relative to the mount point)
 * @read_only
 * @size_out   - File size will be returned if this pointer is non-NULL
 * @mpt_out    - Mount point will be returned if this pointer is non-NULL
 *               (the string space is assumed to be of size PATH_MAX)
 */
int
__open_relpath(
	const char *path,
	const char *relpath,
	int         read_only,
	size_t     *size_out,
	char       *mpt_out)
{
	int openmode = (read_only) ? O_RDONLY : O_RDWR;
	char *rpath = realpath(path, NULL);
	struct stat st;
	int rc, fd;

	if (!rpath)
		return 0;

	while (1) {
		char log_path[PATH_MAX] = {0};

		rc = stat(rpath, &st);
		if (rc < 0)
			goto next;
		if ((st.st_mode & S_IFMT) == S_IFDIR) {
			/* It's a dir; does it have <relpath> under it? */
			snprintf(log_path, PATH_MAX - 1, "%s/%s", rpath, relpath);
			rc = stat(log_path, &st);
			if ((rc == 0) && ((st.st_mode & S_IFMT) == S_IFREG)) {
				/* yes */
				if (size_out)
					*size_out = st.st_size;
				if (mpt_out)
					strncpy(mpt_out, rpath, PATH_MAX - 1);
				fd = open(log_path, openmode, 0);
				free(rpath);
				return fd;
			}
			/* no */
		}

next:
		/* Pop up one level; exit if we're at the top */
		rpath = dirname(rpath);
		if (strcmp(rpath, "/") == 0)
			break;
	}
	free(rpath);
	return -1;
}


/**
 * open_log_file(path)
 *
 * @path - any path within a tagfs file system (from mount pt on down)
 *
 * This will traverse upward from path, looking for a directory containing a .meta/.log
 * If found, it opens the log.
 */
static int
__open_log_file(
	const char *path,
	int         read_only,
	size_t     *sizep,
	char       *mpt_out)
{
	return __open_relpath(path, LOG_FILE_RELPATH, read_only, sizep, mpt_out);
}

int
open_log_file_read_only(
	const char *path,
	size_t     *sizep,
	char       *mpt_out)
{
	return __open_log_file(path, 1, sizep, mpt_out);
}

int
open_log_file_writable(
	const char *path,
	size_t     *sizep,
	char       *mpt_out)
{
	return __open_log_file(path, 0, sizep, mpt_out);
}

static int
__open_superblock_file(
	const char *path,
	int         read_only,
	size_t     *sizep,
	char       *mpt_out)
{
	return __open_relpath(path, SB_FILE_RELPATH, read_only, sizep, mpt_out);
}

int
open_superblock_file_read_only(
	const char *path,
	size_t     *sizep,
	char       *mpt_out)
{
	return __open_superblock_file(path, 1, sizep, mpt_out);
}

int
open_superblock_file_writable(
	const char *path,
	size_t     *sizep,
	char       *mpt_out)
{
	return __open_superblock_file(path, 0, sizep, mpt_out);
}

struct tagfs_superblock *
tagfs_map_superblock_by_path(
	const char *path,
	int         read_only)
{
	struct tagfs_superblock *sb;
	int prot = (read_only) ? PROT_READ : PROT_READ | PROT_WRITE;
	size_t sb_size;
	void *addr;
	int fd;

	fd = __open_superblock_file(path, 1 /* read only */,
				    &sb_size, NULL);
	if (fd < 0) {
		fprintf(stderr, "%s: failed to open log file for filesystem %s\n",
			__func__, path);
		return NULL;
	}
	addr = mmap(0, sb_size, prot, MAP_SHARED, fd, 0);
	close(fd);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "%s: Failed to mmap log file %s", __func__, path);
		return NULL;
	}
	sb = (struct tagfs_superblock *)addr;
	return sb;
}

struct tagfs_log *
tagfs_map_log_by_path(
	const char *path,
	int         read_only)
{
	struct tagfs_log *logp;
	int prot = (read_only) ? PROT_READ : PROT_READ | PROT_WRITE;
	size_t log_size;
	void *addr;
	int fd;

	fd = __open_log_file(path, 1 /* read only */, &log_size, NULL);
	if (fd < 0) {
		fprintf(stderr, "%s: failed to open log file for filesystem %s\n",
			__func__, path);
		return NULL;
	}
	addr = mmap(0, log_size, prot, MAP_SHARED, fd, 0);
	close(fd);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "%s: Failed to mmap log file %s", __func__, path);
		return NULL;
	}
	logp = (struct tagfs_log *)addr;
	return logp;
}

int
tagfs_fsck(
	const char *path,
	int use_mmap,
	int verbose)
{
	struct tagfs_superblock *sb;
	struct tagfs_log *logp;
	struct stat st;
	int malloc_sb_log = 0;
	size_t size;
	int rc;

	assert(path);
	assert(strlen(path) > 1);

	rc = stat(path, &st);
	if (rc < 0) {
		fprintf(stderr, "%s: failed to stat path %s (%s)\n",
			__func__, path, strerror(errno));
		return -errno;
	}

	switch (st.st_mode & S_IFMT) {
	case S_IFBLK:
	case S_IFCHR: {
		char *mpt;
		/* Check if there is a mounted tagfs file system on this device;
		 * fail if so - if mounted, have to fsck by mount pt rather than device
		 */
		mpt = tagfs_get_mpt_by_dev(path);
		if (mpt) {
			fprintf(stderr, "%s: error - cannot fsck by device (%s) when mounted\n",
				__func__, path);
			free(mpt);
			return -EBUSY;
		}
		/* If it's a device, we'll try to mmap superblock and log from the device */
		rc = tagfs_get_device_size(path, &size, NULL);
		if (rc < 0)
			return -1;

		rc = tagfs_mmap_superblock_and_log_raw(path, &sb, &logp, 1 /* read-only */);
		break;
	}
	case S_IFREG:
	case S_IFDIR: {
		if (use_mmap) {
			/* If it's a file or directory, we'll try to mmap the sb and
			 * log from their files
			 *
			 * Note that this tends to fail
			 */
			sb =   tagfs_map_superblock_by_path(path, 1 /* read only */);
			if (!sb) {
				fprintf(stderr, "%s: failed to map superblock from file %s\n",
					__func__, path);
				return -1;
			}

			logp = tagfs_map_log_by_path(path, 1 /* read only */);
			if (!logp) {
				fprintf(stderr, "%s: failed to map log from file %s\n",
					__func__, path);
				return -1;
			}
			break;
		} else {
			int sfd;
			int lfd;
			char *buf;
			int resid;
			int total = 0;

			malloc_sb_log = 1;

			sfd = open_superblock_file_read_only(path, NULL, NULL);
			if (sfd < 0) {
				fprintf(stderr, "%s: failed to open superblock file\n", __func__);
				return -1;
			}
			/* Over-allocate so we can read 2MiB multiple */
			sb = calloc(1, TAGFS_LOG_OFFSET);
			assert(sb);

			/* Read a copy of the superblock */
			rc = read(sfd, sb, TAGFS_LOG_OFFSET); /* 2MiB multiple */
			if (rc < 0) {
				free(sb);
				close(sfd);
				fprintf(stderr, "%s: error %d reading superblock file\n",
					__func__, errno);
				return -errno;
			} else if (rc < sizeof(*sb)) {
				free(sb);
				close(sfd);
				fprintf(stderr, "%s: error: short read of superblock %d/%ld\n",
					__func__, rc, sizeof(*sb));
				return -1;
			}
			close(sfd);

			lfd = open_log_file_read_only(path, NULL, NULL);
			if (lfd < 0) {
				free(sb);
				close(sfd);
				fprintf(stderr, "%s: failed to open log file\n", __func__);
				return -1;
			}

			logp = calloc(1, sb->ts_log_len);
			assert(logp);

			/* Read a copy of the log */
			resid = sb->ts_log_len;
			buf = (char *)logp;
			do {
				rc = read(lfd, &buf[total], resid);
				if (rc < 0) {
					free(sb);
					free(logp);
					close(lfd);
					fprintf(stderr, "%s: error %d reading log file\n",
						__func__, errno);
					return -errno;
				}
				printf("%s: read %d bytes of log\n", __func__, rc);
				resid -= rc;
				total += rc;
			} while (resid > 0);

			close(lfd);
		}
	}
		break;
	default:
		fprintf(stderr, "invalid path or dax device: %s\n", path);
		return -EINVAL;
	}

	if (tagfs_check_super(sb)) {
		fprintf(stderr, "%s: no tagfs superblock on device %s\n", __func__, path);
		return -1;
	}
	rc = tagfs_fsck_scan(sb, logp, verbose);
	if (malloc_sb_log) {
		free(sb);
		free(logp);
	}
	return rc;
}

/**
 * tagfs_validate_superblock_by_path()
 *
 * @path
 *
 * Validate the superblock and return the dax device size, or -1 if sb or size invalid
 */
static ssize_t
tagfs_validate_superblock_by_path(const char *path)
{
	int sfd;
	void *addr;
	size_t sb_size;
	ssize_t daxdevsize;
	struct tagfs_superblock *sb;

	/* XXX should be read only, but that doesn't work */
	sfd = open_superblock_file_writable(path, &sb_size, NULL);
	if (sfd < 0)
		return sfd;

	/* XXX should be read only, but that doesn't work */
	addr = mmap(0, sb_size, PROT_READ, MAP_SHARED, sfd, 0);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "%s: Failed to mmap superblock file\n", __func__);
		close(sfd);
		return -1;
	}
	sb = (struct tagfs_superblock *)addr;

	if (tagfs_check_super(sb)) {
		fprintf(stderr, "%s: invalid superblock\n", __func__);
		return -1;
	}
	daxdevsize = sb->ts_devlist[0].dd_size;
	munmap(sb, TAGFS_SUPERBLOCK_SIZE);
	close(sfd);
	return daxdevsize;
}

/**
 * put sb_log_into_bitmap()
 *
 * The two files that are not in the log are the superblock and the log. So these
 * files need to be manually added to the allocation bitmap. This function does that.
 */
static inline void
put_sb_log_into_bitmap(u8 *bitmap)
{
	int i;

	/* Mark superblock and log as allocated */
	mu_bitmap_set(bitmap, 0);

	for (i = 1; i < ((TAGFS_LOG_OFFSET + TAGFS_LOG_LEN) / TAGFS_ALLOC_UNIT); i++)
		mu_bitmap_set(bitmap, i);
}

/**
 * tagfs_build_bitmap()
 *
 * XXX: this is only aware of the first daxdev in the superblock's list
 * @logp
 * @size_in          - total size of allocation space in bytes
 * @bitmap_size_out  - output: size of the bitmap
 * @alloc_errors_out - output: number of times a file referenced a bit that was already set
 * @size_total_out   - output: if ptr non-null, this is the sum of the file sizes
 * @alloc_total_out  - output: if ptr non-null, this is the sum of all allocation sizes
 *                    (excluding double-allocations; space amplification is
 *                     @alloc_total / @size_total provided there are no double allocations,
 *                     b/c those will increase size_total but not alloc_total)
 * @verbose
 */
u8 *
tagfs_build_bitmap(const struct tagfs_log   *logp,
		   u64                       bitmap_size_in,
		   u64                      *bitmap_size_out,
		   u64                      *alloc_errors_out,
		   u64                      *size_total_out,
		   u64                      *alloc_total_out,
		   int                       verbose)
{
	int npages = (bitmap_size_in - TAGFS_SUPERBLOCK_SIZE - TAGFS_LOG_LEN) / TAGFS_ALLOC_UNIT;
	int bitmap_size = mu_bitmap_size(npages);
	u8 *bitmap = calloc(1, bitmap_size);
	u64 errors = 0;
	size_t alloc_sum = 0;
	size_t size_sum  = 0;
	int i, j;
	int rc;

	if (!bitmap)
		return NULL;

	put_sb_log_into_bitmap(bitmap);

	/* This loop is over all log entries */
	for (i = 0; i < logp->tagfs_log_next_index; i++) {
		const struct tagfs_log_entry *le = &logp->entries[i];

		/* TODO: validate log sequence number */

		switch (le->tagfs_log_entry_type) {
		case TAGFS_LOG_FILE: {
			const struct tagfs_file_creation *fc = &le->tagfs_fc;
			const struct tagfs_log_extent *ext = fc->tagfs_ext_list;

			size_sum += fc->tagfs_fc_size;
			if (verbose)
				printf("%s: file=%s size=%lld\n", __func__,
				       fc->tagfs_relpath, fc->tagfs_fc_size);

			/* For each extent in this log entry, mark the bitmap as allocated */
			for (j = 0; j < fc->tagfs_nextents; j++) {
				s64 page_num;
				s64 np;
				s64 k;

				assert(!(ext[j].se.tagfs_extent_offset % TAGFS_ALLOC_UNIT));
				page_num = ext[j].se.tagfs_extent_offset / TAGFS_ALLOC_UNIT;
				np = (ext[j].se.tagfs_extent_len + TAGFS_ALLOC_UNIT - 1)
					/ TAGFS_ALLOC_UNIT;

				for (k = page_num; k < (page_num + np); k++) {
					rc = mu_bitmap_test_and_set(bitmap, k);
					if (rc == 0) {
						errors++; /* bit was already set */
					} else {
						/* Don't count double allocations */
						alloc_sum += TAGFS_ALLOC_UNIT;
					}
				}
			}
			break;
		}
		case TAGFS_LOG_MKDIR:
			/* Ignore directory log entries - no space is used */

			break;
		case TAGFS_LOG_ACCESS:
		default:
			printf("%s: invalid log entry\n", __func__);
			break;
		}
	}
	if (bitmap_size_out)
		*bitmap_size_out = bitmap_size;
	if (alloc_errors_out)
		*alloc_errors_out = errors;
	if (size_total_out)
		*size_total_out = size_sum;
	if (alloc_total_out)
		*alloc_total_out = alloc_sum;
	return bitmap;
}

/**
 * bitmap_alloc_contigous()
 *
 * @bitmap
 * @nbits - number of bits in the bitmap
 * @size - size to allocate in bytes (must convert to bits)
 *
 * Return value: the offset in bytes
 */
u64
bitmap_alloc_contiguous(u8 *bitmap,
			u64 nbits,
			u64 size)
{
	int i, j;
	int alloc_bits = (size + TAGFS_ALLOC_UNIT - 1) /  TAGFS_ALLOC_UNIT;
	int bitmap_remainder;

	for (i = 0; i < nbits; i++) {
		/* Skip bits that are set... */
		if (mu_bitmap_test(bitmap, i))
			continue;

		bitmap_remainder = nbits - i;
		if (alloc_bits > bitmap_remainder) /* Remaining space is not enough */
			return 0;

		for (j = i; j < (i+alloc_bits); j++) {
			if (mse_bitmap_test32(bitmap, j))
				goto next;
		}
		/* If we get here, we didn't hit the "continue" which means that bits
		 * i-(i+alloc_bits) are available
		 */
		for (j = i; j < (i+alloc_bits); j++)
			mse_bitmap_set32(bitmap, j);

		return i * TAGFS_ALLOC_UNIT;
next:
	}
	fprintf(stderr, "%s: alloc failed\n", __func__);
	return 0;
}

/**
 * tagfs_alloc_bypath()
 *
 * @path    - a path within the tagfs file system
 * @size    - size in bytes
 *
 * XXX currently only contiuous allocations are supported
 */
s64
tagfs_alloc_bypath(
	struct tagfs_log *logp,
	const char       *path,
	u64               size)
{
	ssize_t daxdevsize;
	u8 *bitmap;
	u64 nbits;
	u64 offset;

	if (size <= 0)
		return -1;

	daxdevsize = tagfs_validate_superblock_by_path(path);
	if (daxdevsize < 0)
		return daxdevsize;

	bitmap = tagfs_build_bitmap(logp, daxdevsize, &nbits, NULL, NULL, NULL, 0);
	printf("\nbitmap before:\n");
	mu_print_bitmap(bitmap, nbits);
	offset = bitmap_alloc_contiguous(bitmap, nbits, size);
	printf("\nbitmap after:\n");
	mu_print_bitmap(bitmap, nbits);
	printf("\nAllocated offset: %lld\n", offset);
	free(bitmap);
	return offset;
}

int
__file_not_tagfs(int fd)
{
	int rc;

	rc = ioctl(fd, TAGFSIOC_NOP, 0);
	if (rc)
		return 1;

	return 0;
}

/**
 * tagfs_file_alloc()
 *
 * Alllocate space for a file, making it ready to use
 *
 * @fd
 * @path - full path of file to allocate
 * @mode -
 * @uid
 * @size - size to alloacte
 */
int
tagfs_file_alloc(
	int         fd,
	const char *path,
	mode_t      mode,
	uid_t       uid,
	gid_t       gid,
	u64         size)
{
	struct tagfs_simple_extent ext = {0};
	struct tagfs_log *logp;
	char mpt[PATH_MAX];
	size_t log_size;
	char *relpath;
	char *rpath;
	s64 offset;
	void *addr;
	int lfd;
	int rc;

	assert(fd > 0);

	rpath = realpath(path, NULL);
	/* Log file */
	lfd = open_log_file_writable(rpath, &log_size, mpt);
	if (lfd < 0) {
		/* If we can't open the log file for writing, don't allocate */
		free(rpath);
		return lfd;
	}

	addr = mmap(0, log_size, PROT_READ | PROT_WRITE, MAP_SHARED, lfd, 0);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "%s: Failed to mmap log file", __func__);
		close(lfd);
		return -1;
	}
	close(lfd);
	lfd = 0;
	logp = (struct tagfs_log *)addr;

	/* For the log, we need the path relative to the mount point.
	 * getting this before we allocate is cleaner if the path is sombhow bogus
	 */
	relpath = tagfs_relpath_from_fullpath(mpt, rpath);
	if (!relpath)
		return -EINVAL;

	/* Allocation is always contiguous initially */
	offset = tagfs_alloc_bypath(logp, rpath, size);
	if (offset < 0) {
		rc = -ENOMEM;
		goto out;
	}

	ext.tagfs_extent_len    = round_size_to_alloc_unit(size);
	ext.tagfs_extent_offset = offset;

	rc = tagfs_log_file_creation(logp, 1, &ext,
				     relpath, mode, uid, gid, size);
	if (rc)
		goto out;

	rc =  tagfs_file_map_create(path, fd, size, 1, &ext, TAGFS_REG);
out:
	if (lfd > 0)
		close(lfd);
	if (rpath)
		free(rpath);
	return rc;
}

/**
 * tagfs_file_create()
 *
 * Create a file but don't allocate dax space yet
 *
 * @path
 * @mode
 * @uid  - used if both uid and gid are non-null
 * @gid  - used if both uid and gid are non-null
 * @size
 *
 * Returns a file descriptior or -EBADF if the path is not in a tagfs file system
 *
 * TODO: append "_empty" to function name
 */
int
tagfs_file_create(const char *path,
		  mode_t      mode,
		  uid_t       uid,
		  gid_t       gid)
{
	struct stat st;
	int rc = 0;
	int fd;

	rc = stat(path, &st);
	if (rc == 0) {
		fprintf(stderr, "%s: file already exists: %s\n", __func__, path);
		return -1;
	}

	fd = open(path, O_RDWR | O_CREAT, mode); /* TODO: open as temp file,
						  * move into place after alloc
						  */
	if (fd < 0) {
		fprintf(stderr, "%s: open/creat %s failed fd %d\n",
			__func__, path, fd);
		return fd;
	}

	if (__file_not_tagfs(fd)) {
		close(fd);
		unlink(path);
		fprintf(stderr, "%s: file %s not in a tagfs mount\n",
			__func__, path);
		return -EBADF;
	}

	if (uid && gid) {
		rc = fchown(fd, uid, gid);
		if (rc)
			fprintf(stderr, "%s: fchown returned %d errno %d\n",
				__func__, rc, errno);
	}
	return fd;
}

/**
 * tagfs_mkfile()
 *
 * Create *and* allocate a file
 *
 * Returns an open file descriptor if successful.
 */
int
tagfs_mkfile(char    *filename,
	     mode_t   mode,
	     uid_t    uid,
	     gid_t    gid,
	     size_t   size)
{
	int fd, rc;
	char fullpath[PATH_MAX];

	fd = tagfs_file_create(filename, mode, uid, gid);
	if (fd < 0)
		return fd;

	/* Clean up the filename path. (Can't call realpath until the file exists) */
	if (realpath(filename, fullpath) == NULL) {
		fprintf(stderr, "%s: realpath() unable to rationalize filename %s\n",
			__func__, filename);
	}

	rc = tagfs_file_alloc(fd, fullpath, mode, uid, gid, size);
	if (rc) {
		fprintf(stderr, "%s: tagfs_file_alloc(%s, size=%ld) failed\n",
			__func__, fullpath, size);
		unlink(fullpath);
		return -1;
	}
	return fd;
}

/**
 * tagfs_dir_create()
 *
 * Create a directory
 *
 * @mpt
 * @path
 * @mode
 * @uid  - used if both uid and gid are non-null
 * @gid  - used if both uid and gid are non-null
 * @size
 *
 *
 */
int
tagfs_dir_create(
	const char *mpt,
	const char *rpath,
	mode_t      mode,
	uid_t       uid,
	gid_t       gid)
{
	int rc = 0;
	char fullpath[PATH_MAX];

	snprintf(fullpath, PATH_MAX - 1, "%s/%s", mpt, rpath);
	rc = mkdir(fullpath, mode);
	if (rc) {
		fprintf(stderr, "%s: failed to mkdir %s\n", __func__, fullpath);
		return -1;
	}

	/* Check if dir is in tagfs mount? */

	if (uid && gid) {
		rc = chown(fullpath, uid, gid);
		if (rc)
			fprintf(stderr, "%s: chown returned %d errno %d\n",
				__func__, rc, errno);
		return -1;
	}
	return 0;
}

/**
 * libtagfs:
 *
 * tagfs_cp(srcfile, destfile)
 */

int
tagfs_mkdir(
	const char *dirpath,
	mode_t      mode,
	uid_t       uid,
	gid_t       gid)
{
	int rc;

	char realparent[PATH_MAX];
	char fullpath[PATH_MAX];
	char mpt_out[PATH_MAX];
	struct tagfs_log *logp;
	char *dirdupe   = NULL;
	char *parentdir = NULL;
	char *basedupe  = NULL;
	char *newdir    = NULL;
	char *relpath   = NULL;
	size_t log_size;
	struct stat st;
	void *addr;
	int lfd;

	dirdupe  = strdup(dirpath);  /* call dirname() on this dupe */
	basedupe = strdup(dirpath); /* call basename() on this dupe */
	newdir   = basename(basedupe);

	/* full dirpath should not exist, but the parentdir path must exist and be a directory */
	parentdir = dirname(dirdupe);
	if (strcmp(parentdir, ".") == 0) {
		fprintf(stderr, "%s: bad dirpath %s\n", __func__, dirpath);
		rc = -1;
		goto err_out;
	}
	rc = stat(parentdir, &st);
	if ((st.st_mode & S_IFMT) != S_IFDIR) {
		fprintf(stderr, "%s: parent (%s) of path %s is not a directory\n",
			__func__, dirpath, parentdir);
		rc = -1;
		goto err_out;
	}

	/* parentdir exists and is a directory; rationalize the path with realpath */
	if (realpath(parentdir, realparent) == 0) {
		fprintf(stderr, "%s: failed to rationalize parentdir path (%s)\n",
			__func__, parentdir);
		rc = -1;
		goto err_out;
	}

	/* Rebuild full path of to-be-createed directory from the rationalized parent dir path */
	rc = snprintf(fullpath, PATH_MAX - 1, "%s/%s", realparent, newdir);
	if (rc < 0) {
		fprintf(stderr, "%s: fullpath overflow\n", __func__);
		goto err_out;
	}

	/*
	 * For this operation we need to open the log file, which also gets us
	 * the mount point path
	 */
	lfd  = open_log_file_writable(realparent, &log_size, mpt_out);
	addr = mmap(0, log_size, PROT_READ | PROT_WRITE, MAP_SHARED, lfd, 0);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "%s: Failed to mmap log file\n", __func__);
		rc = -1;
		goto err_out;
	}
	close(lfd);
	lfd  = 0;
	logp = (struct tagfs_log *)addr;

	printf("%s: creating directory %s\n", __func__, fullpath);

	relpath = tagfs_relpath_from_fullpath(mpt_out, fullpath);
	rc = tagfs_dir_create(mpt_out, relpath, mode, uid, gid);
	if (rc) {
		fprintf(stderr, "%s: failed to mkdir %s\n", __func__, fullpath);
		rc = -1;
		goto err_out;
	}

	/* log dir creation */
	rc = tagfs_log_dir_creation(logp, relpath, mode, uid, gid);

err_out:
	if (dirdupe)
		free(dirdupe);
	if (basedupe)
		free(basedupe);

	return rc;
}

int
tagfs_cp(char *srcfile,
	 char *destfile)
{
	struct stat srcstat;
	struct stat deststat;
	int rc, srcfd, destfd;
	char *destp;

	size_t chunksize, remainder, offset;
	ssize_t bytes;

	/**
	 * Check the destination file first, since that is constrained in several ways:
	 * * Dest must be in a tagfs file system
	 * * Dest must not exist already
	 */
	rc = stat(destfile, &deststat);
	if (!rc) {
		fprintf(stderr, "%s: error: dest destfile (%s) exists\n", __func__, destfile);
		return rc;
	}
	rc = stat(srcfile, &srcstat);
	if (rc) {
		fprintf(stderr, "%s: unable to stat srcfile (%s)\n", __func__, srcfile);
		return rc;
	}

	destfd = tagfs_file_create(destfile, srcstat.st_mode, srcstat.st_uid, srcstat.st_gid);
	if (destfd < 0) {
		if (destfd == -EBADF)
			fprintf(stderr,
				"Destination file %s is not in a tagfs file system\n",
				destfile);
		else
			fprintf(stderr, "%s: unable to create destfile (%s)\n",
				__func__, destfile);

		unlink(destfile);
		return destfd;
	}

	/*
	 * Now deal with source file
	 */
	srcfd = open(srcfile, O_RDONLY, 0);
	if (srcfd < 0) {
		fprintf(stderr, "%s: unable to open srcfile (%s)\n", __func__, srcfile);
		unlink(destfile);
		return rc;
	}

	/* TODO: consistent arg order fd, name */
	rc = tagfs_file_alloc(destfd, destfile, srcstat.st_mode, srcstat.st_uid,
			      srcstat.st_gid, srcstat.st_size);
	if (rc) {
		fprintf(stderr, "%s: failed to allocate size %ld for file %s\n",
			__func__, srcstat.st_size, destfile);
		unlink(destfile);
		return -1;
	}

	destp = mmap(0, srcstat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, destfd, 0);
	if (destp == MAP_FAILED) {
		fprintf(stderr, "%s: dest mmap failed\n", __func__);
		unlink(destfile);
		return -1; /* XXX */
	}

	/* Copy the data */
	chunksize = 0x100000; /* 1 MiB copy chunks */
	offset = 0;
	remainder = srcstat.st_size;
	for ( ; remainder > 0; ) {
		size_t cur_chunksize = MIN(chunksize, remainder);

		/* read into mmapped destination */
		bytes = read(srcfd, &destp[offset], cur_chunksize);
		if (bytes < 0) {
			fprintf(stderr, "%s: copy fail: "
				"ofs %ld cur_chunksize %ld remainder %ld\n",
				__func__, offset, cur_chunksize, remainder);
			printf("rc=%ld errno=%d\n", bytes, errno);
			return -1;
		}
		if (bytes < cur_chunksize) {
			fprintf(stderr, "%s: short read: "
				"ofs %ld cur_chunksize %ld remainder %ld\n",
				__func__, offset, cur_chunksize, remainder);
		}

		/* Update offset and remainder */
		offset += bytes;
		remainder -= bytes;
	}

	close(srcfd);
	close(destfd);
	return 0;
}
