/*
 * Copyright (C) 2000 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 * Licensed under the GPL
 */

#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include "hostfs.h"
#include <utime.h>

#ifndef __APPLE__
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#endif
#include <sys/mount.h>

/* TODO ish errno */

#ifdef __APPLE__
#define st_ts(x) st_##x##timespec
#endif
#ifdef __linux__
#define st_ts(x) st_##x##tim
#endif

static void stat_to_hostfs(const struct stat *buf, struct hostfs_stat *p)
{
	p->ino = buf->st_ino;
	p->mode = buf->st_mode;
	p->nlink = buf->st_nlink;
	p->uid = buf->st_uid;
	p->gid = buf->st_gid;
	p->size = buf->st_size;
	p->atime.tv_sec = buf->st_ts(a).tv_sec;
	p->atime.tv_nsec = buf->st_ts(a).tv_nsec;
	p->ctime.tv_sec = buf->st_ts(c).tv_sec;
	p->ctime.tv_nsec = buf->st_ts(c).tv_nsec;
	p->mtime.tv_sec = buf->st_ts(m).tv_sec;
	p->mtime.tv_nsec = buf->st_ts(m).tv_nsec;
	p->blksize = buf->st_blksize;
	p->blocks = buf->st_blocks;
	p->maj = major(buf->st_rdev);
	p->min = minor(buf->st_rdev);
}

int stat_file(const char *path, struct hostfs_stat *p, int fd)
{
	struct stat buf;

	if (fd >= 0) {
		if (fstat(fd, &buf) < 0)
			return -errno;
	} else if (lstat(path, &buf) < 0) {
		return -errno;
	}
	stat_to_hostfs(&buf, p);
	return 0;
}

int access_file(char *path, int r, int w, int x)
{
	int mode = 0;

	if (r)
		mode = R_OK;
	if (w)
		mode |= W_OK;
	if (x)
		mode |= X_OK;
	if (access(path, mode) != 0)
		return -errno;
	else return 0;
}

int open_file(char *path, int r, int w, int append)
{
	int mode = 0, fd;

	if (r && !w)
		mode = O_RDONLY;
	else if (!r && w)
		mode = O_WRONLY;
	else if (r && w)
		mode = O_RDWR;
	else panic("Impossible mode in open_file");

	if (append)
		mode |= O_APPEND;
	fd = open(path, mode);
	if (fd < 0)
		return -errno;
	else return fd;
}

void *open_dir(char *path, int *err_out)
{
	DIR *dir;

	dir = opendir(path);
	*err_out = errno;

	return dir;
}

void seek_dir(void *stream, unsigned long long pos)
{
	DIR *dir = stream;

	seekdir(dir, pos);
}

char *read_dir(void *stream, unsigned long long *pos_out,
	       unsigned long long *ino_out, int *len_out,
	       unsigned int *type_out)
{
	DIR *dir = stream;
	struct dirent *ent;

	ent = readdir(dir);
	if (ent == NULL)
		return NULL;
	*len_out = strlen(ent->d_name);
	*ino_out = ent->d_ino;
	*type_out = ent->d_type;
	*pos_out = telldir(dir);
	return ent->d_name;
}

int read_file(int fd, unsigned long long *offset, char *buf, int len)
{
	int n;

	n = pread(fd, buf, len, *offset);
	if (n < 0)
		return -errno;
	*offset += n;
	return n;
}

int write_file(int fd, unsigned long long *offset, const char *buf, int len)
{
	int n;

	n = pwrite(fd, buf, len, *offset);
	if (n < 0)
		return -errno;
	*offset += n;
	return n;
}

int lseek_file(int fd, long long offset, int whence)
{
	int ret;

	ret = lseek(fd, offset, whence);
	if (ret < 0)
		return -errno;
	return 0;
}

int fsync_file(int fd, int datasync)
{
	int ret;
	/* TODO linus doesn't like this kind of ifdef */
#ifdef __linux__
	if (datasync)
		ret = fdatasync(fd);
	else
#endif
		ret = fsync(fd);

	if (ret < 0)
		return -errno;
	return 0;
}

int replace_file(int oldfd, int fd)
{
	return dup2(oldfd, fd);
}

void close_file(void *stream)
{
	close(*((int *) stream));
}

void close_dir(void *stream)
{
	closedir(stream);
}

int file_create(char *name, int mode)
{
	int fd;

	fd = open(name, O_CREAT | O_RDWR, mode);
	if (fd < 0)
		return -errno;
	return fd;
}

int set_attr(const char *file, struct hostfs_iattr *attrs, int fd)
{
	struct hostfs_stat st;
	struct timeval times[2];
	int err, ma;

	if (attrs->ia_valid & HOSTFS_ATTR_MODE) {
		if (fd >= 0) {
			if (fchmod(fd, attrs->ia_mode) != 0)
				return -errno;
		} else if (chmod(file, attrs->ia_mode) != 0) {
			return -errno;
		}
	}
	if (attrs->ia_valid & HOSTFS_ATTR_UID) {
		if (fd >= 0) {
			if (fchown(fd, attrs->ia_uid, -1))
				return -errno;
		} else if (chown(file, attrs->ia_uid, -1)) {
			return -errno;
		}
	}
	if (attrs->ia_valid & HOSTFS_ATTR_GID) {
		if (fd >= 0) {
			if (fchown(fd, -1, attrs->ia_gid))
				return -errno;
		} else if (chown(file, -1, attrs->ia_gid)) {
			return -errno;
		}
	}
	if (attrs->ia_valid & HOSTFS_ATTR_SIZE) {
		if (fd >= 0) {
			if (ftruncate(fd, attrs->ia_size))
				return -errno;
		} else if (truncate(file, attrs->ia_size)) {
			return -errno;
		}
	}

	/*
	 * Update accessed and/or modified time, in two parts: first set
	 * times according to the changes to perform, and then call futimes()
	 * or utimes() to apply them.
	 */
	ma = (HOSTFS_ATTR_ATIME_SET | HOSTFS_ATTR_MTIME_SET);
	if (attrs->ia_valid & ma) {
		err = stat_file(file, &st, fd);
		if (err != 0)
			return err;

		times[0].tv_sec = st.atime.tv_sec;
		times[0].tv_usec = st.atime.tv_nsec / 1000;
		times[1].tv_sec = st.mtime.tv_sec;
		times[1].tv_usec = st.mtime.tv_nsec / 1000;

		if (attrs->ia_valid & HOSTFS_ATTR_ATIME_SET) {
			times[0].tv_sec = attrs->ia_atime.tv_sec;
			times[0].tv_usec = attrs->ia_atime.tv_nsec / 1000;
		}
		if (attrs->ia_valid & HOSTFS_ATTR_MTIME_SET) {
			times[1].tv_sec = attrs->ia_mtime.tv_sec;
			times[1].tv_usec = attrs->ia_mtime.tv_nsec / 1000;
		}

		if (fd >= 0) {
			if (futimes(fd, times) != 0)
				return -errno;
		} else if (utimes(file, times) != 0) {
			return -errno;
		}
	}

	/* Note: ctime is not handled */
	if (attrs->ia_valid & (HOSTFS_ATTR_ATIME | HOSTFS_ATTR_MTIME)) {
		err = stat_file(file, &st, fd);
		attrs->ia_atime = st.atime;
		attrs->ia_mtime = st.mtime;
		if (err != 0)
			return err;
	}
	return 0;
}

int make_symlink(const char *from, const char *to)
{
	int err;

	err = symlink(to, from);
	if (err)
		return -errno;
	return 0;
}

int unlink_file(const char *file)
{
	int err;

	err = unlink(file);
	if (err)
		return -errno;
	return 0;
}

int do_mkdir(const char *file, int mode)
{
	int err;

	err = mkdir(file, mode);
	if (err)
		return -errno;
	return 0;
}

int hostfs_do_rmdir(const char *file)
{
	int err;

	err = rmdir(file);
	if (err)
		return -errno;
	return 0;
}

int do_mknod(const char *file, int mode, unsigned int major, unsigned int minor)
{
	int err;

	err = mknod(file, mode, makedev(major, minor));
	if (err)
		return -errno;
	return 0;
}

int link_file(const char *to, const char *from)
{
	int err;

	err = link(to, from);
	if (err)
		return -errno;
	return 0;
}

int hostfs_do_readlink(char *file, char *buf, int size)
{
	int n;

	n = readlink(file, buf, size);
	if (n < 0)
		return -errno;
	if (n < size)
		buf[n] = '\0';
	return n;
}

int rename_file(char *from, char *to)
{
	int err;

	err = rename(from, to);
	if (err < 0)
		return -errno;
	return 0;
}

int rename2_file(char *from, char *to, unsigned int flags)
{
	int err;

#ifdef __linux__
#  ifndef SYS_renameat2
#    ifdef __x86_64__
#      define SYS_renameat2 316
#    endif
#    ifdef __i386__
#      define SYS_renameat2 353
#    endif
#  endif
#endif

#ifdef SYS_renameat2
	err = syscall(SYS_renameat2, AT_FDCWD, from, AT_FDCWD, to, flags);
	if (err < 0) {
		if (errno != ENOSYS)
			return -errno;
		else
			return -EINVAL;
	}
	return 0;
#else
	return -EINVAL;
#endif
}

int do_statfs(char *root, long *bsize_out, long long *blocks_out,
	      long long *bfree_out, long long *bavail_out,
	      long long *files_out, long long *ffree_out,
	      void *fsid_out, int fsid_size, long *namelen_out)
{
	struct statfs buf;
	int err;

	err = statfs(root, &buf);
	if (err < 0)
		return -errno;

	*bsize_out = buf.f_bsize;
	*blocks_out = buf.f_blocks;
	*bfree_out = buf.f_bfree;
	*bavail_out = buf.f_bavail;
	*files_out = buf.f_files;
	*ffree_out = buf.f_ffree;
	memcpy(fsid_out, &buf.f_fsid,
	       sizeof(buf.f_fsid) > fsid_size ? fsid_size :
	       sizeof(buf.f_fsid));
#ifdef __linux__
	*namelen_out = buf.f_namelen;
#else
	*namelen_out = NAME_MAX;
#endif

	return 0;
}
