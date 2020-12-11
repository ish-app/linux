#ifndef __ISH_USER_FS_H
#define __ISH_USER_FS_H

#define STDIN_FD 0
#define STDOUT_FD 1
#define STDERR_FD 2
ssize_t host_write(int fd, const void *data, size_t len);
ssize_t host_read(int fd, void *data, size_t len);
ssize_t host_pwrite(int fd, void *data, size_t len, off_t offset);
ssize_t host_pread(int fd, void *data, size_t len, off_t offset);
int fd_set_nonblock(int fd);
int host_open(const char *path, int flags);
int host_close(int fd);

struct user_iovec {
	void *base;
	size_t len;
};

void termio_make_raw(int fd);

int fd_add_irq(int fd, int types, int irq, void *data);
int fd_poll(int fd);

/* net stuff */
int host_socket(int domain, int type, int protocol);
ssize_t host_sendmsg(int fd, struct user_iovec *iov, size_t iov_len, void *name, unsigned name_len, int flags);
ssize_t host_recvmsg(int fd, struct user_iovec *iov, size_t iov_len, void *name, int *name_len_out, int *flags_out, int flags);
int host_bind(int fd, void *name, int name_len);
int host_connect(int fd, void *name, int name_len);
int host_getname(int fd, void *name, int peer);
int host_get_so_error(int fd);

#endif
