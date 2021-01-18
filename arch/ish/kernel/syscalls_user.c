#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <user/user.h>
#include <user/errno.h>
#include <user/fs.h>

int err_map(int err)
{
	switch (err) {
#define ERRNO_CASE(name, val) \
		case name: return -val;
		ERRNOS(ERRNO_CASE)
#undef ERRNO_CASE
		default:
			return -(0x1000 | err);
	}
}
int errno_map()
{
	return err_map(errno);
}

int host_open(const char *file, int flags)
{
	int fd = open(file, flags);
	if (fd < 0)
		return errno_map();
	return fd;
}

int host_pipe(int *r, int *w) {
	int p[2];
	int err = pipe(p);
	if (err < 0)
		return errno_map();
	*r = p[0];
	*w = p[1];
	return 0;
}

ssize_t host_write(int fd, const void *data, size_t len)
{
	ssize_t res = write(fd, data, len);
	if (res < 0)
		return errno_map();
	return res;
}
ssize_t host_read(int fd, void *data, size_t len)
{
	ssize_t res = read(fd, data, len);
	if (res < 0)
		return errno_map();
	return res;
}
ssize_t host_pwrite(int fd, void *data, size_t len, off_t offset)
{
	ssize_t res = pwrite(fd, data, len, offset);
	if (res < 0)
		return errno_map();
	return res;
}
ssize_t host_pread(int fd, void *data, size_t len, off_t offset)
{
	ssize_t res = pread(fd, data, len, offset);
	if (res < 0)
		return errno_map();
	return res;
}

int host_fstat_size(int fd, ssize_t *size)
{
	struct stat stat;
	int err = fstat(fd, &stat);
	if (err < 0)
		return errno_map();
	*size = stat.st_size;
	return 0;
}

int host_close(int fd)
{
	int err = close(fd);
	if (err < 0)
		return errno_map();
	return 0;
}

int host_socket(int domain, int type, int protocol)
{
	/* I can only promise this will work on darwin and linux */
	int sock = socket(domain, type, protocol);
	if (sock < 0)
		return errno_map();
	return sock;
}

static_assert(sizeof(struct iovec) == sizeof(struct user_iovec), "iovec size");
static_assert(offsetof(struct iovec, iov_base) == offsetof(struct user_iovec, base), "iovec.iov_base");
static_assert(offsetof(struct iovec, iov_len) == offsetof(struct user_iovec, len), "iovec.iov_len");

struct kernel_sockaddr {
    uint16_t family;
    char data[14];
};
static_assert(offsetof(struct kernel_sockaddr, data) == offsetof(struct sockaddr, sa_data), "sockaddr.sa_data");

static void sockaddr_from_kernel(void *name, int name_len)
{
	struct sockaddr *host_name = name;
	struct kernel_sockaddr *kernel_name = name;
	if (name) {
		host_name->sa_family = kernel_name->family;
		host_name->sa_len = name_len;
	}
}
static void sockaddr_to_kernel(void *name, int name_len)
{
	struct sockaddr *host_name = name;
	struct kernel_sockaddr *kernel_name = name;
	if (name) {
		kernel_name->family = host_name->sa_family;
	}
}

ssize_t host_sendmsg(int fd, struct user_iovec *iov, size_t iov_len, void *name, unsigned name_len, int flags)
{
	/* need to translate flags */
	/* need to translate name */
	assert(flags == 0);
	sockaddr_from_kernel(name, name_len);
	struct msghdr msg = {
		.msg_iov = (struct iovec *) iov,
		.msg_iovlen = iov_len,
		.msg_name = name,
		.msg_namelen = name_len,
	};
	ssize_t len = sendmsg(fd, &msg, flags);
	if (len < 0)
		return errno_map();
	return len;
}

ssize_t host_recvmsg(int fd, struct user_iovec *iov, size_t iov_len, void *name, int *name_len_out, int *flags_out, int kflags)
{
	int flags = 0;
	if (kflags & 0x40)
		flags |= MSG_DONTWAIT;
	if (kflags & 2)
		flags |= MSG_PEEK;
	assert((kflags&~0x42) == 0);
	struct msghdr msg = {
		.msg_iov = (struct iovec *) iov,
		.msg_iovlen = iov_len,
		.msg_name = name,
		.msg_namelen = 128, /* TODO do better */
	};
	ssize_t len = recvmsg(fd, &msg, flags);
	if (len < 0)
		return errno_map();
	if (name) {
		sockaddr_to_kernel(msg.msg_name, msg.msg_namelen);
		*name_len_out = msg.msg_namelen;
	}
	/*assert(msg.msg_flags == 0); /* TODO */
	if (flags_out)
		*flags_out = msg.msg_flags;
	return len;
}

int host_bind(int fd, void *name, int name_len)
{
	int err;

	sockaddr_from_kernel(name, name_len);
	err = bind(fd, name, name_len);
	if (err < 0)
		return errno_map();
	return 0;
}

int host_connect(int fd, void *name, int name_len)
{
	int err;

	sockaddr_from_kernel(name, name_len);
	err = connect(fd, name, name_len);
	if (err < 0)
		return errno_map();
	return 0;
}

int host_getname(int fd, void *name, int peer)
{
	socklen_t name_len;
	int err = (peer ? getpeername : getsockname)(fd, name, &name_len);
	if (err < 0)
		return errno_map();
	assert(name_len == sizeof(struct sockaddr_in));
	return 0;
}

int host_get_so_error(int fd)
{
	int so_error;
	socklen_t so_error_len = sizeof(so_error);
	int err = getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len);
	if (err < 0)
		return errno_map();
	return so_error;
}

int fd_set_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		return errno_map();
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0)
		return errno_map();
	return 0;
}

int fd_poll(int fd)
{
	int err;
	/* This is dramatically simplified by assuming fd will always be a
	 * socket, and ignoring any Darwin idiosyncracies with other types of
	 * fds. */
	struct pollfd p = {.fd = fd, .events = POLLPRI};
	/* attempt to prevent POLLNVAL */
	int flags = fcntl(fd, F_GETFL, 0);
	if ((flags & O_ACCMODE) != O_WRONLY)
		p.events |= POLLIN;
	if ((flags & O_ACCMODE) != O_RDONLY)
		p.events |= POLLOUT;
	err = poll(&p, 1, 0);
	if (err < 0)
		return errno_map();
	if (err == 0)
		return 0;
	return p.revents;
}
void termio_make_raw(int fd)
{
	struct termios tio;
	tcgetattr(fd, &tio);
	cfmakeraw(&tio);
	tcsetattr(fd, TCSANOW, &tio);
}

void host_pause(void)
{
	pause();
}

void *host_mmap(void *addr, size_t len)
{
	return mmap(addr, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
}

uint64_t host_monotonic_nanos(void)
{
#ifdef __APPLE__
	return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#endif
#ifdef __linux__
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000 + ts.tv_nsec;
#endif
}

uint64_t host_unix_nanos(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec * 1000000000 + ts.tv_nsec;
}
