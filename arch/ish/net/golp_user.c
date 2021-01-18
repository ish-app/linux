#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <user/errno.h>

int rebind_socket(int socket, uint32_t addr, unsigned short port);

int open_udp_socket(uint32_t addr, unsigned short port)
{
	int err;
	int sock_type = 0;
	int sock;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
		return errno_map();
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (int[]){ 1 },
		       sizeof(int)))
		return errno_map();
	err = rebind_socket(sock, addr, port);
	if (err < 0)
		return err;
	return sock;
}

static struct sockaddr_in sin_create(uint32_t addr, unsigned short port)
{
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = addr,
		.sin_port = htons(port),
	};
	return sin;
}

int rebind_socket(int sock, uint32_t addr, unsigned short port)
{
	struct sockaddr_in sin = sin_create(addr, port);
	if (bind(sock, (const void *)&sin, sizeof(sin)) < 0)
		return errno_map();
	return 0;
}

void get_local_addr_for_route(uint32_t remote, uint32_t *local)
{
	static int sock = -1; /* TODO percpu */
	struct sockaddr_in sin = {.sin_family = AF_INET, .sin_port = 1};
	socklen_t socklen = sizeof(sin);
	int err;

	*local = INADDR_NONE;
	if (sock == -1)
		sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	sin.sin_addr.s_addr = remote;
	err = connect(sock, (const void *) &sin, sizeof(sin));
	if (err < 0) {
		printk("failed to route %pI4 (%d)\n", &remote, errno_map());
		return;
	}
	err = getsockname(sock, (void *) &sin, &socklen);
	if (err < 0) {
		printk("failed to get local addr after routing %pI4 (%d)", &remote, errno_map());
		return;
	}
	*local = sin.sin_addr.s_addr;
}

int host_getsockopt(int fd, int sockopt, void *data, size_t size)
{
	socklen_t aaa = size;
	int err;
	int host_sockopt = sockopt;
	if (sockopt == 7)
		host_sockopt = SO_SNDBUF;
	if (sockopt == 4)
		host_sockopt = SO_ERROR;
	err = getsockopt(fd, SOL_SOCKET, host_sockopt, data, &aaa);
	if (err < 0)
		return errno_map();
	return 0;
}

uint32_t host_sock_out_queue_size(int fd)
{
	uint32_t size;
#if defined(__APPLE__)
	socklen_t aaa = sizeof(size);
	int err = getsockopt(fd, SOL_SOCKET, SO_NWRITE, &size, &aaa);
#elif defined(__linux__)
	int err = ioctl(fd, SIOCOUTQ, &size);
#endif
	if (err < 0)
		panic("o fuk");
	return size;
}

int get_so_error(int fd)
{
	int err;
	socklen_t err_len = sizeof(err);
	int err2 = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
	if (err2 < 0)
		return errno_map();
	if (err != 0)
		return err_map(err);
	return 0;
}

int half_close_sock(int fd)
{
	int err = shutdown(fd, SHUT_WR);
	if (err < 0)
		return errno_map();
	return 0;
}
