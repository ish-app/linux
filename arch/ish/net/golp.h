#ifndef __ISH_GOLP_H
#define __ISH_GOLP_H
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/refcount.h>
#include <user/fs.h>

struct sk_buff;
struct net_device;

#define GOLP_HASH_BITS 10

enum gtcp_flag {
	FL_OFF = 0,
	FL_INFLIGHT,
	FL_ON,
};

struct golp_socket {
	refcount_t refcount;
	spinlock_t lock;
	struct hlist_node link;

	int fd;
	u8 protocol;
	__be32 addr;
	__be32 remote_addr;
	unsigned short port;
	unsigned short remote_port;
	struct fd_listener listener;

	/* TCP state */
	u32 send_bufsize;
	u32 local_next;
	u32 local_window;
	u32 remote_next;
	u32 remote_unacked;
	unsigned local_syn:2, remote_syn:2;
	unsigned local_fin:2, remote_fin:2;
};

struct golp_priv {
	struct golp_socket *ping_sock;
	int irq_pipe_read, irq_pipe_write;
	DECLARE_HASHTABLE(udp_hash, 8);
	DECLARE_HASHTABLE(tcp_hash, 8);
	spinlock_t sockets_lock;
};

void golp_rx(struct sk_buff *skb);
extern char __golp_irq_buf[65536];

struct golp_socket *golp_socket_alloc(struct net_device *dev, int proto);
void __golp_socket_destroy(struct golp_socket *sock);
static inline void golp_socket_hold(struct golp_socket *sock)
{
	refcount_inc(&sock->refcount);
}
static inline void golp_socket_put(struct golp_socket *sock)
{
	if (refcount_dec_and_test(&sock->refcount))
		__golp_socket_destroy(sock);
}

void __golp_drop_tx(struct net_device *dev, struct sk_buff *skb, const char *msg, ...);
#define golp_drop_tx(dev, skb, msg, ...) __golp_drop_tx(dev, skb, KERN_INFO "golp: dropping outgoing packet: " msg "\n", ##__VA_ARGS__)
void __golp_drop_rx(struct net_device *dev, const char *msg, ...);
#define golp_drop_rx(dev, msg, ...) __golp_drop_rx(dev, KERN_INFO "golp: dropping incoming packet: " msg "\n", ##__VA_ARGS__)

int golp_ping_up(struct net_device *dev);
int golp_ping_down(struct net_device *dev);
void golp_ping4_tx(struct sk_buff *skb, struct net_device *dev);
void golp_ping4_rx(struct golp_socket *sock, struct net_device *dev);

void golp_udp4_tx(struct sk_buff *skb, struct net_device *dev);
void golp_udp4_rx(struct golp_socket *sock, struct net_device *dev);
int golp_udp4_ip_listen(struct net_device *dev, __be32 address, unsigned short port);
void golp_udp4_ip_unlisten(struct net_device *dev, __be32 address, unsigned short port);

void golp_tcp4_tx(struct sk_buff *skb, struct net_device *dev);
void golp_tcp4_rx(struct golp_socket *sock, struct net_device *dev);

/* user stuff */
int open_udp_socket(uint32_t addr, unsigned short port);
int rebind_socket(int sock, uint32_t addr, unsigned short port);
void get_local_addr_for_route(uint32_t remote, uint32_t *local);
int half_close_sock(int fd);

#endif
