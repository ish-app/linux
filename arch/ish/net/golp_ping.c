#include <net/icmp.h>
#include <user/fs.h>
#include "golp.h"

int golp_ping_up(struct net_device *dev)
{
	struct golp_priv *priv = netdev_priv(dev);
	priv->ping_sock = golp_socket_alloc(dev, IPPROTO_ICMP);
	priv->ping_sock->fd = host_socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	return fd_listen(priv->ping_sock->fd, POLLIN, &priv->ping_sock->listener);
}

int golp_ping_down(struct net_device *dev)
{
	struct golp_priv *priv = netdev_priv(dev);
	golp_socket_put(priv->ping_sock);
	priv->ping_sock = NULL;
	return 0;
}

void golp_ping4_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct golp_priv *priv = netdev_priv(dev);
	struct iphdr *ip = ip_hdr(skb);
	struct icmphdr *icmp = icmp_hdr(skb);
	int err;
	struct sockaddr_in addr = {
		.sin_family = PF_INET,
		.sin_addr.s_addr = ip->daddr,
		.sin_port = 0,
	};
	struct user_iovec data = {
		.base = icmp,
		.len = ip_transport_len(skb),
	};

	if (ip_transport_len(skb) < sizeof(*icmp))
		return golp_drop_tx(dev, skb, "icmp packet too short");
	if (icmp->type != ICMP_ECHO)
		return golp_drop_tx(dev, skb, "wrong icmp type");
	err = host_sendmsg(priv->ping_sock->fd, &data, 1, &addr, sizeof(addr), 0);
	if (err < 0)
		return golp_drop_tx(dev, skb, "icmp sendmsg failed: %pe", ERR_PTR(err));
	skb->dev->stats.tx_packets++;
	skb->dev->stats.tx_bytes += data.len;
}

void golp_ping4_rx(struct golp_socket *sock, struct net_device *dev)
{
	struct sockaddr_storage addr;
	struct user_iovec iov = {
		.base = __golp_irq_buf,
		.len = sizeof(__golp_irq_buf),
	};
	
	for (;;) {
		struct sk_buff *skb;
		int addr_len;
		int rcv_flags;
		ssize_t rcv_len;

		rcv_len = host_recvmsg(sock->fd, &iov, 1, &addr, &addr_len, &rcv_flags, MSG_DONTWAIT);
		if (rcv_len == -EAGAIN)
			break;
		if (rcv_len < 0) {
			golp_drop_rx(dev, "ping read failed: %pe", ERR_PTR(rcv_len));
			continue;
		}

		skb = netdev_alloc_skb(dev, rcv_len);
		if (skb == NULL) {
			golp_drop_rx(dev, "no memory for skb");
			continue;
		}
		memcpy(skb_put(skb, rcv_len), __golp_irq_buf, rcv_len);
		golp_rx(skb);
	}
}
