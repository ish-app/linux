#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/secure_seq.h>
#include "golp.h"
#include <linux/sched/debug.h>

/* TODO: send periodic keepalives to make sure stale sockets get cleaned up */
/* One way to reproduce a problem that keepalives would solve is to drop the
 * final incoming ack packet. */

/* TODO: handle URG bit */

static u32 get_send_window(struct golp_socket *sock)
{
	uint32_t nwrite;
	int err = host_get_so_nwrite(sock->fd, &nwrite);
	if (err < 0)
		panic("can't calculate send window: %pe", ERR_PTR(err));
	return sock->send_bufsize - nwrite;
}

static u32 __tcp_hash(struct net_device *dev, __be32 local_addr,
		      unsigned short local_port, __be32 remote_addr,
		      unsigned short remote_port)
{
	return ipv4_portaddr_hash(dev_net(dev), local_addr, local_port) ^
	       ipv4_portaddr_hash(dev_net(dev), remote_addr, remote_port);
}

static struct golp_socket *
__tcp_socket_lookup(struct net_device *dev, __be32 address, unsigned short port,
		    __be32 remote_address, unsigned short remote_port)
{
	struct golp_priv *priv = netdev_priv(dev);
	struct golp_socket *sock;
	hash_for_each_possible(priv->tcp_hash, sock, link,
			       __tcp_hash(dev, address, port, remote_address,
					  remote_port)) {
		if (sock->addr == address &&
		    sock->port == port &&
		    sock->remote_addr == remote_address &&
		    sock->remote_port == remote_port)
			return sock;
	}
	return NULL;
}

static void __tcp_socket_insert(struct net_device *dev,
				struct golp_socket *sock)
{
	struct golp_priv *priv = netdev_priv(dev);
	spin_lock(&priv->sockets_lock);
	hash_add(priv->tcp_hash, &sock->link,
		 __tcp_hash(dev, sock->addr, sock->port, sock->remote_addr,
			    sock->remote_port));
	spin_unlock(&priv->sockets_lock);
}

static void __tcp_socket_remove(struct net_device *dev,
				struct golp_socket *sock)
{
	struct golp_priv *priv = netdev_priv(dev);
	spin_lock(&priv->sockets_lock);
	hash_del(&sock->link);
	spin_unlock(&priv->sockets_lock);
	golp_socket_put(sock);
}

static struct sk_buff *golp_tcp_make_skb(int size, struct net_device *dev)
{
	struct sk_buff *skb;
	struct tcphdr *tcp;
	struct iphdr *ip;

	skb = netdev_alloc_skb(dev, MAX_TCP_HEADER + size);
	if (skb == NULL) {
		golp_drop_rx(dev, "no memory for skb");
		return NULL;
	}
	skb_reserve(skb, MAX_TCP_HEADER);
	tcp = skb_push(skb, sizeof(*tcp));
	memset(tcp, 0, sizeof(*tcp));
	skb_reset_transport_header(skb);
	ip = skb_push(skb, sizeof(*ip));
	skb_reset_network_header(skb);

	ip->protocol = IPPROTO_TCP;
	tcp->doff = sizeof(*tcp) / 4;
	return skb;
}

static struct sk_buff *golp_tcp_make_recv(struct golp_socket *sock, int size,
					  struct net_device *dev)
{
	struct sk_buff *skb;
	struct iphdr *ip;
	struct tcphdr *tcp;

	skb = golp_tcp_make_skb(size, dev);
	if (skb == NULL)
		return NULL;
	ip = ip_hdr(skb);
	tcp = tcp_hdr(skb);

	ip->saddr = sock->remote_addr;
	ip->daddr = sock->addr;
	tcp->source = htons(sock->remote_port);
	tcp->dest = htons(sock->port);
	tcp->seq = htonl(sock->remote_next);
	tcp->ack = 1;
	tcp->ack_seq = htonl(sock->local_next);
	tcp->window = min_t(u32, get_send_window(sock), U16_MAX);
	/* printk("%s[%d] %s %d  ack_seq=%u\n", current->comm, current->pid, __FUNCTION__, __LINE__, ntohl(tcp->ack_seq)); */

	return skb;
}

static void golp_tcp_reset(struct golp_socket *sock, struct net_device *dev)
{
	struct sk_buff *skb = golp_tcp_make_recv(sock, 0, dev);
	if (skb == NULL)
		return;
	tcp_hdr(skb)->ack = 0;
	tcp_hdr(skb)->rst = 1;
	golp_rx(skb);
	return __tcp_socket_remove(dev, sock);
}

static void golp_tcp_conn_rx(struct golp_socket *sock, struct net_device *dev);

static void golp_tcp_tx_conn(struct golp_socket *sock, struct sk_buff *skb,
			     struct net_device *dev)
{
	struct tcphdr *tcp = tcp_hdr(skb);
	struct user_iovec data = {
		.base = (char *) tcp + tcp_hdrlen(skb),
		.len = ip_transport_len(skb) - tcp_hdrlen(skb),
	};
	struct sk_buff *reply;
	u32 seq = ntohl(tcp->seq);
	u32 ack_seq = ntohl(tcp->ack_seq);
	size_t pop_bytes;

	/* If the packet is too early in the sequence, assume it's a keep-alive
	 * and ack it. */
	if (before(seq, sock->local_next)) {
		reply = golp_tcp_make_recv(sock, 0, dev);
		if (reply == NULL)
			return;
		return golp_rx(reply);
	}

	/* If the packet is not perfectly in sequence, drop. 3.9 p69 */
	if (seq != sock->local_next)
		return golp_drop_tx(dev, skb,
				    "out of order: sending %u, expected %u",
				    seq, sock->local_next);

	/* check rst */
	if (tcp->rst) {
		host_set_so_linger(sock->fd, 1, 0);
		return __tcp_socket_remove(dev, sock);
	}

	/* 3.9 p71: If the SYN is in the window it is an error, send a reset,
	 * any outstanding RECEIVEs and SEND should receive "reset" responses,
	 * all segment queues should be flushed, the user should also receive
	 * an unsolicited general "connection reset" signal, enter the CLOSED
	 * state, delete the TCB, and return. */
	if (tcp->syn) {
		return golp_tcp_reset(sock, dev);
	}

	/* process ack (complicated) */
	if (!tcp->ack)
		return golp_drop_tx(dev, skb, "all packets must be ACKs");
	if (before(ack_seq, sock->remote_unacked))
		return golp_drop_tx(dev, skb,
				    "duplicate ack %u, already acked %u",
				    ack_seq, sock->remote_unacked);
	if (after(ack_seq, sock->remote_next)) {
		printk("golp: received future ack %u, only got %u", ack_seq,
		       sock->remote_next);
		if (sock->local_syn == FL_ON) {
			/* If the ACK acks something not yet sent
			 * (SEG.ACK > SND.NXT) then send an ACK, drop the
			 * segment, and return. */
			reply = golp_tcp_make_recv(sock, 0, dev);
			if (reply == NULL)
				return;
			return golp_rx(reply);
		} else {
			/* If the segment acknowledgment is not acceptable,
			 * form a reset segment and send it. */
			return golp_tcp_reset(sock, dev);
		}
	}

	/* Handle state transitions */
	pop_bytes = ack_seq - sock->remote_unacked;
	/* Can ack a syn if the ack pointer is advanced at all (since the syn
	 * is first in the sequence). */
	if (sock->remote_syn == FL_INFLIGHT &&
	    after(ack_seq, sock->remote_unacked)) {
		sock->remote_syn = FL_ON;
		pop_bytes--;
	}
	/* Can ack a fin if there is a fin in flight and the ack is fully
	 * caught up (this assumes no more data will come from the remote after
	 * sending the fin). */
	if (sock->remote_fin == FL_INFLIGHT && ack_seq == sock->remote_next) {
		sock->remote_fin = FL_ON;
		pop_bytes--;
	}
	if (sock->remote_fin == FL_ON && sock->local_fin == FL_ON)
		return __tcp_socket_remove(dev, sock);

	/* Commit the ack: pop the socket, then update remote_unacked */
	if (pop_bytes != 0) {
		static char bit_bucket[65536];
		struct user_iovec pop_iov = {
			.base = bit_bucket,
			.len = pop_bytes,
		};
		ssize_t pop_res;
		pop_res = host_recvmsg(sock->fd, &pop_iov, 1, NULL, NULL, NULL,
				       0);
		if (pop_res != pop_iov.len) {
			if (pop_res < 0)
				panic("golp: failed pop! %pe",
				      ERR_PTR(pop_res));
			else
				panic("golp: short pop! %lu < %lu",
				      pop_res, pop_iov.len);
		}
	}
	sock->remote_unacked = ack_seq;
	sock->local_window = ntohs(tcp->window);
	if (sock->local_window > 0)
		sock->local_window--;

	golp_tcp_conn_rx(sock, dev);

	/* move data along */
	if (data.len > 0) {
		ssize_t send_len = host_sendmsg(sock->fd, &data, 1, NULL, 0, 0);
		if (send_len == -EAGAIN) {
			printk("eagain, give it a second\n");
			mdelay(1000);
			send_len = host_sendmsg(sock->fd, &data, 1, NULL, 0, 0);
		}
		if (send_len == -EAGAIN)
			send_len = 0;
		if (send_len < 0) {
			pr_notice(
				"golp: failed to send to remote, resetting: %pe\n",
				ERR_PTR(send_len));
			return golp_tcp_reset(sock, dev);
		}
		sock->local_next += send_len;
		if (send_len != data.len)
			pr_warn("golp: short send: %lu out of %lu bytes\n",
			       send_len, data.len);

		reply = golp_tcp_make_recv(sock, 0, dev);
		if (reply == NULL)
			return;
		golp_rx(reply);
	}

	/* process fin */
	if (tcp->fin) {
		host_shutdown_write(sock->fd);
		sock->local_next++;
		reply = golp_tcp_make_recv(sock, 0, dev);
		if (reply == NULL)
			return;
		golp_rx(reply);
		sock->local_fin = FL_ON;
		if (sock->remote_fin == FL_ON && sock->local_fin == FL_ON)
			return __tcp_socket_remove(dev, sock);
	}
}

static void golp_tcp_tx_noconn(struct sk_buff *skb, struct net_device *dev)
{
	struct golp_socket *sock;
	struct iphdr *ip = ip_hdr(skb);
	struct tcphdr *tcp = tcp_hdr(skb);
	struct sockaddr_in sin = { .sin_family = AF_INET };
	int err;
	unsigned long flags;

	/* 3.9 p65: If the state is LISTEN then: */

	if (tcp->rst)
		/* 3.9 p65: An incoming RST should be ignored. */
		return golp_drop_tx(dev, skb, "reset nonexistent connection");
	if (tcp->ack) {
		/* 3.9 p65: Any acknowledgment is bad if it arrives on a
		 * connection still in the LISTEN state. */
		/* This is a unique situation, as we have to send a packet
		 * without an existing connection. */
		struct sk_buff *reply = golp_tcp_make_skb(0, dev);
		if (reply == NULL)
			return;
		ip_hdr(reply)->saddr = ip->daddr;
		ip_hdr(reply)->daddr = ip->saddr;
		tcp_hdr(reply)->source = tcp->dest;
		tcp_hdr(reply)->dest = tcp->source;
		tcp_hdr(reply)->seq = tcp->ack;
		tcp_hdr(reply)->rst = 1;
		return golp_rx(reply);
	}
	if (!tcp->syn)
		/* 3.9 p66: Any other control or text-bearing segment
		 * (not containing SYN) must have an ACK and thus would
		 * be discarded by the ACK processing. An incoming RST
		 * segment could not be valid, since it could not have
		 * been sent in response to anything sent by this
		 * incarnation of the connection. So you are unlikely
		 * to get here, but if you do, drop the segment, and
		 * return. */
		return golp_drop_tx(dev, skb, "wat");

	sock = golp_socket_alloc(dev, IPPROTO_TCP);
	if (sock == NULL)
		return golp_drop_tx(dev, skb, "failed to kmalloc connection");
	sock->fd = host_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock->fd < 0) {
		golp_drop_tx(dev, skb, "failed to create client socket: %pe",
			     ERR_PTR(sock->fd));
		kfree(sock);
		return;
	}

	sock->addr = ip->saddr;
	sock->remote_addr = ip->daddr;
	sock->port = ntohs(tcp->source);
	sock->remote_port = ntohs(tcp->dest);
	sock->local_next = ntohl(tcp->seq);
	sock->remote_next =
		secure_tcp_seq(ip->daddr, ip->saddr, tcp->dest, tcp->source);
	sock->remote_unacked = sock->remote_next;
	err = host_get_so_sndbuf(sock->fd, &sock->send_bufsize);
	if (err < 0)
		panic("failed to get SO_SNDBUF: %pe", ERR_PTR(err));
	sock->local_window = U32_MAX;
	sock->local_syn = FL_INFLIGHT;
	sock->remote_syn = FL_OFF;
	sock->local_fin = sock->remote_fin = FL_OFF;

	/* printk("%s %d  local_next=%u\n", __FUNCTION__, __LINE__, sock->local_next); */
	/* Must lock the socket before calling fd_listen, since fd_listen
	 * publishes the socket for other threads to access on irq */
	spin_lock_irqsave(&sock->lock, flags);

	/* TODO: turn off POLLOUT once the connect() finishes */
	err = fd_listen(sock->fd, POLLIN | POLLOUT | POLLHUP | EPOLLET,
			&sock->listener);
	if (err < 0) {
		spin_unlock_irqrestore(&sock->lock, flags);
		golp_socket_put(sock);
		return golp_drop_tx(dev, skb,
				    "failed to listen on connecting socket");
	}

	err = fd_set_nonblock(sock->fd);
	if (err < 0) {
		spin_unlock_irqrestore(&sock->lock, flags);
		golp_socket_put(sock);
		return golp_drop_tx(
			dev, skb,
			"failed to set connecting socket to nonblock");
	}

	sin.sin_addr.s_addr = ip->daddr;
	sin.sin_port = tcp->dest;
	err = host_connect(sock->fd, &sin, sizeof(sin));
	if (err < 0 && err != -EINPROGRESS) {
		spin_unlock_irqrestore(&sock->lock, flags);
		golp_socket_put(sock);
		/* TODO: should this be a reset? */
		return golp_drop_tx(dev, skb, "failed to initiate connection");
	}

	/* A connection attempt counts for 1 sequence unit */
	sock->local_next++;
	spin_unlock_irqrestore(&sock->lock, flags);

	__tcp_socket_insert(dev, sock);
}

void golp_tcp4_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct golp_priv *priv = netdev_priv(dev);
	struct golp_socket *sock;
	struct iphdr *ip = ip_hdr(skb);
	struct tcphdr *tcp = tcp_hdr(skb);

	if (tcp->rst)
		printk("golp tcp tx reset?\n");

	if (ip_transport_len(skb) < sizeof(*tcp) ||
	    ip_transport_len(skb) < tcp_hdrlen(skb))
		return golp_drop_tx(dev, skb,
				    "tcp packet truncated before header");

	spin_lock(&priv->sockets_lock);
	sock = __tcp_socket_lookup(dev, ip->saddr, ntohs(tcp->source),
				   ip->daddr, ntohs(tcp->dest));
	if (sock) {
		golp_socket_hold(sock);
	}
	spin_unlock(&priv->sockets_lock);
	if (sock) {
		unsigned long flags;
		spin_lock_irqsave(&sock->lock, flags);
		golp_tcp_tx_conn(sock, skb, dev);
		spin_unlock_irqrestore(&sock->lock, flags);
		golp_socket_put(sock);
	} else {
		golp_tcp_tx_noconn(skb, dev);
	}

}

static void golp_tcp_conn_rx(struct golp_socket *sock, struct net_device *dev)
{
	struct sk_buff *skb;
	struct user_iovec buf = {
		.base = __golp_irq_buf,
		.len = sizeof(__golp_irq_buf),
	};
	char *buf_ptr;
	ssize_t data_len;
	u32 seq = sock->remote_unacked;

	/* Send packets, wait for all packets to be acked, and only then send
	 * more. This is a simple (probably overly eager) heuristic to avoid
	 * unnecessary retransmits. If this is causing you trouble, please
	 * delete and rewrite. */
	if (sock->remote_unacked != sock->remote_next) {
		return;
	}

	/* Don't try to receive if the remote end is closed. */
	if (sock->remote_fin)
		return;

	if (sock->local_window < buf.len) {
		buf.len = sock->local_window;
	}
	if (buf.len == 0)
		return;

	data_len = host_recvmsg(sock->fd, &buf, 1, NULL, NULL, NULL, MSG_PEEK);
	if (data_len == -EAGAIN)
		return;

	if (data_len == 0) {
		/* FIN */
		skb = golp_tcp_make_recv(sock, 0, dev);
		tcp_hdr(skb)->fin = 1;
		golp_rx(skb);
		sock->remote_next++;
		sock->remote_fin = FL_INFLIGHT;
		return;
	}
	if (data_len == -ECONNRESET) {
		/* RST */
		return golp_tcp_reset(sock, dev);
	}
	if (data_len < 0) {
		pr_err("golp: recv failed! %pe\n", ERR_PTR(data_len));
		return;
	}

	buf_ptr = buf.base;
	while (data_len > 0) {
		unsigned len = dev->mtu;
		char *skb_data;
		len -= sizeof(struct iphdr) + sizeof(struct tcphdr);
		if (len > data_len)
			len = data_len;
		skb = golp_tcp_make_recv(sock, len, dev);
		tcp_hdr(skb)->seq = htonl(seq);
		tcp_hdr(skb)->psh = 1;
		skb_data = skb_put(skb, len);
		BUG_ON(skb->len > dev->mtu);
		memcpy(skb_data, buf_ptr, len);
		buf_ptr += len;
		data_len -= len;
		seq += len;
		ip_hdr(skb)->id = htons((u16) prandom_u32());

		golp_rx(skb);
	}

	if (seq >= sock->remote_next) {
		sock->remote_next = seq;
	} else {
		panic("golp: data fell off the back of the queue! got to %u, want %u\n",
		      seq, sock->remote_next);
	}
}

static void __golp_tcp4_rx(struct golp_socket *sock, struct net_device *dev)
{
	struct sk_buff *skb;
	int err;

	if (sock->remote_fin) {
		pr_notice("remote end hung up, why did we get notified?\n");
	}

	if (sock->local_syn == FL_INFLIGHT) {
		/* Receive syn/ack, or rst if connection failed */
		skb = golp_tcp_make_recv(sock, 0, dev);
		if (skb == NULL)
			return golp_drop_rx(dev, "no memory for skb");

		err = host_get_so_error(sock->fd);
		if (err < 0) {
			pr_notice("golp: connection failed (%pe), resetting\n",
				  ERR_PTR(err));
			skb = golp_tcp_make_recv(sock, 0, dev);
			if (skb == NULL)
				return;
			tcp_hdr(skb)->rst = 1;
			tcp_hdr(skb)->seq = 0;
			golp_rx(skb);
			return __tcp_socket_remove(dev, sock);
		}

		sock->local_syn = FL_ON;
		tcp_hdr(skb)->syn = 1;
		sock->remote_next++;
		sock->remote_syn = FL_INFLIGHT;
		return golp_rx(skb);
	}

	return golp_tcp_conn_rx(sock, dev);
}

void golp_tcp4_rx(struct golp_socket *sock, struct net_device *dev)
{
	BUG_ON(!in_interrupt());
	spin_lock(&sock->lock);
	/* Do nothing if the socket has been destroyed already */
	if (refcount_read(&sock->refcount) == 0)
		/* TODO @smp: carefully reconsider */
		goto nvm;
	/* We are in the irq, so the socket is not going to get freed, at least until
	 * we finish. */
	golp_socket_hold(sock);
	__golp_tcp4_rx(sock, dev);
	golp_socket_put(sock);
nvm:
	spin_unlock(&sock->lock);
}
