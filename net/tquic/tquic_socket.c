// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Socket Interface
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides BSD socket interface for TQUIC connections with WAN bonding.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/poll.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/inet_connection_sock.h>
#include <net/protocol.h>
#include <net/tquic.h>

#include "protocol.h"

/*
 * Lockdep class keys for TQUIC sockets
 * Indexed: [0] = IPv4, [1] = IPv6
 */
struct lock_class_key tquic_slock_keys[2];
struct lock_class_key tquic_lock_keys[2];

/*
 * Lock class keys for connection, path, and stream locks
 */
struct lock_class_key tquic_conn_lock_key;
struct lock_class_key tquic_path_lock_key;
struct lock_class_key tquic_stream_lock_key;

/*
 * tquic_set_lockdep_class - Initialize lockdep class for socket
 * @sk: socket to initialize lockdep for
 * @is_ipv6: true if socket is IPv6, false for IPv4
 *
 * This allows lockdep to distinguish between IPv4 and IPv6 sockets
 * and properly validate lock ordering.
 */
static void tquic_set_lockdep_class(struct sock *sk, bool is_ipv6)
{
	sock_lock_init_class_and_name(sk,
		is_ipv6 ? "slock-AF_INET6-TQUIC" : "slock-AF_INET-TQUIC",
		&tquic_slock_keys[is_ipv6],
		is_ipv6 ? "sk_lock-AF_INET6-TQUIC" : "sk_lock-AF_INET-TQUIC",
		&tquic_lock_keys[is_ipv6]);
}

/* Socket operations */
static int tquic_release(struct socket *sock);
static int tquic_bind(struct socket *sock, struct sockaddr *addr, int addr_len);
static int tquic_connect_socket(struct socket *sock, struct sockaddr *addr,
				int addr_len, int flags);
static int tquic_accept_socket(struct socket *sock, struct socket *newsock,
			       int flags, bool kern);
static int tquic_getname(struct socket *sock, struct sockaddr *addr, int peer);
static __poll_t tquic_poll_socket(struct file *file, struct socket *sock,
				  poll_table *wait);
static int tquic_listen(struct socket *sock, int backlog);
static int tquic_shutdown(struct socket *sock, int how);
static int tquic_setsockopt(struct socket *sock, int level, int optname,
			    sockptr_t optval, unsigned int optlen);
static int tquic_getsockopt(struct socket *sock, int level, int optname,
			    char __user *optval, int __user *optlen);
static int tquic_sendmsg_socket(struct socket *sock, struct msghdr *msg,
				size_t len);
static int tquic_recvmsg_socket(struct socket *sock, struct msghdr *msg,
				size_t len, int flags);

/* Protocol operations */
static int tquic_init_sock(struct sock *sk);
static void tquic_destroy_sock(struct sock *sk);
static int tquic_hash(struct sock *sk);
static void tquic_unhash(struct sock *sk);
static int tquic_get_port(struct sock *sk, unsigned short snum);

/* Socket family operations */
static const struct proto_ops tquic_proto_ops = {
	.family		= PF_INET,
	.owner		= THIS_MODULE,
	.release	= tquic_release,
	.bind		= tquic_bind,
	.connect	= tquic_connect_socket,
	.socketpair	= sock_no_socketpair,
	.accept		= tquic_accept_socket,
	.getname	= tquic_getname,
	.poll		= tquic_poll_socket,
	.ioctl		= inet_ioctl,
	.listen		= tquic_listen,
	.shutdown	= tquic_shutdown,
	.setsockopt	= tquic_setsockopt,
	.getsockopt	= tquic_getsockopt,
	.sendmsg	= tquic_sendmsg_socket,
	.recvmsg	= tquic_recvmsg_socket,
	.mmap		= sock_no_mmap,
};

/* Socket protocol definition */
static struct proto tquic_prot = {
	.name		= "TQUIC",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct tquic_sock),
	.init		= tquic_init_sock,
	.destroy	= tquic_destroy_sock,
	.hash		= tquic_hash,
	.unhash		= tquic_unhash,
	.get_port	= tquic_get_port,
	.close		= tquic_close,
	.connect	= tquic_connect,
	.sendmsg	= tquic_sendmsg,
	.recvmsg	= tquic_recvmsg,
};

/*
 * Initialize a TQUIC socket
 */
static int tquic_init_sock(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);

	/* Initialize lockdep class for this socket (IPv4) */
	tquic_set_lockdep_class(sk, false);

	/* Initialize connection socket */
	inet_sk_set_state(sk, TCP_CLOSE);

	/* Initialize TQUIC-specific state */
	INIT_LIST_HEAD(&tsk->accept_queue);
	tsk->accept_queue_len = 0;
	tsk->max_accept_queue = 128;

	/* Create connection structure */
	tsk->conn = tquic_conn_create(sk, GFP_KERNEL);
	if (!tsk->conn)
		return -ENOMEM;

	/* Initialize bonding state */
	tsk->conn->scheduler = tquic_bond_init(tsk->conn);

	pr_debug("tquic: socket initialized\n");
	return 0;
}

/*
 * Destroy a TQUIC socket
 */
static void tquic_destroy_sock(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);

	if (tsk->conn) {
		if (tsk->conn->scheduler)
			tquic_bond_cleanup(tsk->conn->scheduler);
		tquic_conn_destroy(tsk->conn);
		tsk->conn = NULL;
	}

	pr_debug("tquic: socket destroyed\n");
}

/*
 * Release socket
 */
static int tquic_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		return 0;

	sock->sk = NULL;
	sock_put(sk);

	return 0;
}

/*
 * Bind socket to address
 */
static int tquic_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);

	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	memcpy(&tsk->bind_addr, addr, min_t(size_t, addr_len,
					    sizeof(struct sockaddr_storage)));

	inet_sk_set_state(sk, TCP_CLOSE);

	return 0;
}

/*
 * Connect to remote address
 */
static int tquic_connect_socket(struct socket *sock, struct sockaddr *addr,
				int addr_len, int flags)
{
	struct sock *sk = sock->sk;

	return tquic_connect(sk, addr, addr_len);
}

/*
 * Connect implementation
 */
int tquic_connect(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	int ret;

	if (!conn)
		return -EINVAL;

	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	memcpy(&tsk->connect_addr, addr, min_t(size_t, addr_len,
					       sizeof(struct sockaddr_storage)));

	/* Add initial path */
	ret = tquic_conn_add_path(conn, (struct sockaddr *)&tsk->bind_addr,
				  (struct sockaddr *)&tsk->connect_addr);
	if (ret < 0)
		return ret;

	/* Initialize the connection state machine for client mode */
	ret = tquic_conn_client_connect(conn, addr);
	if (ret < 0)
		return ret;

	inet_sk_set_state(sk, TCP_SYN_SENT);

	/*
	 * The actual handshake will be completed asynchronously.
	 * For now, we simulate immediate connection for testing.
	 * In production, the state transition to CONNECTED happens
	 * when the handshake completes via tquic_conn_process_handshake().
	 */
	if (conn->state == TQUIC_CONN_CONNECTED)
		inet_sk_set_state(sk, TCP_ESTABLISHED);

	pr_debug("tquic: client connection initiated\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_connect);

/*
 * Listen for incoming connections
 */
static int tquic_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);

	tsk->max_accept_queue = backlog;
	inet_sk_set_state(sk, TCP_LISTEN);

	return 0;
}

/*
 * Accept incoming connection
 */
static int tquic_accept_socket(struct socket *sock, struct socket *newsock,
			       int flags, bool kern)
{
	struct sock *sk = sock->sk;
	struct sock *newsk;
	int ret;

	newsk = sock_alloc();
	if (!newsk)
		return -ENOMEM;

	newsock->sk = newsk;

	ret = tquic_accept(sk, newsk, flags, kern);
	if (ret < 0) {
		sock_release(newsock);
		return ret;
	}

	return 0;
}

int tquic_accept(struct sock *sk, struct sock *newsk, int flags, bool kern)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_sock *new_tsk;
	struct tquic_connection *new_conn;

	/* Check if we're in listen state */
	if (sk->sk_state != TCP_LISTEN)
		return -EINVAL;

	/* Check accept queue */
	if (list_empty(&tsk->accept_queue)) {
		DEFINE_WAIT(wait);
		int err = 0;

		if (flags & O_NONBLOCK)
			return -EAGAIN;

		/* Wait for incoming connection */
		for (;;) {
			prepare_to_wait_exclusive(sk_sleep(sk), &wait,
						  TASK_INTERRUPTIBLE);
			if (!list_empty(&tsk->accept_queue))
				break;
			if (signal_pending(current)) {
				err = -ERESTARTSYS;
				break;
			}
			if (sk->sk_state != TCP_LISTEN) {
				err = -EINVAL;
				break;
			}
			release_sock(sk);
			schedule();
			lock_sock(sk);
		}
		finish_wait(sk_sleep(sk), &wait);
		if (err)
			return err;
	}

	/* Get connection from accept queue */
	spin_lock_bh(&sk->sk_lock.slock);
	if (!list_empty(&tsk->accept_queue)) {
		struct tquic_sock *child_tsk;

		child_tsk = list_first_entry(&tsk->accept_queue,
					     struct tquic_sock, accept_queue);
		list_del_init(&child_tsk->accept_queue);
		tsk->accept_queue_len--;
		spin_unlock_bh(&sk->sk_lock.slock);

		/* Transfer the child connection to the new socket */
		new_tsk = tquic_sk(newsk);
		new_tsk->conn = child_tsk->conn;
		child_tsk->conn = NULL;
		memcpy(&new_tsk->bind_addr, &child_tsk->bind_addr,
		       sizeof(struct sockaddr_storage));
		memcpy(&new_tsk->connect_addr, &child_tsk->connect_addr,
		       sizeof(struct sockaddr_storage));
		new_tsk->default_stream = child_tsk->default_stream;
		child_tsk->default_stream = NULL;
		inet_sk_set_state(newsk, TCP_ESTABLISHED);

		pr_debug("tquic: accepted connection from queue\n");
		return 0;
	}
	spin_unlock_bh(&sk->sk_lock.slock);

	/* Fallback: create a new connection if queue was empty */
	new_tsk = tquic_sk(newsk);
	new_conn = tquic_conn_create(newsk, GFP_KERNEL);
	if (!new_conn)
		return -ENOMEM;

	new_tsk->conn = new_conn;
	inet_sk_set_state(newsk, TCP_ESTABLISHED);

	pr_debug("tquic: accepted connection\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_accept);

/*
 * Get socket name
 */
static int tquic_getname(struct socket *sock, struct sockaddr *addr, int peer)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	struct sockaddr_storage *saddr;
	int len;

	if (peer)
		saddr = &tsk->connect_addr;
	else
		saddr = &tsk->bind_addr;

	len = sizeof(struct sockaddr_in);
	if (saddr->ss_family == AF_INET6)
		len = sizeof(struct sockaddr_in6);

	memcpy(addr, saddr, len);
	return len;
}

/*
 * Poll for events
 */
static __poll_t tquic_poll_socket(struct file *file, struct socket *sock,
				  poll_table *wait)
{
	return tquic_poll(file, sock, wait);
}

__poll_t tquic_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	__poll_t mask = 0;

	sock_poll_wait(file, sock, wait);

	if (sk->sk_state == TCP_LISTEN) {
		if (tsk->accept_queue_len > 0)
			mask |= EPOLLIN | EPOLLRDNORM;
	} else if (sk->sk_state == TCP_ESTABLISHED) {
		/* Check if data available to read */
		if (tsk->conn && tsk->default_stream) {
			if (!skb_queue_empty(&tsk->default_stream->recv_buf))
				mask |= EPOLLIN | EPOLLRDNORM;
		}

		/* Always writable for now */
		mask |= EPOLLOUT | EPOLLWRNORM;
	}

	if (sk->sk_err)
		mask |= EPOLLERR;

	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= EPOLLRDHUP | EPOLLIN | EPOLLRDNORM;

	return mask;
}
EXPORT_SYMBOL_GPL(tquic_poll);

/*
 * Shutdown connection
 */
static int tquic_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	int ret = 0;

	if (tsk->conn && tsk->conn->state == TQUIC_CONN_CONNECTED) {
		/* Use graceful shutdown via state machine */
		ret = tquic_conn_shutdown(tsk->conn);
	}

	if ((how & SEND_SHUTDOWN) && (how & RCV_SHUTDOWN))
		inet_sk_set_state(sk, TCP_CLOSE);

	return ret;
}

/*
 * Close connection
 */
int tquic_close(struct sock *sk, long timeout)
{
	struct tquic_sock *tsk = tquic_sk(sk);

	if (tsk->conn) {
		/*
		 * If we're still connected, initiate graceful close.
		 * The connection close will proceed through CLOSING -> DRAINING -> CLOSED.
		 */
		if (tsk->conn->state == TQUIC_CONN_CONNECTED ||
		    tsk->conn->state == TQUIC_CONN_CONNECTING) {
			tquic_conn_close_with_error(tsk->conn, 0x00, NULL);
		}
	}

	inet_sk_set_state(sk, TCP_CLOSE);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_close);

/*
 * Set socket options
 */
static int tquic_setsockopt(struct socket *sock, int level, int optname,
			    sockptr_t optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	int val;

	if (level != SOL_TQUIC)
		return -ENOPROTOOPT;

	if (optlen < sizeof(int))
		return -EINVAL;

	if (copy_from_sockptr(&val, optval, sizeof(val)))
		return -EFAULT;

	switch (optname) {
	case TQUIC_NODELAY:
		tsk->nodelay = !!val;
		break;

	case TQUIC_IDLE_TIMEOUT:
		if (tsk->conn)
			tsk->conn->idle_timeout = val;
		break;

	case TQUIC_BOND_MODE:
		if (tsk->conn)
			return tquic_bond_set_mode(tsk->conn, val);
		break;

	case TQUIC_BOND_PATH_PRIO:
	case TQUIC_BOND_PATH_WEIGHT:
		/* These require additional path info via ancillary data */
		return -EINVAL;

	case TQUIC_MULTIPATH:
		/* Enable/disable multipath */
		break;

	default:
		return -ENOPROTOOPT;
	}

	return 0;
}

/*
 * Get socket options
 */
static int tquic_getsockopt(struct socket *sock, int level, int optname,
			    char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	int len, val;

	if (level != SOL_TQUIC)
		return -ENOPROTOOPT;

	if (get_user(len, optlen))
		return -EFAULT;

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case TQUIC_INFO:
		if (len < sizeof(struct tquic_info))
			return -EINVAL;
		if (tsk->conn) {
			struct tquic_info info = {0};
			info.state = tsk->conn->state;
			info.version = tsk->conn->version;
			info.paths_active = tsk->conn->num_paths;
			info.bytes_sent = tsk->conn->stats.tx_bytes;
			info.bytes_received = tsk->conn->stats.rx_bytes;
			if (copy_to_user(optval, &info, sizeof(info)))
				return -EFAULT;
			if (put_user(sizeof(info), optlen))
				return -EFAULT;
		}
		return 0;

	case TQUIC_IDLE_TIMEOUT:
		val = tsk->conn ? tsk->conn->idle_timeout : 0;
		break;

	case TQUIC_BOND_MODE:
		if (tsk->conn && tsk->conn->scheduler) {
			struct tquic_bond_state *bond = tsk->conn->scheduler;
			val = bond->mode;
		} else {
			val = 0;
		}
		break;

	case TQUIC_PATH_STATUS:
		if (tsk->conn) {
			val = tsk->conn->num_paths;
		} else {
			val = 0;
		}
		break;

	default:
		return -ENOPROTOOPT;
	}

	len = min_t(unsigned int, len, sizeof(int));
	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;

	return 0;
}

/*
 * Send message
 */
static int tquic_sendmsg_socket(struct socket *sock, struct msghdr *msg,
				size_t len)
{
	return tquic_sendmsg(sock->sk, msg, len);
}

int tquic_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct tquic_stream *stream;
	struct sk_buff *skb;
	int copied = 0;

	if (!conn || conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/* Use or create default stream */
	stream = tsk->default_stream;
	if (!stream) {
		stream = tquic_stream_open(conn, true);
		if (!stream)
			return -ENOMEM;
		tsk->default_stream = stream;
	}

	/* Copy data to stream buffer */
	while (copied < len) {
		size_t chunk = min_t(size_t, len - copied, 1200);

		skb = alloc_skb(chunk, GFP_KERNEL);
		if (!skb)
			return copied > 0 ? copied : -ENOMEM;

		if (copy_from_iter(skb_put(skb, chunk), chunk, &msg->msg_iter) != chunk) {
			kfree_skb(skb);
			return copied > 0 ? copied : -EFAULT;
		}

		skb_queue_tail(&stream->send_buf, skb);
		copied += chunk;

		conn->stats.tx_bytes += chunk;
	}

	/*
	 * Trigger actual transmission.
	 * If nodelay is set, flush immediately. Otherwise, let the
	 * output subsystem coalesce data based on congestion state.
	 */
	if (tsk->nodelay || stream->send_offset == 0) {
		/* Flush stream data to the network */
		tquic_output_flush(conn);
	}

	return copied;
}
EXPORT_SYMBOL_GPL(tquic_sendmsg);

/*
 * Receive message
 */
static int tquic_recvmsg_socket(struct socket *sock, struct msghdr *msg,
				size_t len, int flags)
{
	return tquic_recvmsg(sock->sk, msg, len, flags);
}

int tquic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct tquic_stream *stream;
	struct sk_buff *skb;
	int copied = 0;

	if (!conn || conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	stream = tsk->default_stream;
	if (!stream)
		return 0;

	while (copied < len && !skb_queue_empty(&stream->recv_buf)) {
		size_t chunk;

		skb = skb_dequeue(&stream->recv_buf);
		if (!skb)
			break;

		chunk = min_t(size_t, len - copied, skb->len);

		if (copy_to_iter(skb->data, chunk, &msg->msg_iter) != chunk) {
			skb_queue_head(&stream->recv_buf, skb);
			return copied > 0 ? copied : -EFAULT;
		}

		copied += chunk;

		if (chunk < skb->len) {
			/* Partial read, requeue remainder */
			skb_pull(skb, chunk);
			skb_queue_head(&stream->recv_buf, skb);
		} else {
			kfree_skb(skb);
		}

		conn->stats.rx_bytes += chunk;
	}

	return copied;
}
EXPORT_SYMBOL_GPL(tquic_recvmsg);

/*
 * Hash/unhash operations (minimal for now)
 */
static int tquic_hash(struct sock *sk)
{
	return 0;
}

static void tquic_unhash(struct sock *sk)
{
}

static int tquic_get_port(struct sock *sk, unsigned short snum)
{
	return 0;
}

/*
 * Socket registration
 */
static struct inet_protosw tquic_protosw = {
	.type = SOCK_STREAM,
	.protocol = IPPROTO_TQUIC,
	.prot = &tquic_prot,
	.ops = &tquic_proto_ops,
};

int __init tquic_socket_init(void)
{
	int ret;

	ret = proto_register(&tquic_prot, 1);
	if (ret)
		return ret;

	inet_register_protosw(&tquic_protosw);

	pr_info("tquic: socket interface registered\n");
	return 0;
}

void __exit tquic_socket_exit(void)
{
	inet_unregister_protosw(&tquic_protosw);
	proto_unregister(&tquic_prot);
}
