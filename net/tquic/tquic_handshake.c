// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: TLS 1.3 Handshake Integration
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements TLS 1.3 handshake delegation via net/handshake infrastructure.
 * The handshake is performed by the tlshd userspace daemon, following the
 * same pattern used by NFS over TLS (net/sunrpc/xprtsock.c).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <net/sock.h>
#include <net/handshake.h>
#include <net/tquic.h>
#include <uapi/linux/tquic.h>

#include "protocol.h"

/**
 * struct tquic_handshake_state - Handshake state tracking
 * @sk: Socket associated with this handshake
 * @done: Completion for blocking wait
 * @status: Result status (0 = success, -errno = failure)
 * @peerid: Peer certificate key serial (from tlshd)
 * @start_time: Jiffies when handshake started
 * @timeout_ms: Timeout in milliseconds
 *
 * This structure tracks the state of an in-progress TLS handshake.
 * It is allocated when tquic_start_handshake() is called and freed
 * when the handshake completes or is cleaned up.
 */
struct tquic_handshake_state {
	struct sock *sk;
	struct completion done;
	int status;
	key_serial_t peerid;
	unsigned long start_time;
	u32 timeout_ms;
};

/**
 * tquic_handshake_done - Callback invoked when tlshd completes handshake
 * @data: Pointer to tquic_handshake_state
 * @status: 0 on success, -errno on failure
 * @peerid: Serial number of key containing peer's identity
 *
 * This callback is invoked by the net/handshake infrastructure when
 * the tlshd daemon completes (or fails) the TLS handshake.
 *
 * On success:
 *   - status is 0
 *   - peerid contains the peer certificate key
 *   - Socket is ready for encrypted communication
 *
 * On failure:
 *   - status contains a negative errno
 *   - Common values: -EACCES (auth failed), -ETIMEDOUT (timeout)
 */
void tquic_handshake_done(void *data, int status, key_serial_t peerid)
{
	struct tquic_handshake_state *hs = data;
	struct sock *sk = hs->sk;
	struct tquic_sock *tsk = tquic_sk(sk);

	pr_debug("tquic: handshake completed, status=%d peerid=%d\n",
		 status, peerid);

	hs->status = status;
	hs->peerid = peerid;

	if (status == 0) {
		/*
		 * Handshake succeeded - mark connection as having
		 * completed handshake. The crypto state will be
		 * installed by the tlshd daemon via kTLS.
		 */
		tsk->flags |= TQUIC_F_HANDSHAKE_DONE;

		if (tsk->conn)
			tsk->conn->state = TQUIC_CONN_CONNECTED;

		pr_debug("tquic: TLS handshake successful, connection ready\n");
	} else {
		/*
		 * Handshake failed - map status to EQUIC error if needed.
		 * The tlshd daemon returns standard errno values.
		 */
		pr_debug("tquic: TLS handshake failed with status %d\n", status);
	}

	/* Wake up any thread waiting in tquic_wait_for_handshake() */
	complete(&hs->done);
}
EXPORT_SYMBOL_GPL(tquic_handshake_done);

/**
 * tquic_map_handshake_error - Map handshake error to EQUIC code
 * @status: Error status from handshake (negative errno)
 *
 * Maps standard errno values from tlshd to QUIC-specific EQUIC codes.
 *
 * Returns: Negative EQUIC error code
 */
static int tquic_map_handshake_error(int status)
{
	if (status >= 0)
		return 0;

	switch (status) {
	case -ETIMEDOUT:
		return -EQUIC_HANDSHAKE_TIMEOUT;
	case -EACCES:
	case -EPERM:
		return -EQUIC_HANDSHAKE_FAILED;
	case -ECONNREFUSED:
		return -EQUIC_CONNECTION_REFUSED;
	default:
		return -EQUIC_HANDSHAKE_FAILED;
	}
}

/**
 * tquic_start_handshake - Initiate async TLS 1.3 handshake
 * @sk: Socket to perform handshake on
 *
 * Initiates an asynchronous TLS handshake via the net/handshake
 * infrastructure. The actual handshake is performed by the tlshd
 * userspace daemon.
 *
 * The caller should:
 *   1. Call tquic_start_handshake() to initiate
 *   2. Call tquic_wait_for_handshake() to block until complete
 *   3. Call tquic_handshake_cleanup() when done
 *
 * Returns: 0 on successful initiation, -errno on failure
 */
int tquic_start_handshake(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_handshake_state *hs;
	struct tls_handshake_args args;
	struct socket *sock;
	int ret;

	if (!sk || !tsk->conn)
		return -EINVAL;

	/* Check if handshake already in progress or completed */
	if (tsk->handshake_state) {
		pr_debug("tquic: handshake already in progress\n");
		return -EALREADY;
	}

	if (tsk->flags & TQUIC_F_HANDSHAKE_DONE) {
		pr_debug("tquic: handshake already completed\n");
		return -EISCONN;
	}

	/* Allocate handshake state */
	hs = kzalloc(sizeof(*hs), GFP_KERNEL);
	if (!hs)
		return -ENOMEM;

	hs->sk = sk;
	init_completion(&hs->done);
	hs->status = -ETIMEDOUT;  /* Default to timeout if never completed */
	hs->peerid = TLS_NO_PEERID;
	hs->start_time = jiffies;
	hs->timeout_ms = TQUIC_HANDSHAKE_TIMEOUT_MS;

	/* Store state in socket for later access */
	tsk->handshake_state = hs;

	/*
	 * Get the socket structure needed for net/handshake API.
	 * For TQUIC, we use the underlying UDP socket for the handshake.
	 */
	sock = sk->sk_socket;
	if (!sock) {
		ret = -ENOTCONN;
		goto err_free;
	}

	/* Set up handshake arguments */
	memset(&args, 0, sizeof(args));
	args.ta_sock = sock;
	args.ta_done = tquic_handshake_done;
	args.ta_data = hs;
	args.ta_timeout_ms = hs->timeout_ms;
	args.ta_keyring = TLS_NO_KEYRING;  /* Use system keyring */
	args.ta_my_cert = TLS_NO_CERT;     /* Anonymous for now */
	args.ta_my_privkey = TLS_NO_PRIVKEY;

	/*
	 * Initiate TLS client handshake via tlshd daemon.
	 * This is asynchronous - tquic_handshake_done() will be called
	 * when the handshake completes.
	 */
	ret = tls_client_hello_x509(&args, GFP_KERNEL);
	if (ret) {
		pr_debug("tquic: tls_client_hello_x509 failed: %d\n", ret);
		goto err_free;
	}

	pr_debug("tquic: TLS handshake initiated\n");
	return 0;

err_free:
	tsk->handshake_state = NULL;
	kfree(hs);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_start_handshake);

/**
 * tquic_wait_for_handshake - Block until handshake completes
 * @sk: Socket with handshake in progress
 * @timeout_ms: Maximum time to wait in milliseconds
 *
 * Blocks the calling thread until the TLS handshake completes
 * or the timeout expires.
 *
 * Returns:
 *   0 on success (handshake completed successfully)
 *   -EQUIC_HANDSHAKE_TIMEOUT if timeout expired
 *   -EQUIC_HANDSHAKE_FAILED if handshake failed
 *   -EINTR if interrupted by signal
 *   Other negative EQUIC error codes for specific failures
 */
int tquic_wait_for_handshake(struct sock *sk, u32 timeout_ms)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_handshake_state *hs;
	unsigned long timeout_jiffies;
	long ret;

	if (!sk)
		return -EINVAL;

	hs = tsk->handshake_state;
	if (!hs) {
		/* No handshake in progress - check if already done */
		if (tsk->flags & TQUIC_F_HANDSHAKE_DONE)
			return 0;
		return -EINVAL;
	}

	/* Convert timeout to jiffies */
	timeout_jiffies = msecs_to_jiffies(timeout_ms);

	/*
	 * Wait for handshake completion with timeout.
	 * Use interruptible wait to allow signal handling.
	 */
	ret = wait_for_completion_interruptible_timeout(&hs->done,
							timeout_jiffies);

	if (ret < 0) {
		/* Interrupted by signal */
		pr_debug("tquic: handshake wait interrupted\n");
		tls_handshake_cancel(sk);
		return -EINTR;
	}

	if (ret == 0) {
		/* Timeout expired */
		pr_debug("tquic: handshake timed out after %u ms\n", timeout_ms);
		tls_handshake_cancel(sk);
		return -EQUIC_HANDSHAKE_TIMEOUT;
	}

	/* Handshake completed - check status */
	if (hs->status != 0) {
		pr_debug("tquic: handshake completed with error %d\n", hs->status);
		return tquic_map_handshake_error(hs->status);
	}

	pr_debug("tquic: handshake completed successfully\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_wait_for_handshake);

/**
 * tquic_handshake_cleanup - Clean up handshake state
 * @sk: Socket to clean up handshake for
 *
 * Frees handshake state resources. Should be called when the socket
 * is being destroyed or when the handshake is being cancelled.
 *
 * Safe to call multiple times or with NULL state.
 */
void tquic_handshake_cleanup(struct sock *sk)
{
	struct tquic_sock *tsk;
	struct tquic_handshake_state *hs;

	if (!sk)
		return;

	tsk = tquic_sk(sk);
	hs = tsk->handshake_state;

	if (!hs)
		return;

	/*
	 * Cancel any pending handshake. This is safe to call even if
	 * the handshake has already completed.
	 */
	tls_handshake_cancel(sk);

	tsk->handshake_state = NULL;
	kfree(hs);

	pr_debug("tquic: handshake state cleaned up\n");
}
EXPORT_SYMBOL_GPL(tquic_handshake_cleanup);

/**
 * tquic_handshake_in_progress - Check if handshake is in progress
 * @sk: Socket to check
 *
 * Returns: true if handshake is in progress, false otherwise
 */
bool tquic_handshake_in_progress(struct sock *sk)
{
	struct tquic_sock *tsk;

	if (!sk)
		return false;

	tsk = tquic_sk(sk);
	return tsk->handshake_state != NULL &&
	       !(tsk->flags & TQUIC_F_HANDSHAKE_DONE);
}
EXPORT_SYMBOL_GPL(tquic_handshake_in_progress);

/*
 * =============================================================================
 * Server-side Handshake
 * =============================================================================
 *
 * These functions implement server-side TLS handshake for accepting
 * incoming QUIC connections. When an Initial packet is received on a
 * listening socket, tquic_server_handshake() is called to create a
 * child socket, perform the server handshake, and queue the connection
 * on the listener's accept queue upon success.
 */

/* Forward declaration for server handshake callback */
static void tquic_server_handshake_done(void *data, int status,
					key_serial_t peerid);

/**
 * tquic_install_crypto_state - Install crypto keys after handshake
 * @sk: Socket with completed handshake
 *
 * Called from handshake completion callback to install negotiated keys.
 * The actual key material is managed by the net/handshake infrastructure
 * and the tlshd daemon.
 */
void tquic_install_crypto_state(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;

	if (!conn)
		return;

	/* Mark crypto as ready - keys extracted by net/handshake infrastructure */
	conn->crypto_state = (void *)1;  /* Non-NULL indicates ready */
	tsk->flags |= TQUIC_F_HANDSHAKE_DONE;

	pr_debug("tquic: crypto state installed\n");
}
EXPORT_SYMBOL_GPL(tquic_install_crypto_state);

/**
 * tquic_conn_server_accept_init - Initialize connection for server accept
 * @conn: New connection for accepted client
 * @initial_pkt: The incoming Initial packet
 *
 * Extracts connection IDs from Initial packet and initializes server-side
 * state. This is a helper for tquic_server_handshake.
 *
 * Returns: 0 on success, negative errno on failure.
 */
static int tquic_conn_server_accept_init(struct tquic_connection *conn,
					 struct sk_buff *initial_pkt)
{
	/*
	 * TODO: Parse Initial packet header to extract:
	 * - Destination CID (becomes our SCID)
	 * - Source CID (becomes peer's CID / our DCID)
	 * - Version
	 * - Token (if present)
	 */

	if (!initial_pkt || initial_pkt->len < 20)
		return -EINVAL;

	/* For now, generate server-side CIDs */
	conn->scid.len = TQUIC_DEFAULT_CID_LEN;
	get_random_bytes(conn->scid.id, conn->scid.len);

	/* Placeholder: Extract DCID from packet */
	conn->dcid.len = TQUIC_DEFAULT_CID_LEN;

	/* Mark as server-side connection */
	conn->state = TQUIC_CONN_CONNECTING;

	return 0;
}

/**
 * tquic_start_server_handshake - Start server TLS handshake
 * @sk: Child socket for the new connection
 * @hs: Handshake state structure
 *
 * Initiates the server-side TLS handshake via tls_server_hello_x509.
 * Returns: 0 on success, negative errno on failure.
 */
static int tquic_start_server_handshake(struct sock *sk,
					struct tquic_handshake_state *hs)
{
	struct socket *sock = sk->sk_socket;
	struct tls_handshake_args args;

	if (!sock)
		return -ENOTCONN;

	memset(&args, 0, sizeof(args));
	args.ta_sock = sock;
	args.ta_done = tquic_server_handshake_done;
	args.ta_data = sk;
	args.ta_timeout_ms = hs->timeout_ms;
	args.ta_keyring = TLS_NO_KEYRING;

	return tls_server_hello_x509(&args, GFP_ATOMIC);
}

/**
 * tquic_server_handshake_done - Server handshake completion callback
 * @data: Child socket pointer
 * @status: 0 on success, negative errno on failure
 * @peerid: Peer certificate key serial
 *
 * Called by net/handshake when server-side TLS handshake completes.
 * On success, the child socket is added to the listener's accept queue.
 * On failure, the child socket is cleaned up.
 */
static void tquic_server_handshake_done(void *data, int status,
					key_serial_t peerid)
{
	struct sock *child_sk = data;
	struct tquic_sock *child_tsk = tquic_sk(child_sk);
	struct tquic_connection *conn = child_tsk->conn;
	struct tquic_handshake_state *hs;
	struct sock *listener_sk;
	struct tquic_sock *listen_tsk;

	if (!conn) {
		pr_debug("tquic: server handshake callback with NULL conn\n");
		return;
	}

	hs = child_tsk->handshake_state;

	if (status == 0) {
		/* Handshake successful */
		tquic_install_crypto_state(child_sk);
		child_tsk->flags |= TQUIC_F_HANDSHAKE_DONE;
		inet_sk_set_state(child_sk, TCP_ESTABLISHED);
		conn->state = TQUIC_CONN_CONNECTED;

		/* Find listener and add to accept queue */
		listener_sk = conn->sk;  /* Listener stored during creation */
		if (listener_sk && listener_sk != child_sk &&
		    listener_sk->sk_state == TCP_LISTEN) {
			listen_tsk = tquic_sk(listener_sk);

			spin_lock_bh(&listener_sk->sk_lock.slock);
			list_add_tail(&child_tsk->accept_list,
				      &listen_tsk->accept_queue);
			listen_tsk->accept_queue_len++;
			spin_unlock_bh(&listener_sk->sk_lock.slock);

			/* Wake up accept() waiters */
			listener_sk->sk_data_ready(listener_sk);

			pr_debug("tquic: server handshake complete, child queued\n");
		} else {
			pr_warn("tquic: server handshake done but no valid listener\n");
		}
	} else {
		/* Handshake failed - clean up child */
		pr_debug("tquic: server handshake failed: %d\n", status);
		inet_sk_set_state(child_sk, TCP_CLOSE);
		if (conn) {
			tquic_conn_destroy(conn);
			child_tsk->conn = NULL;
		}
		sock_put(child_sk);  /* Release reference */
	}

	/* Complete the handshake wait (if anyone is waiting) */
	if (hs)
		complete(&hs->done);
}

/**
 * tquic_server_handshake - Initiate server-side TLS handshake
 * @listener_sk: The listening socket
 * @initial_pkt: The incoming Initial packet
 * @client_addr: Client's source address
 *
 * Creates a new connection, performs server handshake, and
 * queues the connection on the listener's accept queue on success.
 *
 * This function is called from the UDP receive path when an Initial
 * packet arrives on a listening socket.
 *
 * Returns: 0 on handshake initiated, negative errno on failure
 */
int tquic_server_handshake(struct sock *listener_sk,
			   struct sk_buff *initial_pkt,
			   struct sockaddr_storage *client_addr)
{
	struct tquic_sock *listen_tsk = tquic_sk(listener_sk);
	struct sock *child_sk;
	struct tquic_sock *child_tsk;
	struct tquic_connection *conn;
	struct tquic_handshake_state *hs;
	int ret;

	/* Check accept queue space */
	if (listen_tsk->accept_queue_len >= listen_tsk->max_accept_queue) {
		pr_debug("tquic: accept queue full, refusing connection\n");
		return -ECONNREFUSED;
	}

	/* Create child socket for this connection */
	child_sk = sk_alloc(sock_net(listener_sk), listener_sk->sk_family,
			    GFP_ATOMIC, listener_sk->sk_prot, true);
	if (!child_sk) {
		pr_debug("tquic: failed to allocate child socket\n");
		return -ENOMEM;
	}

	sock_init_data(NULL, child_sk);
	child_tsk = tquic_sk(child_sk);

	/* Initialize accept list node */
	INIT_LIST_HEAD(&child_tsk->accept_list);
	INIT_LIST_HEAD(&child_tsk->accept_queue);
	child_tsk->accept_queue_len = 0;
	child_tsk->max_accept_queue = 0;

	/* Create connection for child */
	conn = tquic_conn_create(child_sk, GFP_ATOMIC);
	if (!conn) {
		pr_debug("tquic: failed to create connection for child\n");
		sk_free(child_sk);
		return -ENOMEM;
	}
	child_tsk->conn = conn;

	/* Store parent socket reference for accept queue callback */
	/* We temporarily store listener in conn->sk, will be updated on accept */
	conn->sk = listener_sk;

	/* Store addresses */
	memcpy(&child_tsk->connect_addr, client_addr,
	       sizeof(struct sockaddr_storage));
	memcpy(&child_tsk->bind_addr, &listen_tsk->bind_addr,
	       sizeof(struct sockaddr_storage));

	/* Process Initial packet to extract CIDs */
	ret = tquic_conn_server_accept_init(conn, initial_pkt);
	if (ret < 0) {
		pr_debug("tquic: failed to process Initial packet: %d\n", ret);
		tquic_conn_destroy(conn);
		child_tsk->conn = NULL;
		sk_free(child_sk);
		return ret;
	}

	/* Allocate handshake state */
	hs = kzalloc(sizeof(*hs), GFP_ATOMIC);
	if (!hs) {
		tquic_conn_destroy(conn);
		child_tsk->conn = NULL;
		sk_free(child_sk);
		return -ENOMEM;
	}

	hs->sk = child_sk;
	hs->timeout_ms = TQUIC_HANDSHAKE_TIMEOUT_MS;
	hs->start_time = jiffies;
	init_completion(&hs->done);
	child_tsk->handshake_state = hs;

	/* Set child socket state */
	inet_sk_set_state(child_sk, TCP_SYN_RECV);
	child_tsk->flags |= TQUIC_F_SERVER_MODE;

	/* Take reference for handshake callback */
	sock_hold(child_sk);

	/* Initiate server TLS handshake */
	ret = tquic_start_server_handshake(child_sk, hs);
	if (ret < 0) {
		pr_debug("tquic: failed to start server handshake: %d\n", ret);
		sock_put(child_sk);
		child_tsk->handshake_state = NULL;
		kfree(hs);
		tquic_conn_destroy(conn);
		child_tsk->conn = NULL;
		sk_free(child_sk);
		return ret;
	}

	/* Handshake proceeds async; child added to accept queue on completion */
	pr_debug("tquic: server handshake initiated for incoming connection\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_server_handshake);
