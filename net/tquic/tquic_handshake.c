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
