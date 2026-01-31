/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * QUIC	An implementation of the QUIC transport protocol for the LINUX
 *	operating system. QUIC is implemented using the BSD Socket
 *	interface as the means of communication with user level.
 *
 *	Definitions for the QUIC protocol (RFC 9000, RFC 9001, RFC 9002).
 *
 * Authors:	QUIC Kernel Development Team
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */
#ifndef _UAPI_LINUX_QUIC_H
#define _UAPI_LINUX_QUIC_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>

/*
 * Address family for QUIC sockets.
 * Note: This value needs to be officially allocated.
 * Currently using next available after AF_MCTP (45).
 */
#define AF_QUIC			46
#define PF_QUIC			AF_QUIC

/*
 * QUIC socket option level
 */
#define SOL_QUIC		287

/*
 * QUIC protocol constants (RFC 9000)
 */
#define QUIC_VERSION_1			0x00000001	/* RFC 9000 */
#define QUIC_VERSION_2			0x6b3343cf	/* RFC 9369 */
#define QUIC_VERSION_NEGOTIATION	0x00000000	/* Version negotiation */

/* Maximum sizes per RFC 9000 */
#define QUIC_MAX_PACKET_SIZE		65527		/* Maximum UDP payload */
#define QUIC_MIN_INITIAL_SIZE		1200		/* Minimum Initial packet */
#define QUIC_MAX_CID_LENGTH		20		/* Max Connection ID length */
#define QUIC_MIN_CID_LENGTH		0		/* Min Connection ID length */
#define QUIC_MAX_STREAMS		(1ULL << 62)	/* Max stream count */
#define QUIC_MAX_STREAM_DATA		(1ULL << 62)	/* Max stream data */
#define QUIC_MAX_DATA			(1ULL << 62)	/* Max connection data */
#define QUIC_MAX_UDP_PAYLOAD		65527		/* Max UDP payload size */
#define QUIC_DEFAULT_MTU		1280		/* Default path MTU */
#define QUIC_MAX_ALPN_LENGTH		255		/* Max ALPN string length */
#define QUIC_MAX_TOKEN_LENGTH		2048		/* Max token length */
#define QUIC_STATELESS_RESET_TOKEN_LEN	16		/* Reset token size */

/* Flow control defaults */
#define QUIC_DEFAULT_MAX_DATA			(1 << 20)	/* 1MB */
#define QUIC_DEFAULT_MAX_STREAM_DATA_BIDI_LOCAL	(1 << 18)	/* 256KB */
#define QUIC_DEFAULT_MAX_STREAM_DATA_BIDI_REMOTE (1 << 18)	/* 256KB */
#define QUIC_DEFAULT_MAX_STREAM_DATA_UNI	(1 << 18)	/* 256KB */
#define QUIC_DEFAULT_MAX_STREAMS_BIDI		128
#define QUIC_DEFAULT_MAX_STREAMS_UNI		128

/* Timing constants (in milliseconds) */
#define QUIC_DEFAULT_IDLE_TIMEOUT	30000		/* 30 seconds */
#define QUIC_DEFAULT_MAX_ACK_DELAY	25		/* 25 ms */
#define QUIC_MIN_ACK_DELAY		1		/* 1 ms */
#define QUIC_DEFAULT_HANDSHAKE_TIMEOUT	60000		/* 60 seconds */

/*
 * QUIC socket options for getsockopt/setsockopt at SOL_QUIC level
 */
#define QUIC_SOCKOPT_CONNECTION_ID	1	/* Get/set local connection ID */
#define QUIC_SOCKOPT_STREAM_ID		2	/* Get/set current stream ID */
#define QUIC_SOCKOPT_KEY		3	/* Set encryption keys */
#define QUIC_SOCKOPT_ALPN		4	/* Set/get ALPN protocols */
#define QUIC_SOCKOPT_TRANSPORT_PARAMS	5	/* Set/get transport parameters */
#define QUIC_SOCKOPT_CONNECTION_STATE	6	/* Get connection state */
#define QUIC_SOCKOPT_STREAM_STATE	7	/* Get stream state */
#define QUIC_SOCKOPT_CONNECTION_INFO	8	/* Get connection info */
#define QUIC_SOCKOPT_STREAM_INFO	9	/* Get stream info */
#define QUIC_SOCKOPT_PATH_INFO		10	/* Get path info */
#define QUIC_SOCKOPT_TOKEN		11	/* Set/get address validation token */
#define QUIC_SOCKOPT_RETRY_TOKEN	12	/* Set/get retry token */
#define QUIC_SOCKOPT_ORIGINAL_DCID	13	/* Get original dest connection ID */
#define QUIC_SOCKOPT_RETRY_SCID		14	/* Get retry source connection ID */
#define QUIC_SOCKOPT_STATELESS_RESET	15	/* Set stateless reset token */
#define QUIC_SOCKOPT_VERSION		16	/* Set/get QUIC version */
#define QUIC_SOCKOPT_IDLE_TIMEOUT	17	/* Set/get idle timeout */
#define QUIC_SOCKOPT_MAX_DATA		18	/* Set/get max_data */
#define QUIC_SOCKOPT_MAX_STREAM_DATA	19	/* Set/get max_stream_data */
#define QUIC_SOCKOPT_MAX_STREAMS_BIDI	20	/* Set/get max_streams_bidi */
#define QUIC_SOCKOPT_MAX_STREAMS_UNI	21	/* Set/get max_streams_uni */
#define QUIC_SOCKOPT_ACK_DELAY		22	/* Set/get ack_delay_exponent */
#define QUIC_SOCKOPT_MAX_ACK_DELAY	23	/* Set/get max_ack_delay */
#define QUIC_SOCKOPT_ACTIVE_CID		24	/* Set/get active connection ID */
#define QUIC_SOCKOPT_DISABLE_MIGRATION	25	/* Disable connection migration */
#define QUIC_SOCKOPT_PREFERRED_ADDRESS	26	/* Set preferred address */
#define QUIC_SOCKOPT_CONGESTION		27	/* Set/get congestion control algo */
#define QUIC_SOCKOPT_PACING		28	/* Enable/disable pacing */
#define QUIC_SOCKOPT_ZEROCOPY		29	/* Enable zero-copy receive */
#define QUIC_SOCKOPT_0RTT_ENABLED	30	/* Enable 0-RTT */
#define QUIC_SOCKOPT_0RTT_KEY		31	/* Set 0-RTT encryption key */
#define QUIC_SOCKOPT_ECN		32	/* Enable ECN */
#define QUIC_SOCKOPT_DATAGRAM		33	/* Enable DATAGRAM extension */
#define QUIC_SOCKOPT_GREASE_QUIC_BIT	34	/* Enable GREASE QUIC bit */
#define QUIC_SOCKOPT_PATH_MTU		35	/* Set/get path MTU */
#define QUIC_SOCKOPT_NEW_CONNECTION_ID	36	/* Issue new connection ID */
#define QUIC_SOCKOPT_RETIRE_CONNECTION_ID 37	/* Retire connection ID */
#define QUIC_SOCKOPT_KEY_UPDATE		38	/* Trigger key update */
#define QUIC_SOCKOPT_HANDSHAKE_CONFIRMED 39	/* Check if handshake confirmed */
#define QUIC_SOCKOPT_SESSION_TICKET	40	/* Get/set TLS session ticket */
#define QUIC_SOCKOPT_EARLY_DATA		41	/* Get early data status */
#define QUIC_SOCKOPT_CC_INFO		42	/* Get congestion control info */
#define QUIC_SOCKOPT_CRYPTO_LEVEL	43	/* Set current crypto level */

/*
 * QUIC connection states
 */
enum quic_connection_state {
	QUIC_STATE_IDLE = 0,		/* Initial state */
	QUIC_STATE_CONNECTING,		/* Client sending Initial */
	QUIC_STATE_ACCEPTING,		/* Server received Initial */
	QUIC_STATE_HANDSHAKING,		/* Handshake in progress */
	QUIC_STATE_CONNECTED,		/* Handshake complete, 1-RTT available */
	QUIC_STATE_CONFIRMED,		/* Handshake confirmed */
	QUIC_STATE_DRAINING,		/* Draining period after close */
	QUIC_STATE_CLOSING,		/* Sending CONNECTION_CLOSE */
	QUIC_STATE_CLOSED,		/* Connection terminated */
};

#define QUICF_STATE_IDLE		(1 << QUIC_STATE_IDLE)
#define QUICF_STATE_CONNECTING		(1 << QUIC_STATE_CONNECTING)
#define QUICF_STATE_ACCEPTING		(1 << QUIC_STATE_ACCEPTING)
#define QUICF_STATE_HANDSHAKING		(1 << QUIC_STATE_HANDSHAKING)
#define QUICF_STATE_CONNECTED		(1 << QUIC_STATE_CONNECTED)
#define QUICF_STATE_CONFIRMED		(1 << QUIC_STATE_CONFIRMED)
#define QUICF_STATE_DRAINING		(1 << QUIC_STATE_DRAINING)
#define QUICF_STATE_CLOSING		(1 << QUIC_STATE_CLOSING)
#define QUICF_STATE_CLOSED		(1 << QUIC_STATE_CLOSED)

/*
 * QUIC stream states
 */
enum quic_stream_state {
	QUIC_STREAM_IDLE = 0,		/* Not yet opened */
	QUIC_STREAM_READY,		/* Ready to send/receive */
	QUIC_STREAM_SEND,		/* Send only (unidirectional) */
	QUIC_STREAM_RECV,		/* Receive only (unidirectional) */
	QUIC_STREAM_DATA_SENT,		/* All data sent, awaiting acks */
	QUIC_STREAM_DATA_RECVD,		/* All data received */
	QUIC_STREAM_RESET_SENT,		/* RESET_STREAM sent */
	QUIC_STREAM_RESET_RECVD,	/* RESET_STREAM received */
	QUIC_STREAM_CLOSED,		/* Stream fully closed */
};

#define QUICF_STREAM_IDLE		(1 << QUIC_STREAM_IDLE)
#define QUICF_STREAM_READY		(1 << QUIC_STREAM_READY)
#define QUICF_STREAM_SEND		(1 << QUIC_STREAM_SEND)
#define QUICF_STREAM_RECV		(1 << QUIC_STREAM_RECV)
#define QUICF_STREAM_DATA_SENT		(1 << QUIC_STREAM_DATA_SENT)
#define QUICF_STREAM_DATA_RECVD		(1 << QUIC_STREAM_DATA_RECVD)
#define QUICF_STREAM_RESET_SENT		(1 << QUIC_STREAM_RESET_SENT)
#define QUICF_STREAM_RESET_RECVD	(1 << QUIC_STREAM_RESET_RECVD)
#define QUICF_STREAM_CLOSED		(1 << QUIC_STREAM_CLOSED)

/*
 * QUIC error codes (RFC 9000 Section 20)
 */
enum quic_error_code {
	QUIC_NO_ERROR = 0x00,			/* No error */
	QUIC_INTERNAL_ERROR = 0x01,		/* Implementation error */
	QUIC_CONNECTION_REFUSED = 0x02,		/* Server refuses connection */
	QUIC_FLOW_CONTROL_ERROR = 0x03,		/* Flow control violated */
	QUIC_STREAM_LIMIT_ERROR = 0x04,		/* Too many streams */
	QUIC_STREAM_STATE_ERROR = 0x05,		/* Frame in wrong stream state */
	QUIC_FINAL_SIZE_ERROR = 0x06,		/* Change in final size */
	QUIC_FRAME_ENCODING_ERROR = 0x07,	/* Frame encoding error */
	QUIC_TRANSPORT_PARAMETER_ERROR = 0x08,	/* Transport parameter error */
	QUIC_CONNECTION_ID_LIMIT_ERROR = 0x09,	/* Too many connection IDs */
	QUIC_PROTOCOL_VIOLATION = 0x0a,		/* Generic protocol error */
	QUIC_INVALID_TOKEN = 0x0b,		/* Invalid token received */
	QUIC_APPLICATION_ERROR = 0x0c,		/* Application specific error */
	QUIC_CRYPTO_BUFFER_EXCEEDED = 0x0d,	/* CRYPTO data buffer exceeded */
	QUIC_KEY_UPDATE_ERROR = 0x0e,		/* Key update failure */
	QUIC_AEAD_LIMIT_REACHED = 0x0f,		/* AEAD usage limit reached */
	QUIC_NO_VIABLE_PATH = 0x10,		/* No usable network path */
	/* 0x0100-0x01ff: Crypto errors (TLS alert codes + 0x0100) */
	QUIC_CRYPTO_ERROR_BASE = 0x0100,	/* Base for crypto errors */
	QUIC_CRYPTO_ERROR_MAX = 0x01ff,		/* Max crypto error */
};

/* TLS-derived crypto error codes (base + TLS alert code) */
#define QUIC_CRYPTO_ERROR(alert)	(QUIC_CRYPTO_ERROR_BASE + (alert))

/* Common TLS alert mappings */
#define QUIC_CRYPTO_UNEXPECTED_MESSAGE		QUIC_CRYPTO_ERROR(10)
#define QUIC_CRYPTO_BAD_CERTIFICATE		QUIC_CRYPTO_ERROR(42)
#define QUIC_CRYPTO_CERTIFICATE_REVOKED		QUIC_CRYPTO_ERROR(44)
#define QUIC_CRYPTO_CERTIFICATE_EXPIRED		QUIC_CRYPTO_ERROR(45)
#define QUIC_CRYPTO_CERTIFICATE_UNKNOWN		QUIC_CRYPTO_ERROR(46)
#define QUIC_CRYPTO_HANDSHAKE_FAILURE		QUIC_CRYPTO_ERROR(40)
#define QUIC_CRYPTO_NO_APPLICATION_PROTOCOL	QUIC_CRYPTO_ERROR(120)

/*
 * QUIC frame types (RFC 9000 Section 12.4)
 */
enum quic_frame_type {
	QUIC_FRAME_PADDING = 0x00,
	QUIC_FRAME_PING = 0x01,
	QUIC_FRAME_ACK = 0x02,
	QUIC_FRAME_ACK_ECN = 0x03,
	QUIC_FRAME_RESET_STREAM = 0x04,
	QUIC_FRAME_STOP_SENDING = 0x05,
	QUIC_FRAME_CRYPTO = 0x06,
	QUIC_FRAME_NEW_TOKEN = 0x07,
	QUIC_FRAME_STREAM = 0x08,		/* 0x08-0x0f based on flags */
	QUIC_FRAME_STREAM_FIN = 0x09,
	QUIC_FRAME_STREAM_LEN = 0x0a,
	QUIC_FRAME_STREAM_LEN_FIN = 0x0b,
	QUIC_FRAME_STREAM_OFF = 0x0c,
	QUIC_FRAME_STREAM_OFF_FIN = 0x0d,
	QUIC_FRAME_STREAM_OFF_LEN = 0x0e,
	QUIC_FRAME_STREAM_OFF_LEN_FIN = 0x0f,
	QUIC_FRAME_MAX_DATA = 0x10,
	QUIC_FRAME_MAX_STREAM_DATA = 0x11,
	QUIC_FRAME_MAX_STREAMS_BIDI = 0x12,
	QUIC_FRAME_MAX_STREAMS_UNI = 0x13,
	QUIC_FRAME_DATA_BLOCKED = 0x14,
	QUIC_FRAME_STREAM_DATA_BLOCKED = 0x15,
	QUIC_FRAME_STREAMS_BLOCKED_BIDI = 0x16,
	QUIC_FRAME_STREAMS_BLOCKED_UNI = 0x17,
	QUIC_FRAME_NEW_CONNECTION_ID = 0x18,
	QUIC_FRAME_RETIRE_CONNECTION_ID = 0x19,
	QUIC_FRAME_PATH_CHALLENGE = 0x1a,
	QUIC_FRAME_PATH_RESPONSE = 0x1b,
	QUIC_FRAME_CONNECTION_CLOSE = 0x1c,
	QUIC_FRAME_CONNECTION_CLOSE_APP = 0x1d,
	QUIC_FRAME_HANDSHAKE_DONE = 0x1e,
	/* Extension frames */
	QUIC_FRAME_DATAGRAM = 0x30,		/* RFC 9221 */
	QUIC_FRAME_DATAGRAM_LEN = 0x31,		/* RFC 9221 */
	QUIC_FRAME_ACK_FREQUENCY = 0xaf,	/* RFC 9221 */
	QUIC_FRAME_IMMEDIATE_ACK = 0x1f,	/* RFC 9221 */
};

/* Stream frame flags (bits 0-2 of type) */
#define QUIC_STREAM_FRAME_FIN		0x01	/* Final frame for stream */
#define QUIC_STREAM_FRAME_LEN		0x02	/* Length field present */
#define QUIC_STREAM_FRAME_OFF		0x04	/* Offset field present */

/*
 * QUIC packet types (RFC 9000 Section 17)
 */
enum quic_packet_type {
	/* Long header packets (bits 4-5 of first byte) */
	QUIC_PKT_INITIAL = 0,		/* Initial packet (0x00) */
	QUIC_PKT_0RTT = 1,		/* 0-RTT Protected (0x01) */
	QUIC_PKT_HANDSHAKE = 2,		/* Handshake packet (0x02) */
	QUIC_PKT_RETRY = 3,		/* Retry packet (0x03) */
	/* Short header packets */
	QUIC_PKT_1RTT = 4,		/* Short header 1-RTT */
	/* Special packet types */
	QUIC_PKT_VERSION_NEG = 5,	/* Version Negotiation */
};

/* Packet header flags */
#define QUIC_HEADER_FORM_LONG		0x80	/* Long header form */
#define QUIC_HEADER_FORM_SHORT		0x00	/* Short header form */
#define QUIC_FIXED_BIT			0x40	/* Fixed bit (must be 1) */
#define QUIC_LONG_PACKET_TYPE_MASK	0x30	/* Packet type in long header */
#define QUIC_LONG_PACKET_TYPE_SHIFT	4
#define QUIC_SHORT_SPIN_BIT		0x20	/* Spin bit in short header */
#define QUIC_SHORT_RESERVED_MASK	0x18	/* Reserved bits */
#define QUIC_SHORT_KEY_PHASE		0x04	/* Key phase bit */
#define QUIC_SHORT_PN_LENGTH_MASK	0x03	/* Packet number length - 1 */

/*
 * Encryption levels / packet number spaces
 */
enum quic_crypto_level {
	QUIC_CRYPTO_INITIAL = 0,	/* Initial secrets */
	QUIC_CRYPTO_HANDSHAKE = 1,	/* Handshake secrets */
	QUIC_CRYPTO_APPLICATION = 2,	/* 1-RTT secrets */
	QUIC_CRYPTO_EARLY_DATA = 3,	/* 0-RTT secrets */
};

#define QUIC_CRYPTO_LEVEL_MAX		4

/*
 * ioctl commands for QUIC connection control
 */
#define QUIC_IOC_MAGIC			'Q'

/* Connection management */
#define QUIC_IOC_NEW_CONNECTION		_IO(QUIC_IOC_MAGIC, 1)
#define QUIC_IOC_CLOSE_CONNECTION	_IOW(QUIC_IOC_MAGIC, 2, struct quic_close_info)
#define QUIC_IOC_GET_CONNECTION_INFO	_IOR(QUIC_IOC_MAGIC, 3, struct quic_connection_info)
#define QUIC_IOC_MIGRATE_CONNECTION	_IOW(QUIC_IOC_MAGIC, 4, struct quic_migration_info)

/* Stream management */
#define QUIC_IOC_NEW_STREAM		_IOWR(QUIC_IOC_MAGIC, 10, struct quic_stream_open)
#define QUIC_IOC_CLOSE_STREAM		_IOW(QUIC_IOC_MAGIC, 11, __u64)
#define QUIC_IOC_RESET_STREAM		_IOW(QUIC_IOC_MAGIC, 12, struct quic_stream_reset)
#define QUIC_IOC_STOP_SENDING		_IOW(QUIC_IOC_MAGIC, 13, struct quic_stop_sending)
#define QUIC_IOC_GET_STREAM_INFO	_IOWR(QUIC_IOC_MAGIC, 14, struct quic_stream_info)

/* Path management */
#define QUIC_IOC_PATH_PROBE		_IOW(QUIC_IOC_MAGIC, 20, struct quic_path_probe)
#define QUIC_IOC_PATH_ABANDON		_IOW(QUIC_IOC_MAGIC, 21, __u32)
#define QUIC_IOC_GET_PATH_INFO		_IOWR(QUIC_IOC_MAGIC, 22, struct quic_path_info)

/* Connection ID management */
#define QUIC_IOC_NEW_CID		_IOWR(QUIC_IOC_MAGIC, 30, struct quic_connection_id_info)
#define QUIC_IOC_RETIRE_CID		_IOW(QUIC_IOC_MAGIC, 31, __u64)
#define QUIC_IOC_GET_CID_INFO		_IOR(QUIC_IOC_MAGIC, 32, struct quic_connection_id_info)

/* Key management */
#define QUIC_IOC_KEY_UPDATE		_IO(QUIC_IOC_MAGIC, 40)
#define QUIC_IOC_SET_KEY		_IOW(QUIC_IOC_MAGIC, 41, struct quic_key_info)
#define QUIC_IOC_GET_KEY_INFO		_IOR(QUIC_IOC_MAGIC, 42, struct quic_key_info)

/* Datagram extension (RFC 9221) */
#define QUIC_IOC_SEND_DATAGRAM		_IOW(QUIC_IOC_MAGIC, 50, struct quic_datagram)
#define QUIC_IOC_RECV_DATAGRAM		_IOR(QUIC_IOC_MAGIC, 51, struct quic_datagram)

/*
 * Connection ID information structure
 */
struct quic_connection_id {
	__u8	length;				/* Connection ID length (0-20) */
	__u8	id[QUIC_MAX_CID_LENGTH];	/* Connection ID bytes */
} __attribute__((packed));

struct quic_connection_id_info {
	__u64			sequence_number;	/* Sequence number */
	__u64			retire_prior_to;	/* Retire prior to value */
	struct quic_connection_id cid;			/* Connection ID */
	__u8			stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];
	__u32			flags;			/* CID flags */
} __attribute__((aligned(8)));

/* Connection ID flags */
#define QUIC_CID_FLAG_ACTIVE		0x01	/* Currently active CID */
#define QUIC_CID_FLAG_RETIRED		0x02	/* CID has been retired */
#define QUIC_CID_FLAG_PREFERRED		0x04	/* Preferred CID */

/*
 * Connection information structure (for QUIC_SOCKOPT_CONNECTION_INFO)
 */
struct quic_connection_info {
	/* State information */
	__u8		state;			/* quic_connection_state */
	__u8		version_negotiated;	/* 1 if version was negotiated */
	__u8		handshake_confirmed;	/* 1 if handshake confirmed */
	__u8		early_data_accepted;	/* 1 if 0-RTT was accepted */

	/* Connection identifiers */
	struct quic_connection_id local_cid;	/* Local connection ID */
	struct quic_connection_id remote_cid;	/* Remote connection ID */
	struct quic_connection_id original_dcid; /* Original destination CID */

	/* Version info */
	__u32		version;		/* Negotiated version */
	__u32		chosen_version;		/* Version in use */

	/* Addresses */
	struct __kernel_sockaddr_storage local_addr;	/* Local address */
	struct __kernel_sockaddr_storage remote_addr;	/* Remote address */

	/* Transport parameters */
	__u64		max_data;		/* Max connection data */
	__u64		max_stream_data_bidi_local;
	__u64		max_stream_data_bidi_remote;
	__u64		max_stream_data_uni;
	__u64		max_streams_bidi;
	__u64		max_streams_uni;
	__u32		max_idle_timeout;	/* Idle timeout (ms) */
	__u32		max_udp_payload_size;
	__u8		ack_delay_exponent;
	__u8		disable_active_migration;
	__u8		active_cid_limit;
	__u8		reserved;

	/* Statistics */
	__u64		bytes_sent;		/* Total bytes sent */
	__u64		bytes_received;		/* Total bytes received */
	__u64		bytes_acked;		/* Bytes acknowledged */
	__u64		bytes_lost;		/* Bytes lost */
	__u32		packets_sent;		/* Packets sent */
	__u32		packets_received;	/* Packets received */
	__u32		packets_lost;		/* Packets lost */
	__u32		packets_retransmitted;	/* Packets retransmitted */

	/* RTT measurements */
	__u32		min_rtt;		/* Minimum RTT (us) */
	__u32		smoothed_rtt;		/* Smoothed RTT (us) */
	__u32		rtt_variance;		/* RTT variance (us) */
	__u32		latest_rtt;		/* Latest RTT (us) */

	/* Congestion control */
	__u64		congestion_window;	/* Current cwnd (bytes) */
	__u64		bytes_in_flight;	/* Bytes in flight */
	__u32		ssthresh;		/* Slow start threshold */
	__u8		congestion_state;	/* CC state */
	__u8		ecn_ce_count;		/* ECN CE counter */
	__u16		reserved2;

	/* Timing */
	__u64		connection_established;	/* Timestamp when connected */
	__u64		last_packet_sent;	/* Last packet sent time */
	__u64		last_packet_received;	/* Last packet received time */

	/* Active counts */
	__u32		streams_open_bidi;	/* Open bidirectional streams */
	__u32		streams_open_uni;	/* Open unidirectional streams */
	__u32		cids_active;		/* Active connection IDs */
	__u32		paths_active;		/* Active paths */
} __attribute__((aligned(8)));

/*
 * Stream information structure
 */
struct quic_stream_info {
	__u64		stream_id;		/* Stream identifier */
	__u8		state;			/* quic_stream_state */
	__u8		is_local;		/* 1 if locally initiated */
	__u8		is_unidirectional;	/* 1 if unidirectional */
	__u8		fin_sent;		/* 1 if FIN sent */
	__u8		fin_received;		/* 1 if FIN received */
	__u8		reset_sent;		/* 1 if RESET sent */
	__u8		reset_received;		/* 1 if RESET received */
	__u8		reserved;

	/* Flow control */
	__u64		bytes_sent;		/* Bytes sent on stream */
	__u64		bytes_received;		/* Bytes received */
	__u64		bytes_acked;		/* Bytes acknowledged */
	__u64		max_data_local;		/* Local max_stream_data */
	__u64		max_data_remote;	/* Remote max_stream_data */
	__u64		send_offset;		/* Current send offset */
	__u64		receive_offset;		/* Current receive offset */
	__u64		final_size;		/* Final size if known */

	/* Buffering */
	__u32		send_buffer_size;	/* Send buffer bytes */
	__u32		recv_buffer_size;	/* Receive buffer bytes */

	/* Error information */
	__u64		error_code;		/* Error code if reset */
} __attribute__((aligned(8)));

/*
 * Path information structure
 */
struct quic_path_info {
	__u32		path_id;		/* Path identifier */
	__u8		state;			/* Path state */
	__u8		is_primary;		/* 1 if primary path */
	__u8		validated;		/* 1 if path validated */
	__u8		reserved;

	/* Addresses */
	struct __kernel_sockaddr_storage local_addr;
	struct __kernel_sockaddr_storage remote_addr;

	/* Path characteristics */
	__u32		mtu;			/* Path MTU */
	__u32		rtt;			/* Path RTT (us) */
	__u32		rtt_variance;		/* RTT variance (us) */
	__u32		min_rtt;		/* Minimum RTT (us) */

	/* Congestion control per path */
	__u64		congestion_window;
	__u64		bytes_in_flight;
	__u32		ssthresh;
	__u32		reserved2;

	/* Statistics */
	__u64		bytes_sent;
	__u64		bytes_received;
	__u32		packets_sent;
	__u32		packets_received;
	__u32		packets_lost;
	__u32		packets_spurious;

	/* ECN */
	__u64		ecn_ect0_count;
	__u64		ecn_ect1_count;
	__u64		ecn_ce_count;

	/* Timestamps */
	__u64		last_packet_sent;
	__u64		last_packet_received;
} __attribute__((aligned(8)));

/*
 * Structures for ioctl operations
 */

/* Stream opening */
struct quic_stream_open {
	__u64		stream_id;		/* out: assigned stream ID */
	__u32		flags;			/* in: QUIC_STREAM_FLAG_* */
	__u32		priority;		/* in: stream priority */
} __attribute__((aligned(8)));

/* Stream flags for opening */
#define QUIC_STREAM_FLAG_UNI		0x01	/* Unidirectional stream */
#define QUIC_STREAM_FLAG_BIDI		0x00	/* Bidirectional stream */
#define QUIC_STREAM_FLAG_NONBLOCK	0x02	/* Non-blocking operation */

/* Stream reset */
struct quic_stream_reset {
	__u64		stream_id;		/* Stream to reset */
	__u64		error_code;		/* Application error code */
} __attribute__((aligned(8)));

/* Stop sending */
struct quic_stop_sending {
	__u64		stream_id;		/* Stream to stop */
	__u64		error_code;		/* Application error code */
} __attribute__((aligned(8)));

/* Connection close */
struct quic_close_info {
	__u64		error_code;		/* Error code */
	__u32		frame_type;		/* Frame type that caused error */
	__u32		reason_len;		/* Length of reason phrase */
	__u8		reason[256];		/* Reason phrase (UTF-8) */
	__u8		is_app_error;		/* 1 for application error */
	__u8		reserved[7];
} __attribute__((aligned(8)));

/* Connection migration */
struct quic_migration_info {
	struct __kernel_sockaddr_storage new_local_addr;
	struct __kernel_sockaddr_storage new_remote_addr;
	__u32		flags;
	__u32		reserved;
} __attribute__((aligned(8)));

#define QUIC_MIGRATE_FLAG_PROBE_FIRST	0x01	/* Probe path before migration */
#define QUIC_MIGRATE_FLAG_DROP_OLD	0x02	/* Drop old path immediately */

/* Path probing */
struct quic_path_probe {
	struct __kernel_sockaddr_storage local_addr;
	struct __kernel_sockaddr_storage remote_addr;
	__u32		timeout_ms;		/* Probe timeout */
	__u32		flags;
} __attribute__((aligned(8)));

/*
 * Key information structure
 */
struct quic_key_info {
	__u8		level;			/* quic_crypto_level */
	__u8		direction;		/* 0=rx, 1=tx */
	__u8		key_phase;		/* Key phase bit */
	__u8		reserved;
	__u32		key_len;		/* Key length */
	__u32		iv_len;			/* IV length */
	__u32		hp_key_len;		/* Header protection key len */
	__u8		key[32];		/* Traffic key */
	__u8		iv[12];			/* Initialization vector */
	__u8		hp_key[32];		/* Header protection key */
} __attribute__((aligned(8)));

/*
 * Datagram structure (RFC 9221)
 */
struct quic_datagram {
	__u32		length;			/* Data length */
	__u32		flags;			/* Flags */
	__u8		data[0];		/* Variable length data */
} __attribute__((aligned(8)));

#define QUIC_DATAGRAM_FLAG_RELIABLE	0x01	/* Request reliability */

/*
 * Transport parameters structure
 */
struct quic_transport_params {
	struct quic_connection_id original_dcid;
	struct quic_connection_id initial_scid;
	struct quic_connection_id retry_scid;
	__u8		stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];
	__u64		max_idle_timeout;
	__u64		max_udp_payload_size;
	__u64		initial_max_data;
	__u64		initial_max_stream_data_bidi_local;
	__u64		initial_max_stream_data_bidi_remote;
	__u64		initial_max_stream_data_uni;
	__u64		initial_max_streams_bidi;
	__u64		initial_max_streams_uni;
	__u64		ack_delay_exponent;
	__u64		max_ack_delay;
	__u64		active_connection_id_limit;
	__u8		disable_active_migration;
	__u8		grease_quic_bit;
	__u8		max_datagram_frame_size_present;
	__u8		reserved[5];
	__u64		max_datagram_frame_size;
	/* Preferred address (optional) */
	__u8		preferred_address_present;
	__u8		preferred_address_ipv4[4];
	__u16		preferred_address_ipv4_port;
	__u8		preferred_address_ipv6[16];
	__u16		preferred_address_ipv6_port;
	struct quic_connection_id preferred_address_cid;
	__u8		preferred_address_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];
} __attribute__((aligned(8)));

/*
 * ALPN protocol list
 */
struct quic_alpn_list {
	__u32		count;			/* Number of protocols */
	__u32		total_len;		/* Total length of all strings */
	/* Followed by null-terminated strings */
} __attribute__((aligned(8)));

/*
 * Address validation token
 */
struct quic_token {
	__u32		length;			/* Token length */
	__u32		flags;			/* Token flags */
	__u8		data[QUIC_MAX_TOKEN_LENGTH];
} __attribute__((aligned(8)));

#define QUIC_TOKEN_FLAG_RETRY		0x01	/* Retry token */
#define QUIC_TOKEN_FLAG_NEW_TOKEN	0x02	/* NEW_TOKEN frame */

/*
 * Congestion control info
 */
struct quic_cc_info {
	char		name[16];		/* Algorithm name */
	__u8		state;			/* CC state */
	__u8		reserved[7];
	__u64		congestion_window;
	__u64		bytes_in_flight;
	__u64		ssthresh;
	__u64		pacing_rate;		/* bytes/second */
	__u32		smoothed_rtt;
	__u32		rtt_variance;
	__u32		min_rtt;
	__u32		latest_rtt;
	__u64		delivered;		/* Bytes delivered */
	__u64		lost;			/* Bytes lost */
} __attribute__((aligned(8)));

/* Congestion control states */
enum quic_cc_state {
	QUIC_CC_SLOW_START = 0,
	QUIC_CC_CONGESTION_AVOIDANCE,
	QUIC_CC_RECOVERY,
	QUIC_CC_APPLICATION_LIMITED,
};

/*
 * Stream type helpers
 */
#define QUIC_STREAM_TYPE_MASK		0x03
#define QUIC_STREAM_CLIENT_BIDI		0x00
#define QUIC_STREAM_SERVER_BIDI		0x01
#define QUIC_STREAM_CLIENT_UNI		0x02
#define QUIC_STREAM_SERVER_UNI		0x03

#define QUIC_STREAM_IS_CLIENT_INITIATED(id) (((id) & 0x01) == 0)
#define QUIC_STREAM_IS_SERVER_INITIATED(id) (((id) & 0x01) == 1)
#define QUIC_STREAM_IS_BIDI(id)		    (((id) & 0x02) == 0)
#define QUIC_STREAM_IS_UNI(id)		    (((id) & 0x02) == 2)

/*
 * cmsg types for sendmsg/recvmsg
 */
#define QUIC_CMSG_STREAM_ID		1	/* Stream ID for message */
#define QUIC_CMSG_FIN			2	/* FIN flag */
#define QUIC_CMSG_DATAGRAM		3	/* Datagram message */
#define QUIC_CMSG_STREAM_FLAGS		4	/* Stream flags */

/*
 * Socket address structure for QUIC
 */
struct sockaddr_quic {
	__kernel_sa_family_t	sq_family;	/* AF_QUIC */
	__u16			sq_port;	/* Port number */
	__u32			sq_flowinfo;	/* Flow info */
	union {
		struct in_addr	sq_addr4;	/* IPv4 address */
		struct in6_addr	sq_addr6;	/* IPv6 address */
	};
	__u32			sq_scope_id;	/* Scope ID for link-local */
	struct quic_connection_id sq_cid;	/* Connection ID */
};

#endif /* _UAPI_LINUX_QUIC_H */
