// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC Packet Handling
 *
 * Implementation of QUIC packet parsing, construction, and frame handling
 * according to RFC 9000 and RFC 9001.
 *
 * Copyright (c) 2024
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/hrtimer.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/inet_common.h>
#include <net/ip.h>
#include <net/quic.h>
#include <net/tquic.h>
#include <uapi/linux/quic.h>

/*
 * QUIC Variable-Length Integer Encoding (RFC 9000 Section 16)
 */

/**
 * quic_varint_encode - Encode a variable-length integer
 * @buf: Buffer to write to
 * @val: Value to encode
 * @len: Available buffer length
 *
 * Returns: Number of bytes written, or negative error
 */
int quic_varint_encode(u8 *buf, u64 val, size_t len)
{
	if (val <= 63) {
		if (len < 1)
			return -ENOBUFS;
		buf[0] = (u8)val;
		return 1;
	} else if (val <= 16383) {
		if (len < 2)
			return -ENOBUFS;
		buf[0] = (u8)(0x40 | (val >> 8));
		buf[1] = (u8)(val & 0xff);
		return 2;
	} else if (val <= 1073741823) {
		if (len < 4)
			return -ENOBUFS;
		buf[0] = (u8)(0x80 | (val >> 24));
		buf[1] = (u8)((val >> 16) & 0xff);
		buf[2] = (u8)((val >> 8) & 0xff);
		buf[3] = (u8)(val & 0xff);
		return 4;
	} else {
		if (len < 8)
			return -ENOBUFS;
		buf[0] = (u8)(0xc0 | (val >> 56));
		buf[1] = (u8)((val >> 48) & 0xff);
		buf[2] = (u8)((val >> 40) & 0xff);
		buf[3] = (u8)((val >> 32) & 0xff);
		buf[4] = (u8)((val >> 24) & 0xff);
		buf[5] = (u8)((val >> 16) & 0xff);
		buf[6] = (u8)((val >> 8) & 0xff);
		buf[7] = (u8)(val & 0xff);
		return 8;
	}
}
EXPORT_SYMBOL_GPL(quic_varint_encode);

/**
 * quic_varint_decode - Decode a variable-length integer
 * @buf: Buffer to read from
 * @len: Available buffer length
 * @val: Pointer to store decoded value
 *
 * Returns: Number of bytes read, or negative error
 */
int quic_varint_decode(const u8 *buf, size_t len, u64 *val)
{
	u8 prefix;
	int enc_len;

	if (len < 1)
		return -EINVAL;

	prefix = buf[0] >> 6;
	enc_len = 1 << prefix;

	if (len < enc_len)
		return -EINVAL;

	switch (enc_len) {
	case 1:
		*val = buf[0] & 0x3f;
		break;
	case 2:
		*val = ((u64)(buf[0] & 0x3f) << 8) | buf[1];
		break;
	case 4:
		*val = ((u64)(buf[0] & 0x3f) << 24) |
		       ((u64)buf[1] << 16) |
		       ((u64)buf[2] << 8) |
		       buf[3];
		break;
	case 8:
		*val = ((u64)(buf[0] & 0x3f) << 56) |
		       ((u64)buf[1] << 48) |
		       ((u64)buf[2] << 40) |
		       ((u64)buf[3] << 32) |
		       ((u64)buf[4] << 24) |
		       ((u64)buf[5] << 16) |
		       ((u64)buf[6] << 8) |
		       buf[7];
		break;
	}

	return enc_len;
}
EXPORT_SYMBOL_GPL(quic_varint_decode);

/**
 * quic_varint_len - Get encoding length for a value
 * @val: Value to check
 *
 * Returns: Number of bytes needed to encode value
 */
int quic_varint_len(u64 val)
{
	if (val <= 63)
		return 1;
	else if (val <= 16383)
		return 2;
	else if (val <= 1073741823)
		return 4;
	else
		return 8;
}
EXPORT_SYMBOL_GPL(quic_varint_len);

/*
 * Packet Number Handling (RFC 9000 Section 17.1)
 */

/**
 * quic_pn_encode - Encode a packet number
 * @pn: Full packet number
 * @largest_acked: Largest acknowledged packet number
 * @buf: Buffer to write to
 * @len: Available buffer length
 *
 * Returns: Number of bytes written (1-4), or negative error
 */
int quic_pn_encode(u64 pn, u64 largest_acked, u8 *buf, size_t len)
{
	u64 range = pn - largest_acked;
	int pn_len;

	if (range < (1ULL << 7))
		pn_len = 1;
	else if (range < (1ULL << 15))
		pn_len = 2;
	else if (range < (1ULL << 23))
		pn_len = 3;
	else
		pn_len = 4;

	if (len < pn_len)
		return -ENOBUFS;

	switch (pn_len) {
	case 4:
		buf[0] = (pn >> 24) & 0xff;
		buf[1] = (pn >> 16) & 0xff;
		buf[2] = (pn >> 8) & 0xff;
		buf[3] = pn & 0xff;
		break;
	case 3:
		buf[0] = (pn >> 16) & 0xff;
		buf[1] = (pn >> 8) & 0xff;
		buf[2] = pn & 0xff;
		break;
	case 2:
		buf[0] = (pn >> 8) & 0xff;
		buf[1] = pn & 0xff;
		break;
	case 1:
		buf[0] = pn & 0xff;
		break;
	}

	return pn_len;
}
EXPORT_SYMBOL_GPL(quic_pn_encode);

/**
 * quic_pn_decode - Decode a truncated packet number
 * @buf: Buffer containing truncated packet number
 * @pn_len: Length of truncated packet number (1-4)
 * @largest_pn: Largest packet number received so far
 *
 * Returns: Full packet number
 */
u64 quic_pn_decode(const u8 *buf, int pn_len, u64 largest_pn)
{
	u64 truncated_pn = 0;
	u64 expected_pn = largest_pn + 1;
	u64 pn_win = 1ULL << (pn_len * 8);
	u64 pn_hwin = pn_win / 2;
	u64 pn_mask = pn_win - 1;
	u64 candidate_pn;
	int i;

	for (i = 0; i < pn_len; i++)
		truncated_pn = (truncated_pn << 8) | buf[i];

	candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

	if (candidate_pn <= expected_pn - pn_hwin &&
	    candidate_pn < (1ULL << 62) - pn_win)
		return candidate_pn + pn_win;

	if (candidate_pn > expected_pn + pn_hwin &&
	    candidate_pn >= pn_win)
		return candidate_pn - pn_win;

	return candidate_pn;
}
EXPORT_SYMBOL_GPL(quic_pn_decode);

/**
 * quic_pn_get_length - Get packet number encoding length from first byte
 * @first_byte: First byte of short header (after removing protection)
 *
 * Returns: Packet number length (1-4)
 */
int quic_pn_get_length(u8 first_byte)
{
	return (first_byte & 0x03) + 1;
}
EXPORT_SYMBOL_GPL(quic_pn_get_length);

/*
 * Packet Header Handling
 */

/**
 * quic_packet_is_long_header - Check if packet has long header
 * @buf: Packet buffer
 *
 * Returns: true if long header, false if short header
 */
bool quic_packet_is_long_header(const u8 *buf)
{
	return (buf[0] & 0x80) != 0;
}
EXPORT_SYMBOL_GPL(quic_packet_is_long_header);

/**
 * quic_packet_get_type - Get packet type from long header
 * @buf: Packet buffer (must be long header)
 *
 * Returns: Packet type
 */
int quic_packet_get_type(const u8 *buf)
{
	if (!quic_packet_is_long_header(buf))
		return QUIC_PKT_1RTT;

	switch ((buf[0] & 0x30) >> 4) {
	case 0x00:
		return QUIC_PKT_INITIAL;
	case 0x01:
		return QUIC_PKT_0RTT;
	case 0x02:
		return QUIC_PKT_HANDSHAKE;
	case 0x03:
		return QUIC_PKT_RETRY;
	default:
		return QUIC_PKT_INVALID;
	}
}
EXPORT_SYMBOL_GPL(quic_packet_get_type);

/**
 * quic_build_long_header - Build a long header packet
 */
int quic_build_long_header(u8 *buf, size_t len,
			   int type, u32 version,
			   const u8 *dcid, u8 dcid_len,
			   const u8 *scid, u8 scid_len,
			   const u8 *token, size_t token_len,
			   size_t payload_len, u64 pn, int pn_len)
{
	u8 first_byte;
	size_t offset = 0;
	int ret;

	size_t min_len = 1 + 4 + 1 + dcid_len + 1 + scid_len + pn_len;
	if (type == QUIC_PKT_INITIAL)
		min_len += quic_varint_len(token_len) + token_len;
	min_len += quic_varint_len(payload_len);

	if (len < min_len)
		return -ENOBUFS;

	first_byte = 0xc0;
	switch (type) {
	case QUIC_PKT_INITIAL:
		first_byte |= 0x00;
		break;
	case QUIC_PKT_0RTT:
		first_byte |= 0x10;
		break;
	case QUIC_PKT_HANDSHAKE:
		first_byte |= 0x20;
		break;
	default:
		return -EINVAL;
	}
	first_byte |= (pn_len - 1);
	buf[offset++] = first_byte;

	buf[offset++] = (version >> 24) & 0xff;
	buf[offset++] = (version >> 16) & 0xff;
	buf[offset++] = (version >> 8) & 0xff;
	buf[offset++] = version & 0xff;

	buf[offset++] = dcid_len;
	if (dcid_len > 0) {
		memcpy(&buf[offset], dcid, dcid_len);
		offset += dcid_len;
	}

	buf[offset++] = scid_len;
	if (scid_len > 0) {
		memcpy(&buf[offset], scid, scid_len);
		offset += scid_len;
	}

	if (type == QUIC_PKT_INITIAL) {
		ret = quic_varint_encode(&buf[offset], token_len, len - offset);
		if (ret < 0)
			return ret;
		offset += ret;

		if (token_len > 0 && token) {
			memcpy(&buf[offset], token, token_len);
			offset += token_len;
		}
	}

	ret = quic_varint_encode(&buf[offset], payload_len, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	ret = quic_pn_encode(pn, 0, &buf[offset], len - offset);
	if (ret != pn_len)
		return -EINVAL;
	offset += pn_len;

	return offset;
}
EXPORT_SYMBOL_GPL(quic_build_long_header);

/**
 * quic_build_short_header - Build a short header (1-RTT) packet
 */
int quic_build_short_header(u8 *buf, size_t len,
			    const u8 *dcid, u8 dcid_len,
			    u64 pn, int pn_len,
			    bool key_phase, bool spin_bit)
{
	u8 first_byte;
	size_t offset = 0;
	int ret;

	if (len < 1 + dcid_len + pn_len)
		return -ENOBUFS;

	first_byte = 0x40;
	if (spin_bit)
		first_byte |= 0x20;
	if (key_phase)
		first_byte |= 0x04;
	first_byte |= (pn_len - 1);
	buf[offset++] = first_byte;

	if (dcid_len > 0) {
		memcpy(&buf[offset], dcid, dcid_len);
		offset += dcid_len;
	}

	ret = quic_pn_encode(pn, 0, &buf[offset], len - offset);
	if (ret != pn_len)
		return -EINVAL;
	offset += pn_len;

	return offset;
}
EXPORT_SYMBOL_GPL(quic_build_short_header);

/**
 * quic_parse_long_header - Parse a long header packet
 */
int quic_parse_long_header(const u8 *buf, size_t len,
			   struct quic_packet_header *hdr)
{
	size_t offset = 0;
	int ret;
	u64 token_len_val, payload_len_val;

	if (len < 7)
		return -EINVAL;

	hdr->form = 1;
	hdr->type = quic_packet_get_type(buf);
	hdr->pn_len = (buf[0] & 0x03) + 1;
	offset++;

	hdr->version = ((u32)buf[offset] << 24) |
		       ((u32)buf[offset + 1] << 16) |
		       ((u32)buf[offset + 2] << 8) |
		       buf[offset + 3];
	offset += 4;

	hdr->dcid_len = buf[offset++];
	if (hdr->dcid_len > QUIC_MAX_CID_LEN || offset + hdr->dcid_len > len)
		return -EINVAL;
	memcpy(hdr->dcid, &buf[offset], hdr->dcid_len);
	offset += hdr->dcid_len;

	if (offset >= len)
		return -EINVAL;
	hdr->scid_len = buf[offset++];
	if (hdr->scid_len > QUIC_MAX_CID_LEN || offset + hdr->scid_len > len)
		return -EINVAL;
	memcpy(hdr->scid, &buf[offset], hdr->scid_len);
	offset += hdr->scid_len;

	if (hdr->type == QUIC_PKT_INITIAL) {
		ret = quic_varint_decode(&buf[offset], len - offset, &token_len_val);
		if (ret < 0)
			return ret;
		offset += ret;
		hdr->token_len = token_len_val;

		if (hdr->token_len > 0) {
			if (offset + hdr->token_len > len)
				return -EINVAL;
			hdr->token = &buf[offset];
			offset += hdr->token_len;
		}
	} else {
		hdr->token = NULL;
		hdr->token_len = 0;
	}

	ret = quic_varint_decode(&buf[offset], len - offset, &payload_len_val);
	if (ret < 0)
		return ret;
	offset += ret;
	hdr->payload_len = payload_len_val;

	hdr->pn_offset = offset;

	if (offset + hdr->pn_len > len)
		return -EINVAL;

	hdr->header_len = offset + hdr->pn_len;

	return hdr->header_len;
}
EXPORT_SYMBOL_GPL(quic_parse_long_header);

/**
 * quic_parse_short_header - Parse a short header packet
 */
int quic_parse_short_header(const u8 *buf, size_t len, u8 dcid_len,
			    struct quic_packet_header *hdr)
{
	size_t offset = 0;

	if (len < 1 + dcid_len + 1)
		return -EINVAL;

	hdr->form = 0;
	hdr->type = QUIC_PKT_1RTT;
	hdr->spin_bit = (buf[0] & 0x20) != 0;
	hdr->key_phase = (buf[0] & 0x04) != 0;
	hdr->pn_len = (buf[0] & 0x03) + 1;
	offset++;

	hdr->dcid_len = dcid_len;
	if (offset + dcid_len > len)
		return -EINVAL;
	memcpy(hdr->dcid, &buf[offset], dcid_len);
	offset += dcid_len;

	hdr->scid_len = 0;
	hdr->version = 0;
	hdr->token = NULL;
	hdr->token_len = 0;

	hdr->pn_offset = offset;

	if (offset + hdr->pn_len > len)
		return -EINVAL;

	hdr->header_len = offset + hdr->pn_len;

	return hdr->header_len;
}
EXPORT_SYMBOL_GPL(quic_parse_short_header);

/*
 * Frame Building Functions
 */

int quic_build_padding_frame(u8 *buf, size_t len)
{
	memset(buf, QUIC_FRAME_PADDING, len);
	return len;
}
EXPORT_SYMBOL_GPL(quic_build_padding_frame);

int quic_build_ping_frame(u8 *buf, size_t len)
{
	if (len < 1)
		return -ENOBUFS;
	buf[0] = QUIC_FRAME_PING;
	return 1;
}
EXPORT_SYMBOL_GPL(quic_build_ping_frame);

int quic_build_ack_frame(u8 *buf, size_t len,
			 u64 largest_acked, u64 ack_delay,
			 u64 first_range,
			 const struct quic_ack_range *ranges,
			 size_t range_count,
			 const struct quic_ecn_counts *ecn)
{
	size_t offset = 0;
	int ret;
	size_t i;

	if (len < 1)
		return -ENOBUFS;
	buf[offset++] = ecn ? QUIC_FRAME_ACK_ECN : QUIC_FRAME_ACK;

	ret = quic_varint_encode(&buf[offset], largest_acked, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	ret = quic_varint_encode(&buf[offset], ack_delay, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	ret = quic_varint_encode(&buf[offset], range_count, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	ret = quic_varint_encode(&buf[offset], first_range, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	for (i = 0; i < range_count && ranges; i++) {
		ret = quic_varint_encode(&buf[offset], ranges[i].gap, len - offset);
		if (ret < 0)
			return ret;
		offset += ret;

		ret = quic_varint_encode(&buf[offset], ranges[i].length, len - offset);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	if (ecn) {
		ret = quic_varint_encode(&buf[offset], ecn->ect0, len - offset);
		if (ret < 0)
			return ret;
		offset += ret;

		ret = quic_varint_encode(&buf[offset], ecn->ect1, len - offset);
		if (ret < 0)
			return ret;
		offset += ret;

		ret = quic_varint_encode(&buf[offset], ecn->ce, len - offset);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(quic_build_ack_frame);

int quic_build_crypto_frame(u8 *buf, size_t len,
			    u64 offset_val, const u8 *data, size_t data_len)
{
	size_t pos = 0;
	int ret;

	if (len < 1)
		return -ENOBUFS;
	buf[pos++] = QUIC_FRAME_CRYPTO;

	ret = quic_varint_encode(&buf[pos], offset_val, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	ret = quic_varint_encode(&buf[pos], data_len, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	if (pos + data_len > len)
		return -ENOBUFS;
	memcpy(&buf[pos], data, data_len);
	pos += data_len;

	return pos;
}
EXPORT_SYMBOL_GPL(quic_build_crypto_frame);

int quic_build_stream_frame(u8 *buf, size_t len,
			    u64 stream_id, u64 offset_val,
			    const u8 *data, size_t data_len,
			    bool fin, bool include_len, bool include_off)
{
	size_t pos = 0;
	int ret;
	u8 frame_type;

	frame_type = QUIC_FRAME_STREAM;
	if (include_off)
		frame_type |= 0x04;
	if (include_len)
		frame_type |= 0x02;
	if (fin)
		frame_type |= 0x01;

	if (len < 1)
		return -ENOBUFS;
	buf[pos++] = frame_type;

	ret = quic_varint_encode(&buf[pos], stream_id, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	if (include_off) {
		ret = quic_varint_encode(&buf[pos], offset_val, len - pos);
		if (ret < 0)
			return ret;
		pos += ret;
	}

	if (include_len) {
		ret = quic_varint_encode(&buf[pos], data_len, len - pos);
		if (ret < 0)
			return ret;
		pos += ret;
	}

	if (pos + data_len > len)
		return -ENOBUFS;
	memcpy(&buf[pos], data, data_len);
	pos += data_len;

	return pos;
}
EXPORT_SYMBOL_GPL(quic_build_stream_frame);

int quic_build_max_data_frame(u8 *buf, size_t len, u64 max_data)
{
	size_t pos = 0;
	int ret;

	if (len < 1)
		return -ENOBUFS;
	buf[pos++] = QUIC_FRAME_MAX_DATA;

	ret = quic_varint_encode(&buf[pos], max_data, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	return pos;
}
EXPORT_SYMBOL_GPL(quic_build_max_data_frame);

int quic_build_max_stream_data_frame(u8 *buf, size_t len,
				     u64 stream_id, u64 max_data)
{
	size_t pos = 0;
	int ret;

	if (len < 1)
		return -ENOBUFS;
	buf[pos++] = QUIC_FRAME_MAX_STREAM_DATA;

	ret = quic_varint_encode(&buf[pos], stream_id, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	ret = quic_varint_encode(&buf[pos], max_data, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	return pos;
}
EXPORT_SYMBOL_GPL(quic_build_max_stream_data_frame);

int quic_build_max_streams_frame(u8 *buf, size_t len, u64 max_streams, bool bidi)
{
	size_t pos = 0;
	int ret;

	if (len < 1)
		return -ENOBUFS;
	buf[pos++] = bidi ? QUIC_FRAME_MAX_STREAMS_BIDI : QUIC_FRAME_MAX_STREAMS_UNI;

	ret = quic_varint_encode(&buf[pos], max_streams, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	return pos;
}
EXPORT_SYMBOL_GPL(quic_build_max_streams_frame);

int quic_build_connection_close_frame(u8 *buf, size_t len,
				      u64 error_code, u64 frame_type,
				      const u8 *reason, size_t reason_len,
				      bool is_app_error)
{
	size_t pos = 0;
	int ret;

	if (len < 1)
		return -ENOBUFS;
	buf[pos++] = is_app_error ? QUIC_FRAME_CONN_CLOSE_APP : QUIC_FRAME_CONN_CLOSE;

	ret = quic_varint_encode(&buf[pos], error_code, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	if (!is_app_error) {
		ret = quic_varint_encode(&buf[pos], frame_type, len - pos);
		if (ret < 0)
			return ret;
		pos += ret;
	}

	ret = quic_varint_encode(&buf[pos], reason_len, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	if (reason_len > 0 && reason) {
		if (pos + reason_len > len)
			return -ENOBUFS;
		memcpy(&buf[pos], reason, reason_len);
		pos += reason_len;
	}

	return pos;
}
EXPORT_SYMBOL_GPL(quic_build_connection_close_frame);

int quic_build_path_challenge_frame(u8 *buf, size_t len, const u8 *data)
{
	if (len < 9)
		return -ENOBUFS;

	buf[0] = QUIC_FRAME_PATH_CHALLENGE;
	memcpy(&buf[1], data, 8);
	return 9;
}
EXPORT_SYMBOL_GPL(quic_build_path_challenge_frame);

int quic_build_path_response_frame(u8 *buf, size_t len, const u8 *data)
{
	if (len < 9)
		return -ENOBUFS;

	buf[0] = QUIC_FRAME_PATH_RESPONSE;
	memcpy(&buf[1], data, 8);
	return 9;
}
EXPORT_SYMBOL_GPL(quic_build_path_response_frame);

int quic_build_new_connection_id_frame(u8 *buf, size_t len,
				       u64 seq_num, u64 retire_prior_to,
				       const u8 *cid, u8 cid_len,
				       const u8 *reset_token)
{
	size_t pos = 0;
	int ret;

	if (len < 1)
		return -ENOBUFS;
	buf[pos++] = QUIC_FRAME_NEW_CONN_ID;

	ret = quic_varint_encode(&buf[pos], seq_num, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	ret = quic_varint_encode(&buf[pos], retire_prior_to, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	if (pos + 1 + cid_len + 16 > len)
		return -ENOBUFS;
	buf[pos++] = cid_len;
	memcpy(&buf[pos], cid, cid_len);
	pos += cid_len;

	memcpy(&buf[pos], reset_token, 16);
	pos += 16;

	return pos;
}
EXPORT_SYMBOL_GPL(quic_build_new_connection_id_frame);

int quic_build_retire_connection_id_frame(u8 *buf, size_t len, u64 seq_num)
{
	size_t pos = 0;
	int ret;

	if (len < 1)
		return -ENOBUFS;
	buf[pos++] = QUIC_FRAME_RETIRE_CONN_ID;

	ret = quic_varint_encode(&buf[pos], seq_num, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	return pos;
}
EXPORT_SYMBOL_GPL(quic_build_retire_connection_id_frame);

int quic_build_handshake_done_frame(u8 *buf, size_t len)
{
	if (len < 1)
		return -ENOBUFS;
	buf[0] = QUIC_FRAME_HANDSHAKE_DONE;
	return 1;
}
EXPORT_SYMBOL_GPL(quic_build_handshake_done_frame);

/*
 * Frame Parsing Functions
 */

int quic_parse_frame_type(const u8 *buf, size_t len, u64 *frame_type)
{
	return quic_varint_decode(buf, len, frame_type);
}
EXPORT_SYMBOL_GPL(quic_parse_frame_type);

int quic_parse_ack_frame(const u8 *buf, size_t len, struct quic_ack_frame *ack)
{
	size_t pos = 0;
	int ret;
	u64 range_count, val;
	size_t i;

	ret = quic_varint_decode(&buf[pos], len - pos, &ack->largest_acked);
	if (ret < 0)
		return ret;
	pos += ret;

	ret = quic_varint_decode(&buf[pos], len - pos, &ack->ack_delay);
	if (ret < 0)
		return ret;
	pos += ret;

	ret = quic_varint_decode(&buf[pos], len - pos, &range_count);
	if (ret < 0)
		return ret;
	pos += ret;
	ack->range_count = range_count;

	ret = quic_varint_decode(&buf[pos], len - pos, &ack->first_range);
	if (ret < 0)
		return ret;
	pos += ret;

	for (i = 0; i < range_count; i++) {
		ret = quic_varint_decode(&buf[pos], len - pos, &val);
		if (ret < 0)
			return ret;
		pos += ret;

		ret = quic_varint_decode(&buf[pos], len - pos, &val);
		if (ret < 0)
			return ret;
		pos += ret;
	}

	ack->frame_len = pos;
	return pos;
}
EXPORT_SYMBOL_GPL(quic_parse_ack_frame);

int quic_parse_stream_frame(const u8 *buf, size_t len,
			    struct quic_stream_frame *frame)
{
	size_t pos = 0;
	int ret;
	u8 type_byte;

	if (len < 1)
		return -EINVAL;

	type_byte = buf[pos++];
	frame->fin = (type_byte & 0x01) != 0;
	frame->has_length = (type_byte & 0x02) != 0;
	frame->has_offset = (type_byte & 0x04) != 0;

	ret = quic_varint_decode(&buf[pos], len - pos, &frame->stream_id);
	if (ret < 0)
		return ret;
	pos += ret;

	if (frame->has_offset) {
		ret = quic_varint_decode(&buf[pos], len - pos, &frame->offset);
		if (ret < 0)
			return ret;
		pos += ret;
	} else {
		frame->offset = 0;
	}

	if (frame->has_length) {
		u64 data_len;
		ret = quic_varint_decode(&buf[pos], len - pos, &data_len);
		if (ret < 0)
			return ret;
		pos += ret;
		frame->data_len = data_len;
	} else {
		frame->data_len = len - pos;
	}

	if (pos + frame->data_len > len)
		return -EINVAL;
	frame->data = &buf[pos];
	pos += frame->data_len;

	frame->frame_len = pos;
	return pos;
}
EXPORT_SYMBOL_GPL(quic_parse_stream_frame);

int quic_parse_crypto_frame(const u8 *buf, size_t len,
			    struct quic_crypto_frame *frame)
{
	size_t pos = 0;
	int ret;
	u64 data_len;

	ret = quic_varint_decode(&buf[pos], len - pos, &frame->offset);
	if (ret < 0)
		return ret;
	pos += ret;

	ret = quic_varint_decode(&buf[pos], len - pos, &data_len);
	if (ret < 0)
		return ret;
	pos += ret;
	frame->data_len = data_len;

	if (pos + frame->data_len > len)
		return -EINVAL;
	frame->data = &buf[pos];
	pos += frame->data_len;

	frame->frame_len = pos;
	return pos;
}
EXPORT_SYMBOL_GPL(quic_parse_crypto_frame);

/*
 * Packet Number Space Helpers
 */

int quic_pkt_type_to_pn_space(int type)
{
	switch (type) {
	case QUIC_PKT_INITIAL:
		return QUIC_PN_SPACE_INITIAL;
	case QUIC_PKT_HANDSHAKE:
		return QUIC_PN_SPACE_HANDSHAKE;
	case QUIC_PKT_0RTT:
	case QUIC_PKT_1RTT:
	default:
		return QUIC_PN_SPACE_APPLICATION;
	}
}
EXPORT_SYMBOL_GPL(quic_pkt_type_to_pn_space);

/*
 * Packet Transmission
 */

struct sk_buff *quic_alloc_skb(size_t size)
{
	struct sk_buff *skb;

	skb = alloc_skb(size + 256, GFP_ATOMIC);
	if (!skb)
		return NULL;

	skb_reserve(skb, 128);
	return skb;
}
EXPORT_SYMBOL_GPL(quic_alloc_skb);

struct sk_buff *quic_coalesce_packets(struct sk_buff **packets, int count)
{
	struct sk_buff *skb;
	size_t total_len = 0;
	u8 *ptr;
	int i;

	for (i = 0; i < count; i++)
		total_len += packets[i]->len;

	if (total_len > QUIC_MAX_UDP_PAYLOAD)
		return NULL;

	skb = alloc_skb(total_len + 256, GFP_ATOMIC);
	if (!skb)
		return NULL;

	skb_reserve(skb, 128);
	ptr = skb_put(skb, total_len);

	for (i = 0; i < count; i++) {
		skb_copy_bits(packets[i], 0, ptr, packets[i]->len);
		ptr += packets[i]->len;
		kfree_skb(packets[i]);
	}

	return skb;
}
EXPORT_SYMBOL_GPL(quic_coalesce_packets);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("QUIC Packet Handling");
MODULE_AUTHOR("Linux QUIC Authors");
