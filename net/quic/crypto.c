// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC Cryptographic Operations
 *
 * Implementation of QUIC packet protection as specified in RFC 9001.
 * Provides key derivation, header protection, and AEAD encryption/decryption
 * using the Linux kernel crypto API.
 *
 * Copyright (c) 2024 Linux QUIC Implementation Authors
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/time.h>
#include <linux/jhash.h>
#include <crypto/aead.h>
#include <crypto/aes.h>
#include <crypto/hash.h>
#include <crypto/sha2.h>
#include <crypto/skcipher.h>
#include <net/ip.h>

#include "crypto.h"

/*
 * QUIC cipher suite identifiers (TLS 1.3)
 */
#define TLS_AES_128_GCM_SHA256		0x1301
#define TLS_AES_256_GCM_SHA384		0x1302
#define TLS_CHACHA20_POLY1305_SHA256	0x1303

/*
 * Cryptographic constants
 */
#define QUIC_IV_LEN			12
#define QUIC_HP_SAMPLE_LEN		16
#define QUIC_HP_MASK_LEN		5
#define QUIC_TAG_LEN			16
#define QUIC_MAX_KEY_LEN		32
#define QUIC_MAX_IV_LEN			12
#define QUIC_MAX_HASH_LEN		48

/*
 * HKDF label constants (RFC 9001 Section 5.1)
 */
#define QUIC_HKDF_LABEL_KEY		"quic key"
#define QUIC_HKDF_LABEL_IV		"quic iv"
#define QUIC_HKDF_LABEL_HP		"quic hp"
#define QUIC_HKDF_LABEL_KU		"quic ku"

/*
 * Initial key derivation labels (RFC 9001 Section 5.2)
 */
#define QUIC_LABEL_CLIENT_IN		"client in"
#define QUIC_LABEL_SERVER_IN		"server in"

/*
 * QUIC version 1 initial salt (RFC 9001 Section 5.2)
 * 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
 */
static const u8 quic_v1_initial_salt[] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a
};

/*
 * QUIC version 2 initial salt (RFC 9369)
 * 0x0dede3def700a6db819381be6e269dcbf9bd2ed9
 */
static const u8 quic_v2_initial_salt[] = {
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
	0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
	0xf9, 0xbd, 0x2e, 0xd9
};

/*
 * Retry key and nonce for QUIC v1 (RFC 9001 Section 5.8)
 */
static const u8 quic_v1_retry_key[] = {
	0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
	0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e
};

static const u8 quic_v1_retry_nonce[] = {
	0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
	0x23, 0x98, 0x25, 0xbb
};

/*
 * Retry key and nonce for QUIC v2 (RFC 9369)
 */
static const u8 quic_v2_retry_key[] = {
	0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
	0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92
};

static const u8 quic_v2_retry_nonce[] = {
	0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99,
	0x90, 0xef, 0xb0, 0x4a
};

/*
 * Cipher suite parameters
 */
struct quic_cipher_suite {
	u16 id;
	const char *aead_name;
	const char *hash_name;
	const char *hp_name;
	u8 key_len;
	u8 iv_len;
	u8 hash_len;
	u8 tag_len;
};

static const struct quic_cipher_suite quic_cipher_suites[] = {
	{
		.id = TLS_AES_128_GCM_SHA256,
		.aead_name = "gcm(aes)",
		.hash_name = "hmac(sha256)",
		.hp_name = "ecb(aes)",
		.key_len = 16,
		.iv_len = 12,
		.hash_len = 32,
		.tag_len = 16,
	},
	{
		.id = TLS_AES_256_GCM_SHA384,
		.aead_name = "gcm(aes)",
		.hash_name = "hmac(sha384)",
		.hp_name = "ecb(aes)",
		.key_len = 32,
		.iv_len = 12,
		.hash_len = 48,
		.tag_len = 16,
	},
};

/*
 * QUIC crypto context - holds all cryptographic state for a connection
 */
struct quic_crypto_ctx {
	/* Cipher suite being used */
	const struct quic_cipher_suite *suite;

	/* AEAD cipher for packet protection */
	struct crypto_aead *aead;

	/* Cipher for header protection */
	struct crypto_skcipher *hp_cipher;

	/* HMAC for HKDF operations */
	struct crypto_shash *hmac;

	/* Traffic keys */
	u8 key[QUIC_MAX_KEY_LEN];
	u8 iv[QUIC_MAX_IV_LEN];
	u8 hp_key[QUIC_MAX_KEY_LEN];

	/* Key phase bit for key updates */
	u8 key_phase;

	/* Traffic secret for key updates */
	u8 secret[QUIC_MAX_HASH_LEN];
	u8 secret_len;

	/* Reference counting */
	refcount_t refcnt;
};

/*
 * Retry token structure
 */
struct quic_retry_token {
	u8 odcid[20];		/* Original Destination CID */
	u8 odcid_len;
	__be32 client_ip;	/* Client IP (v4) */
	struct in6_addr client_ip6;	/* Client IP (v6) */
	u8 ip_version;
	__be64 timestamp;	/* Token creation time */
	u8 random[8];		/* Random bytes for uniqueness */
};

static const struct quic_cipher_suite *quic_find_cipher_suite(u16 cipher_id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(quic_cipher_suites); i++) {
		if (quic_cipher_suites[i].id == cipher_id)
			return &quic_cipher_suites[i];
	}
	return NULL;
}

/*
 * HKDF-Extract (RFC 5869)
 *
 * PRK = HMAC-Hash(salt, IKM)
 */
int quic_hkdf_extract(struct crypto_shash *hmac,
		      const u8 *salt, size_t salt_len,
		      const u8 *ikm, size_t ikm_len,
		      u8 *prk, size_t prk_len)
{
	SHASH_DESC_ON_STACK(desc, hmac);
	int err;

	desc->tfm = hmac;

	/* Set the salt as the HMAC key */
	err = crypto_shash_setkey(hmac, salt, salt_len);
	if (err)
		return err;

	/* PRK = HMAC(salt, IKM) */
	err = crypto_shash_init(desc);
	if (err)
		goto out;

	err = crypto_shash_update(desc, ikm, ikm_len);
	if (err)
		goto out;

	err = crypto_shash_final(desc, prk);

out:
	shash_desc_zero(desc);
	return err;
}
EXPORT_SYMBOL_GPL(quic_hkdf_extract);

/*
 * HKDF-Expand (RFC 5869)
 *
 * Expands the PRK to the desired length using the info parameter.
 */
static int quic_hkdf_expand(struct crypto_shash *hmac,
			    const u8 *prk, size_t prk_len,
			    const u8 *info, size_t info_len,
			    u8 *okm, size_t okm_len)
{
	SHASH_DESC_ON_STACK(desc, hmac);
	unsigned int hash_len = crypto_shash_digestsize(hmac);
	u8 t[QUIC_MAX_HASH_LEN];
	u8 counter = 1;
	size_t t_len = 0;
	size_t copied = 0;
	int err;

	if (okm_len > 255 * hash_len)
		return -EINVAL;

	desc->tfm = hmac;

	err = crypto_shash_setkey(hmac, prk, prk_len);
	if (err)
		return err;

	while (copied < okm_len) {
		size_t to_copy;

		err = crypto_shash_init(desc);
		if (err)
			goto out;

		/* T(n) = HMAC(PRK, T(n-1) | info | counter) */
		if (t_len > 0) {
			err = crypto_shash_update(desc, t, t_len);
			if (err)
				goto out;
		}

		err = crypto_shash_update(desc, info, info_len);
		if (err)
			goto out;

		err = crypto_shash_update(desc, &counter, 1);
		if (err)
			goto out;

		err = crypto_shash_final(desc, t);
		if (err)
			goto out;

		t_len = hash_len;
		to_copy = min(hash_len, okm_len - copied);
		memcpy(okm + copied, t, to_copy);
		copied += to_copy;
		counter++;
	}

out:
	memzero_explicit(t, sizeof(t));
	shash_desc_zero(desc);
	return err;
}

/*
 * Build HKDF-Expand-Label info structure (RFC 8446 Section 7.1)
 *
 * struct {
 *     uint16 length = Length;
 *     opaque label<7..255> = "tls13 " + Label;
 *     opaque context<0..255> = Context;
 * } HkdfLabel;
 */
static int quic_build_hkdf_label(u8 *info, size_t info_size,
				 u16 length, const char *label,
				 const u8 *context, size_t context_len)
{
	size_t label_len = strlen(label);
	size_t full_label_len = 6 + label_len; /* "tls13 " prefix */
	size_t total_len;

	total_len = 2 + 1 + full_label_len + 1 + context_len;
	if (total_len > info_size)
		return -EINVAL;

	/* Length (2 bytes, big-endian) */
	info[0] = (length >> 8) & 0xff;
	info[1] = length & 0xff;

	/* Label length and label */
	info[2] = full_label_len;
	memcpy(&info[3], "tls13 ", 6);
	memcpy(&info[9], label, label_len);

	/* Context length and context */
	info[3 + full_label_len] = context_len;
	if (context_len > 0)
		memcpy(&info[4 + full_label_len], context, context_len);

	return total_len;
}

/*
 * HKDF-Expand-Label (RFC 8446)
 *
 * Derives keying material using the TLS 1.3 key derivation function.
 */
int quic_hkdf_expand_label(struct crypto_shash *hmac,
			   const u8 *secret, size_t secret_len,
			   const char *label,
			   const u8 *context, size_t context_len,
			   u8 *out, size_t out_len)
{
	u8 info[256];
	int info_len;

	info_len = quic_build_hkdf_label(info, sizeof(info), out_len,
					 label, context, context_len);
	if (info_len < 0)
		return info_len;

	return quic_hkdf_expand(hmac, secret, secret_len,
				info, info_len, out, out_len);
}
EXPORT_SYMBOL_GPL(quic_hkdf_expand_label);

/*
 * Derive traffic keys from a traffic secret
 */
static int quic_derive_traffic_keys(struct quic_crypto_ctx *ctx,
				    const u8 *secret, size_t secret_len)
{
	int err;

	/* Derive the packet protection key */
	err = quic_hkdf_expand_label(ctx->hmac, secret, secret_len,
				     QUIC_HKDF_LABEL_KEY, NULL, 0,
				     ctx->key, ctx->suite->key_len);
	if (err)
		return err;

	/* Derive the IV */
	err = quic_hkdf_expand_label(ctx->hmac, secret, secret_len,
				     QUIC_HKDF_LABEL_IV, NULL, 0,
				     ctx->iv, ctx->suite->iv_len);
	if (err)
		return err;

	/* Derive the header protection key */
	err = quic_hkdf_expand_label(ctx->hmac, secret, secret_len,
				     QUIC_HKDF_LABEL_HP, NULL, 0,
				     ctx->hp_key, ctx->suite->key_len);
	if (err)
		return err;

	/* Set keys on the cipher handles */
	err = crypto_aead_setkey(ctx->aead, ctx->key, ctx->suite->key_len);
	if (err)
		return err;

	err = crypto_aead_setauthsize(ctx->aead, ctx->suite->tag_len);
	if (err)
		return err;

	err = crypto_skcipher_setkey(ctx->hp_cipher, ctx->hp_key,
				     ctx->suite->key_len);
	if (err)
		return err;

	/* Store secret for key updates */
	memcpy(ctx->secret, secret, secret_len);
	ctx->secret_len = secret_len;

	return 0;
}

/*
 * Allocate and initialize a QUIC crypto context
 */
struct quic_crypto_ctx *quic_crypto_ctx_alloc(u16 cipher_suite, gfp_t gfp)
{
	struct quic_crypto_ctx *ctx;
	const struct quic_cipher_suite *suite;
	int err;

	suite = quic_find_cipher_suite(cipher_suite);
	if (!suite)
		return ERR_PTR(-ENOENT);

	ctx = kzalloc(sizeof(*ctx), gfp);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->suite = suite;
	refcount_set(&ctx->refcnt, 1);

	/* Allocate AEAD cipher */
	ctx->aead = crypto_alloc_aead(suite->aead_name, 0, 0);
	if (IS_ERR(ctx->aead)) {
		err = PTR_ERR(ctx->aead);
		ctx->aead = NULL;
		goto err_free;
	}

	/* Allocate header protection cipher (AES-ECB) */
	ctx->hp_cipher = crypto_alloc_skcipher(suite->hp_name, 0, 0);
	if (IS_ERR(ctx->hp_cipher)) {
		err = PTR_ERR(ctx->hp_cipher);
		ctx->hp_cipher = NULL;
		goto err_free;
	}

	/* Allocate HMAC for HKDF */
	ctx->hmac = crypto_alloc_shash(suite->hash_name, 0, 0);
	if (IS_ERR(ctx->hmac)) {
		err = PTR_ERR(ctx->hmac);
		ctx->hmac = NULL;
		goto err_free;
	}

	return ctx;

err_free:
	quic_crypto_ctx_free(ctx);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(quic_crypto_ctx_alloc);

/*
 * Free a QUIC crypto context
 */
void quic_crypto_ctx_free(struct quic_crypto_ctx *ctx)
{
	if (!ctx)
		return;

	if (!refcount_dec_and_test(&ctx->refcnt))
		return;

	crypto_free_aead(ctx->aead);
	crypto_free_skcipher(ctx->hp_cipher);
	crypto_free_shash(ctx->hmac);

	/* Zeroize sensitive material */
	memzero_explicit(ctx->key, sizeof(ctx->key));
	memzero_explicit(ctx->iv, sizeof(ctx->iv));
	memzero_explicit(ctx->hp_key, sizeof(ctx->hp_key));
	memzero_explicit(ctx->secret, sizeof(ctx->secret));

	kfree_sensitive(ctx);
}
EXPORT_SYMBOL_GPL(quic_crypto_ctx_free);

/*
 * Get a reference to a crypto context
 */
struct quic_crypto_ctx *quic_crypto_ctx_get(struct quic_crypto_ctx *ctx)
{
	if (ctx)
		refcount_inc(&ctx->refcnt);
	return ctx;
}
EXPORT_SYMBOL_GPL(quic_crypto_ctx_get);

/*
 * Release a reference to a crypto context
 */
void quic_crypto_ctx_put(struct quic_crypto_ctx *ctx)
{
	quic_crypto_ctx_free(ctx);
}
EXPORT_SYMBOL_GPL(quic_crypto_ctx_put);

/*
 * Derive initial secrets from connection ID (RFC 9001 Section 5.2)
 *
 * The initial keys are derived using the destination connection ID
 * as the input keying material (IKM) and a version-specific salt.
 */
int quic_derive_initial_secrets(struct quic_crypto_ctx *ctx,
				const u8 *dcid, size_t dcid_len,
				bool is_server, u32 version)
{
	u8 initial_secret[QUIC_MAX_HASH_LEN];
	u8 client_secret[QUIC_MAX_HASH_LEN];
	u8 server_secret[QUIC_MAX_HASH_LEN];
	const u8 *salt;
	size_t salt_len;
	size_t hash_len;
	int err;

	if (!ctx || !dcid)
		return -EINVAL;

	hash_len = ctx->suite->hash_len;

	/* Select version-specific salt */
	switch (version) {
	case 0x00000001: /* QUIC v1 */
	case 0xff000000: /* Draft versions */
		salt = quic_v1_initial_salt;
		salt_len = sizeof(quic_v1_initial_salt);
		break;
	case 0x6b3343cf: /* QUIC v2 */
		salt = quic_v2_initial_salt;
		salt_len = sizeof(quic_v2_initial_salt);
		break;
	default:
		return -EINVAL;
	}

	/* initial_secret = HKDF-Extract(salt, dcid) */
	err = quic_hkdf_extract(ctx->hmac, salt, salt_len,
				dcid, dcid_len, initial_secret, hash_len);
	if (err)
		goto out;

	/* client_initial_secret = HKDF-Expand-Label(initial_secret,
	 *                                           "client in", "", Hash.length) */
	err = quic_hkdf_expand_label(ctx->hmac, initial_secret, hash_len,
				     QUIC_LABEL_CLIENT_IN, NULL, 0,
				     client_secret, hash_len);
	if (err)
		goto out;

	/* server_initial_secret = HKDF-Expand-Label(initial_secret,
	 *                                           "server in", "", Hash.length) */
	err = quic_hkdf_expand_label(ctx->hmac, initial_secret, hash_len,
				     QUIC_LABEL_SERVER_IN, NULL, 0,
				     server_secret, hash_len);
	if (err)
		goto out;

	/* Derive traffic keys from appropriate secret */
	if (is_server)
		err = quic_derive_traffic_keys(ctx, server_secret, hash_len);
	else
		err = quic_derive_traffic_keys(ctx, client_secret, hash_len);

out:
	memzero_explicit(initial_secret, sizeof(initial_secret));
	memzero_explicit(client_secret, sizeof(client_secret));
	memzero_explicit(server_secret, sizeof(server_secret));
	return err;
}
EXPORT_SYMBOL_GPL(quic_derive_initial_secrets);

/*
 * Derive handshake secrets from TLS handshake
 */
int quic_derive_handshake_secrets(struct quic_crypto_ctx *ctx,
				  const u8 *secret, size_t secret_len)
{
	if (!ctx || !secret || secret_len == 0)
		return -EINVAL;

	if (secret_len > sizeof(ctx->secret))
		return -EINVAL;

	return quic_derive_traffic_keys(ctx, secret, secret_len);
}
EXPORT_SYMBOL_GPL(quic_derive_handshake_secrets);

/*
 * Derive application (1-RTT) secrets
 */
int quic_derive_application_secrets(struct quic_crypto_ctx *ctx,
				    const u8 *secret, size_t secret_len)
{
	if (!ctx || !secret || secret_len == 0)
		return -EINVAL;

	if (secret_len > sizeof(ctx->secret))
		return -EINVAL;

	ctx->key_phase = 0;
	return quic_derive_traffic_keys(ctx, secret, secret_len);
}
EXPORT_SYMBOL_GPL(quic_derive_application_secrets);

/*
 * Generate header protection mask (RFC 9001 Section 5.4.1)
 *
 * For AES-based cipher suites, the mask is generated by encrypting
 * the sample with AES-ECB.
 */
int quic_hp_mask(struct quic_crypto_ctx *ctx,
		 const u8 *sample, u8 *mask)
{
	struct skcipher_request *req;
	struct scatterlist sg_in, sg_out;
	u8 ecb_block[AES_BLOCK_SIZE];
	DECLARE_CRYPTO_WAIT(wait);
	int err;

	if (!ctx || !sample || !mask)
		return -EINVAL;

	req = skcipher_request_alloc(ctx->hp_cipher, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	/* Copy sample to ECB input block */
	memcpy(ecb_block, sample, AES_BLOCK_SIZE);

	sg_init_one(&sg_in, ecb_block, AES_BLOCK_SIZE);
	sg_init_one(&sg_out, ecb_block, AES_BLOCK_SIZE);

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &sg_in, &sg_out, AES_BLOCK_SIZE, NULL);

	err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	if (err)
		goto out;

	/* The mask is the first 5 bytes of the encrypted block */
	memcpy(mask, ecb_block, QUIC_HP_MASK_LEN);

out:
	skcipher_request_free(req);
	return err;
}
EXPORT_SYMBOL_GPL(quic_hp_mask);

/*
 * Apply header protection to a QUIC packet (RFC 9001 Section 5.4.1)
 *
 * Header protection encrypts part of the first byte and the entire
 * packet number field.
 */
int quic_protect_header(struct quic_crypto_ctx *ctx,
			u8 *packet, size_t packet_len,
			size_t pn_offset, size_t pn_len)
{
	u8 mask[QUIC_HP_MASK_LEN];
	const u8 *sample;
	size_t sample_offset;
	int err;
	int i;

	if (!ctx || !packet || pn_len < 1 || pn_len > 4)
		return -EINVAL;

	/* Sample starts 4 bytes after the start of the packet number field */
	sample_offset = pn_offset + 4;
	if (sample_offset + QUIC_HP_SAMPLE_LEN > packet_len)
		return -EINVAL;

	sample = packet + sample_offset;

	/* Generate the mask */
	err = quic_hp_mask(ctx, sample, mask);
	if (err)
		return err;

	/* Protect the first byte */
	if (packet[0] & 0x80) {
		/* Long header: mask the lower 4 bits */
		packet[0] ^= mask[0] & 0x0f;
	} else {
		/* Short header: mask the lower 5 bits */
		packet[0] ^= mask[0] & 0x1f;
	}

	/* Protect the packet number */
	for (i = 0; i < pn_len; i++)
		packet[pn_offset + i] ^= mask[1 + i];

	return 0;
}
EXPORT_SYMBOL_GPL(quic_protect_header);

/*
 * Remove header protection from a QUIC packet (RFC 9001 Section 5.4.1)
 *
 * This function reverses header protection to reveal the packet
 * number and the original first byte.
 */
int quic_unprotect_header(struct quic_crypto_ctx *ctx,
			  u8 *packet, size_t packet_len,
			  size_t pn_offset, size_t *pn_len)
{
	u8 mask[QUIC_HP_MASK_LEN];
	const u8 *sample;
	size_t sample_offset;
	int err;
	int i;

	if (!ctx || !packet || !pn_len)
		return -EINVAL;

	/* Sample starts 4 bytes after the start of the packet number field */
	sample_offset = pn_offset + 4;
	if (sample_offset + QUIC_HP_SAMPLE_LEN > packet_len)
		return -EINVAL;

	sample = packet + sample_offset;

	/* Generate the mask */
	err = quic_hp_mask(ctx, sample, mask);
	if (err)
		return err;

	/* Unprotect the first byte to get the packet number length */
	if (packet[0] & 0x80) {
		/* Long header: unmask the lower 4 bits */
		packet[0] ^= mask[0] & 0x0f;
	} else {
		/* Short header: unmask the lower 5 bits */
		packet[0] ^= mask[0] & 0x1f;
	}

	/* The packet number length is encoded in bits 0-1 of the first byte */
	*pn_len = (packet[0] & 0x03) + 1;

	if (pn_offset + *pn_len > packet_len)
		return -EINVAL;

	/* Unprotect the packet number */
	for (i = 0; i < *pn_len; i++)
		packet[pn_offset + i] ^= mask[1 + i];

	return 0;
}
EXPORT_SYMBOL_GPL(quic_unprotect_header);

/*
 * Construct the nonce for AEAD encryption/decryption
 *
 * The nonce is the IV XORed with the reconstructed packet number.
 */
static void quic_construct_nonce(const u8 *iv, u64 packet_number, u8 *nonce)
{
	int i;

	memcpy(nonce, iv, QUIC_IV_LEN);

	/* XOR the packet number into the last 8 bytes of the IV */
	for (i = 0; i < 8; i++) {
		nonce[QUIC_IV_LEN - 1 - i] ^= (packet_number >> (8 * i)) & 0xff;
	}
}

/*
 * Encrypt a QUIC packet payload using AEAD (RFC 9001 Section 5.3)
 *
 * The AAD (Additional Authenticated Data) is the QUIC header up to
 * and including the packet number.
 */
int quic_encrypt_packet(struct quic_crypto_ctx *ctx,
			u64 packet_number,
			const u8 *aad, size_t aad_len,
			const u8 *plaintext, size_t plaintext_len,
			u8 *ciphertext, size_t *ciphertext_len)
{
	struct aead_request *req;
	struct scatterlist sg_in[2], sg_out[2];
	u8 nonce[QUIC_IV_LEN];
	u8 *buffer;
	size_t total_in_len, total_out_len;
	DECLARE_CRYPTO_WAIT(wait);
	int err;

	if (!ctx || !aad || !plaintext || !ciphertext || !ciphertext_len)
		return -EINVAL;

	total_in_len = aad_len + plaintext_len;
	total_out_len = aad_len + plaintext_len + ctx->suite->tag_len;

	if (*ciphertext_len < total_out_len)
		return -ENOSPC;

	/* Allocate buffer for AAD + plaintext */
	buffer = kmalloc(total_in_len, GFP_ATOMIC);
	if (!buffer)
		return -ENOMEM;

	memcpy(buffer, aad, aad_len);
	memcpy(buffer + aad_len, plaintext, plaintext_len);

	req = aead_request_alloc(ctx->aead, GFP_ATOMIC);
	if (!req) {
		err = -ENOMEM;
		goto out_free_buffer;
	}

	/* Construct the nonce */
	quic_construct_nonce(ctx->iv, packet_number, nonce);

	/* Set up scatterlists */
	sg_init_table(sg_in, 2);
	sg_set_buf(&sg_in[0], buffer, aad_len);
	sg_set_buf(&sg_in[1], buffer + aad_len, plaintext_len);

	sg_init_table(sg_out, 2);
	sg_set_buf(&sg_out[0], ciphertext, aad_len);
	sg_set_buf(&sg_out[1], ciphertext + aad_len,
		   plaintext_len + ctx->suite->tag_len);

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_crypt(req, sg_in, sg_out, plaintext_len, nonce);
	aead_request_set_ad(req, aad_len);

	err = crypto_wait_req(crypto_aead_encrypt(req), &wait);
	if (err)
		goto out_free_req;

	*ciphertext_len = total_out_len;

out_free_req:
	aead_request_free(req);
out_free_buffer:
	kfree_sensitive(buffer);
	return err;
}
EXPORT_SYMBOL_GPL(quic_encrypt_packet);

/*
 * Decrypt a QUIC packet payload using AEAD (RFC 9001 Section 5.3)
 *
 * Returns -EBADMSG if authentication fails.
 */
int quic_decrypt_packet(struct quic_crypto_ctx *ctx,
			u64 packet_number,
			const u8 *aad, size_t aad_len,
			const u8 *ciphertext, size_t ciphertext_len,
			u8 *plaintext, size_t *plaintext_len)
{
	struct aead_request *req;
	struct scatterlist sg_in[2], sg_out[2];
	u8 nonce[QUIC_IV_LEN];
	u8 *buffer;
	size_t ct_only_len;
	DECLARE_CRYPTO_WAIT(wait);
	int err;

	if (!ctx || !aad || !ciphertext || !plaintext || !plaintext_len)
		return -EINVAL;

	if (ciphertext_len < ctx->suite->tag_len)
		return -EINVAL;

	ct_only_len = ciphertext_len - ctx->suite->tag_len;

	if (*plaintext_len < ct_only_len)
		return -ENOSPC;

	/* Allocate buffer for AAD + ciphertext + tag */
	buffer = kmalloc(aad_len + ciphertext_len, GFP_ATOMIC);
	if (!buffer)
		return -ENOMEM;

	memcpy(buffer, aad, aad_len);
	memcpy(buffer + aad_len, ciphertext, ciphertext_len);

	req = aead_request_alloc(ctx->aead, GFP_ATOMIC);
	if (!req) {
		err = -ENOMEM;
		goto out_free_buffer;
	}

	/* Construct the nonce */
	quic_construct_nonce(ctx->iv, packet_number, nonce);

	/* Set up scatterlists */
	sg_init_table(sg_in, 2);
	sg_set_buf(&sg_in[0], buffer, aad_len);
	sg_set_buf(&sg_in[1], buffer + aad_len, ciphertext_len);

	sg_init_table(sg_out, 2);
	sg_set_buf(&sg_out[0], plaintext, aad_len);
	sg_set_buf(&sg_out[1], plaintext + aad_len, ct_only_len);

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_crypt(req, sg_in, sg_out, ciphertext_len, nonce);
	aead_request_set_ad(req, aad_len);

	err = crypto_wait_req(crypto_aead_decrypt(req), &wait);
	if (err)
		goto out_free_req;

	*plaintext_len = ct_only_len;

out_free_req:
	aead_request_free(req);
out_free_buffer:
	kfree_sensitive(buffer);
	return err;
}
EXPORT_SYMBOL_GPL(quic_decrypt_packet);

/*
 * Perform key update (RFC 9001 Section 6)
 *
 * Derives new traffic keys from the current secret using HKDF-Expand-Label.
 */
int quic_key_update(struct quic_crypto_ctx *ctx)
{
	u8 new_secret[QUIC_MAX_HASH_LEN];
	int err;

	if (!ctx || ctx->secret_len == 0)
		return -EINVAL;

	/* new_secret = HKDF-Expand-Label(secret, "quic ku", "", Hash.length) */
	err = quic_hkdf_expand_label(ctx->hmac, ctx->secret, ctx->secret_len,
				     QUIC_HKDF_LABEL_KU, NULL, 0,
				     new_secret, ctx->secret_len);
	if (err)
		goto out;

	/* Derive new traffic keys */
	err = quic_derive_traffic_keys(ctx, new_secret, ctx->secret_len);
	if (err)
		goto out;

	/* Toggle the key phase bit */
	ctx->key_phase ^= 1;

out:
	memzero_explicit(new_secret, sizeof(new_secret));
	return err;
}
EXPORT_SYMBOL_GPL(quic_key_update);

/*
 * Get current key phase
 */
u8 quic_get_key_phase(const struct quic_crypto_ctx *ctx)
{
	return ctx ? ctx->key_phase : 0;
}
EXPORT_SYMBOL_GPL(quic_get_key_phase);

/*
 * Generate a retry integrity tag (RFC 9001 Section 5.8)
 *
 * The retry integrity tag is computed using AEAD with a fixed key and nonce.
 */
static int quic_compute_retry_integrity_tag(u32 version,
					    const u8 *pseudo_packet,
					    size_t pseudo_packet_len,
					    u8 *tag)
{
	struct crypto_aead *aead;
	struct aead_request *req;
	struct scatterlist sg_in, sg_out;
	const u8 *key, *nonce;
	u8 *buffer;
	size_t buffer_len;
	DECLARE_CRYPTO_WAIT(wait);
	int err;

	/* Select version-specific key and nonce */
	switch (version) {
	case 0x00000001:
		key = quic_v1_retry_key;
		nonce = quic_v1_retry_nonce;
		break;
	case 0x6b3343cf:
		key = quic_v2_retry_key;
		nonce = quic_v2_retry_nonce;
		break;
	default:
		return -EINVAL;
	}

	aead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(aead))
		return PTR_ERR(aead);

	err = crypto_aead_setkey(aead, key, 16);
	if (err)
		goto out_free_aead;

	err = crypto_aead_setauthsize(aead, QUIC_TAG_LEN);
	if (err)
		goto out_free_aead;

	req = aead_request_alloc(aead, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto out_free_aead;
	}

	/* Allocate buffer for pseudo packet + tag */
	buffer_len = pseudo_packet_len + QUIC_TAG_LEN;
	buffer = kzalloc(buffer_len, GFP_KERNEL);
	if (!buffer) {
		err = -ENOMEM;
		goto out_free_req;
	}

	memcpy(buffer, pseudo_packet, pseudo_packet_len);

	sg_init_one(&sg_in, buffer, pseudo_packet_len);
	sg_init_one(&sg_out, buffer, buffer_len);

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_crypt(req, &sg_in, &sg_out, 0, (u8 *)nonce);
	aead_request_set_ad(req, pseudo_packet_len);

	err = crypto_wait_req(crypto_aead_encrypt(req), &wait);
	if (err)
		goto out_free_buffer;

	/* Copy the tag */
	memcpy(tag, buffer + pseudo_packet_len, QUIC_TAG_LEN);

out_free_buffer:
	kfree_sensitive(buffer);
out_free_req:
	aead_request_free(req);
out_free_aead:
	crypto_free_aead(aead);
	return err;
}

/*
 * Generate a retry token
 *
 * The token contains the original DCID, client IP, and timestamp,
 * encrypted with a server-specific key.
 */
int quic_generate_retry_token(const u8 *odcid, size_t odcid_len,
			      const struct sockaddr *client_addr,
			      u8 *token, size_t *token_len,
			      const u8 *server_key, size_t key_len)
{
	struct crypto_aead *aead;
	struct aead_request *req;
	struct scatterlist sg_in, sg_out;
	struct quic_retry_token token_data;
	u8 nonce[QUIC_IV_LEN];
	u8 *buffer;
	size_t buffer_len;
	DECLARE_CRYPTO_WAIT(wait);
	int err;

	if (!odcid || !client_addr || !token || !token_len || !server_key)
		return -EINVAL;

	if (odcid_len > sizeof(token_data.odcid))
		return -EINVAL;

	/* Initialize token data */
	memset(&token_data, 0, sizeof(token_data));
	memcpy(token_data.odcid, odcid, odcid_len);
	token_data.odcid_len = odcid_len;
	token_data.timestamp = cpu_to_be64(ktime_get_real_seconds());
	get_random_bytes(token_data.random, sizeof(token_data.random));

	/* Store client IP */
	if (client_addr->sa_family == AF_INET) {
		token_data.ip_version = 4;
		token_data.client_ip = ((struct sockaddr_in *)client_addr)->sin_addr.s_addr;
	} else if (client_addr->sa_family == AF_INET6) {
		token_data.ip_version = 6;
		token_data.client_ip6 = ((struct sockaddr_in6 *)client_addr)->sin6_addr;
	} else {
		return -EAFNOSUPPORT;
	}

	/* Encrypt the token */
	aead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(aead))
		return PTR_ERR(aead);

	err = crypto_aead_setkey(aead, server_key, key_len);
	if (err)
		goto out_free_aead;

	err = crypto_aead_setauthsize(aead, QUIC_TAG_LEN);
	if (err)
		goto out_free_aead;

	req = aead_request_alloc(aead, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto out_free_aead;
	}

	/* Generate random nonce */
	get_random_bytes(nonce, sizeof(nonce));

	/* Allocate output buffer: nonce + encrypted token + tag */
	buffer_len = sizeof(nonce) + sizeof(token_data) + QUIC_TAG_LEN;
	if (*token_len < buffer_len) {
		err = -ENOSPC;
		goto out_free_req;
	}

	buffer = kzalloc(buffer_len, GFP_KERNEL);
	if (!buffer) {
		err = -ENOMEM;
		goto out_free_req;
	}

	/* Store nonce at the beginning */
	memcpy(buffer, nonce, sizeof(nonce));

	sg_init_one(&sg_in, &token_data, sizeof(token_data));
	sg_init_one(&sg_out, buffer + sizeof(nonce),
		    sizeof(token_data) + QUIC_TAG_LEN);

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_crypt(req, &sg_in, &sg_out, sizeof(token_data), nonce);
	aead_request_set_ad(req, 0);

	err = crypto_wait_req(crypto_aead_encrypt(req), &wait);
	if (err)
		goto out_free_buffer;

	memcpy(token, buffer, buffer_len);
	*token_len = buffer_len;

out_free_buffer:
	kfree_sensitive(buffer);
out_free_req:
	aead_request_free(req);
out_free_aead:
	crypto_free_aead(aead);
	return err;
}
EXPORT_SYMBOL_GPL(quic_generate_retry_token);

/*
 * Validate a retry token
 *
 * Decrypts and validates the token, checking the client IP and timestamp.
 */
int quic_validate_retry_token(const u8 *token, size_t token_len,
			      const struct sockaddr *client_addr,
			      u8 *odcid, size_t *odcid_len,
			      const u8 *server_key, size_t key_len,
			      u32 max_age_seconds)
{
	struct crypto_aead *aead;
	struct aead_request *req;
	struct scatterlist sg_in, sg_out;
	struct quic_retry_token token_data;
	u8 nonce[QUIC_IV_LEN];
	const u8 *ciphertext;
	size_t ciphertext_len;
	u64 timestamp, now;
	DECLARE_CRYPTO_WAIT(wait);
	int err;

	if (!token || !client_addr || !odcid || !odcid_len || !server_key)
		return -EINVAL;

	/* Token format: nonce (12 bytes) + encrypted data + tag (16 bytes) */
	if (token_len < QUIC_IV_LEN + QUIC_TAG_LEN)
		return -EINVAL;

	memcpy(nonce, token, QUIC_IV_LEN);
	ciphertext = token + QUIC_IV_LEN;
	ciphertext_len = token_len - QUIC_IV_LEN;

	if (ciphertext_len != sizeof(token_data) + QUIC_TAG_LEN)
		return -EINVAL;

	aead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(aead))
		return PTR_ERR(aead);

	err = crypto_aead_setkey(aead, server_key, key_len);
	if (err)
		goto out_free_aead;

	err = crypto_aead_setauthsize(aead, QUIC_TAG_LEN);
	if (err)
		goto out_free_aead;

	req = aead_request_alloc(aead, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto out_free_aead;
	}

	sg_init_one(&sg_in, ciphertext, ciphertext_len);
	sg_init_one(&sg_out, &token_data, sizeof(token_data));

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_crypt(req, &sg_in, &sg_out, ciphertext_len, nonce);
	aead_request_set_ad(req, 0);

	err = crypto_wait_req(crypto_aead_decrypt(req), &wait);
	if (err)
		goto out_free_req;

	/* Validate timestamp */
	timestamp = be64_to_cpu(token_data.timestamp);
	now = ktime_get_real_seconds();
	if (now < timestamp || (now - timestamp) > max_age_seconds) {
		err = -ETIMEDOUT;
		goto out_free_req;
	}

	/* Validate client IP */
	if (client_addr->sa_family == AF_INET) {
		if (token_data.ip_version != 4) {
			err = -EINVAL;
			goto out_free_req;
		}
		if (token_data.client_ip !=
		    ((struct sockaddr_in *)client_addr)->sin_addr.s_addr) {
			err = -EACCES;
			goto out_free_req;
		}
	} else if (client_addr->sa_family == AF_INET6) {
		if (token_data.ip_version != 6) {
			err = -EINVAL;
			goto out_free_req;
		}
		if (!ipv6_addr_equal(&token_data.client_ip6,
				     &((struct sockaddr_in6 *)client_addr)->sin6_addr)) {
			err = -EACCES;
			goto out_free_req;
		}
	} else {
		err = -EAFNOSUPPORT;
		goto out_free_req;
	}

	/* Return the original DCID */
	if (*odcid_len < token_data.odcid_len) {
		err = -ENOSPC;
		goto out_free_req;
	}

	memcpy(odcid, token_data.odcid, token_data.odcid_len);
	*odcid_len = token_data.odcid_len;

out_free_req:
	aead_request_free(req);
out_free_aead:
	crypto_free_aead(aead);
	return err;
}
EXPORT_SYMBOL_GPL(quic_validate_retry_token);

/*
 * Compute retry packet integrity tag
 */
int quic_compute_retry_tag(u32 version,
			   const u8 *odcid, size_t odcid_len,
			   const u8 *retry_packet, size_t retry_packet_len,
			   u8 *tag)
{
	u8 *pseudo_packet;
	size_t pseudo_packet_len;
	int err;

	if (!odcid || !retry_packet || !tag)
		return -EINVAL;

	/* Pseudo-packet = ODCID length (1 byte) + ODCID + Retry packet (without tag) */
	pseudo_packet_len = 1 + odcid_len + retry_packet_len;
	pseudo_packet = kmalloc(pseudo_packet_len, GFP_KERNEL);
	if (!pseudo_packet)
		return -ENOMEM;

	pseudo_packet[0] = odcid_len;
	memcpy(pseudo_packet + 1, odcid, odcid_len);
	memcpy(pseudo_packet + 1 + odcid_len, retry_packet, retry_packet_len);

	err = quic_compute_retry_integrity_tag(version, pseudo_packet,
					       pseudo_packet_len, tag);

	kfree(pseudo_packet);
	return err;
}
EXPORT_SYMBOL_GPL(quic_compute_retry_tag);

/*
 * Verify retry packet integrity tag
 */
int quic_verify_retry_tag(u32 version,
			  const u8 *odcid, size_t odcid_len,
			  const u8 *retry_packet, size_t retry_packet_len,
			  const u8 *tag)
{
	u8 computed_tag[QUIC_TAG_LEN];
	int err;

	err = quic_compute_retry_tag(version, odcid, odcid_len,
				     retry_packet, retry_packet_len,
				     computed_tag);
	if (err)
		return err;

	if (crypto_memneq(computed_tag, tag, QUIC_TAG_LEN))
		return -EBADMSG;

	return 0;
}
EXPORT_SYMBOL_GPL(quic_verify_retry_tag);

/*
 * Get cipher suite parameters
 */
int quic_crypto_get_params(const struct quic_crypto_ctx *ctx,
			   u8 *key_len, u8 *iv_len, u8 *tag_len)
{
	if (!ctx || !ctx->suite)
		return -EINVAL;

	if (key_len)
		*key_len = ctx->suite->key_len;
	if (iv_len)
		*iv_len = ctx->suite->iv_len;
	if (tag_len)
		*tag_len = ctx->suite->tag_len;

	return 0;
}
EXPORT_SYMBOL_GPL(quic_crypto_get_params);

/*
 * Directly set traffic keys (for testing or external key management)
 */
int quic_crypto_set_keys(struct quic_crypto_ctx *ctx,
			 const u8 *key, const u8 *iv, const u8 *hp_key)
{
	int err;

	if (!ctx || !key || !iv || !hp_key)
		return -EINVAL;

	memcpy(ctx->key, key, ctx->suite->key_len);
	memcpy(ctx->iv, iv, ctx->suite->iv_len);
	memcpy(ctx->hp_key, hp_key, ctx->suite->key_len);

	err = crypto_aead_setkey(ctx->aead, ctx->key, ctx->suite->key_len);
	if (err)
		return err;

	err = crypto_aead_setauthsize(ctx->aead, ctx->suite->tag_len);
	if (err)
		return err;

	return crypto_skcipher_setkey(ctx->hp_cipher, ctx->hp_key,
				      ctx->suite->key_len);
}
EXPORT_SYMBOL_GPL(quic_crypto_set_keys);

/*
 * Export current traffic keys (for debugging or key logging)
 */
int quic_crypto_get_keys(const struct quic_crypto_ctx *ctx,
			 u8 *key, u8 *iv, u8 *hp_key)
{
	if (!ctx)
		return -EINVAL;

	if (key)
		memcpy(key, ctx->key, ctx->suite->key_len);
	if (iv)
		memcpy(iv, ctx->iv, ctx->suite->iv_len);
	if (hp_key)
		memcpy(hp_key, ctx->hp_key, ctx->suite->key_len);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_crypto_get_keys);

/*
 * Check if cipher suite is supported
 */
bool quic_crypto_is_cipher_supported(u16 cipher_suite)
{
	return quic_find_cipher_suite(cipher_suite) != NULL;
}
EXPORT_SYMBOL_GPL(quic_crypto_is_cipher_supported);

/*
 * Get list of supported cipher suites
 */
int quic_crypto_get_supported_ciphers(u16 *ciphers, size_t *count)
{
	int i;

	if (!ciphers || !count)
		return -EINVAL;

	if (*count < ARRAY_SIZE(quic_cipher_suites))
		return -ENOSPC;

	for (i = 0; i < ARRAY_SIZE(quic_cipher_suites); i++)
		ciphers[i] = quic_cipher_suites[i].id;

	*count = ARRAY_SIZE(quic_cipher_suites);
	return 0;
}
EXPORT_SYMBOL_GPL(quic_crypto_get_supported_ciphers);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("QUIC Cryptographic Operations");
MODULE_AUTHOR("Linux QUIC Implementation Authors");
