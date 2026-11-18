/*
 * holywisp/sha256.h - SHA-256 (FIPS 180-4), HMAC-SHA-256 (RFC 2104), HKDF (RFC 5869) and the
 * TLS 1.3 HKDF-Expand-Label (RFC 8446 section 7.1). The hash of the TLS 1.3 and QUIC stack
 * (holywisp/tls13.h, holywisp/quic.h): its transcript, key schedule and packet keys, the
 * certificate hashes WebTransport clients pin, and the server's address-validation tokens.
 *
 * Pure functions with no state outside their arguments; safe from any thread.
 */
#ifndef HOLYWISP_SHA256_H
#define HOLYWISP_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define HW_SHA256_LEN   32
#define HW_SHA256_BLOCK 64

typedef struct {
	uint32_t h[8];
	uint64_t len; // bytes hashed so far
	uint8_t buf[HW_SHA256_BLOCK];
	size_t n; // bytes in buf
} hw_sha256_ctx;

// Incremental SHA-256. A context may be copied by value to fork a running hash (the TLS
// transcript hash is read at several points of the handshake while it keeps growing).
void hw_sha256_init(hw_sha256_ctx *c);
void hw_sha256_update(hw_sha256_ctx *c, const void *data, size_t len);
void hw_sha256_final(hw_sha256_ctx *c, uint8_t out[HW_SHA256_LEN]);

// One-shot SHA-256 of data.
void hw_sha256(const void *data, size_t len, uint8_t out[HW_SHA256_LEN]);

// HMAC-SHA-256 of data under key (any length).
void hw_hmac_sha256(const uint8_t *key, size_t key_len, const void *data, size_t len, uint8_t out[HW_SHA256_LEN]);

// HKDF-Extract(salt, ikm). A NULL or empty salt is HashLen zero bytes, as RFC 5869 says.
void hw_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                     uint8_t prk[HW_SHA256_LEN]);

// HKDF-Expand(prk, info, out_len). Returns 0, or -1 when out_len is over 255 * HashLen.
int hw_hkdf_expand(const uint8_t prk[HW_SHA256_LEN], const uint8_t *info, size_t info_len, uint8_t *out,
                   size_t out_len);

// HKDF-Expand-Label(secret, label, context, out_len) of TLS 1.3: the info is the HkdfLabel struct,
// whose label is "tls13 " followed by label. QUIC uses it with labels such as "client in",
// "quic key" and "quic hp" (RFC 9001 section 5). Returns 0, or -1 when the label is over 249 bytes,
// the context over 255 or out_len over 255 * HashLen.
int hw_hkdf_expand_label(const uint8_t secret[HW_SHA256_LEN], const char *label, const uint8_t *context,
                         size_t context_len, uint8_t *out, size_t out_len);

#endif
