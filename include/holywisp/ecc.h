/*
 * holywisp/ecc.h - the public-key primitives of the TLS 1.3 server (holywisp/tls13.h): X25519
 * key agreement (RFC 7748) and ECDSA over P-256 with SHA-256 (FIPS 186-5, deterministic nonces
 * per RFC 6979) for CertificateVerify and for signing the server's own certificates
 * (holywisp/cert.h).
 *
 * Every operation on a private key or a shared secret is constant-time: no branch and no memory
 * index depends on secret data. Pure and thread-safe; key generation draws from hw_sys_random.
 */
#ifndef HOLYWISP_ECC_H
#define HOLYWISP_ECC_H

#include <stddef.h>
#include <stdint.h>

#define HW_X25519_LEN       32
#define HW_P256_PRIV_LEN    32
#define HW_P256_PUB_LEN     65 // uncompressed: 0x04 || X || Y
#define HW_P256_SIG_DER_MAX 72 // DER SEQUENCE { INTEGER r, INTEGER s }

// X25519(scalar, point) into out. The scalar is clamped as RFC 7748 says. Returns 0, or -1 when
// the result is all zero (a small-order point), which TLS 1.3 must refuse.
int hw_x25519(uint8_t out[HW_X25519_LEN], const uint8_t scalar[HW_X25519_LEN], const uint8_t point[HW_X25519_LEN]);

// A fresh X25519 key pair. Returns 0, or -1 when the random source fails.
int hw_x25519_keygen(uint8_t priv[HW_X25519_LEN], uint8_t pub[HW_X25519_LEN]);

// A fresh P-256 key pair (priv in [1, n-1]). Returns 0, or -1 when the random source fails.
int hw_p256_keygen(uint8_t priv[HW_P256_PRIV_LEN], uint8_t pub[HW_P256_PUB_LEN]);

// The public key of priv. Returns 0, or -1 when priv is 0 or not below the group order.
int hw_p256_public(const uint8_t priv[HW_P256_PRIV_LEN], uint8_t pub[HW_P256_PUB_LEN]);

// 1 when pub is an uncompressed point (0x04 || X || Y, both below p) on P-256, else 0. Public
// data: not constant-time. The point at infinity has no such encoding and is never valid.
int hw_p256_public_valid(const uint8_t pub[HW_P256_PUB_LEN]);

// ECDSA signature of a SHA-256 digest, DER-encoded (as TLS and X.509 carry it), with the nonce
// derived from the key and digest per RFC 6979 section 3.2 (HMAC-SHA-256). Returns the DER
// length, or -1 on an invalid key.
int hw_p256_sign(const uint8_t priv[HW_P256_PRIV_LEN], const uint8_t digest[32], uint8_t sig[HW_P256_SIG_DER_MAX]);

// 1 when sig (DER) is a valid signature of digest under pub, 0 when it is not, including any
// malformed encoding or a public key that is not on the curve. Not constant-time (public data).
int hw_p256_verify(const uint8_t pub[HW_P256_PUB_LEN], const uint8_t digest[32], const uint8_t *sig, size_t sig_len);

#endif
