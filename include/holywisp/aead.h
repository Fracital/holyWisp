/*
 * holywisp/aead.h - the symmetric ciphers of the QUIC stack (holywisp/quic.h, holywisp/tls13.h):
 * AES-128 with GCM (FIPS 197, NIST SP 800-38D) and ChaCha20-Poly1305 (RFC 8439), plus the raw
 * block functions QUIC's header protection needs (RFC 9001 section 5.4).
 *
 * Which is used for what (docs/webtransport.md, "Cryptography"):
 * - AES-128-GCM and AES-128 header protection protect QUIC Initial packets, which RFC 9001
 *   requires. Their keys are derived from the client's Destination Connection ID, which is on
 *   the wire, so they protect nothing secret; the table-free but not hardware-accelerated AES
 *   here is acceptable for them only.
 * - ChaCha20-Poly1305 (TLS_CHACHA20_POLY1305_SHA256) is the only suite the server selects for
 *   the Handshake and 1-RTT keys, where the keys are secret. Its code must be constant-time.
 *
 * Every function is pure and thread-safe. Lengths are bytes. Seal writes len bytes of ciphertext
 * followed by the HW_AEAD_TAG-byte tag; open takes ciphertext with its tag and fails (-1, output
 * zeroed) when the tag does not verify. In both, out may equal in (in place) but may not
 * otherwise overlap it.
 */
#ifndef HOLYWISP_AEAD_H
#define HOLYWISP_AEAD_H

#include <stddef.h>
#include <stdint.h>

#define HW_AEAD_TAG   16
#define HW_AEAD_NONCE 12

// 1 when the n bytes at a and b are equal, 0 otherwise, in time that depends only on n.
int hw_ct_equal(const void *a, const void *b, size_t n);

// ---- AES-128 ------------------------------------------------------------------------------
typedef struct {
	uint32_t rk[44]; // expanded key schedule
} hw_aes128;

void hw_aes128_init(hw_aes128 *k, const uint8_t key[16]);
void hw_aes128_encrypt(const hw_aes128 *k, const uint8_t in[16], uint8_t out[16]);

// AES-128-GCM with a 12-byte nonce. init precomputes H and its tables from the key.
typedef struct {
	hw_aes128 aes;
	uint64_t htable[32]; // GHASH multiplication table for H (layout is the implementation's)
} hw_aes128gcm;

void hw_aes128gcm_init(hw_aes128gcm *g, const uint8_t key[16]);
void hw_aes128gcm_seal(const hw_aes128gcm *g, const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                       const uint8_t *in, size_t len, uint8_t *out);
int hw_aes128gcm_open(const hw_aes128gcm *g, const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                      const uint8_t *in, size_t len, uint8_t *out);

// ---- ChaCha20-Poly1305 --------------------------------------------------------------------
// The ChaCha20 keystream XORed into len bytes, starting at block counter (RFC 8439 2.4).
// QUIC header protection calls it with the first four sample bytes as the counter and the
// other twelve as the nonce over five zero bytes.
void hw_chacha20_xor(const uint8_t key[32], uint32_t counter, const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *in,
                     uint8_t *out, size_t len);

// The Poly1305 one-time authenticator of len bytes under a 32-byte one-time key (RFC 8439 2.5).
// The AEAD below uses it internally; it is public for its RFC vectors.
void hw_poly1305(const uint8_t key[32], const uint8_t *msg, size_t len, uint8_t tag[HW_AEAD_TAG]);

void hw_chacha20poly1305_seal(const uint8_t key[32], const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *aad,
                              size_t aad_len, const uint8_t *in, size_t len, uint8_t *out);
int hw_chacha20poly1305_open(const uint8_t key[32], const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *aad,
                             size_t aad_len, const uint8_t *in, size_t len, uint8_t *out);

#endif
