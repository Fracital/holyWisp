/*
 * src/quic/tls13_internal.h - the parts of src/quic/tls13.c that tests reach past the contract
 * (holywisp/tls13.h): the key schedule of RFC 8446 section 7.1 on its own, so it can be held to
 * the RFC 8448 trace; a client that sends no key share, so the HelloRetryRequest path can be
 * driven by both roles; and what the reassembly buffer holds. Nothing outside tests/ includes
 * this.
 */
#ifndef HOLYWISP_QUIC_TLS13_INTERNAL_H
#define HOLYWISP_QUIC_TLS13_INTERNAL_H

#include "holywisp/tls13.h"

#include <stddef.h>
#include <stdint.h>

// Derive-Secret(secret, label, messages) where th is already Transcript-Hash(messages).
void hw_tls_derive_secret(const uint8_t secret[32], const char *label, const uint8_t th[32], uint8_t out[32]);

// The handshake secret and the client and server handshake traffic secrets, with no PSK, from the
// (EC)DHE shared secret and Transcript-Hash(ClientHello..ServerHello).
void hw_tls_schedule_handshake(const uint8_t ecdhe[32], const uint8_t th_sh[32], uint8_t hs[32], uint8_t c_hs[32],
                               uint8_t s_hs[32]);

// The master secret and the client and server application traffic secrets, from the handshake
// secret and Transcript-Hash(ClientHello..server Finished).
void hw_tls_schedule_app(const uint8_t hs[32], const uint8_t th_sf[32], uint8_t master[32], uint8_t c_ap[32],
                         uint8_t s_ap[32]);

// finished_key = HKDF-Expand-Label(traffic secret, "finished", "", 32).
void hw_tls_finished_key(const uint8_t traffic[32], uint8_t out[32]);

// Client, before hw_tls_start: list X25519 but send no key share for it, so a server answers
// with a HelloRetryRequest and the client sends its share in a second ClientHello.
void hw_tls_test_omit_key_share(hw_tls *t);

// The bytes held for reassembling the handshake message being received (0 when none are).
size_t hw_tls_test_rx_cap(const hw_tls *t);

#endif
