/*
 * holywisp/tls13.h - TLS 1.3 (RFC 8446) as QUIC uses it (RFC 9001): the handshake only, with no
 * record layer. QUIC carries the handshake messages in CRYPTO frames at three encryption levels
 * and protects packets with the secrets this module derives (holywisp/quic.h).
 *
 * Sans-IO: the caller feeds received handshake bytes per level with hw_tls_input and receives
 * bytes to send and new secrets through callbacks, synchronously, from inside hw_tls_start or
 * hw_tls_input. One hw_tls is used by one thread.
 *
 * Deliberately narrow (docs/webtransport.md, "Cryptography"):
 * - Only TLS 1.3, only (EC)DHE: key exchange X25519 (a ClientHello without an X25519 key share
 *   but listing it gets a HelloRetryRequest), signatures ecdsa_secp256r1_sha256, cipher suite
 *   TLS_CHACHA20_POLY1305_SHA256 for the server's choice. A client that does not offer all three
 *   is refused with handshake_failure.
 * - No PSK, no resumption tickets, no 0-RTT (early data is never accepted), no client
 *   certificates, no post-handshake messages other than an ignored NewSessionTicket on the
 *   client side and KeyUpdate, which QUIC forbids (unexpected_message).
 * - ALPN is required (QUIC requires it): the server picks the first of its own list the client
 *   offers, or fails with no_application_protocol (alert 120).
 * - The quic_transport_parameters extension (0x39) is carried both ways as opaque bytes; its
 *   absence is a missing_extension alert. Its contents are holywisp/quic.h's business.
 *
 * The client role exists for holyWisp's own tests and client; it verifies the server by the
 * SHA-256 of its leaf certificate (pin), or of the leaf's public key (a key pin, which survives a
 * renewal that keeps the key), and the CertificateVerify signature, not by a CA chain.
 */
#ifndef HOLYWISP_TLS13_H
#define HOLYWISP_TLS13_H

#include "holywisp/cert.h"

#include <stddef.h>
#include <stdint.h>

// Encryption levels, numbered as QUIC's packet number spaces are not: there is no 0-RTT here.
typedef enum {
	HW_TLS_INITIAL = 0,
	HW_TLS_HANDSHAKE = 1,
	HW_TLS_APP = 2,
} hw_tls_level;

#define HW_TLS_KEY_PINS_MAX 4 // key pins a client may hold at once (the key in use and its successors)

#define HW_TLS_CIPHER_AES128GCM 0x1301 // only ever the Initial level's, which TLS does not choose
#define HW_TLS_CIPHER_CHACHA20  0x1303

// TLS alerts the module raises (QUIC sends them as CRYPTO_ERROR 0x100 + alert).
#define HW_TLS_ALERT_UNEXPECTED_MESSAGE 10
#define HW_TLS_ALERT_HANDSHAKE_FAILURE  40
#define HW_TLS_ALERT_BAD_CERTIFICATE    42
#define HW_TLS_ALERT_ILLEGAL_PARAMETER  47
#define HW_TLS_ALERT_DECODE_ERROR       50
#define HW_TLS_ALERT_DECRYPT_ERROR      51
#define HW_TLS_ALERT_PROTOCOL_VERSION   70
#define HW_TLS_ALERT_INTERNAL_ERROR     80
#define HW_TLS_ALERT_MISSING_EXTENSION  109
#define HW_TLS_ALERT_UNSUPPORTED_EXT    110 // client: the server answered with an extension never offered
#define HW_TLS_ALERT_NO_APP_PROTOCOL    120

typedef struct {
	void *ud;
	// Handshake bytes to send at a level, in order. Returns 0, or -1 to abort the handshake
	// (internal_error).
	int (*emit)(void *ud, hw_tls_level level, const uint8_t *data, size_t len);
	// A traffic secret is ready: write = 1 for the secret this side sends with, 0 for the one it
	// receives with. cipher is HW_TLS_CIPHER_*. Called for HW_TLS_HANDSHAKE and HW_TLS_APP (the
	// Initial secrets come from QUIC). The secret is only valid during the call.
	int (*secret)(void *ud, hw_tls_level level, int write, uint16_t cipher, const uint8_t secret[32]);
} hw_tls_callbacks;

typedef struct {
	int is_server;
	// Server: the certificate chain (leaf first) and the leaf's P-256 private key.
	const hw_der *chain;
	size_t chain_len;
	const uint8_t *key; // HW_P256_PRIV_LEN bytes
	// Server, optional: called once the ClientHello is read, with its SNI (NULL when it sent
	// none). Returning 1 with *chain, *chain_len and *key set answers with that certificate
	// instead (copied during the call, so the caller's may change after it); 0 keeps the one
	// above. A chain that would not have been accepted above fails the handshake
	// (internal_error). The function and cert_ud are copied, not what cert_ud points at.
	int (*cert_for)(void *cert_ud, const char *server_name, const hw_der **chain, size_t *chain_len,
	                const uint8_t **key);
	void *cert_ud;
	// Both: ALPN protocols. The server's are acceptable ones in preference order; the client's
	// are offered.
	const char *const *alpn;
	size_t alpn_count;
	// Both: this side's quic_transport_parameters extension body.
	const uint8_t *transport_params;
	size_t transport_params_len;
	// Client: SNI to send (NULL for none), and the SHA-256 the server's leaf must have (NULL to
	// accept any leaf, for tests only).
	const char *server_name;
	const uint8_t *pin_sha256;
	// Client: key pins, key_pin_count SHA-256 values of 32 bytes each, back to back: the leaf's
	// SubjectPublicKeyInfo (hw_cert_spki) must hash to one of them. With pin_sha256 as well, both
	// must hold. 0: none. More than HW_TLS_KEY_PINS_MAX is a config hw_tls_new cannot use.
	const uint8_t *key_pins_sha256;
	size_t key_pin_count;
} hw_tls_config;

typedef struct hw_tls hw_tls;

// A handshake for one connection. The config's buffers are copied. NULL on allocation failure,
// or for a config it cannot use: no emit callback, no ALPN or a name that is empty or over 255
// bytes, transport parameters over 65535 bytes, an SNI that is empty or over 255 bytes, or a
// server without a key or a chain of 1 to HW_CERT_CHAIN_MAX certificates whose Certificate
// message fits in 64 KiB, or a client with more than HW_TLS_KEY_PINS_MAX key pins.
hw_tls *hw_tls_new(const hw_tls_config *cfg, const hw_tls_callbacks *cb);
void hw_tls_free(hw_tls *t);

// Client: emit the ClientHello. Server: does nothing. Returns 0, or -1 (see hw_tls_alert).
int hw_tls_start(hw_tls *t);

// Handshake bytes received at a level, in order (QUIC reassembles CRYPTO frames before this).
// Messages may be split anywhere across calls. Returns 0, or -1 when the handshake failed;
// hw_tls_alert then says why and nothing more may be fed.
int hw_tls_input(hw_tls *t, hw_tls_level level, const uint8_t *data, size_t len);

// 1 once this side has sent and received Finished (the server: received the client's).
int hw_tls_done(const hw_tls *t);

// The alert of a failed handshake, 0 while none.
uint8_t hw_tls_alert(const hw_tls *t);

// After the ServerHello: the negotiated ALPN (NUL-terminated), and the peer's transport
// parameters (NULL until they are known). The client's SNI on the server side (NULL if none).
const char *hw_tls_alpn(const hw_tls *t);
const uint8_t *hw_tls_peer_transport_params(const hw_tls *t, size_t *len);
const char *hw_tls_server_name(const hw_tls *t);

#endif
