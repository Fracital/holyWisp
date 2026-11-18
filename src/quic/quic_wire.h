/*
 * src/quic/quic_wire.h - QUIC's bytes, below the connection state machine: variable-length
 * integers, packet headers, packet and header protection, the Initial secrets, Retry integrity,
 * address-validation tokens, stateless reset tokens and the transport parameters codec
 * (RFC 9000 sections 12, 16-18; RFC 9001 sections 5 and A).
 *
 * Internal to src/quic. Pure functions, no allocation, no state; every length is checked
 * against the buffer it reads and a malformed input is -1, never a read past it. quic.c
 * (connections, frames, recovery) is built on this; the stateless functions of
 * holywisp/quic.h (hw_quic_parse_header, _version_negotiation, _retry, _token_valid,
 * _stateless_reset) are implemented in quic_wire.c on top of it.
 */
#ifndef HOLYWISP_QUIC_WIRE_H
#define HOLYWISP_QUIC_WIRE_H

#include "holywisp/aead.h"
#include "holywisp/quic.h"

#include <stddef.h>
#include <stdint.h>

// ---- Variable-length integers (RFC 9000 section 16) ---------------------------------------
#define HW_QW_VARINT_MAX 0x3fffffffffffffffull

// Bytes the shortest encoding of v takes: 1, 2, 4 or 8 (v <= HW_QW_VARINT_MAX).
size_t hw_qw_varint_len(uint64_t v);
// Writes the shortest encoding at p (cap bytes available). Returns the bytes written, 0 when
// they do not fit or v is too large.
size_t hw_qw_varint_put(uint8_t *p, size_t cap, uint64_t v);
// Writes v in exactly n bytes (1, 2, 4 or 8), as the Length field needs before the payload's
// size is known. Returns n, or 0 when v does not fit n bytes or cap < n.
size_t hw_qw_varint_put_n(uint8_t *p, size_t cap, uint64_t v, size_t n);
// Reads one at p. Returns the bytes read, 0 when len is too short.
size_t hw_qw_varint_get(const uint8_t *p, size_t len, uint64_t *v);

// ---- Packet headers -----------------------------------------------------------------------
enum {
	HW_QW_INITIAL = 0,
	HW_QW_0RTT = 1,
	HW_QW_HANDSHAKE = 2,
	HW_QW_RETRY = 3,
	HW_QW_SHORT = 4, // a 1-RTT packet
};

typedef struct {
	int type; // HW_QW_*
	uint32_t version;
	const uint8_t *dcid;
	uint8_t dcid_len;
	const uint8_t *scid; // long header only
	uint8_t scid_len;
	const uint8_t *token; // Initial only
	size_t token_len;
	size_t pn_offset;  // where the (protected) packet number starts
	size_t packet_len; // this packet's length within the datagram (the rest of it for a short header)
} hw_qw_hdr;

// Parse the header of the packet at p (len bytes left in the datagram) without removing
// header protection. Short headers are read with dcid_len_short-byte DCIDs. For a long header
// packet_len comes from its Length field (so coalesced packets can be walked); a Retry or a
// Version Negotiation packet (version 0, type stays as read) has no pn_offset. A Retry's token
// is set too (everything after the SCID but the 16-byte integrity tag). A long header of any
// version other than 1 is read only as far as its invariant fields (RFC 8999: version and both
// CIDs), which is what Version Negotiation needs: pn_offset 0, no token, packet_len the rest
// of the datagram; the caller tests h->version before anything else. A short header is
// version 1. Only framing is checked: whether the packet is long enough for a header-protection
// sample is hw_qw_unprotect's to say. Returns 0, or -1 when the bytes cannot be a QUIC packet of
// a version this parses (fixed bit clear in version 1, lengths past the end, a CID over 20
// bytes).
int hw_qw_parse(const uint8_t *p, size_t len, size_t dcid_len_short, hw_qw_hdr *h);

// The packet number a truncated one (pn_len bytes, value truncated) stands for, given the
// largest packet number received in the space (RFC 9000 A.3). largest = -1 for none yet.
uint64_t hw_qw_pn_decode(int64_t largest, uint64_t truncated, size_t pn_len);
// The number of bytes to send pn in, given the largest acknowledged in the space (A.2).
size_t hw_qw_pn_len(uint64_t pn, int64_t largest_acked);

// ---- Packet protection (RFC 9001 section 5) -----------------------------------------------
typedef struct {
	uint16_t cipher; // HW_TLS_CIPHER_AES128GCM or HW_TLS_CIPHER_CHACHA20
	uint8_t secret[32];
	uint8_t key[32]; // 16 bytes for AES-128-GCM
	uint8_t iv[HW_AEAD_NONCE];
	uint8_t hp[32];
	hw_aes128gcm gcm; // AES only
	hw_aes128 hp_aes; // AES only
} hw_qw_keys;

// Keys from a traffic secret: "quic key", "quic iv", "quic hp" (HKDF-Expand-Label, SHA-256).
void hw_qw_keys_from_secret(hw_qw_keys *k, uint16_t cipher, const uint8_t secret[32]);
// The next generation for a key update: secret' = Expand-Label(secret, "quic ku"); hp unchanged.
void hw_qw_keys_update(hw_qw_keys *next, const hw_qw_keys *cur);
// The Initial keys of a connection whose client chose dcid (RFC 9001 section 5.2, v1 salt).
void hw_qw_initial_keys(const uint8_t *dcid, size_t dcid_len, hw_qw_keys *client, hw_qw_keys *server);
// Wipe a key set.
void hw_qw_keys_clear(hw_qw_keys *k);

// Seal a packet in place. pkt holds the header (pn_offset is where its pn_len-byte packet number
// already is, and a long header's Length already counts pn_len + payload_len + HW_AEAD_TAG)
// followed by payload_len bytes of plaintext frames, with HW_AEAD_TAG bytes of room after them.
// The payload must be long enough for a header-protection sample (pn_len + payload_len >= 4).
// The first byte's Packet Number Length bits and the packet number field are (re)written here
// from pn_len and pn, so the caller may leave them as anything. Encrypts, appends the tag,
// applies header protection. Returns the packet's whole length, or 0 for pn_len outside 1..4, a
// payload too short to sample or an unknown cipher.
size_t hw_qw_protect(const hw_qw_keys *k, uint8_t *pkt, size_t pn_offset, size_t pn_len, uint64_t pn,
                     size_t payload_len);

// Open a packet in place: remove header protection, decode the packet number against largest
// (the largest received in its space, -1 for none), decrypt. pkt_len is h->packet_len. On 0,
// *pn is the full packet number, *payload and *payload_len the plaintext frames and *key_phase
// the short header's key phase bit (0 for long headers), and pkt[0] and the packet number field
// hold their unprotected values: the reserved bits of pkt[0] are the caller's to check (nonzero
// after a successful decryption is PROTOCOL_VIOLATION, RFC 9000 17.2). On -1 the packet must be
// dropped (its bytes are then garbage: the caller does not reuse them); a packet too short for a
// header-protection sample (pkt_len < pn_offset + 4 + 16) is -1 without anything read past it.
int hw_qw_unprotect(const hw_qw_keys *k, uint8_t *pkt, size_t pkt_len, size_t pn_offset, int64_t largest, uint64_t *pn,
                    uint8_t **payload, size_t *payload_len, int *key_phase);

// hw_qw_unprotect with the header-protection mask already computed (hw_qw_hp_mask over the
// sample at pkt + pn_offset + 4), for a caller that needed the unmasked first byte to choose
// k: a 1-RTT packet's key phase bit says which generation opens it, and every generation has
// the same header-protection key (hw_qw_keys_update), so the mask made with one serves them
// all. Everything else, the lengths checked included, is hw_qw_unprotect's.
int hw_qw_unprotect_masked(const hw_qw_keys *k, const uint8_t mask[5], uint8_t *pkt, size_t pkt_len, size_t pn_offset,
                           int64_t largest, uint64_t *pn, uint8_t **payload, size_t *payload_len, int *key_phase);

// The 5-byte header-protection mask for a 16-byte sample (RFC 9001 section 5.4), for callers
// that need the unmasked first byte before choosing keys. Returns 0, or -1 for an unknown cipher.
int hw_qw_hp_mask(const hw_qw_keys *k, const uint8_t sample[16], uint8_t mask[5]);

// ---- Retry, tokens, stateless reset -------------------------------------------------------
// The Retry Integrity Tag of a Retry packet (pkt, without its tag) answering odcid
// (RFC 9001 section 5.8, AES-128-GCM under the v1 fixed key). Returns 0, or -1 (tag zeroed:
// never compare it) when odcid_len is over 20 or len over HW_QW_RETRY_MAX.
#define HW_QW_RETRY_MAX 4096 // the longest Retry (without its tag) this computes a tag for
int hw_qw_retry_tag(const uint8_t *odcid, size_t odcid_len, const uint8_t *pkt, size_t len, uint8_t tag[HW_AEAD_TAG]);
// 1 when the Retry packet pkt (len bytes, its tag included: h.packet_len from hw_qw_parse)
// carries the right integrity tag for odcid, compared in constant time; 0 otherwise.
int hw_qw_retry_verify(const uint8_t *odcid, size_t odcid_len, const uint8_t *pkt, size_t len);

// The stateless reset token for a connection ID under the listener's key:
// HMAC-SHA-256(key, cid) truncated to 16 bytes.
void hw_qw_reset_token(const uint8_t key[HW_QUIC_KEY_LEN], const uint8_t *cid, size_t cid_len,
                       uint8_t token[HW_QUIC_RESET_LEN]);

// ---- Transport parameters (RFC 9000 section 18, RFC 9221 section 3) -----------------------
typedef struct {
	uint64_t max_idle_timeout;
	uint64_t max_udp_payload_size; // default 65527
	uint64_t initial_max_data;
	uint64_t initial_max_stream_data_bidi_local;
	uint64_t initial_max_stream_data_bidi_remote;
	uint64_t initial_max_stream_data_uni;
	uint64_t initial_max_streams_bidi;
	uint64_t initial_max_streams_uni;
	uint64_t ack_delay_exponent;         // default 3
	uint64_t max_ack_delay;              // default 25
	uint64_t active_connection_id_limit; // default 2
	uint64_t max_datagram_frame_size;    // 0 = absent
	int disable_active_migration;
	int has_original_dcid, has_initial_scid, has_retry_scid, has_reset_token;
	uint8_t original_dcid[20], original_dcid_len;
	uint8_t initial_scid[20], initial_scid_len;
	uint8_t retry_scid[20], retry_scid_len;
	uint8_t reset_token[HW_QUIC_RESET_LEN];
} hw_qw_tp;

// The RFC defaults (everything else 0 / absent).
void hw_qw_tp_defaults(hw_qw_tp *tp);
// Encode, as this side sends them (a client never sends the server-only ones). Returns the
// length, 0 when cap is too small.
size_t hw_qw_tp_encode(const hw_qw_tp *tp, int is_server, uint8_t *out, size_t cap);
// Decode the peer's (from_server says which side sent them), applying the defaults first.
// Unknown and GREASE ids are skipped; preferred_address is checked and then ignored. Returns 0,
// or -1 for anything TRANSPORT_PARAMETER_ERROR: a duplicate, a value out of range
// (max_udp_payload_size < 1200, ack_delay_exponent > 20, max_ack_delay >= 2^14,
// active_connection_id_limit < 2, initial_max_streams_* > 2^60), a server-only parameter from a
// client, a bad length (preferred_address: other than 41 bytes plus its CID's, or a CID of 0
// or over 20 bytes).
int hw_qw_tp_decode(const uint8_t *in, size_t len, int from_server, hw_qw_tp *tp);

#endif
