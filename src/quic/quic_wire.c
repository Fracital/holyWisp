/*
 * src/quic/quic_wire.c - QUIC's bytes below the connection state machine (quic_wire.h), and the
 * stateless half of holywisp/quic.h the listener uses before a connection exists: header
 * parsing, Version Negotiation, Retry with address-validation tokens, stateless reset.
 *
 * Every read is bounded by the length it was given; nothing here allocates or keeps state.
 */
#include "quic_wire.h"

#include "holywisp/hw.h"
#include "holywisp/sha256.h"
#include "holywisp/sys.h"

#include <string.h>

#include <netinet/in.h>

// RFC 9001 section 5.2: the version 1 Initial salt.
static const uint8_t INITIAL_SALT[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                                         0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
// RFC 9001 section 5.8: the version 1 Retry integrity key and nonce.
static const uint8_t RETRY_KEY[16] = {0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
                                      0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e};
static const uint8_t RETRY_NONCE[HW_AEAD_NONCE] = {0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
                                                   0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb};

#define CID_MAX     20
#define SAMPLE_LEN  16
#define PN_LEN_MAX  4
#define VN_HDR_LEN  7 // first byte, version, two CID lengths
#define RESET_MIN   21
#define RESET_EXACT 43 // up to this, a reset is one byte shorter than what it answers

// The address-validation token hw_quic_retry issues:
//   format (1) | nonce (12) | ChaCha20-Poly1305(ts_ms u64 BE | odcid_len (1) | odcid (20, zero padded)) | tag (16)
// with the format byte, the peer's address as 16 bytes (IPv4 as ::ffff:a.b.c.d) and its port as
// the associated data. The address is bound, not carried: a token says nothing about who got it.
#define TOKEN_FORMAT 0x52
#define TOKEN_PLAIN  (8 + 1 + CID_MAX)
#define TOKEN_LEN    (1 + HW_AEAD_NONCE + TOKEN_PLAIN + HW_AEAD_TAG)
#define TOKEN_AAD    (1 + 16 + 2)

static void wipe(void *p, size_t n) {
	volatile uint8_t *v = p;
	while (n--) *v++ = 0;
}

static void put_be32(uint8_t *p, uint32_t v) {
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t *p) {
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

// ---- Variable-length integers ---------------------------------------------------------------

size_t hw_qw_varint_len(uint64_t v) {
	if (v < 0x40) return 1;
	if (v < 0x4000) return 2;
	if (v < 0x40000000) return 4;
	return 8;
}

size_t hw_qw_varint_put_n(uint8_t *p, size_t cap, uint64_t v, size_t n) {
	uint8_t prefix;
	switch (n) {
	case 1:
		prefix = 0x00;
		break;
	case 2:
		prefix = 0x40;
		break;
	case 4:
		prefix = 0x80;
		break;
	case 8:
		prefix = 0xc0;
		break;
	default:
		return 0;
	}
	if (cap < n || v > HW_QW_VARINT_MAX || (n < 8 && v >> (8 * n - 2))) return 0;
	for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
	p[0] |= prefix;
	return n;
}

size_t hw_qw_varint_put(uint8_t *p, size_t cap, uint64_t v) {
	if (v > HW_QW_VARINT_MAX) return 0;
	return hw_qw_varint_put_n(p, cap, v, hw_qw_varint_len(v));
}

size_t hw_qw_varint_get(const uint8_t *p, size_t len, uint64_t *v) {
	if (len < 1) return 0;
	size_t n = (size_t)1 << (p[0] >> 6);
	if (len < n) return 0;
	uint64_t x = p[0] & 0x3f;
	for (size_t i = 1; i < n; i++) x = x << 8 | p[i];
	*v = x;
	return n;
}

// ---- Packet headers -------------------------------------------------------------------------

int hw_qw_parse(const uint8_t *p, size_t len, size_t dcid_len_short, hw_qw_hdr *h) {
	memset(h, 0, sizeof(*h));
	if (len < 1) return -1;
	uint8_t b0 = p[0];
	if (!(b0 & 0x80)) {
		// Short header: only version 1 has one, and its fixed bit is set.
		if (!(b0 & 0x40) || dcid_len_short > CID_MAX || len < 1 + dcid_len_short) return -1;
		h->type = HW_QW_SHORT;
		h->version = HW_QUIC_VERSION_1;
		h->dcid = p + 1;
		h->dcid_len = (uint8_t)dcid_len_short;
		h->pn_offset = 1 + dcid_len_short;
		h->packet_len = len;
		return 0;
	}
	if (len < VN_HDR_LEN) return -1;
	h->version = get_be32(p + 1);
	h->type = (b0 >> 4) & 3;
	size_t off = 5;
	size_t dl = p[off++];
	if (dl > CID_MAX || len - off < dl + 1) return -1;
	h->dcid = p + off;
	h->dcid_len = (uint8_t)dl;
	off += dl;
	size_t sl = p[off++];
	if (sl > CID_MAX || len - off < sl) return -1;
	h->scid = p + off;
	h->scid_len = (uint8_t)sl;
	off += sl;
	if (h->version != HW_QUIC_VERSION_1) {
		// Version Negotiation or a version this does not speak: the invariants are all there is.
		h->packet_len = len;
		return 0;
	}
	if (!(b0 & 0x40)) return -1;
	if (h->type == HW_QW_RETRY) {
		if (len - off < HW_AEAD_TAG) return -1;
		h->token = p + off;
		h->token_len = len - off - HW_AEAD_TAG;
		h->packet_len = len;
		return 0;
	}
	uint64_t v;
	size_t n;
	if (h->type == HW_QW_INITIAL) {
		n = hw_qw_varint_get(p + off, len - off, &v);
		if (!n) return -1;
		off += n;
		if (v > len - off) return -1;
		h->token = p + off;
		h->token_len = (size_t)v;
		off += (size_t)v;
	}
	n = hw_qw_varint_get(p + off, len - off, &v);
	if (!n) return -1;
	off += n;
	if (v > len - off) return -1;
	h->pn_offset = off;
	h->packet_len = off + (size_t)v;
	return 0;
}

uint64_t hw_qw_pn_decode(int64_t largest, uint64_t truncated, size_t pn_len) {
	if (pn_len < 1 || pn_len > PN_LEN_MAX) return truncated;
	uint64_t expected = (uint64_t)(largest + 1);
	uint64_t win = (uint64_t)1 << (8 * pn_len);
	uint64_t hwin = win / 2;
	uint64_t mask = win - 1;
	uint64_t candidate = (expected & ~mask) | (truncated & mask);
	if (expected >= hwin && candidate <= expected - hwin && candidate < ((uint64_t)1 << 62) - win) {
		return candidate + win;
	}
	if (candidate > expected + hwin && candidate >= win) return candidate - win;
	return candidate;
}

size_t hw_qw_pn_len(uint64_t pn, int64_t largest_acked) {
	uint64_t unacked;
	if (largest_acked < 0) {
		unacked = pn + 1;
	} else {
		unacked = pn > (uint64_t)largest_acked ? pn - (uint64_t)largest_acked : 1;
	}
	// At least one bit more than log2 of the unacknowledged range: unacked <= 2^(8n - 1).
	for (size_t n = 1; n < PN_LEN_MAX; n++) {
		if (unacked <= (uint64_t)1 << (8 * n - 1)) return n;
	}
	return PN_LEN_MAX;
}

// ---- Packet protection ----------------------------------------------------------------------

static size_t cipher_key_len(uint16_t cipher) {
	if (cipher == HW_TLS_CIPHER_AES128GCM) return 16;
	if (cipher == HW_TLS_CIPHER_CHACHA20) return 32;
	return 0;
}

// key and iv from k->secret; hp is left alone (a key update keeps it).
static void keys_derive_packet(hw_qw_keys *k) {
	size_t kl = cipher_key_len(k->cipher);
	if (!kl) return;
	hw_hkdf_expand_label(k->secret, "quic key", NULL, 0, k->key, kl);
	hw_hkdf_expand_label(k->secret, "quic iv", NULL, 0, k->iv, HW_AEAD_NONCE);
	if (k->cipher == HW_TLS_CIPHER_AES128GCM) hw_aes128gcm_init(&k->gcm, k->key);
}

void hw_qw_keys_from_secret(hw_qw_keys *k, uint16_t cipher, const uint8_t secret[32]) {
	uint8_t s[32];
	memcpy(s, secret, sizeof(s)); // secret may point into k
	wipe(k, sizeof(*k));
	k->cipher = cipher;
	memcpy(k->secret, s, sizeof(s));
	wipe(s, sizeof(s));
	size_t kl = cipher_key_len(cipher);
	if (!kl) return;
	keys_derive_packet(k);
	hw_hkdf_expand_label(k->secret, "quic hp", NULL, 0, k->hp, kl);
	if (cipher == HW_TLS_CIPHER_AES128GCM) hw_aes128_init(&k->hp_aes, k->hp);
}

void hw_qw_keys_update(hw_qw_keys *next, const hw_qw_keys *cur) {
	uint8_t s[32];
	hw_hkdf_expand_label(cur->secret, "quic ku", NULL, 0, s, sizeof(s));
	if (next != cur) *next = *cur; // carries hp and hp_aes over
	memcpy(next->secret, s, sizeof(s));
	wipe(s, sizeof(s));
	keys_derive_packet(next);
}

void hw_qw_initial_keys(const uint8_t *dcid, size_t dcid_len, hw_qw_keys *client, hw_qw_keys *server) {
	uint8_t initial[HW_SHA256_LEN], secret[HW_SHA256_LEN];
	hw_hkdf_extract(INITIAL_SALT, sizeof(INITIAL_SALT), dcid, dcid_len, initial);
	if (client) {
		hw_hkdf_expand_label(initial, "client in", NULL, 0, secret, sizeof(secret));
		hw_qw_keys_from_secret(client, HW_TLS_CIPHER_AES128GCM, secret);
	}
	if (server) {
		hw_hkdf_expand_label(initial, "server in", NULL, 0, secret, sizeof(secret));
		hw_qw_keys_from_secret(server, HW_TLS_CIPHER_AES128GCM, secret);
	}
	wipe(initial, sizeof(initial));
	wipe(secret, sizeof(secret));
}

void hw_qw_keys_clear(hw_qw_keys *k) {
	wipe(k, sizeof(*k));
}

int hw_qw_hp_mask(const hw_qw_keys *k, const uint8_t sample[16], uint8_t mask[5]) {
	if (k->cipher == HW_TLS_CIPHER_AES128GCM) {
		uint8_t block[16];
		hw_aes128_encrypt(&k->hp_aes, sample, block);
		memcpy(mask, block, 5);
		return 0;
	}
	if (k->cipher == HW_TLS_CIPHER_CHACHA20) {
		static const uint8_t zeros[5] = {0};
		uint32_t counter = (uint32_t)sample[0] | (uint32_t)sample[1] << 8 | (uint32_t)sample[2] << 16 |
		                   (uint32_t)sample[3] << 24;
		hw_chacha20_xor(k->hp, counter, sample + 4, zeros, mask, 5);
		return 0;
	}
	return -1;
}

// The AEAD nonce: the IV XOR the packet number, left-padded to its length (RFC 9001 5.3).
static void keys_nonce(const hw_qw_keys *k, uint64_t pn, uint8_t nonce[HW_AEAD_NONCE]) {
	memcpy(nonce, k->iv, HW_AEAD_NONCE);
	for (size_t i = 0; i < 8; i++) nonce[HW_AEAD_NONCE - 1 - i] ^= (uint8_t)(pn >> (8 * i));
}

size_t hw_qw_protect(const hw_qw_keys *k, uint8_t *pkt, size_t pn_offset, size_t pn_len, uint64_t pn,
                     size_t payload_len) {
	if (pn_len < 1 || pn_len > PN_LEN_MAX || pn_offset < 1 || pn_len + payload_len < PN_LEN_MAX) return 0;
	if (!cipher_key_len(k->cipher)) return 0;
	pkt[0] = (uint8_t)((pkt[0] & ~3u) | (pn_len - 1));
	for (size_t i = 0; i < pn_len; i++) pkt[pn_offset + i] = (uint8_t)(pn >> (8 * (pn_len - 1 - i)));
	size_t hdr_len = pn_offset + pn_len;
	uint8_t nonce[HW_AEAD_NONCE];
	keys_nonce(k, pn, nonce);
	uint8_t *body = pkt + hdr_len;
	if (k->cipher == HW_TLS_CIPHER_AES128GCM) {
		hw_aes128gcm_seal(&k->gcm, nonce, pkt, hdr_len, body, payload_len, body);
	} else {
		hw_chacha20poly1305_seal(k->key, nonce, pkt, hdr_len, body, payload_len, body);
	}
	uint8_t mask[5];
	hw_qw_hp_mask(k, pkt + pn_offset + PN_LEN_MAX, mask);
	pkt[0] ^= mask[0] & ((pkt[0] & 0x80) ? 0x0f : 0x1f);
	for (size_t i = 0; i < pn_len; i++) pkt[pn_offset + i] ^= mask[1 + i];
	return hdr_len + payload_len + HW_AEAD_TAG;
}

int hw_qw_unprotect(const hw_qw_keys *k, uint8_t *pkt, size_t pkt_len, size_t pn_offset, int64_t largest, uint64_t *pn,
                    uint8_t **payload, size_t *payload_len, int *key_phase) {
	if (pn_offset < 1 || pn_offset > pkt_len || pkt_len - pn_offset < PN_LEN_MAX + SAMPLE_LEN) return -1;
	uint8_t mask[5];
	if (hw_qw_hp_mask(k, pkt + pn_offset + PN_LEN_MAX, mask) < 0) return -1;
	return hw_qw_unprotect_masked(k, mask, pkt, pkt_len, pn_offset, largest, pn, payload, payload_len, key_phase);
}

int hw_qw_unprotect_masked(const hw_qw_keys *k, const uint8_t mask[5], uint8_t *pkt, size_t pkt_len, size_t pn_offset,
                           int64_t largest, uint64_t *pn, uint8_t **payload, size_t *payload_len, int *key_phase) {
	if (pn_offset < 1 || pn_offset > pkt_len || pkt_len - pn_offset < PN_LEN_MAX + SAMPLE_LEN) return -1;
	if (!cipher_key_len(k->cipher)) return -1;
	int is_long = (pkt[0] & 0x80) != 0;
	pkt[0] ^= mask[0] & (is_long ? 0x0f : 0x1f);
	size_t pn_len = (size_t)(pkt[0] & 3) + 1;
	uint64_t truncated = 0;
	for (size_t i = 0; i < pn_len; i++) {
		pkt[pn_offset + i] ^= mask[1 + i];
		truncated = truncated << 8 | pkt[pn_offset + i];
	}
	uint64_t full = hw_qw_pn_decode(largest, truncated, pn_len);
	size_t hdr_len = pn_offset + pn_len;
	size_t ct_len = pkt_len - hdr_len; // >= HW_AEAD_TAG: the sample check above covers it
	uint8_t nonce[HW_AEAD_NONCE];
	keys_nonce(k, full, nonce);
	uint8_t *body = pkt + hdr_len;
	int rc;
	if (k->cipher == HW_TLS_CIPHER_AES128GCM) {
		rc = hw_aes128gcm_open(&k->gcm, nonce, pkt, hdr_len, body, ct_len, body);
	} else {
		rc = hw_chacha20poly1305_open(k->key, nonce, pkt, hdr_len, body, ct_len, body);
	}
	if (rc != 0) return -1;
	*pn = full;
	*payload = body;
	*payload_len = ct_len - HW_AEAD_TAG;
	*key_phase = is_long ? 0 : (pkt[0] >> 2) & 1;
	return 0;
}

// ---- Retry, tokens, stateless reset ---------------------------------------------------------

int hw_qw_retry_tag(const uint8_t *odcid, size_t odcid_len, const uint8_t *pkt, size_t len, uint8_t tag[HW_AEAD_TAG]) {
	uint8_t pseudo[1 + CID_MAX + HW_QW_RETRY_MAX];
	memset(tag, 0, HW_AEAD_TAG);
	if (odcid_len > CID_MAX || len > HW_QW_RETRY_MAX) return -1;
	pseudo[0] = (uint8_t)odcid_len;
	if (odcid_len) memcpy(pseudo + 1, odcid, odcid_len);
	if (len) memcpy(pseudo + 1 + odcid_len, pkt, len);
	hw_aes128gcm g;
	hw_aes128gcm_init(&g, RETRY_KEY);
	hw_aes128gcm_seal(&g, RETRY_NONCE, pseudo, 1 + odcid_len + len, NULL, 0, tag);
	return 0;
}

int hw_qw_retry_verify(const uint8_t *odcid, size_t odcid_len, const uint8_t *pkt, size_t len) {
	uint8_t tag[HW_AEAD_TAG];
	if (len < HW_AEAD_TAG) return 0;
	if (hw_qw_retry_tag(odcid, odcid_len, pkt, len - HW_AEAD_TAG, tag) < 0) return 0;
	return hw_ct_equal(tag, pkt + len - HW_AEAD_TAG, HW_AEAD_TAG);
}

void hw_qw_reset_token(const uint8_t key[HW_QUIC_KEY_LEN], const uint8_t *cid, size_t cid_len,
                       uint8_t token[HW_QUIC_RESET_LEN]) {
	uint8_t mac[HW_SHA256_LEN];
	hw_hmac_sha256(key, HW_QUIC_KEY_LEN, cid, cid_len, mac);
	memcpy(token, mac, HW_QUIC_RESET_LEN);
	wipe(mac, sizeof(mac));
}

// ---- Transport parameters -------------------------------------------------------------------

enum {
	TP_ORIGINAL_DCID = 0x00,
	TP_MAX_IDLE_TIMEOUT = 0x01,
	TP_RESET_TOKEN = 0x02,
	TP_MAX_UDP_PAYLOAD = 0x03,
	TP_MAX_DATA = 0x04,
	TP_MAX_STREAM_DATA_BIDI_LOCAL = 0x05,
	TP_MAX_STREAM_DATA_BIDI_REMOTE = 0x06,
	TP_MAX_STREAM_DATA_UNI = 0x07,
	TP_MAX_STREAMS_BIDI = 0x08,
	TP_MAX_STREAMS_UNI = 0x09,
	TP_ACK_DELAY_EXPONENT = 0x0a,
	TP_MAX_ACK_DELAY = 0x0b,
	TP_DISABLE_MIGRATION = 0x0c,
	TP_PREFERRED_ADDRESS = 0x0d,
	TP_ACTIVE_CID_LIMIT = 0x0e,
	TP_INITIAL_SCID = 0x0f,
	TP_RETRY_SCID = 0x10,
	TP_MAX_DATAGRAM_FRAME = 0x20, // RFC 9221
};

#define TP_DEFAULT_MAX_UDP_PAYLOAD 65527
#define TP_DEFAULT_ACK_DELAY_EXP   3
#define TP_DEFAULT_MAX_ACK_DELAY   25
#define TP_DEFAULT_CID_LIMIT       2
#define TP_STREAMS_MAX             ((uint64_t)1 << 60)
// preferred_address (RFC 9000 18.2): IPv4 address and port, IPv6 address and port, then the
// CID's length byte, the CID and a stateless reset token.
#define TP_PREFERRED_CID_LEN_AT (4 + 2 + 16 + 2)
#define TP_PREFERRED_FIXED      (TP_PREFERRED_CID_LEN_AT + 1 + HW_QUIC_RESET_LEN)

void hw_qw_tp_defaults(hw_qw_tp *tp) {
	memset(tp, 0, sizeof(*tp));
	tp->max_udp_payload_size = TP_DEFAULT_MAX_UDP_PAYLOAD;
	tp->ack_delay_exponent = TP_DEFAULT_ACK_DELAY_EXP;
	tp->max_ack_delay = TP_DEFAULT_MAX_ACK_DELAY;
	tp->active_connection_id_limit = TP_DEFAULT_CID_LIMIT;
}

typedef struct {
	uint8_t *p;
	size_t cap, len;
	int fail;
} tp_writer;

static void tp_writer_bytes(tp_writer *w, uint64_t id, const uint8_t *v, size_t n) {
	if (w->fail) return;
	size_t a = hw_qw_varint_put(w->p + w->len, w->cap - w->len, id);
	if (!a) goto fail;
	w->len += a;
	size_t b = hw_qw_varint_put(w->p + w->len, w->cap - w->len, n);
	if (!b || w->cap - w->len - b < n) goto fail;
	w->len += b;
	if (n) memcpy(w->p + w->len, v, n);
	w->len += n;
	return;
fail:
	w->fail = 1;
}

static void tp_writer_int(tp_writer *w, uint64_t id, uint64_t v) {
	uint8_t buf[8];
	size_t n = hw_qw_varint_put(buf, sizeof(buf), v);
	if (!n) {
		w->fail = 1;
		return;
	}
	tp_writer_bytes(w, id, buf, n);
}

size_t hw_qw_tp_encode(const hw_qw_tp *tp, int is_server, uint8_t *out, size_t cap) {
	tp_writer w = {.p = out, .cap = cap};
	if (is_server && tp->has_original_dcid) {
		if (tp->original_dcid_len > CID_MAX) return 0;
		tp_writer_bytes(&w, TP_ORIGINAL_DCID, tp->original_dcid, tp->original_dcid_len);
	}
	if (tp->max_idle_timeout) tp_writer_int(&w, TP_MAX_IDLE_TIMEOUT, tp->max_idle_timeout);
	if (is_server && tp->has_reset_token) tp_writer_bytes(&w, TP_RESET_TOKEN, tp->reset_token, HW_QUIC_RESET_LEN);
	if (tp->max_udp_payload_size != TP_DEFAULT_MAX_UDP_PAYLOAD) {
		tp_writer_int(&w, TP_MAX_UDP_PAYLOAD, tp->max_udp_payload_size);
	}
	if (tp->initial_max_data) tp_writer_int(&w, TP_MAX_DATA, tp->initial_max_data);
	if (tp->initial_max_stream_data_bidi_local) {
		tp_writer_int(&w, TP_MAX_STREAM_DATA_BIDI_LOCAL, tp->initial_max_stream_data_bidi_local);
	}
	if (tp->initial_max_stream_data_bidi_remote) {
		tp_writer_int(&w, TP_MAX_STREAM_DATA_BIDI_REMOTE, tp->initial_max_stream_data_bidi_remote);
	}
	if (tp->initial_max_stream_data_uni) tp_writer_int(&w, TP_MAX_STREAM_DATA_UNI, tp->initial_max_stream_data_uni);
	if (tp->initial_max_streams_bidi) tp_writer_int(&w, TP_MAX_STREAMS_BIDI, tp->initial_max_streams_bidi);
	if (tp->initial_max_streams_uni) tp_writer_int(&w, TP_MAX_STREAMS_UNI, tp->initial_max_streams_uni);
	if (tp->ack_delay_exponent != TP_DEFAULT_ACK_DELAY_EXP) {
		tp_writer_int(&w, TP_ACK_DELAY_EXPONENT, tp->ack_delay_exponent);
	}
	if (tp->max_ack_delay != TP_DEFAULT_MAX_ACK_DELAY) tp_writer_int(&w, TP_MAX_ACK_DELAY, tp->max_ack_delay);
	if (tp->disable_active_migration) tp_writer_bytes(&w, TP_DISABLE_MIGRATION, NULL, 0);
	if (tp->active_connection_id_limit != TP_DEFAULT_CID_LIMIT) {
		tp_writer_int(&w, TP_ACTIVE_CID_LIMIT, tp->active_connection_id_limit);
	}
	if (tp->has_initial_scid) {
		if (tp->initial_scid_len > CID_MAX) return 0;
		tp_writer_bytes(&w, TP_INITIAL_SCID, tp->initial_scid, tp->initial_scid_len);
	}
	if (is_server && tp->has_retry_scid) {
		if (tp->retry_scid_len > CID_MAX) return 0;
		tp_writer_bytes(&w, TP_RETRY_SCID, tp->retry_scid, tp->retry_scid_len);
	}
	if (tp->max_datagram_frame_size) tp_writer_int(&w, TP_MAX_DATAGRAM_FRAME, tp->max_datagram_frame_size);
	return w.fail ? 0 : w.len;
}

// An integer parameter's value: one varint that fills the parameter exactly.
static int tp_int(const uint8_t *v, size_t n, uint64_t *out) {
	return n > 0 && hw_qw_varint_get(v, n, out) == n ? 0 : -1;
}

static int tp_cid(const uint8_t *v, size_t n, uint8_t cid[CID_MAX], uint8_t *cid_len, int *has) {
	if (n > CID_MAX) return -1;
	if (n) memcpy(cid, v, n);
	*cid_len = (uint8_t)n;
	*has = 1;
	return 0;
}

int hw_qw_tp_decode(const uint8_t *in, size_t len, int from_server, hw_qw_tp *tp) {
	hw_qw_tp_defaults(tp);
	uint32_t seen = 0; // one bit per known id; 0x20 is folded onto bit 31
	size_t off = 0;
	while (off < len) {
		uint64_t id, plen;
		size_t a = hw_qw_varint_get(in + off, len - off, &id);
		if (!a) return -1;
		off += a;
		size_t b = hw_qw_varint_get(in + off, len - off, &plen);
		if (!b) return -1;
		off += b;
		if (plen > len - off) return -1;
		const uint8_t *v = in + off;
		size_t n = (size_t)plen;
		off += n;
		int bit;
		if (id <= TP_RETRY_SCID) {
			bit = (int)id;
		} else if (id == TP_MAX_DATAGRAM_FRAME) {
			bit = 31;
		} else {
			continue; // unknown or GREASE (31 * N + 27)
		}
		if (seen & (1u << bit)) return -1;
		seen |= 1u << bit;
		uint64_t x = 0;
		switch (id) {
		case TP_ORIGINAL_DCID:
			if (!from_server) return -1;
			if (tp_cid(v, n, tp->original_dcid, &tp->original_dcid_len, &tp->has_original_dcid) < 0) return -1;
			break;
		case TP_RESET_TOKEN:
			if (!from_server || n != HW_QUIC_RESET_LEN) return -1;
			memcpy(tp->reset_token, v, HW_QUIC_RESET_LEN);
			tp->has_reset_token = 1;
			break;
		case TP_PREFERRED_ADDRESS:
			// Not acted on (the client stays where it is), but it must have its shape: a CID of
			// 1 to 20 bytes (a server with a zero-length one may not send it) and nothing more.
			if (!from_server || n <= TP_PREFERRED_FIXED) return -1;
			if (v[TP_PREFERRED_CID_LEN_AT] < 1 || v[TP_PREFERRED_CID_LEN_AT] > CID_MAX) return -1;
			if (n != TP_PREFERRED_FIXED + (size_t)v[TP_PREFERRED_CID_LEN_AT]) return -1;
			break;
		case TP_RETRY_SCID:
			if (!from_server) return -1;
			if (tp_cid(v, n, tp->retry_scid, &tp->retry_scid_len, &tp->has_retry_scid) < 0) return -1;
			break;
		case TP_INITIAL_SCID:
			if (tp_cid(v, n, tp->initial_scid, &tp->initial_scid_len, &tp->has_initial_scid) < 0) return -1;
			break;
		case TP_DISABLE_MIGRATION:
			if (n != 0) return -1;
			tp->disable_active_migration = 1;
			break;
		default:
			if (tp_int(v, n, &x) < 0) return -1;
			switch (id) {
			case TP_MAX_IDLE_TIMEOUT:
				tp->max_idle_timeout = x;
				break;
			case TP_MAX_UDP_PAYLOAD:
				if (x < HW_QUIC_MIN_DGRAM) return -1;
				tp->max_udp_payload_size = x;
				break;
			case TP_MAX_DATA:
				tp->initial_max_data = x;
				break;
			case TP_MAX_STREAM_DATA_BIDI_LOCAL:
				tp->initial_max_stream_data_bidi_local = x;
				break;
			case TP_MAX_STREAM_DATA_BIDI_REMOTE:
				tp->initial_max_stream_data_bidi_remote = x;
				break;
			case TP_MAX_STREAM_DATA_UNI:
				tp->initial_max_stream_data_uni = x;
				break;
			case TP_MAX_STREAMS_BIDI:
				if (x > TP_STREAMS_MAX) return -1;
				tp->initial_max_streams_bidi = x;
				break;
			case TP_MAX_STREAMS_UNI:
				if (x > TP_STREAMS_MAX) return -1;
				tp->initial_max_streams_uni = x;
				break;
			case TP_ACK_DELAY_EXPONENT:
				if (x > 20) return -1;
				tp->ack_delay_exponent = x;
				break;
			case TP_MAX_ACK_DELAY:
				if (x >= (1u << 14)) return -1;
				tp->max_ack_delay = x;
				break;
			case TP_ACTIVE_CID_LIMIT:
				if (x < 2) return -1;
				tp->active_connection_id_limit = x;
				break;
			case TP_MAX_DATAGRAM_FRAME:
				tp->max_datagram_frame_size = x;
				break;
			default:
				break;
			}
			break;
		}
	}
	return 0;
}

// ---- The listener's stateless half of holywisp/quic.h ---------------------------------------

int hw_quic_parse_header(const uint8_t *dgram, size_t len, hw_quic_header *h) {
	hw_qw_hdr q;
	memset(h, 0, sizeof(*h));
	if (hw_qw_parse(dgram, len, HW_QUIC_CID_LEN, &q) < 0) return -1;
	h->long_header = q.type != HW_QW_SHORT;
	h->dgram_len = len;
	memcpy(h->dcid, q.dcid, q.dcid_len);
	h->dcid_len = q.dcid_len;
	if (h->long_header) {
		h->type = (uint8_t)q.type;
		h->version = q.version;
		if (q.scid_len) memcpy(h->scid, q.scid, q.scid_len);
		h->scid_len = q.scid_len;
		h->token = q.token;
		h->token_len = q.token_len;
	}
	return 0;
}

size_t hw_quic_version_negotiation(const hw_quic_header *h, uint8_t *out, size_t cap) {
	if (!h->long_header || h->version == 0 || h->dgram_len < HW_QUIC_MIN_DGRAM) return 0;
	if (h->dcid_len > CID_MAX || h->scid_len > CID_MAX) return 0;
	size_t need = VN_HDR_LEN + h->dcid_len + h->scid_len + 8;
	if (cap < need) return 0;
	uint8_t r[5] = {0};
	if (hw_sys_random(r, sizeof(r)) < 0) memset(r, 0, sizeof(r)); // nothing secret depends on these
	size_t off = 0;
	out[off++] = (uint8_t)(0xc0 | (r[0] & 0x3f));
	put_be32(out + off, 0);
	off += 4;
	// The client's SCID becomes our DCID and the other way around (RFC 9000 17.2.1).
	out[off++] = h->scid_len;
	memcpy(out + off, h->scid, h->scid_len);
	off += h->scid_len;
	out[off++] = h->dcid_len;
	memcpy(out + off, h->dcid, h->dcid_len);
	off += h->dcid_len;
	put_be32(out + off, HW_QUIC_VERSION_1);
	off += 4;
	// A reserved version (0x?a?a?a?a, RFC 9000 15) so clients keep handling lists they do not know.
	uint32_t grease = 0;
	for (int i = 0; i < 4; i++) grease = grease << 8 | (uint32_t)((r[1 + i] & 0xf0) | 0x0a);
	put_be32(out + off, grease);
	off += 4;
	return off;
}

// The peer's address as the 16 bytes of IPv6 (IPv4 as ::ffff:a.b.c.d) and its port, or -1.
static int peer_key(const struct sockaddr *peer, uint8_t addr[16], uint8_t port[2]) {
	if (!peer) return -1;
	if (peer->sa_family == AF_INET) {
		struct sockaddr_in in;
		memcpy(&in, peer, sizeof(in));
		memset(addr, 0, 10);
		addr[10] = 0xff;
		addr[11] = 0xff;
		memcpy(addr + 12, &in.sin_addr, 4);
		memcpy(port, &in.sin_port, 2);
		return 0;
	}
	if (peer->sa_family == AF_INET6) {
		struct sockaddr_in6 in6;
		memcpy(&in6, peer, sizeof(in6));
		memcpy(addr, &in6.sin6_addr, 16);
		memcpy(port, &in6.sin6_port, 2);
		return 0;
	}
	return -1;
}

static void token_aad(const uint8_t addr[16], const uint8_t port[2], uint8_t aad[TOKEN_AAD]) {
	aad[0] = TOKEN_FORMAT;
	memcpy(aad + 1, addr, 16);
	memcpy(aad + 17, port, 2);
}

size_t hw_quic_retry(const hw_quic_header *h, const struct sockaddr *peer, const uint8_t key[HW_QUIC_KEY_LEN],
                     uint64_t now_ms, const uint8_t new_scid[HW_QUIC_CID_LEN], uint8_t *out, size_t cap) {
	if (!h->long_header || h->version != HW_QUIC_VERSION_1 || h->type != HW_QW_INITIAL) return 0;
	if (h->dgram_len < HW_QUIC_MIN_DGRAM || h->dcid_len > CID_MAX || h->scid_len > CID_MAX) return 0;
	if (h->dcid_len == HW_QUIC_CID_LEN && memcmp(h->dcid, new_scid, HW_QUIC_CID_LEN) == 0) return 0;
	uint8_t addr[16], port[2];
	if (peer_key(peer, addr, port) < 0) return 0;
	size_t need = VN_HDR_LEN + h->scid_len + HW_QUIC_CID_LEN + TOKEN_LEN + HW_AEAD_TAG;
	if (cap < need) return 0;
	uint8_t r[1 + HW_AEAD_NONCE];
	if (hw_sys_random(r, sizeof(r)) < 0) return 0; // a predictable nonce would repeat under one key

	size_t off = 0;
	out[off++] = (uint8_t)(0xf0 | (r[0] & 0x0f));
	put_be32(out + off, HW_QUIC_VERSION_1);
	off += 4;
	out[off++] = h->scid_len;
	memcpy(out + off, h->scid, h->scid_len);
	off += h->scid_len;
	out[off++] = HW_QUIC_CID_LEN;
	memcpy(out + off, new_scid, HW_QUIC_CID_LEN);
	off += HW_QUIC_CID_LEN;

	uint8_t *tok = out + off;
	uint8_t plain[TOKEN_PLAIN] = {0};
	for (int i = 0; i < 8; i++) plain[i] = (uint8_t)(now_ms >> (56 - 8 * i));
	plain[8] = h->dcid_len;
	memcpy(plain + 9, h->dcid, h->dcid_len);
	uint8_t aad[TOKEN_AAD];
	token_aad(addr, port, aad);
	tok[0] = TOKEN_FORMAT;
	memcpy(tok + 1, r + 1, HW_AEAD_NONCE);
	hw_chacha20poly1305_seal(key, tok + 1, aad, sizeof(aad), plain, sizeof(plain), tok + 1 + HW_AEAD_NONCE);
	wipe(plain, sizeof(plain));
	off += TOKEN_LEN;

	if (hw_qw_retry_tag(h->dcid, h->dcid_len, out, off, out + off) < 0) return 0;
	return off + HW_AEAD_TAG;
}

int hw_quic_token_valid(const uint8_t *token, size_t len, const struct sockaddr *peer,
                        const uint8_t key[HW_QUIC_KEY_LEN], uint64_t now_ms, uint64_t max_age_ms, uint8_t odcid[20],
                        uint8_t *odcid_len) {
	*odcid_len = 0;
	if (!token || len != TOKEN_LEN || token[0] != TOKEN_FORMAT) return 0;
	uint8_t addr[16], port[2];
	if (peer_key(peer, addr, port) < 0) return 0;
	uint8_t aad[TOKEN_AAD], plain[TOKEN_PLAIN];
	token_aad(addr, port, aad);
	if (hw_chacha20poly1305_open(key, token + 1, aad, sizeof(aad), token + 1 + HW_AEAD_NONCE, TOKEN_PLAIN + HW_AEAD_TAG,
	                             plain) != 0) {
		return 0;
	}
	uint64_t ts = 0;
	for (int i = 0; i < 8; i++) ts = ts << 8 | plain[i];
	int ok = ts <= now_ms && now_ms - ts <= max_age_ms && plain[8] <= CID_MAX;
	if (ok) {
		memcpy(odcid, plain + 9, plain[8]);
		*odcid_len = plain[8];
	}
	wipe(plain, sizeof(plain));
	return ok;
}

size_t hw_quic_stateless_reset(const uint8_t cid[HW_QUIC_CID_LEN], const uint8_t key[HW_QUIC_KEY_LEN], size_t in_len,
                               uint8_t *out, size_t cap) {
	if (in_len < RESET_MIN + 1 || cap < RESET_MIN) return 0;
	size_t n = in_len - 1;
	if (n > RESET_EXACT) {
		uint8_t r;
		if (hw_sys_random(&r, 1) < 0) return 0;
		size_t hi = HW_MIN(n, (size_t)RESET_EXACT + 30); // 42..73
		n = RESET_EXACT - 1 + r % (hi - (RESET_EXACT - 1) + 1);
	}
	if (n > cap) n = cap;
	size_t rnd = n - HW_QUIC_RESET_LEN;
	if (hw_sys_random(out, rnd) < 0) return 0;
	out[0] = (uint8_t)((out[0] & 0x3f) | 0x40);
	hw_qw_reset_token(key, cid, HW_QUIC_CID_LEN, out + rnd);
	return n;
}
