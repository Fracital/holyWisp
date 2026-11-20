/*
 * src/quic/tls13.c - the TLS 1.3 handshake (RFC 8446) as QUIC carries it (RFC 9001), both roles.
 * The contract is holywisp/tls13.h. There is no record layer: messages arrive and leave per
 * encryption level, and what QUIC protects packets with is handed out as traffic secrets.
 *
 * Each handshake message is reassembled whole (at most TLS_MSG_MAX bytes, header included) and
 * then handled by the function for the state the handshake is in; anything else in that state,
 * or any byte at a level the state does not read, is unexpected_message. The transcript hash runs
 * over every message sent and received; the points where the key schedule or a signature needs
 * it are read from a copy of the running hash.
 */
#include "holywisp/tls13.h"

#include "holywisp/aead.h"
#include "holywisp/ecc.h"
#include "holywisp/hw.h"
#include "holywisp/sha256.h"
#include "holywisp/sys.h"

#include "tls13_internal.h"

#include <stdlib.h>
#include <string.h>

#define TLS_MSG_MAX (64 * 1024) // one reassembled handshake message, its 4-byte header included
#define TLS_HASH    HW_SHA256_LEN

#define TLS13_VERSION  0x0304
#define LEGACY_VERSION 0x0303
#define GROUP_X25519   0x001d
#define SIG_ECDSA_P256 0x0403

enum {
	HS_CLIENT_HELLO = 1,
	HS_SERVER_HELLO = 2,
	HS_NEW_SESSION_TICKET = 4,
	HS_ENCRYPTED_EXTENSIONS = 8,
	HS_CERTIFICATE = 11,
	HS_CERTIFICATE_VERIFY = 15,
	HS_FINISHED = 20,
	HS_MESSAGE_HASH = 254,
};

enum {
	EXT_SERVER_NAME = 0,
	EXT_SUPPORTED_GROUPS = 10,
	EXT_SIGNATURE_ALGORITHMS = 13,
	EXT_ALPN = 16,
	EXT_PADDING = 21,
	EXT_PRE_SHARED_KEY = 41,
	EXT_EARLY_DATA = 42,
	EXT_SUPPORTED_VERSIONS = 43,
	EXT_COOKIE = 44,
	EXT_PSK_KEY_EXCHANGE_MODES = 45,
	EXT_KEY_SHARE = 51,
	EXT_QUIC_TRANSPORT_PARAMETERS = 57,
	EXT_ECH = 0xfe0d,
};

// SHA-256("HelloRetryRequest"): the ServerHello.random that makes a ServerHello a HelloRetryRequest.
static const uint8_t HRR_RANDOM[32] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

typedef enum {
	ST_CLIENT_START,
	ST_CLIENT_WAIT_SH,
	ST_CLIENT_WAIT_EE,
	ST_CLIENT_WAIT_CERT,
	ST_CLIENT_WAIT_CV,
	ST_CLIENT_WAIT_FIN,
	ST_CLIENT_DONE,
	ST_SERVER_WAIT_CH,
	ST_SERVER_WAIT_CH2, // after a HelloRetryRequest
	ST_SERVER_WAIT_FIN,
	ST_SERVER_DONE,
} tls_state;

// Owned by the one thread that drives the handshake.
struct hw_tls {
	int is_server;
	hw_tls_callbacks cb;
	tls_state state;
	uint8_t alert;
	int done;
	// The config, copied.
	hw_der chain[HW_CERT_CHAIN_MAX];
	size_t chain_len;
	uint8_t key[HW_P256_PRIV_LEN];
	int (*cert_for)(void *, const char *, const hw_der **, size_t *, const uint8_t **);
	void *cert_ud;
	char **alpn;
	size_t alpn_count;
	uint8_t *tp;
	size_t tp_len;
	uint8_t pin[TLS_HASH];
	int has_pin;
	uint8_t key_pins[HW_TLS_KEY_PINS_MAX][TLS_HASH];
	size_t key_pin_count;
	int omit_share;  // tests: the first ClientHello carries no key share
	int offered_aes; // client: the first ClientHello offered AES-128-GCM (a second repeats it)
	// What was negotiated or learnt from the peer.
	char alpn_sel[256];
	int has_alpn;
	uint16_t cipher; // the suite of the Handshake and 1-RTT keys, from the (first) ServerHello
	uint8_t *peer_tp;
	size_t peer_tp_len;
	char *server_name; // the client's configured SNI, or the one the server received
	// The handshake in progress.
	hw_sha256_ctx th;
	int hrr; // a HelloRetryRequest was sent (server) or received (client)
	// Server, after a HelloRetryRequest: ch_parse's digest of the first ClientHello, which the
	// second one must repeat (RFC 8446 section 4.1.2).
	uint8_t ch1_digest[TLS_HASH];
	uint8_t random[32];
	uint8_t eph_priv[HW_X25519_LEN];
	uint8_t eph_pub[HW_X25519_LEN];
	uint8_t *cookie; // client: from the HelloRetryRequest, echoed in the second ClientHello
	size_t cookie_len;
	uint8_t hs[TLS_HASH];
	uint8_t c_hs[TLS_HASH];
	uint8_t s_hs[TLS_HASH];
	uint8_t peer_fin[TLS_HASH]; // server: the verify_data the client's Finished must carry
	uint8_t leaf_pub[HW_P256_PUB_LEN];
	// Reassembly of the message being received: its header first, then the whole message.
	uint8_t hdr[4];
	size_t hdr_len;
	uint8_t *rx;
	size_t rx_len;
	size_t rx_want; // the message's whole length, once hdr is complete
	size_t rx_cap;
};

// ---- small helpers ------------------------------------------------------------------------

// Zeroes n bytes in a way the compiler may not drop as a dead store.
static void wipe(void *p, size_t n) {
	volatile uint8_t *v = p;
	while (n--) *v++ = 0;
}

static int bytes_equal_ct(const uint8_t *a, const uint8_t *b, size_t n) {
	uint8_t d = 0;
	for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
	return d == 0;
}

static void th_peek(const hw_sha256_ctx *c, uint8_t out[TLS_HASH]) {
	hw_sha256_ctx x = *c;
	hw_sha256_final(&x, out);
	wipe(&x, sizeof x);
}

// A growable buffer to build a message in. An allocation failure or a vector that overflows its
// length field sets err, which every later call honours.
typedef struct {
	uint8_t *p;
	size_t len;
	size_t cap;
	int err;
} tbuf;

static void tbuf_put(tbuf *b, const void *d, size_t n) {
	if (b->err || n == 0) return;
	if (n > b->cap - b->len) {
		if (n > SIZE_MAX / 2 - b->len) {
			b->err = 1;
			return;
		}
		size_t cap = HW_MAX(HW_MAX(b->cap * 2, b->len + n), (size_t)256);
		uint8_t *p = realloc(b->p, cap);
		if (!p) {
			b->err = 1;
			return;
		}
		b->p = p;
		b->cap = cap;
	}
	memcpy(b->p + b->len, d, n);
	b->len += n;
}

static void tbuf_u8(tbuf *b, unsigned v) {
	uint8_t x = (uint8_t)v;
	tbuf_put(b, &x, 1);
}

static void tbuf_u16(tbuf *b, unsigned v) {
	uint8_t x[2] = {(uint8_t)(v >> 8), (uint8_t)v};
	tbuf_put(b, x, 2);
}

// Opens a vector with an n-byte length (1 to 3) and returns where its length goes.
static size_t tbuf_open(tbuf *b, size_t n) {
	static const uint8_t zero[3] = {0};
	size_t at = b->len;
	tbuf_put(b, zero, n);
	return at;
}

static void tbuf_close(tbuf *b, size_t at, size_t n) {
	if (b->err) return;
	size_t body = b->len - at - n;
	if (body >> (8 * n)) {
		b->err = 1;
		return;
	}
	for (size_t i = 0; i < n; i++) b->p[at + i] = (uint8_t)(body >> (8 * (n - 1 - i)));
}

static void tbuf_free(tbuf *b) {
	free(b->p);
	b->p = NULL;
	b->len = b->cap = 0;
}

// A reader over received bytes. Every read checks what is left; -1 when it is not enough.
typedef struct {
	const uint8_t *p;
	size_t n;
} rd;

static int rd_u8(rd *r, uint8_t *v) {
	if (r->n < 1) return -1;
	*v = r->p[0];
	r->p++;
	r->n--;
	return 0;
}

static int rd_u16(rd *r, uint16_t *v) {
	if (r->n < 2) return -1;
	*v = (uint16_t)(r->p[0] << 8 | r->p[1]);
	r->p += 2;
	r->n -= 2;
	return 0;
}

static int rd_take(rd *r, size_t n, rd *out) {
	if (r->n < n) return -1;
	out->p = r->p;
	out->n = n;
	r->p += n;
	r->n -= n;
	return 0;
}

// A vector with an lb-byte length prefix (1 to 3) into out.
static int rd_vec(rd *r, size_t lb, rd *out) {
	if (r->n < lb) return -1;
	size_t n = 0;
	for (size_t i = 0; i < lb; i++) n = n << 8 | r->p[i];
	r->p += lb;
	r->n -= lb;
	return rd_take(r, n, out);
}

// Extension types seen in one message, for refusing duplicates (illegal_parameter).
typedef struct {
	uint8_t bits[65536 / 8];
} ext_seen;

static int ext_seen_add(ext_seen *s, uint16_t type) {
	uint8_t bit = (uint8_t)(1u << (type & 7));
	if (s->bits[type >> 3] & bit) return -1;
	s->bits[type >> 3] |= bit;
	return 0;
}

// ---- key schedule (RFC 8446 section 7.1) ---------------------------------------------------

void hw_tls_derive_secret(const uint8_t secret[32], const char *label, const uint8_t th[32], uint8_t out[32]) {
	// Only fails for labels over 249 bytes; these are this file's own and short.
	(void)hw_hkdf_expand_label(secret, label, th, TLS_HASH, out, TLS_HASH);
}

void hw_tls_schedule_handshake(const uint8_t ecdhe[32], const uint8_t th_sh[32], uint8_t hs[32], uint8_t c_hs[32],
                               uint8_t s_hs[32]) {
	uint8_t zero[TLS_HASH] = {0}, empty[TLS_HASH], early[TLS_HASH], derived[TLS_HASH];
	hw_sha256("", 0, empty);
	hw_hkdf_extract(NULL, 0, zero, sizeof zero, early); // no PSK: the IKM is HashLen zeros
	hw_tls_derive_secret(early, "derived", empty, derived);
	hw_hkdf_extract(derived, sizeof derived, ecdhe, 32, hs);
	hw_tls_derive_secret(hs, "c hs traffic", th_sh, c_hs);
	hw_tls_derive_secret(hs, "s hs traffic", th_sh, s_hs);
	wipe(early, sizeof early);
	wipe(derived, sizeof derived);
}

void hw_tls_schedule_app(const uint8_t hs[32], const uint8_t th_sf[32], uint8_t master[32], uint8_t c_ap[32],
                         uint8_t s_ap[32]) {
	uint8_t zero[TLS_HASH] = {0}, empty[TLS_HASH], derived[TLS_HASH];
	hw_sha256("", 0, empty);
	hw_tls_derive_secret(hs, "derived", empty, derived);
	hw_hkdf_extract(derived, sizeof derived, zero, sizeof zero, master);
	hw_tls_derive_secret(master, "c ap traffic", th_sf, c_ap);
	hw_tls_derive_secret(master, "s ap traffic", th_sf, s_ap);
	wipe(derived, sizeof derived);
}

void hw_tls_finished_key(const uint8_t traffic[32], uint8_t out[32]) {
	(void)hw_hkdf_expand_label(traffic, "finished", NULL, 0, out, TLS_HASH);
}

// Finished.verify_data = HMAC(finished_key, Transcript-Hash(...)).
static void verify_data(const uint8_t traffic[TLS_HASH], const uint8_t th[TLS_HASH], uint8_t out[TLS_HASH]) {
	uint8_t fk[TLS_HASH];
	hw_tls_finished_key(traffic, fk);
	hw_hmac_sha256(fk, sizeof fk, th, TLS_HASH, out);
	wipe(fk, sizeof fk);
}

// The digest a server's CertificateVerify signs: 64 spaces, the context string, a zero byte, and
// Transcript-Hash(ClientHello..Certificate) (RFC 8446 section 4.4.3).
static void cv_digest(const uint8_t th[TLS_HASH], uint8_t out[TLS_HASH]) {
	static const char context[] = "TLS 1.3, server CertificateVerify"; // its NUL is the separator
	uint8_t pad[64];
	memset(pad, 0x20, sizeof pad);
	hw_sha256_ctx c;
	hw_sha256_init(&c);
	hw_sha256_update(&c, pad, sizeof pad);
	hw_sha256_update(&c, context, sizeof context);
	hw_sha256_update(&c, th, TLS_HASH);
	hw_sha256_final(&c, out);
}

// ---- failure, sending, secrets -------------------------------------------------------------

// A server chain of 1 to HW_CERT_CHAIN_MAX certificates whose Certificate message fits what a
// peer reassembles, as this side's own does.
static int chain_usable(const hw_der *chain, size_t n) {
	if (!chain || n == 0 || n > HW_CERT_CHAIN_MAX) return 0;
	size_t total = 4 + 1 + 3;
	for (size_t i = 0; i < n; i++) {
		if (!chain[i].der || chain[i].len == 0 || chain[i].len > TLS_MSG_MAX) return 0;
		total += 3 + chain[i].len + 2;
	}
	return total <= TLS_MSG_MAX;
}

static void chain_clear(hw_tls *t) {
	for (size_t i = 0; i < t->chain_len; i++) free(t->chain[i].der);
	memset(t->chain, 0, sizeof t->chain);
	t->chain_len = 0;
}

// Replace the chain and key with copies of these (already checked by chain_usable). 0, or -1 with
// no chain at all (no memory).
static int chain_set(hw_tls *t, const hw_der *chain, size_t n, const uint8_t *key) {
	chain_clear(t);
	for (size_t i = 0; i < n; i++) {
		t->chain[i].der = malloc(chain[i].len);
		if (!t->chain[i].der) {
			chain_clear(t);
			return -1;
		}
		memcpy(t->chain[i].der, chain[i].der, chain[i].len);
		t->chain[i].len = chain[i].len;
		t->chain_len = i + 1;
	}
	memcpy(t->key, key, sizeof t->key);
	return 0;
}

static int tls_fail(hw_tls *t, uint8_t alert) {
	if (!t->alert) t->alert = alert;
	return -1;
}

// A whole handshake message: into the transcript, then out at level.
static int tls_send(hw_tls *t, hw_tls_level level, const tbuf *msg) {
	if (msg->err) return tls_fail(t, HW_TLS_ALERT_INTERNAL_ERROR);
	hw_sha256_update(&t->th, msg->p, msg->len);
	if (t->cb.emit(t->cb.ud, level, msg->p, msg->len) != 0) return tls_fail(t, HW_TLS_ALERT_INTERNAL_ERROR);
	return 0;
}

static int tls_install(hw_tls *t, hw_tls_level level, int write, const uint8_t secret[TLS_HASH]) {
	if (!t->cb.secret) return 0;
	if (t->cb.secret(t->cb.ud, level, write, t->cipher, secret) != 0) {
		return tls_fail(t, HW_TLS_ALERT_INTERNAL_ERROR);
	}
	return 0;
}

static int tls_set_peer_tp(hw_tls *t, const rd *tp) {
	uint8_t *p = malloc(tp->n ? tp->n : 1);
	if (!p) return tls_fail(t, HW_TLS_ALERT_INTERNAL_ERROR);
	if (tp->n) memcpy(p, tp->p, tp->n);
	free(t->peer_tp);
	t->peer_tp = p;
	t->peer_tp_len = tp->n;
	return 0;
}

static void tls_set_alpn(hw_tls *t, const uint8_t *name, size_t len) {
	memcpy(t->alpn_sel, name, len);
	t->alpn_sel[len] = '\0';
	t->has_alpn = 1;
}

// The handshake secrets from the shared secret and the transcript so far (through ServerHello),
// installed for both directions.
static int tls_enter_handshake(hw_tls *t, uint8_t ecdhe[HW_X25519_LEN]) {
	uint8_t th[TLS_HASH];
	th_peek(&t->th, th);
	hw_tls_schedule_handshake(ecdhe, th, t->hs, t->c_hs, t->s_hs);
	wipe(ecdhe, HW_X25519_LEN);
	wipe(t->eph_priv, sizeof t->eph_priv);
	const uint8_t *wr = t->is_server ? t->s_hs : t->c_hs;
	const uint8_t *rdk = t->is_server ? t->c_hs : t->s_hs;
	if (tls_install(t, HW_TLS_HANDSHAKE, 0, rdk) || tls_install(t, HW_TLS_HANDSHAKE, 1, wr)) return -1;
	return 0;
}

// The application secrets from Transcript-Hash(ClientHello..server Finished), installed for both
// directions. The handshake secret is no longer needed after this.
static int tls_enter_app(hw_tls *t, const uint8_t th[TLS_HASH]) {
	uint8_t master[TLS_HASH], c_ap[TLS_HASH], s_ap[TLS_HASH];
	hw_tls_schedule_app(t->hs, th, master, c_ap, s_ap);
	wipe(master, sizeof master);
	wipe(t->hs, sizeof t->hs);
	int rc = 0;
	if (t->is_server) {
		rc = (tls_install(t, HW_TLS_APP, 1, s_ap) || tls_install(t, HW_TLS_APP, 0, c_ap)) ? -1 : 0;
	} else {
		rc = (tls_install(t, HW_TLS_APP, 0, s_ap) || tls_install(t, HW_TLS_APP, 1, c_ap)) ? -1 : 0;
	}
	wipe(c_ap, sizeof c_ap);
	wipe(s_ap, sizeof s_ap);
	return rc;
}

// Starts a handshake message of the given type; tbuf_close(b, 1, 3) ends it.
static void msg_open(tbuf *b, unsigned type) {
	tbuf_u8(b, type);
	(void)tbuf_open(b, 3);
}

// ---- server --------------------------------------------------------------------------------

typedef struct {
	rd session_id;
	int chacha;
	int aes;          // TLS_AES_128_GCM_SHA256 offered
	int chacha_first; // and ChaCha20 before it: the client has no AES instructions of its own
	int bad_comp;     // legacy_compression_methods other than one null method: refused once it is TLS 1.3
	int has_versions;
	int tls13;
	int has_groups;
	int x25519_listed;
	int has_sigalgs;
	int ecdsa;
	int has_shares;
	size_t shares;               // KeyShareEntry count, every group
	const uint8_t *x25519_share; // 32 bytes inside the message
	int has_alpn;
	rd alpn;
	int has_tp;
	rd tp;
	int has_sni;
	rd sni;
	int has_early_data;
	int has_psk;
	int has_psk_modes;
	// SHA-256 over what a second ClientHello must repeat after a HelloRetryRequest: everything
	// before the extensions and every extension, in order, except those RFC 8446 section 4.1.2
	// lets change (key_share, early_data, cookie, pre_shared_key, padding) and
	// encrypted_client_hello, whose payload a real ECH client seals anew for the second hello
	// and which this server never reads.
	uint8_t digest[TLS_HASH];
} client_hello;

static int ext_may_change_on_retry(uint16_t type) {
	return type == EXT_KEY_SHARE || type == EXT_EARLY_DATA || type == EXT_COOKIE || type == EXT_PRE_SHARED_KEY ||
	       type == EXT_PADDING || type == EXT_ECH;
}

// A host_name as RFC 6066 has it: printable ASCII (no NUL, control byte, space or DEL), at most
// 255 bytes.
static int sni_ok(const rd *name) {
	if (name->n > 255) return 0;
	for (size_t i = 0; i < name->n; i++) {
		if (name->p[i] <= 0x20 || name->p[i] >= 0x7f) return 0;
	}
	return 1;
}

static uint8_t ch_ext(client_hello *ch, uint16_t type, rd body) {
	rd v;
	uint16_t x;
	uint8_t b;
	switch (type) {
	case EXT_SERVER_NAME:
		// ServerNameList <1..2^16-1> of { NameType, HostName <1..2^16-1> }, one host_name at most.
		if (rd_vec(&body, 2, &v) || body.n || v.n == 0) return HW_TLS_ALERT_DECODE_ERROR;
		while (v.n) {
			rd name;
			if (rd_u8(&v, &b) || rd_vec(&v, 2, &name) || name.n == 0) return HW_TLS_ALERT_DECODE_ERROR;
			if (b != 0) continue; // a name type this does not know
			if (ch->has_sni || !sni_ok(&name)) return HW_TLS_ALERT_ILLEGAL_PARAMETER;
			ch->has_sni = 1;
			ch->sni = name;
		}
		return 0;
	case EXT_SUPPORTED_GROUPS:
		if (rd_vec(&body, 2, &v) || body.n || v.n < 2 || v.n % 2) return HW_TLS_ALERT_DECODE_ERROR;
		ch->has_groups = 1;
		while (!rd_u16(&v, &x)) ch->x25519_listed |= x == GROUP_X25519;
		return 0;
	case EXT_SIGNATURE_ALGORITHMS:
		if (rd_vec(&body, 2, &v) || body.n || v.n < 2 || v.n % 2) return HW_TLS_ALERT_DECODE_ERROR;
		ch->has_sigalgs = 1;
		while (!rd_u16(&v, &x)) ch->ecdsa |= x == SIG_ECDSA_P256;
		return 0;
	case EXT_ALPN:
		if (rd_vec(&body, 2, &v) || body.n || v.n < 2) return HW_TLS_ALERT_DECODE_ERROR;
		ch->has_alpn = 1;
		ch->alpn = v;
		while (v.n) {
			rd name;
			if (rd_vec(&v, 1, &name) || name.n == 0) return HW_TLS_ALERT_DECODE_ERROR;
		}
		return 0;
	case EXT_SUPPORTED_VERSIONS:
		if (rd_vec(&body, 1, &v) || body.n || v.n < 2 || v.n % 2) return HW_TLS_ALERT_DECODE_ERROR;
		ch->has_versions = 1;
		while (!rd_u16(&v, &x)) ch->tls13 |= x == TLS13_VERSION;
		return 0;
	case EXT_KEY_SHARE:
		// KeyShareEntry client_shares <0..2^16-1>, each { NamedGroup, key_exchange <1..2^16-1> }.
		// Only X25519's is read, and it is exactly 32 bytes; the others (GREASE, the hybrid
		// post-quantum one, P-256) are framed and counted, never used.
		if (rd_vec(&body, 2, &v) || body.n) return HW_TLS_ALERT_DECODE_ERROR;
		ch->has_shares = 1;
		while (v.n) {
			rd ke;
			if (rd_u16(&v, &x) || rd_vec(&v, 2, &ke) || ke.n == 0) return HW_TLS_ALERT_DECODE_ERROR;
			ch->shares++;
			if (x != GROUP_X25519) continue;
			if (ch->x25519_share || ke.n != HW_X25519_LEN) return HW_TLS_ALERT_ILLEGAL_PARAMETER;
			ch->x25519_share = ke.p;
		}
		return 0;
	case EXT_QUIC_TRANSPORT_PARAMETERS:
		ch->has_tp = 1;
		ch->tp = body;
		return 0;
	case EXT_EARLY_DATA:
		// Empty in a ClientHello. 0-RTT is never accepted: the EncryptedExtensions carry no
		// early_data, which is the refusal, and QUIC drops the 0-RTT packets.
		if (body.n) return HW_TLS_ALERT_DECODE_ERROR;
		ch->has_early_data = 1;
		return 0;
	case EXT_PSK_KEY_EXCHANGE_MODES:
		if (rd_vec(&body, 1, &v) || body.n || v.n == 0) return HW_TLS_ALERT_DECODE_ERROR;
		ch->has_psk_modes = 1;
		return 0;
	case EXT_PRE_SHARED_KEY: {
		// OfferedPsks { identities <7..2^16-1>, binders <33..2^16-1> }: framed, then ignored, as a
		// server without PSKs does; the handshake goes on as a full (EC)DHE one.
		rd ids, binders;
		if (rd_vec(&body, 2, &ids) || rd_vec(&body, 2, &binders) || body.n || ids.n < 7 || binders.n < 33) {
			return HW_TLS_ALERT_DECODE_ERROR;
		}
		ch->has_psk = 1;
		return 0;
	}
	default:
		return 0; // GREASE, padding, cookie, ECH, ALPS, compress_certificate, ...
	}
}

// Parses a ClientHello body into ch (pointers into body). 0, or the alert.
static uint8_t ch_parse(const uint8_t *p, size_t len, client_hello *ch) {
	rd r = {p, len}, v, cs, comp, exts;
	uint16_t x;
	memset(ch, 0, sizeof *ch);
	if (rd_u16(&r, &x) || rd_take(&r, 32, &v)) return HW_TLS_ALERT_DECODE_ERROR; // legacy_version, random
	if (rd_vec(&r, 1, &ch->session_id) || ch->session_id.n > 32) return HW_TLS_ALERT_DECODE_ERROR;
	if (rd_vec(&r, 2, &cs) || cs.n < 2 || cs.n % 2) return HW_TLS_ALERT_DECODE_ERROR;
	while (!rd_u16(&cs, &x)) {
		if (x == HW_TLS_CIPHER_AES128GCM) ch->aes = 1;
		if (x == HW_TLS_CIPHER_CHACHA20 && !ch->aes) ch->chacha_first = 1;
		ch->chacha |= x == HW_TLS_CIPHER_CHACHA20;
	}
	if (rd_vec(&r, 1, &comp) || comp.n == 0) return HW_TLS_ALERT_DECODE_ERROR;
	ch->bad_comp = comp.n != 1 || comp.p[0] != 0;
	if (r.n == 0) return 0; // no extensions: a TLS 1.2 hello, refused for its version
	hw_sha256_ctx dig;
	hw_sha256_init(&dig);
	hw_sha256_update(&dig, p, len - r.n);
	if (rd_vec(&r, 2, &exts) || r.n) return HW_TLS_ALERT_DECODE_ERROR;
	ext_seen *seen = calloc(1, sizeof *seen);
	if (!seen) return HW_TLS_ALERT_INTERNAL_ERROR;
	uint8_t alert = 0;
	while (exts.n && !alert) {
		const uint8_t *at = exts.p;
		rd body;
		if (rd_u16(&exts, &x) || rd_vec(&exts, 2, &body)) {
			alert = HW_TLS_ALERT_DECODE_ERROR;
		} else if (ext_seen_add(seen, x) || (x == EXT_PRE_SHARED_KEY && exts.n)) {
			alert = HW_TLS_ALERT_ILLEGAL_PARAMETER; // a duplicate, or a pre_shared_key that is not last
		} else {
			if (!ext_may_change_on_retry(x)) hw_sha256_update(&dig, at, (size_t)(exts.p - at));
			alert = ch_ext(ch, x, body);
		}
	}
	free(seen);
	hw_sha256_final(&dig, ch->digest);
	return alert;
}

// ServerHello, or a HelloRetryRequest when hrr: the selected version and the key share (or only
// its group).
static void server_hello_build(hw_tls *t, const client_hello *ch, int hrr, tbuf *b) {
	msg_open(b, HS_SERVER_HELLO);
	tbuf_u16(b, LEGACY_VERSION);
	tbuf_put(b, hrr ? HRR_RANDOM : t->random, 32);
	size_t at = tbuf_open(b, 1);
	tbuf_put(b, ch->session_id.p, ch->session_id.n);
	tbuf_close(b, at, 1);
	tbuf_u16(b, t->cipher);
	tbuf_u8(b, 0);
	size_t exts = tbuf_open(b, 2);
	tbuf_u16(b, EXT_SUPPORTED_VERSIONS);
	tbuf_u16(b, 2);
	tbuf_u16(b, TLS13_VERSION);
	tbuf_u16(b, EXT_KEY_SHARE);
	at = tbuf_open(b, 2);
	tbuf_u16(b, GROUP_X25519);
	if (!hrr) {
		tbuf_u16(b, HW_X25519_LEN);
		tbuf_put(b, t->eph_pub, HW_X25519_LEN);
	}
	tbuf_close(b, at, 2);
	tbuf_close(b, exts, 2);
	tbuf_close(b, 1, 3);
}

// The transcript after a HelloRetryRequest starts over with message_hash(ClientHello1).
static void th_restart_hrr(hw_tls *t) {
	uint8_t h[TLS_HASH];
	hw_sha256_final(&t->th, h);
	hw_sha256_init(&t->th);
	static const uint8_t hdr[4] = {HS_MESSAGE_HASH, 0, 0, TLS_HASH};
	hw_sha256_update(&t->th, hdr, sizeof hdr);
	hw_sha256_update(&t->th, h, sizeof h);
}

// EncryptedExtensions, Certificate, CertificateVerify and Finished at the Handshake level, then
// the application secrets.
static int server_flight(hw_tls *t) {
	tbuf b = {0};
	size_t exts, at, list;
	uint8_t th[TLS_HASH], digest[TLS_HASH], sig[HW_P256_SIG_DER_MAX], fin[TLS_HASH];
	int sig_len;
	msg_open(&b, HS_ENCRYPTED_EXTENSIONS);
	exts = tbuf_open(&b, 2);
	tbuf_u16(&b, EXT_ALPN);
	at = tbuf_open(&b, 2);
	list = tbuf_open(&b, 2);
	size_t n = strlen(t->alpn_sel);
	tbuf_u8(&b, (unsigned)n);
	tbuf_put(&b, t->alpn_sel, n);
	tbuf_close(&b, list, 2);
	tbuf_close(&b, at, 2);
	tbuf_u16(&b, EXT_QUIC_TRANSPORT_PARAMETERS);
	at = tbuf_open(&b, 2);
	tbuf_put(&b, t->tp, t->tp_len);
	tbuf_close(&b, at, 2);
	tbuf_close(&b, exts, 2);
	tbuf_close(&b, 1, 3);
	if (tls_send(t, HW_TLS_HANDSHAKE, &b)) goto fail;

	b.len = 0;
	msg_open(&b, HS_CERTIFICATE);
	tbuf_u8(&b, 0); // certificate_request_context
	list = tbuf_open(&b, 3);
	for (size_t i = 0; i < t->chain_len; i++) {
		at = tbuf_open(&b, 3);
		tbuf_put(&b, t->chain[i].der, t->chain[i].len);
		tbuf_close(&b, at, 3);
		tbuf_u16(&b, 0); // no per-certificate extensions
	}
	tbuf_close(&b, list, 3);
	tbuf_close(&b, 1, 3);
	if (tls_send(t, HW_TLS_HANDSHAKE, &b)) goto fail;

	th_peek(&t->th, th);
	cv_digest(th, digest);
	sig_len = hw_p256_sign(t->key, digest, sig);
	if (sig_len < 0) {
		tls_fail(t, HW_TLS_ALERT_INTERNAL_ERROR);
		goto fail;
	}
	b.len = 0;
	msg_open(&b, HS_CERTIFICATE_VERIFY);
	tbuf_u16(&b, SIG_ECDSA_P256);
	tbuf_u16(&b, (unsigned)sig_len);
	tbuf_put(&b, sig, (size_t)sig_len);
	tbuf_close(&b, 1, 3);
	if (tls_send(t, HW_TLS_HANDSHAKE, &b)) goto fail;

	th_peek(&t->th, th);
	verify_data(t->s_hs, th, fin);
	b.len = 0;
	msg_open(&b, HS_FINISHED);
	tbuf_put(&b, fin, sizeof fin);
	tbuf_close(&b, 1, 3);
	if (tls_send(t, HW_TLS_HANDSHAKE, &b)) goto fail;
	tbuf_free(&b);

	// The client's Finished covers the transcript through ours: what it must be is known now.
	th_peek(&t->th, th);
	verify_data(t->c_hs, th, t->peer_fin);
	wipe(t->c_hs, sizeof t->c_hs);
	wipe(t->s_hs, sizeof t->s_hs);
	if (tls_enter_app(t, th)) return -1;
	t->state = ST_SERVER_WAIT_FIN;
	return 0;
fail:
	tbuf_free(&b);
	return -1;
}

static int server_on_client_hello(hw_tls *t, const uint8_t *msg, size_t len) {
	client_hello ch;
	uint8_t alert = ch_parse(msg + 4, len - 4, &ch);
	if (alert) return tls_fail(t, alert);
	if (t->state == ST_SERVER_WAIT_CH2) {
		// The same hello but for one X25519 share and no early_data (RFC 8446 section 4.1.2): any
		// other change could negotiate what the first hello would not have.
		if (memcmp(ch.digest, t->ch1_digest, TLS_HASH) != 0 || ch.has_early_data || ch.shares != 1 ||
		    !ch.x25519_share) {
			return tls_fail(t, HW_TLS_ALERT_ILLEGAL_PARAMETER);
		}
	}
	if (!ch.tls13) return tls_fail(t, HW_TLS_ALERT_PROTOCOL_VERSION);
	if (ch.bad_comp) return tls_fail(t, HW_TLS_ALERT_ILLEGAL_PARAMETER);
	// AES-128-GCM where this CPU runs it on its own instructions and the client offers it, unless
	// the client lists ChaCha20 first (BoringSSL and NSS do on a CPU without AES instructions, and
	// the cost is the client's too); ChaCha20-Poly1305 otherwise. Never AES in software for secret
	// keys. A second hello repeats the suites of the first, so the HelloRetryRequest's choice holds.
	if (t->state != ST_SERVER_WAIT_CH2) {
		if (ch.aes && (!ch.chacha || !ch.chacha_first) && hw_aes128gcm_hw()) {
			t->cipher = HW_TLS_CIPHER_AES128GCM;
		} else if (ch.chacha) {
			t->cipher = HW_TLS_CIPHER_CHACHA20;
		} else {
			return tls_fail(t, HW_TLS_ALERT_HANDSHAKE_FAILURE);
		}
	}
	if (!ch.has_sigalgs || !ch.has_groups || !ch.has_shares) return tls_fail(t, HW_TLS_ALERT_MISSING_EXTENSION);
	// A share for a group the client does not list (RFC 8446 section 4.2.8).
	if (ch.x25519_share && !ch.x25519_listed) return tls_fail(t, HW_TLS_ALERT_ILLEGAL_PARAMETER);
	if (!ch.ecdsa || !ch.x25519_listed) return tls_fail(t, HW_TLS_ALERT_HANDSHAKE_FAILURE);
	// A pre_shared_key needs its modes (RFC 8446 section 4.2.9), even one that is ignored.
	if (ch.has_psk && !ch.has_psk_modes) return tls_fail(t, HW_TLS_ALERT_MISSING_EXTENSION);
	if (!ch.has_alpn) return tls_fail(t, HW_TLS_ALERT_NO_APP_PROTOCOL);
	int picked = 0;
	for (size_t i = 0; i < t->alpn_count && !picked; i++) {
		size_t n = strlen(t->alpn[i]);
		rd v = ch.alpn, name;
		while (!rd_vec(&v, 1, &name)) {
			if (name.n == n && memcmp(name.p, t->alpn[i], n) == 0) {
				tls_set_alpn(t, name.p, n);
				picked = 1;
				break;
			}
		}
	}
	if (!picked) return tls_fail(t, HW_TLS_ALERT_NO_APP_PROTOCOL);
	if (!ch.has_tp) return tls_fail(t, HW_TLS_ALERT_MISSING_EXTENSION);

	if (!ch.x25519_share) {
		// Listed but no share: ask once for one (a second hello without it was refused above).
		memcpy(t->ch1_digest, ch.digest, TLS_HASH);
		hw_sha256_update(&t->th, msg, len);
		th_restart_hrr(t);
		tbuf b = {0};
		server_hello_build(t, &ch, 1, &b);
		int rc = tls_send(t, HW_TLS_INITIAL, &b);
		tbuf_free(&b);
		if (rc) return -1;
		t->hrr = 1;
		t->state = ST_SERVER_WAIT_CH2;
		return 0;
	}

	free(t->server_name);
	t->server_name = NULL;
	if (ch.has_sni) {
		t->server_name = malloc(ch.sni.n + 1);
		if (!t->server_name) return tls_fail(t, HW_TLS_ALERT_INTERNAL_ERROR);
		memcpy(t->server_name, ch.sni.p, ch.sni.n);
		t->server_name[ch.sni.n] = '\0';
	}
	if (t->cert_for) {
		const hw_der *chain = NULL;
		const uint8_t *key = NULL;
		size_t n = 0;
		if (t->cert_for(t->cert_ud, t->server_name, &chain, &n, &key) == 1) {
			if (!chain_usable(chain, n) || !key || chain_set(t, chain, n, key)) {
				return tls_fail(t, HW_TLS_ALERT_INTERNAL_ERROR);
			}
		}
	}
	if (tls_set_peer_tp(t, &ch.tp)) return -1;

	uint8_t ecdhe[HW_X25519_LEN];
	if (hw_sys_random(t->random, sizeof t->random) || hw_x25519_keygen(t->eph_priv, t->eph_pub)) {
		return tls_fail(t, HW_TLS_ALERT_INTERNAL_ERROR);
	}
	if (hw_x25519(ecdhe, t->eph_priv, ch.x25519_share)) {
		wipe(ecdhe, sizeof ecdhe);
		return tls_fail(t, HW_TLS_ALERT_ILLEGAL_PARAMETER); // a small-order point
	}
	hw_sha256_update(&t->th, msg, len);
	tbuf b = {0};
	server_hello_build(t, &ch, 0, &b);
	int rc = tls_send(t, HW_TLS_INITIAL, &b);
	tbuf_free(&b);
	if (rc) {
		wipe(ecdhe, sizeof ecdhe);
		return -1;
	}
	if (tls_enter_handshake(t, ecdhe)) return -1;
	return server_flight(t);
}

static int server_on_finished(hw_tls *t, const uint8_t *msg, size_t len) {
	if (len != 4 + TLS_HASH) return tls_fail(t, HW_TLS_ALERT_DECODE_ERROR);
	if (!bytes_equal_ct(msg + 4, t->peer_fin, TLS_HASH)) return tls_fail(t, HW_TLS_ALERT_DECRYPT_ERROR);
	hw_sha256_update(&t->th, msg, len);
	wipe(t->peer_fin, sizeof t->peer_fin);
	t->state = ST_SERVER_DONE;
	t->done = 1;
	return 0;
}

// ---- client --------------------------------------------------------------------------------

static int client_send_hello(hw_tls *t) {
	tbuf b = {0};
	size_t at, list;
	msg_open(&b, HS_CLIENT_HELLO);
	tbuf_u16(&b, LEGACY_VERSION);
	tbuf_put(&b, t->random, 32);
	tbuf_u8(&b, 0); // legacy_session_id: empty in QUIC
	// AES-128-GCM first only where it runs on this CPU's instructions: a server may take the
	// first suite offered, and AES in software is never used for secret keys. A second hello
	// (after a HelloRetryRequest) offers what the first did.
	if (!t->hrr) t->offered_aes = hw_aes128gcm_hw();
	if (t->offered_aes) {
		tbuf_u16(&b, 4);
		tbuf_u16(&b, HW_TLS_CIPHER_AES128GCM);
	} else {
		tbuf_u16(&b, 2);
	}
	tbuf_u16(&b, HW_TLS_CIPHER_CHACHA20);
	tbuf_u8(&b, 1);
	tbuf_u8(&b, 0); // legacy_compression_methods: null
	size_t exts = tbuf_open(&b, 2);
	if (t->server_name) {
		size_t n = strlen(t->server_name);
		tbuf_u16(&b, EXT_SERVER_NAME);
		at = tbuf_open(&b, 2);
		list = tbuf_open(&b, 2);
		tbuf_u8(&b, 0); // host_name
		tbuf_u16(&b, (unsigned)n);
		tbuf_put(&b, t->server_name, n);
		tbuf_close(&b, list, 2);
		tbuf_close(&b, at, 2);
	}
	static const uint8_t fixed[] = {
	    0x00, EXT_SUPPORTED_GROUPS,     0x00, 0x04, 0x00, 0x02, 0x00, 0x1d, // x25519
	    0x00, EXT_SIGNATURE_ALGORITHMS, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03, // ecdsa_secp256r1_sha256
	    0x00, EXT_SUPPORTED_VERSIONS,   0x00, 0x03, 0x02, 0x03, 0x04,       // TLS 1.3
	};
	tbuf_put(&b, fixed, sizeof fixed);
	tbuf_u16(&b, EXT_ALPN);
	at = tbuf_open(&b, 2);
	list = tbuf_open(&b, 2);
	for (size_t i = 0; i < t->alpn_count; i++) {
		size_t n = strlen(t->alpn[i]);
		tbuf_u8(&b, (unsigned)n);
		tbuf_put(&b, t->alpn[i], n);
	}
	tbuf_close(&b, list, 2);
	tbuf_close(&b, at, 2);
	tbuf_u16(&b, EXT_KEY_SHARE);
	at = tbuf_open(&b, 2);
	list = tbuf_open(&b, 2);
	if (!t->omit_share) {
		tbuf_u16(&b, GROUP_X25519);
		tbuf_u16(&b, HW_X25519_LEN);
		tbuf_put(&b, t->eph_pub, HW_X25519_LEN);
	}
	tbuf_close(&b, list, 2);
	tbuf_close(&b, at, 2);
	if (t->cookie) {
		tbuf_u16(&b, EXT_COOKIE);
		at = tbuf_open(&b, 2);
		list = tbuf_open(&b, 2);
		tbuf_put(&b, t->cookie, t->cookie_len);
		tbuf_close(&b, list, 2);
		tbuf_close(&b, at, 2);
	}
	tbuf_u16(&b, EXT_QUIC_TRANSPORT_PARAMETERS);
	at = tbuf_open(&b, 2);
	tbuf_put(&b, t->tp, t->tp_len);
	tbuf_close(&b, at, 2);
	tbuf_close(&b, exts, 2);
	tbuf_close(&b, 1, 3);
	int rc = tls_send(t, HW_TLS_INITIAL, &b);
	tbuf_free(&b);
	return rc;
}

static int client_on_server_hello(hw_tls *t, const uint8_t *msg, size_t len) {
	rd r = {msg + 4, len - 4}, random, sid, exts;
	uint16_t version, cipher, x;
	uint8_t comp;
	if (rd_u16(&r, &version) || rd_take(&r, 32, &random) || rd_vec(&r, 1, &sid) || rd_u16(&r, &cipher) ||
	    rd_u8(&r, &comp) || rd_vec(&r, 2, &exts) || r.n) {
		return tls_fail(t, HW_TLS_ALERT_DECODE_ERROR);
	}
	int hrr = memcmp(random.p, HRR_RANDOM, 32) == 0;
	if (version != LEGACY_VERSION) return tls_fail(t, HW_TLS_ALERT_PROTOCOL_VERSION);
	// The suite must be one offered (AES-128-GCM only when it was), and after a HelloRetryRequest
	// the one it named (RFC 8446 section 4.1.4).
	int offered = cipher == HW_TLS_CIPHER_CHACHA20 || (cipher == HW_TLS_CIPHER_AES128GCM && t->offered_aes);
	if (sid.n != 0 || !offered || (t->hrr && cipher != t->cipher) || comp != 0) {
		return tls_fail(t, HW_TLS_ALERT_ILLEGAL_PARAMETER);
	}
	t->cipher = cipher;
	ext_seen *seen = calloc(1, sizeof *seen);
	if (!seen) return tls_fail(t, HW_TLS_ALERT_INTERNAL_ERROR);
	int has_version = 0, has_share = 0;
	uint16_t group = 0;
	rd share = {0}, cookie = {0};
	uint8_t alert = 0;
	while (exts.n && !alert) {
		rd body;
		if (rd_u16(&exts, &x) || rd_vec(&exts, 2, &body)) {
			alert = HW_TLS_ALERT_DECODE_ERROR;
		} else if (ext_seen_add(seen, x)) {
			alert = HW_TLS_ALERT_ILLEGAL_PARAMETER;
		} else if (x == EXT_SUPPORTED_VERSIONS) {
			if (rd_u16(&body, &version) || body.n) {
				alert = HW_TLS_ALERT_DECODE_ERROR;
			} else if (version != TLS13_VERSION) {
				alert = HW_TLS_ALERT_ILLEGAL_PARAMETER;
			}
			has_version = 1;
		} else if (x == EXT_KEY_SHARE) {
			if (rd_u16(&body, &group) || (!hrr && (rd_vec(&body, 2, &share) || share.n == 0)) || body.n) {
				alert = HW_TLS_ALERT_DECODE_ERROR;
			}
			has_share = 1;
		} else if (x == EXT_COOKIE && hrr) {
			if (rd_vec(&body, 2, &cookie) || body.n || cookie.n == 0) alert = HW_TLS_ALERT_DECODE_ERROR;
		} else {
			alert = HW_TLS_ALERT_UNSUPPORTED_EXT; // includes pre_shared_key, which this client never offers
		}
	}
	free(seen);
	if (alert) return tls_fail(t, alert);
	if (!has_version) return tls_fail(t, HW_TLS_ALERT_PROTOCOL_VERSION);
	if (!has_share) return tls_fail(t, HW_TLS_ALERT_MISSING_EXTENSION);
	if (group != GROUP_X25519) return tls_fail(t, HW_TLS_ALERT_ILLEGAL_PARAMETER);

	if (hrr) {
		// Only one, and only when it changes something: the client sent no X25519 share.
		if (t->hrr) return tls_fail(t, HW_TLS_ALERT_UNEXPECTED_MESSAGE);
		if (!t->omit_share) return tls_fail(t, HW_TLS_ALERT_ILLEGAL_PARAMETER);
		t->hrr = 1;
		t->omit_share = 0;
		if (cookie.n) {
			t->cookie = malloc(cookie.n);
			if (!t->cookie) return tls_fail(t, HW_TLS_ALERT_INTERNAL_ERROR);
			memcpy(t->cookie, cookie.p, cookie.n);
			t->cookie_len = cookie.n;
		}
		th_restart_hrr(t);
		hw_sha256_update(&t->th, msg, len);
		return client_send_hello(t);
	}
	if (t->omit_share || share.n != HW_X25519_LEN) return tls_fail(t, HW_TLS_ALERT_ILLEGAL_PARAMETER);
	uint8_t ecdhe[HW_X25519_LEN];
	if (hw_x25519(ecdhe, t->eph_priv, share.p)) {
		wipe(ecdhe, sizeof ecdhe);
		return tls_fail(t, HW_TLS_ALERT_ILLEGAL_PARAMETER);
	}
	hw_sha256_update(&t->th, msg, len);
	if (tls_enter_handshake(t, ecdhe)) return -1;
	t->state = ST_CLIENT_WAIT_EE;
	return 0;
}

static int client_on_encrypted_extensions(hw_tls *t, const uint8_t *msg, size_t len) {
	rd r = {msg + 4, len - 4}, exts;
	uint16_t x;
	if (rd_vec(&r, 2, &exts) || r.n) return tls_fail(t, HW_TLS_ALERT_DECODE_ERROR);
	ext_seen *seen = calloc(1, sizeof *seen);
	if (!seen) return tls_fail(t, HW_TLS_ALERT_INTERNAL_ERROR);
	int has_tp = 0;
	rd tp = {0};
	uint8_t alert = 0;
	while (exts.n && !alert) {
		rd body, list, name;
		if (rd_u16(&exts, &x) || rd_vec(&exts, 2, &body)) {
			alert = HW_TLS_ALERT_DECODE_ERROR;
		} else if (ext_seen_add(seen, x)) {
			alert = HW_TLS_ALERT_ILLEGAL_PARAMETER;
		} else if (x == EXT_ALPN) {
			// Exactly one name, and one this client offered.
			if (rd_vec(&body, 2, &list) || body.n || rd_vec(&list, 1, &name) || list.n || name.n == 0) {
				alert = HW_TLS_ALERT_DECODE_ERROR;
				continue;
			}
			alert = HW_TLS_ALERT_ILLEGAL_PARAMETER;
			for (size_t i = 0; i < t->alpn_count; i++) {
				if (strlen(t->alpn[i]) == name.n && memcmp(t->alpn[i], name.p, name.n) == 0) {
					tls_set_alpn(t, name.p, name.n);
					alert = 0;
					break;
				}
			}
		} else if (x == EXT_QUIC_TRANSPORT_PARAMETERS) {
			has_tp = 1;
			tp = body;
		} else if (x == EXT_SERVER_NAME && t->server_name) {
			if (body.n) alert = HW_TLS_ALERT_DECODE_ERROR; // the acknowledgement is empty
		} else if (x != EXT_SUPPORTED_GROUPS) {
			alert = HW_TLS_ALERT_UNSUPPORTED_EXT;
		}
	}
	free(seen);
	if (alert) return tls_fail(t, alert);
	if (!t->has_alpn) return tls_fail(t, HW_TLS_ALERT_NO_APP_PROTOCOL);
	if (!has_tp) return tls_fail(t, HW_TLS_ALERT_MISSING_EXTENSION);
	if (tls_set_peer_tp(t, &tp)) return -1;
	hw_sha256_update(&t->th, msg, len);
	t->state = ST_CLIENT_WAIT_CERT;
	return 0;
}

static int client_on_certificate(hw_tls *t, const uint8_t *msg, size_t len) {
	rd r = {msg + 4, len - 4}, ctx, list, leaf = {0};
	if (rd_vec(&r, 1, &ctx) || rd_vec(&r, 3, &list) || r.n) return tls_fail(t, HW_TLS_ALERT_DECODE_ERROR);
	if (ctx.n) return tls_fail(t, HW_TLS_ALERT_ILLEGAL_PARAMETER);
	size_t count = 0;
	while (list.n) {
		rd data, ext;
		if (rd_vec(&list, 3, &data) || data.n == 0 || rd_vec(&list, 2, &ext)) {
			return tls_fail(t, HW_TLS_ALERT_DECODE_ERROR);
		}
		if (count++ == 0) leaf = data;
	}
	if (count == 0) return tls_fail(t, HW_TLS_ALERT_DECODE_ERROR);
	if (t->has_pin) {
		uint8_t h[TLS_HASH];
		hw_sha256(leaf.p, leaf.n, h);
		if (memcmp(h, t->pin, TLS_HASH) != 0) return tls_fail(t, HW_TLS_ALERT_BAD_CERTIFICATE);
	}
	if (t->key_pin_count) {
		// The key the CertificateVerify below must have signed with: any certificate for it.
		const uint8_t *spki;
		size_t spki_len;
		uint8_t h[TLS_HASH];
		if (hw_cert_spki(leaf.p, leaf.n, &spki, &spki_len) != 0) return tls_fail(t, HW_TLS_ALERT_BAD_CERTIFICATE);
		hw_sha256(spki, spki_len, h);
		int match = 0;
		for (size_t i = 0; i < t->key_pin_count; i++) match |= memcmp(h, t->key_pins[i], TLS_HASH) == 0;
		if (!match) return tls_fail(t, HW_TLS_ALERT_BAD_CERTIFICATE);
	}
	if (hw_cert_p256_pubkey(leaf.p, leaf.n, t->leaf_pub)) return tls_fail(t, HW_TLS_ALERT_BAD_CERTIFICATE);
	hw_sha256_update(&t->th, msg, len);
	t->state = ST_CLIENT_WAIT_CV;
	return 0;
}

static int client_on_certificate_verify(hw_tls *t, const uint8_t *msg, size_t len) {
	rd r = {msg + 4, len - 4}, sig;
	uint16_t alg;
	if (rd_u16(&r, &alg) || rd_vec(&r, 2, &sig) || r.n) return tls_fail(t, HW_TLS_ALERT_DECODE_ERROR);
	if (alg != SIG_ECDSA_P256) return tls_fail(t, HW_TLS_ALERT_ILLEGAL_PARAMETER);
	uint8_t th[TLS_HASH], digest[TLS_HASH];
	th_peek(&t->th, th);
	cv_digest(th, digest);
	if (!hw_p256_verify(t->leaf_pub, digest, sig.p, sig.n)) return tls_fail(t, HW_TLS_ALERT_DECRYPT_ERROR);
	hw_sha256_update(&t->th, msg, len);
	t->state = ST_CLIENT_WAIT_FIN;
	return 0;
}

static int client_on_finished(hw_tls *t, const uint8_t *msg, size_t len) {
	if (len != 4 + TLS_HASH) return tls_fail(t, HW_TLS_ALERT_DECODE_ERROR);
	uint8_t th[TLS_HASH], want[TLS_HASH];
	th_peek(&t->th, th);
	verify_data(t->s_hs, th, want);
	if (!bytes_equal_ct(msg + 4, want, TLS_HASH)) return tls_fail(t, HW_TLS_ALERT_DECRYPT_ERROR);
	hw_sha256_update(&t->th, msg, len);
	th_peek(&t->th, th);
	uint8_t fin[TLS_HASH];
	verify_data(t->c_hs, th, fin);
	tbuf b = {0};
	msg_open(&b, HS_FINISHED);
	tbuf_put(&b, fin, sizeof fin);
	tbuf_close(&b, 1, 3);
	int rc = tls_send(t, HW_TLS_HANDSHAKE, &b);
	tbuf_free(&b);
	if (rc) return -1;
	wipe(t->c_hs, sizeof t->c_hs);
	wipe(t->s_hs, sizeof t->s_hs);
	if (tls_enter_app(t, th)) return -1; // th: still through the server's Finished
	t->state = ST_CLIENT_DONE;
	t->done = 1;
	return 0;
}

// ---- the contract --------------------------------------------------------------------------

static char *str_dup(const char *s) {
	size_t n = strlen(s) + 1;
	char *p = malloc(n);
	if (p) memcpy(p, s, n);
	return p;
}

hw_tls *hw_tls_new(const hw_tls_config *cfg, const hw_tls_callbacks *cb) {
	if (!cfg || !cb || !cb->emit || cfg->alpn_count == 0 || !cfg->alpn) return NULL;
	if (cfg->transport_params_len > 0xffff || (cfg->transport_params_len && !cfg->transport_params)) return NULL;
	size_t alpn_total = 0;
	for (size_t i = 0; i < cfg->alpn_count; i++) {
		size_t n = cfg->alpn[i] ? strlen(cfg->alpn[i]) : 0;
		if (n == 0 || n > 255) return NULL;
		alpn_total += 1 + n;
	}
	if (alpn_total > 0xffff - 4) return NULL;
	if (cfg->is_server) {
		if (!chain_usable(cfg->chain, cfg->chain_len) || !cfg->key) return NULL;
	} else if (cfg->server_name && (cfg->server_name[0] == '\0' || strlen(cfg->server_name) > 255)) {
		return NULL;
	}

	hw_tls *t = calloc(1, sizeof *t);
	if (!t) return NULL;
	t->is_server = cfg->is_server ? 1 : 0;
	t->cb = *cb;
	t->state = t->is_server ? ST_SERVER_WAIT_CH : ST_CLIENT_START;
	hw_sha256_init(&t->th);
	t->alpn = calloc(cfg->alpn_count, sizeof *t->alpn);
	if (!t->alpn) goto fail;
	t->alpn_count = cfg->alpn_count;
	for (size_t i = 0; i < cfg->alpn_count; i++) {
		t->alpn[i] = str_dup(cfg->alpn[i]);
		if (!t->alpn[i]) goto fail;
	}
	t->tp = malloc(cfg->transport_params_len ? cfg->transport_params_len : 1);
	if (!t->tp) goto fail;
	if (cfg->transport_params_len) memcpy(t->tp, cfg->transport_params, cfg->transport_params_len);
	t->tp_len = cfg->transport_params_len;
	if (t->is_server) {
		if (chain_set(t, cfg->chain, cfg->chain_len, cfg->key)) goto fail;
		t->cert_for = cfg->cert_for;
		t->cert_ud = cfg->cert_ud;
	} else {
		if (cfg->server_name) {
			t->server_name = str_dup(cfg->server_name);
			if (!t->server_name) goto fail;
		}
		if (cfg->pin_sha256) {
			memcpy(t->pin, cfg->pin_sha256, sizeof t->pin);
			t->has_pin = 1;
		}
		if (cfg->key_pin_count > HW_TLS_KEY_PINS_MAX || (cfg->key_pin_count && !cfg->key_pins_sha256)) goto fail;
		for (size_t i = 0; i < cfg->key_pin_count; i++) {
			memcpy(t->key_pins[i], cfg->key_pins_sha256 + i * TLS_HASH, TLS_HASH);
		}
		t->key_pin_count = cfg->key_pin_count;
	}
	return t;
fail:
	hw_tls_free(t);
	return NULL;
}

void hw_tls_free(hw_tls *t) {
	if (!t) return;
	for (size_t i = 0; i < t->chain_len; i++) free(t->chain[i].der);
	for (size_t i = 0; t->alpn && i < t->alpn_count; i++) free(t->alpn[i]);
	free(t->alpn);
	free(t->tp);
	free(t->peer_tp);
	free(t->server_name);
	free(t->cookie);
	if (t->rx) wipe(t->rx, t->rx_cap);
	free(t->rx);
	wipe(t, sizeof *t); // the private key, the ephemeral key and every secret
	free(t);
}

void hw_tls_test_omit_key_share(hw_tls *t) {
	t->omit_share = 1;
}

size_t hw_tls_test_rx_cap(const hw_tls *t) {
	return t->rx_cap;
}

int hw_tls_start(hw_tls *t) {
	if (t->is_server) return 0;
	if (t->state != ST_CLIENT_START) return tls_fail(t, HW_TLS_ALERT_INTERNAL_ERROR);
	if (hw_sys_random(t->random, sizeof t->random) || hw_x25519_keygen(t->eph_priv, t->eph_pub)) {
		return tls_fail(t, HW_TLS_ALERT_INTERNAL_ERROR);
	}
	t->state = ST_CLIENT_WAIT_SH;
	return client_send_hello(t);
}

static hw_tls_level tls_expected_level(const hw_tls *t) {
	switch (t->state) {
	case ST_CLIENT_WAIT_SH:
	case ST_SERVER_WAIT_CH:
	case ST_SERVER_WAIT_CH2:
		return HW_TLS_INITIAL;
	case ST_CLIENT_WAIT_EE:
	case ST_CLIENT_WAIT_CERT:
	case ST_CLIENT_WAIT_CV:
	case ST_CLIENT_WAIT_FIN:
	case ST_SERVER_WAIT_FIN:
		return HW_TLS_HANDSHAKE;
	default:
		return HW_TLS_APP;
	}
}

static int tls_on_message(hw_tls *t, const uint8_t *msg, size_t len) {
	uint8_t type = msg[0];
	switch (t->state) {
	case ST_SERVER_WAIT_CH:
	case ST_SERVER_WAIT_CH2:
		if (type == HS_CLIENT_HELLO) return server_on_client_hello(t, msg, len);
		break;
	case ST_SERVER_WAIT_FIN:
		if (type == HS_FINISHED) return server_on_finished(t, msg, len);
		break;
	case ST_CLIENT_WAIT_SH:
		if (type == HS_SERVER_HELLO) return client_on_server_hello(t, msg, len);
		break;
	case ST_CLIENT_WAIT_EE:
		if (type == HS_ENCRYPTED_EXTENSIONS) return client_on_encrypted_extensions(t, msg, len);
		break;
	case ST_CLIENT_WAIT_CERT:
		if (type == HS_CERTIFICATE) return client_on_certificate(t, msg, len);
		break;
	case ST_CLIENT_WAIT_CV:
		if (type == HS_CERTIFICATE_VERIFY) return client_on_certificate_verify(t, msg, len);
		break;
	case ST_CLIENT_WAIT_FIN:
		if (type == HS_FINISHED) return client_on_finished(t, msg, len);
		break;
	case ST_CLIENT_DONE:
		if (type == HS_NEW_SESSION_TICKET) return 0; // no resumption: dropped unread
		break;
	default:
		break;
	}
	return tls_fail(t, HW_TLS_ALERT_UNEXPECTED_MESSAGE);
}

// Room for need bytes of the message being received, keeping the rx_len bytes it holds. It grows
// with what has arrived, not with what a header claims: a 4-byte header naming 64 KiB costs the
// peer what it costs this side.
static int rx_grow(hw_tls *t, size_t need) {
	if (need <= t->rx_cap) return 0;
	size_t cap = HW_MIN(HW_MAX(HW_MAX(need, t->rx_cap * 2), (size_t)256), (size_t)TLS_MSG_MAX);
	uint8_t *p = malloc(cap);
	if (!p) return -1;
	if (t->rx_len) memcpy(p, t->rx, t->rx_len);
	if (t->rx) wipe(t->rx, t->rx_cap);
	free(t->rx);
	t->rx = p;
	t->rx_cap = cap;
	return 0;
}

static void rx_release(hw_tls *t) {
	if (t->rx) wipe(t->rx, t->rx_cap);
	free(t->rx);
	t->rx = NULL;
	t->rx_cap = 0;
}

int hw_tls_input(hw_tls *t, hw_tls_level level, const uint8_t *data, size_t len) {
	if (t->alert) return -1;
	if (t->state == ST_CLIENT_START && len) return tls_fail(t, HW_TLS_ALERT_UNEXPECTED_MESSAGE);
	for (;;) {
		if (t->hdr_len == 4 && t->rx_len == t->rx_want) {
			t->hdr_len = 0;
			t->rx_len = 0;
			if (tls_on_message(t, t->rx, t->rx_want)) return -1;
			continue;
		}
		if (!len) {
			// A connection keeps its hw_tls: once done, no reassembly buffer stays with it.
			if (t->done && t->hdr_len == 0) rx_release(t);
			return 0;
		}
		// Checked again after each message: a message may not continue past a change of keys.
		if (level != tls_expected_level(t)) return tls_fail(t, HW_TLS_ALERT_UNEXPECTED_MESSAGE);
		if (t->hdr_len < 4) {
			t->hdr[t->hdr_len++] = *data++;
			len--;
			if (t->hdr_len < 4) continue;
			size_t want = 4 + ((size_t)t->hdr[1] << 16 | (size_t)t->hdr[2] << 8 | t->hdr[3]);
			if (want > TLS_MSG_MAX) return tls_fail(t, HW_TLS_ALERT_DECODE_ERROR);
			t->rx_len = 0;
			if (rx_grow(t, 4)) return tls_fail(t, HW_TLS_ALERT_INTERNAL_ERROR);
			memcpy(t->rx, t->hdr, 4);
			t->rx_len = 4;
			t->rx_want = want;
			continue;
		}
		size_t take = HW_MIN(t->rx_want - t->rx_len, len);
		if (rx_grow(t, t->rx_len + take)) return tls_fail(t, HW_TLS_ALERT_INTERNAL_ERROR);
		memcpy(t->rx + t->rx_len, data, take);
		t->rx_len += take;
		data += take;
		len -= take;
	}
}

int hw_tls_done(const hw_tls *t) {
	return t->done && !t->alert;
}

uint8_t hw_tls_alert(const hw_tls *t) {
	return t->alert;
}

const char *hw_tls_alpn(const hw_tls *t) {
	return t->has_alpn ? t->alpn_sel : NULL;
}

const uint8_t *hw_tls_peer_transport_params(const hw_tls *t, size_t *len) {
	if (len) *len = t->peer_tp ? t->peer_tp_len : 0;
	return t->peer_tp;
}

const char *hw_tls_server_name(const hw_tls *t) {
	return t->server_name;
}

uint16_t hw_tls_cipher(const hw_tls *t) {
	return t->cipher;
}
