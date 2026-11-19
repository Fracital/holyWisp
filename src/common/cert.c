/*
 * src/common/cert.c - the X.509 of the WebTransport listener: a DER writer for the self-signed
 * certificate, a strict DER reader (every length checked against what is left, definite minimal
 * lengths only, no read past the buffer) for certificates and keys, and PEM with a strict
 * Base64 decoder.
 *
 * The reader understands only what holyWisp needs: where a certificate's validity and public key
 * are, and the two encodings of a P-256 private key (SEC 1 and PKCS#8). Everything else in a
 * certificate is checked for well-formed TLVs and otherwise passed through untouched.
 */
#include "holywisp/cert.h"

#include "holywisp/sha256.h"
#include "holywisp/sys.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ASN.1 tags.
#define TAG_BOOLEAN      0x01
#define TAG_INTEGER      0x02
#define TAG_BIT_STRING   0x03
#define TAG_OCTET_STRING 0x04
#define TAG_OID          0x06
#define TAG_UTF8STRING   0x0c
#define TAG_UTCTIME      0x17
#define TAG_GENTIME      0x18
#define TAG_SEQUENCE     0x30
#define TAG_SET          0x31
#define TAG_CTX0         0xa0 // [0] constructed
#define TAG_CTX1         0xa1 // [1] constructed
#define TAG_CTX3         0xa3 // [3] constructed
#define TAG_DNSNAME      0x82 // GeneralName dNSName, [2] IMPLICIT IA5String

// OID contents.
static const uint8_t OID_ECDSA_SHA256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}; // 1.2.840.10045.4.3.2
static const uint8_t OID_EC_PUBLIC_KEY[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};      // 1.2.840.10045.2.1
static const uint8_t OID_P256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};         // 1.2.840.10045.3.1.7
static const uint8_t OID_CN[] = {0x55, 0x04, 0x03};                                         // 2.5.4.3
static const uint8_t OID_BASIC_CONSTRAINTS[] = {0x55, 0x1d, 0x13};                          // 2.5.29.19
static const uint8_t OID_KEY_USAGE[] = {0x55, 0x1d, 0x0f};                                  // 2.5.29.15
static const uint8_t OID_SUBJECT_ALT_NAME[] = {0x55, 0x1d, 0x11};                           // 2.5.29.17

#define DER_DEPTH  8
#define CN_MAX     255
#define LABEL_MAX  64
#define SERIAL_LEN 16

static void wipe(void *p, size_t n) {
	volatile uint8_t *v = p;
	while (n--) *v++ = 0;
}

void hw_der_free(hw_der *d) {
	if (!d) return;
	free(d->der);
	d->der = NULL;
	d->len = 0;
}

// --- DER writer -------------------------------------------------------------------------------
// A constructed value is opened with its tag and closed once its content is written: the
// content is then moved up to make room for its length. Errors stick and are checked at the end.

typedef struct {
	uint8_t *p;
	size_t len, cap;
	size_t open[DER_DEPTH]; // where each open value's content starts
	int depth;
	int err;
} der_w;

static void w_reserve(der_w *w, size_t n) {
	if (w->err) return;
	if (w->cap - w->len >= n) return;
	size_t cap = w->cap ? w->cap : 512;
	while (cap - w->len < n) cap *= 2;
	uint8_t *p = realloc(w->p, cap);
	if (!p) {
		w->err = 1;
		return;
	}
	w->p = p;
	w->cap = cap;
}

static void w_bytes(der_w *w, const void *b, size_t n) {
	w_reserve(w, n);
	if (w->err) return;
	if (n) memcpy(w->p + w->len, b, n);
	w->len += n;
}

static void w_byte(der_w *w, uint8_t b) {
	w_bytes(w, &b, 1);
}

static void w_begin(der_w *w, uint8_t tag) {
	if (w->depth == DER_DEPTH) w->err = 1;
	w_byte(w, tag);
	if (w->err) return;
	w->open[w->depth++] = w->len;
}

static void w_end(der_w *w) {
	if (w->err) return;
	if (w->depth == 0) {
		w->err = 1;
		return;
	}
	size_t start = w->open[--w->depth];
	size_t n = w->len - start;
	uint8_t hdr[5];
	size_t hl = 0;
	if (n < 0x80) {
		hdr[hl++] = (uint8_t)n;
	} else {
		size_t bytes = n > 0xffffff ? 4 : n > 0xffff ? 3 : n > 0xff ? 2 : 1;
		hdr[hl++] = (uint8_t)(0x80 | bytes);
		for (size_t i = bytes; i > 0; i--) hdr[hl++] = (uint8_t)(n >> (8 * (i - 1)));
	}
	w_reserve(w, hl);
	if (w->err) return;
	memmove(w->p + start + hl, w->p + start, n);
	memcpy(w->p + start, hdr, hl);
	w->len += hl;
}

static void w_tlv(der_w *w, uint8_t tag, const void *b, size_t n) {
	w_begin(w, tag);
	w_bytes(w, b, n);
	w_end(w);
}

// --- Time -------------------------------------------------------------------------------------
// The proleptic Gregorian calendar between 1950 (UTCTime's first year) and 9999 (the last that
// GeneralizedTime's four digits hold), in Unix seconds.

#define YEAR_MIN 1950
#define YEAR_MAX 9999

static int is_leap(int y) {
	return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

static int month_days(int y, int m) {
	static const int days[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
	return days[m - 1] + (m == 2 && is_leap(y));
}

typedef struct {
	int year, month, day, hour, min, sec;
} civil;

// Days from 1970-01-01 to the first of the given month.
static int64_t days_from_civil(int y, int m) {
	int64_t days = 0;
	for (int i = 1970; i < y; i++) days += 365 + is_leap(i);
	for (int i = y; i < 1970; i++) days -= 365 + is_leap(i);
	for (int i = 1; i < m; i++) days += month_days(y, i);
	return days;
}

static int civil_from_unix(int64_t t, civil *c) {
	// 1950-01-01T00:00:00Z and 9999-12-31T23:59:59Z.
	if (t < -631152000LL || t > 253402300799LL) return -1;
	int64_t days = t / 86400, secs = t % 86400;
	if (secs < 0) {
		secs += 86400;
		days--;
	}
	int y = 1970;
	while (days < 0) {
		y--;
		days += 365 + is_leap(y);
	}
	while (days >= 365 + is_leap(y)) {
		days -= 365 + is_leap(y);
		y++;
	}
	int m = 1;
	while (days >= month_days(y, m)) {
		days -= month_days(y, m);
		m++;
	}
	c->year = y;
	c->month = m;
	c->day = (int)days + 1;
	c->hour = (int)(secs / 3600);
	c->min = (int)(secs / 60 % 60);
	c->sec = (int)(secs % 60);
	return 0;
}

static void put_digits(char *out, int v, int n) {
	for (int i = n - 1; i >= 0; i--) {
		out[i] = (char)('0' + v % 10);
		v /= 10;
	}
}

// UTCTime for 1950 to 2049 and GeneralizedTime from 2050, as RFC 5280 section 4.1.2.5 requires.
static int w_time(der_w *w, int64_t t) {
	civil c;
	if (civil_from_unix(t, &c) != 0) return -1;
	char s[16];
	size_t o = 0;
	int utc = c.year < 2050;
	if (utc) {
		put_digits(s, c.year % 100, 2);
		o = 2;
	} else {
		put_digits(s, c.year, 4);
		o = 4;
	}
	put_digits(s + o, c.month, 2);
	put_digits(s + o + 2, c.day, 2);
	put_digits(s + o + 4, c.hour, 2);
	put_digits(s + o + 6, c.min, 2);
	put_digits(s + o + 8, c.sec, 2);
	s[o + 10] = 'Z';
	w_tlv(w, utc ? TAG_UTCTIME : TAG_GENTIME, s, o + 11);
	return 0;
}

static int read_digits(const uint8_t *s, int n, int *out) {
	int v = 0;
	for (int i = 0; i < n; i++) {
		if (s[i] < '0' || s[i] > '9') return -1;
		v = v * 10 + (s[i] - '0');
	}
	*out = v;
	return 0;
}

// A UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ) in the only form DER allows
// for a certificate: seconds present, no fraction, Z.
static int parse_time(uint8_t tag, const uint8_t *s, size_t n, int64_t *out) {
	civil c;
	size_t o;
	if (tag == TAG_UTCTIME && n == 13) {
		if (read_digits(s, 2, &c.year) != 0) return -1;
		c.year += c.year >= 50 ? 1900 : 2000;
		o = 2;
	} else if (tag == TAG_GENTIME && n == 15) {
		if (read_digits(s, 4, &c.year) != 0) return -1;
		o = 4;
	} else {
		return -1;
	}
	if (read_digits(s + o, 2, &c.month) != 0 || read_digits(s + o + 2, 2, &c.day) != 0 ||
	    read_digits(s + o + 4, 2, &c.hour) != 0 || read_digits(s + o + 6, 2, &c.min) != 0 ||
	    read_digits(s + o + 8, 2, &c.sec) != 0 || s[o + 10] != 'Z') {
		return -1;
	}
	if (c.year < YEAR_MIN || c.month < 1 || c.month > 12 || c.day < 1 || c.day > month_days(c.year, c.month) ||
	    c.hour > 23 || c.min > 59 || c.sec > 59) {
		return -1;
	}
	int64_t days = days_from_civil(c.year, c.month) + c.day - 1;
	*out = days * 86400 + c.hour * 3600 + c.min * 60 + c.sec;
	return 0;
}

// --- The self-signed certificate ----------------------------------------------------------

static void w_name(der_w *w, const char *cn, size_t cn_len) {
	w_begin(w, TAG_SEQUENCE);
	w_begin(w, TAG_SET);
	w_begin(w, TAG_SEQUENCE);
	w_tlv(w, TAG_OID, OID_CN, sizeof(OID_CN));
	w_tlv(w, TAG_UTF8STRING, cn, cn_len);
	w_end(w);
	w_end(w);
	w_end(w);
}

static void w_sig_alg(der_w *w) {
	w_begin(w, TAG_SEQUENCE);
	w_tlv(w, TAG_OID, OID_ECDSA_SHA256, sizeof(OID_ECDSA_SHA256));
	w_end(w);
}

// Opens an Extension and its extnValue; the value's DER follows, then ext_end.
static void w_ext_begin(der_w *w, const uint8_t *oid, size_t oid_len, int critical) {
	static const uint8_t bool_true = 0xff;
	w_begin(w, TAG_SEQUENCE);
	w_tlv(w, TAG_OID, oid, oid_len);
	if (critical) w_tlv(w, TAG_BOOLEAN, &bool_true, 1);
	w_begin(w, TAG_OCTET_STRING);
}

static void w_ext_end(der_w *w) {
	w_end(w);
	w_end(w);
}

// A dNSName is an IA5String: printable ASCII here, no space, no control byte, at most 255 bytes.
static int cn_ok(const char *cn, size_t *len) {
	size_t n = 0;
	while (n <= CN_MAX && cn[n]) {
		if ((unsigned char)cn[n] <= 0x20 || (unsigned char)cn[n] >= 0x7f) return 0;
		n++;
	}
	if (n == 0 || n > CN_MAX) return 0;
	*len = n;
	return 1;
}

int hw_cert_selfsigned(const uint8_t priv[HW_P256_PRIV_LEN], const uint8_t pub[HW_P256_PUB_LEN], const char *cn,
                       int64_t not_before, int64_t not_after, hw_der *out) {
	if (!priv || !pub || !cn || !out) return -1;
	out->der = NULL;
	out->len = 0;
	size_t cn_len;
	if (!cn_ok(cn, &cn_len) || not_after < not_before) return -1;
	// A key pair that does not match would make a certificate nothing can verify.
	uint8_t check[HW_P256_PUB_LEN];
	if (hw_p256_public(priv, check) != 0 || memcmp(check, pub, HW_P256_PUB_LEN) != 0) return -1;

	// A positive 16-byte serial: the top bit clear keeps it positive, the next set keeps the
	// DER at 16 bytes.
	uint8_t serial[SERIAL_LEN];
	if (hw_sys_random(serial, sizeof(serial)) != 0) return -1;
	serial[0] = (uint8_t)((serial[0] & 0x7f) | 0x40);

	der_w w = {0};
	w_begin(&w, TAG_SEQUENCE); // Certificate
	size_t tbs_off = w.len;
	w_begin(&w, TAG_SEQUENCE); // TBSCertificate
	static const uint8_t v3[] = {TAG_INTEGER, 1, 2};
	w_tlv(&w, TAG_CTX0, v3, sizeof(v3));
	w_tlv(&w, TAG_INTEGER, serial, sizeof(serial));
	w_sig_alg(&w);
	w_name(&w, cn, cn_len);
	w_begin(&w, TAG_SEQUENCE);
	int bad_time = w_time(&w, not_before) != 0 || w_time(&w, not_after) != 0;
	w_end(&w);
	w_name(&w, cn, cn_len);
	w_begin(&w, TAG_SEQUENCE); // SubjectPublicKeyInfo
	w_begin(&w, TAG_SEQUENCE);
	w_tlv(&w, TAG_OID, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY));
	w_tlv(&w, TAG_OID, OID_P256, sizeof(OID_P256));
	w_end(&w);
	w_begin(&w, TAG_BIT_STRING);
	w_byte(&w, 0); // no unused bits
	w_bytes(&w, pub, HW_P256_PUB_LEN);
	w_end(&w);
	w_end(&w);
	w_begin(&w, TAG_CTX3);
	w_begin(&w, TAG_SEQUENCE);
	w_ext_begin(&w, OID_BASIC_CONSTRAINTS, sizeof(OID_BASIC_CONSTRAINTS), 1);
	w_begin(&w, TAG_SEQUENCE); // cA defaults to FALSE, so DER leaves it out
	w_end(&w);
	w_ext_end(&w);
	w_ext_begin(&w, OID_KEY_USAGE, sizeof(OID_KEY_USAGE), 1);
	static const uint8_t digital_signature[] = {7, 0x80}; // bit 0, 7 unused bits
	w_tlv(&w, TAG_BIT_STRING, digital_signature, sizeof(digital_signature));
	w_ext_end(&w);
	w_ext_begin(&w, OID_SUBJECT_ALT_NAME, sizeof(OID_SUBJECT_ALT_NAME), 0);
	w_begin(&w, TAG_SEQUENCE);
	w_tlv(&w, TAG_DNSNAME, cn, cn_len);
	w_end(&w);
	w_ext_end(&w);
	w_end(&w);
	w_end(&w);
	w_end(&w); // TBSCertificate
	if (w.err || bad_time) goto fail;

	uint8_t digest[HW_SHA256_LEN], sig[HW_P256_SIG_DER_MAX];
	hw_sha256(w.p + tbs_off, w.len - tbs_off, digest);
	int sig_len = hw_p256_sign(priv, digest, sig);
	if (sig_len < 0) goto fail;
	w_sig_alg(&w);
	w_begin(&w, TAG_BIT_STRING);
	w_byte(&w, 0);
	w_bytes(&w, sig, (size_t)sig_len);
	w_end(&w);
	w_end(&w); // Certificate
	if (w.err || w.depth != 0) goto fail;
	out->der = w.p;
	out->len = w.len;
	return 0;
fail:
	free(w.p);
	return -1;
}

// --- DER reader ---------------------------------------------------------------------------

typedef struct {
	const uint8_t *p, *end;
} der_r;

// The next TLV of r, which must have the given tag and a definite, minimal length that fits in
// what is left. Its content goes to *content (when not NULL) and r moves past it.
static int r_tlv(der_r *r, uint8_t tag, der_r *content) {
	size_t left = (size_t)(r->end - r->p);
	if (left < 2 || r->p[0] != tag) return -1;
	const uint8_t *q = r->p + 1;
	left--;
	size_t len = *q++;
	left--;
	if (len & 0x80) {
		size_t nb = len & 0x7f;
		if (nb == 0 || nb > 4 || nb > left || q[0] == 0) return -1; // indefinite, huge, leading zero
		len = 0;
		for (size_t i = 0; i < nb; i++) len = len << 8 | q[i];
		q += nb;
		left -= nb;
		if (len < 0x80) return -1; // the short form was required
	}
	if (len > left) return -1;
	if (content) {
		content->p = q;
		content->end = q + len;
	}
	r->p = q + len;
	return 0;
}

static int r_peek(const der_r *r, uint8_t tag) {
	return r->p < r->end && r->p[0] == tag;
}

static int r_done(const der_r *r) {
	return r->p == r->end;
}

static int der_eq(const der_r *v, const uint8_t *b, size_t n) {
	return (size_t)(v->end - v->p) == n && memcmp(v->p, b, n) == 0;
}

// An AlgorithmIdentifier that is exactly { id-ecPublicKey, prime256v1 }.
static int r_p256_alg(der_r *r) {
	der_r alg, oid;
	if (r_tlv(r, TAG_SEQUENCE, &alg) != 0) return -1;
	if (r_tlv(&alg, TAG_OID, &oid) != 0 || !der_eq(&oid, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY))) return -1;
	if (r_tlv(&alg, TAG_OID, &oid) != 0 || !der_eq(&oid, OID_P256, sizeof(OID_P256))) return -1;
	return r_done(&alg) ? 0 : -1;
}

// A certificate's validity and SubjectPublicKeyInfo (its content, and with spki_whole its whole
// TLV). The outer structure must be exactly Certificate { TBSCertificate, AlgorithmIdentifier,
// BIT STRING } and fill the buffer.
static int cert_parse_spki(const uint8_t *der, size_t len, der_r *validity, der_r *spki, der_r *spki_whole) {
	if (!der) return -1;
	der_r all = {der, der + len}, cert, tbs;
	if (r_tlv(&all, TAG_SEQUENCE, &cert) != 0 || !r_done(&all)) return -1;
	if (r_tlv(&cert, TAG_SEQUENCE, &tbs) != 0 || r_tlv(&cert, TAG_SEQUENCE, NULL) != 0 ||
	    r_tlv(&cert, TAG_BIT_STRING, NULL) != 0 || !r_done(&cert)) {
		return -1;
	}
	if (r_peek(&tbs, TAG_CTX0) && r_tlv(&tbs, TAG_CTX0, NULL) != 0) return -1; // version
	if (r_tlv(&tbs, TAG_INTEGER, NULL) != 0) return -1;                        // serialNumber
	if (r_tlv(&tbs, TAG_SEQUENCE, NULL) != 0) return -1;                       // signature
	if (r_tlv(&tbs, TAG_SEQUENCE, NULL) != 0) return -1;                       // issuer
	if (r_tlv(&tbs, TAG_SEQUENCE, validity) != 0) return -1;
	if (r_tlv(&tbs, TAG_SEQUENCE, NULL) != 0) return -1; // subject
	const uint8_t *start = tbs.p;
	if (r_tlv(&tbs, TAG_SEQUENCE, spki) != 0) return -1;
	if (spki_whole) {
		spki_whole->p = start;
		spki_whole->end = tbs.p;
	}
	return 0;
}

static int cert_parse(const uint8_t *der, size_t len, der_r *validity, der_r *spki) {
	return cert_parse_spki(der, len, validity, spki, NULL);
}

int hw_cert_spki(const uint8_t *der, size_t len, const uint8_t **spki, size_t *spki_len) {
	der_r validity, content, whole;
	if (cert_parse_spki(der, len, &validity, &content, &whole) != 0) return -1;
	*spki = whole.p;
	*spki_len = (size_t)(whole.end - whole.p);
	return 0;
}

int hw_cert_p256_pubkey(const uint8_t *der, size_t len, uint8_t pub[HW_P256_PUB_LEN]) {
	der_r validity, spki, bits;
	if (cert_parse(der, len, &validity, &spki) != 0) return -1;
	if (r_p256_alg(&spki) != 0 || r_tlv(&spki, TAG_BIT_STRING, &bits) != 0 || !r_done(&spki)) return -1;
	if (bits.end - bits.p != 1 + HW_P256_PUB_LEN || bits.p[0] != 0) return -1;
	if (!hw_p256_public_valid(bits.p + 1)) return -1;
	memcpy(pub, bits.p + 1, HW_P256_PUB_LEN);
	return 0;
}

int hw_cert_not_after(const uint8_t *der, size_t len, int64_t *out) {
	der_r validity, spki, t;
	if (cert_parse(der, len, &validity, &spki) != 0) return -1;
	uint8_t tag;
	int64_t nb, na;
	for (int i = 0; i < 2; i++) {
		if (r_peek(&validity, TAG_UTCTIME)) {
			tag = TAG_UTCTIME;
		} else if (r_peek(&validity, TAG_GENTIME)) {
			tag = TAG_GENTIME;
		} else {
			return -1;
		}
		if (r_tlv(&validity, tag, &t) != 0 || parse_time(tag, t.p, (size_t)(t.end - t.p), i == 0 ? &nb : &na) != 0) {
			return -1;
		}
	}
	if (!r_done(&validity)) return -1;
	*out = na;
	return 0;
}

// --- PEM ----------------------------------------------------------------------------------

// The first occurrence of needle in [p, end), or NULL.
static const char *find(const char *p, const char *end, const char *needle) {
	size_t n = strlen(needle);
	for (; (size_t)(end - p) >= n; p++) {
		if (memcmp(p, needle, n) == 0) return p;
	}
	return NULL;
}

typedef struct {
	const char *label, *body;
	size_t label_len, body_len;
} pem_block;

// The next "-----BEGIN label-----" ... "-----END label-----" block from *pos. Returns 1 and
// moves *pos past it, 0 when there are no more, -1 for a BEGIN without its END.
static int pem_next(const char **pos, const char *end, pem_block *b) {
	static const char begin[] = "-----BEGIN ";
	static const char dashes[] = "-----";
	const char *s = find(*pos, end, begin);
	if (!s) return 0;
	const char *label = s + sizeof(begin) - 1;
	const char *close = find(label, end, dashes);
	if (!close || close - label > LABEL_MAX || memchr(label, '\n', (size_t)(close - label))) return -1;
	char end_line[sizeof("-----END ") + LABEL_MAX + sizeof(dashes)];
	size_t ll = (size_t)(close - label);
	snprintf(end_line, sizeof(end_line), "-----END %.*s-----", (int)ll, label);
	const char *body = close + sizeof(dashes) - 1;
	const char *e = find(body, end, end_line);
	if (!e) return -1;
	b->label = label;
	b->label_len = ll;
	b->body = body;
	b->body_len = (size_t)(e - body);
	*pos = e + strlen(end_line);
	return 1;
}

static int pem_is(const pem_block *b, const char *label) {
	return b->label_len == strlen(label) && memcmp(b->label, label, b->label_len) == 0;
}

static int b64_value(char c) {
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

// Strict Base64 of a PEM body: whitespace anywhere, otherwise only the alphabet, then at most two
// '=' that complete the last quantum, and zero unused bits. Returns a malloc'ed buffer, or NULL.
static uint8_t *b64_decode(const char *s, size_t n, size_t *out_len) {
	uint8_t *out = malloc(n / 4 * 3 + 3);
	if (!out) return NULL;
	size_t o = 0, pad = 0;
	uint32_t acc = 0;
	unsigned k = 0; // characters in the current quantum
	for (size_t i = 0; i < n; i++) {
		char c = s[i];
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
		if (c == '=') {
			if (k < 2) goto fail; // '=' stands for the third or fourth character only
			pad++;
			acc <<= 6;
			if (++k == 4) {
				out[o++] = (uint8_t)(acc >> 16);
				if (pad == 1) out[o++] = (uint8_t)(acc >> 8);
				// The bits the padding stands for must be zero.
				if ((pad == 1 && (acc & 0xff)) || (pad == 2 && (acc & 0xffff))) goto fail;
				k = 0;
			}
			continue;
		}
		int v = b64_value(c);
		if (v < 0 || pad) goto fail;
		acc = acc << 6 | (uint32_t)v;
		if (++k == 4) {
			out[o++] = (uint8_t)(acc >> 16);
			out[o++] = (uint8_t)(acc >> 8);
			out[o++] = (uint8_t)acc;
			k = 0;
			acc = 0;
		}
	}
	if (k != 0 || o == 0) goto fail;
	*out_len = o;
	return out;
fail:
	wipe(out, n / 4 * 3 + 3);
	free(out);
	return NULL;
}

// A buffer that is exactly one DER SEQUENCE.
static int der_one_sequence(const uint8_t *p, size_t n) {
	der_r r = {p, p + n};
	return r_tlv(&r, TAG_SEQUENCE, NULL) == 0 && r_done(&r);
}

int hw_cert_load_chain(const char *pem, size_t len, hw_der *out, size_t max, size_t *n) {
	if (!n) return -1;
	*n = 0;
	if (!pem || !out) return -1;
	const char *pos = pem, *end = pem + len;
	pem_block b;
	int r;
	while ((r = pem_next(&pos, end, &b)) == 1) {
		if (!pem_is(&b, "CERTIFICATE")) continue;
		if (*n == max) goto fail;
		size_t dl;
		uint8_t *der = b64_decode(b.body, b.body_len, &dl);
		if (!der) goto fail;
		if (!der_one_sequence(der, dl)) {
			free(der);
			goto fail;
		}
		out[*n].der = der;
		out[*n].len = dl;
		(*n)++;
	}
	if (r < 0 || *n == 0) goto fail;
	return 0;
fail:
	for (size_t i = 0; i < *n; i++) hw_der_free(&out[i]);
	*n = 0;
	return -1;
}

// ECPrivateKey (SEC 1 C.4, RFC 5915): { version 1, privateKey OCTET STRING, [0] parameters
// OPTIONAL, [1] publicKey OPTIONAL }. Standalone, the curve must be named and P-256; inside
// PKCS#8 the algorithm already said so, and [0] may be left out. A [1] must be the key's own
// public point.
static int parse_ec_private_key(der_r r, int need_curve, uint8_t priv[HW_P256_PRIV_LEN]) {
	der_r key, v, d;
	if (r_tlv(&r, TAG_SEQUENCE, &key) != 0 || !r_done(&r)) return -1;
	static const uint8_t one[] = {1};
	if (r_tlv(&key, TAG_INTEGER, &v) != 0 || !der_eq(&v, one, 1)) return -1;
	if (r_tlv(&key, TAG_OCTET_STRING, &d) != 0) return -1;
	size_t dl = (size_t)(d.end - d.p);
	if (dl == 0 || dl > HW_P256_PRIV_LEN) return -1;
	if (r_peek(&key, TAG_CTX0)) {
		der_r params, oid;
		if (r_tlv(&key, TAG_CTX0, &params) != 0 || r_tlv(&params, TAG_OID, &oid) != 0 || !r_done(&params) ||
		    !der_eq(&oid, OID_P256, sizeof(OID_P256))) {
			return -1;
		}
	} else if (need_curve) {
		return -1;
	}
	der_r pubkey = {NULL, NULL};
	if (r_peek(&key, TAG_CTX1)) {
		der_r wrap;
		if (r_tlv(&key, TAG_CTX1, &wrap) != 0 || r_tlv(&wrap, TAG_BIT_STRING, &pubkey) != 0 || !r_done(&wrap)) {
			return -1;
		}
	}
	if (!r_done(&key)) return -1;

	uint8_t k[HW_P256_PRIV_LEN] = {0}, pub[HW_P256_PUB_LEN];
	memcpy(k + HW_P256_PRIV_LEN - dl, d.p, dl); // some writers drop leading zero bytes
	int rc = hw_p256_public(k, pub);
	if (rc == 0 && pubkey.p &&
	    (pubkey.end - pubkey.p != 1 + HW_P256_PUB_LEN || pubkey.p[0] != 0 ||
	     memcmp(pubkey.p + 1, pub, HW_P256_PUB_LEN) != 0)) {
		rc = -1;
	}
	if (rc == 0) memcpy(priv, k, HW_P256_PRIV_LEN);
	wipe(k, sizeof(k));
	return rc;
}

// PrivateKeyInfo / OneAsymmetricKey (RFC 5208, RFC 5958): { version 0 or 1, { id-ecPublicKey,
// prime256v1 }, OCTET STRING { ECPrivateKey }, [0] attributes OPTIONAL, [1] publicKey OPTIONAL }.
static int parse_pkcs8(der_r r, uint8_t priv[HW_P256_PRIV_LEN]) {
	der_r info, v, inner;
	if (r_tlv(&r, TAG_SEQUENCE, &info) != 0 || !r_done(&r)) return -1;
	if (r_tlv(&info, TAG_INTEGER, &v) != 0 || v.end - v.p != 1 || v.p[0] > 1) return -1;
	if (r_p256_alg(&info) != 0 || r_tlv(&info, TAG_OCTET_STRING, &inner) != 0) return -1;
	if (r_peek(&info, TAG_CTX0) && r_tlv(&info, TAG_CTX0, NULL) != 0) return -1;
	if (r_peek(&info, 0x81) && r_tlv(&info, 0x81, NULL) != 0) return -1; // [1] IMPLICIT BIT STRING
	if (!r_done(&info)) return -1;
	return parse_ec_private_key(inner, 0, priv);
}

int hw_cert_load_p256_key(const char *pem, size_t len, uint8_t priv[HW_P256_PRIV_LEN]) {
	if (!pem || !priv) return -1;
	const char *pos = pem, *end = pem + len;
	pem_block b;
	while (pem_next(&pos, end, &b) == 1) {
		int sec1 = pem_is(&b, "EC PRIVATE KEY");
		if (!sec1 && !pem_is(&b, "PRIVATE KEY")) continue;
		size_t dl;
		uint8_t *der = b64_decode(b.body, b.body_len, &dl);
		if (!der) return -1;
		der_r r = {der, der + dl};
		int rc = sec1 ? parse_ec_private_key(r, 1, priv) : parse_pkcs8(r, priv);
		wipe(der, dl);
		free(der);
		return rc;
	}
	return -1;
}
