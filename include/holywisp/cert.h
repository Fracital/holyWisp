/*
 * holywisp/cert.h - the X.509 the WebTransport listener needs, and no more: loading an operator's
 * ECDSA P-256 certificate chain and key from PEM, and making the short-lived self-signed
 * certificate whose SHA-256 a browser pins with WebTransport's serverCertificateHashes. The
 * client takes a leaf's public key out of it, for the signature and for a key pin.
 *
 * Chrome accepts a pinned certificate only when it is X.509 v3, ECDSA (P-256), and valid for at
 * most 14 days (docs/webtransport.md, "Certificates"). The server makes a new one before the old
 * one expires and publishes the hashes of both (holywisp/webtransport.h).
 *
 * Pure and thread-safe. Returned buffers are malloc'ed and the caller frees them.
 */
#ifndef HOLYWISP_CERT_H
#define HOLYWISP_CERT_H

#include "holywisp/ecc.h"

#include <stddef.h>
#include <stdint.h>

#define HW_CERT_CHAIN_MAX 8

typedef struct {
	uint8_t *der;
	size_t len;
} hw_der;

// A self-signed X.509 v3 certificate for key (priv, pub), signed with ECDSA-with-SHA256, with
// subject and issuer CN=cn, a random 16-byte positive serial, validity [not_before, not_after]
// (Unix seconds, encoded as UTCTime, or GeneralizedTime from 2050 as RFC 5280 requires), a
// subjectAltName dNSName of cn, basicConstraints CA:FALSE and keyUsage digitalSignature (both
// critical). Returns 0 and the DER in *out, or -1 (and *out empty) when pub is not priv's public
// key, cn is empty, over 255 bytes or holds anything but printable ASCII without spaces,
// not_after is before not_before, either time is outside 1950 to 9999, or the random source fails.
int hw_cert_selfsigned(const uint8_t priv[HW_P256_PRIV_LEN], const uint8_t pub[HW_P256_PUB_LEN], const char *cn,
                       int64_t not_before, int64_t not_after, hw_der *out);

// Every "CERTIFICATE" block of a PEM text, leaf first as the file has them, into out[0..*n).
// Other blocks (a key in the same file) are skipped. Returns 0, or -1 (and *n = 0) when there is
// none, more than max, a BEGIN without its END, or a block that is not strict Base64 of exactly
// one DER SEQUENCE.
int hw_cert_load_chain(const char *pem, size_t len, hw_der *out, size_t max, size_t *n);

// The P-256 private key of the first PEM "EC PRIVATE KEY" (SEC 1) or "PRIVATE KEY" (PKCS#8)
// block. Returns 0, or -1 when there is no such block, it is not strict DER, its key is not on
// P-256 (RSA, another curve) or not in [1, n-1], or a public key it carries is not the key's own.
int hw_cert_load_p256_key(const char *pem, size_t len, uint8_t priv[HW_P256_PRIV_LEN]);

// The P-256 public key in a certificate's SubjectPublicKeyInfo. Returns 0, or -1 when the
// certificate does not parse or its key is not an uncompressed P-256 point on the curve.
int hw_cert_p256_pubkey(const uint8_t *der, size_t len, uint8_t pub[HW_P256_PUB_LEN]);

// A certificate's SubjectPublicKeyInfo as it is encoded there, tag and length included: the bytes
// whose SHA-256 is a key pin (RFC 7469's, curl's --pinnedpubkey), which stays the same across
// certificates for one key. *spki points into der. Any key type. Returns 0, or -1 when the
// certificate does not parse.
int hw_cert_spki(const uint8_t *der, size_t len, const uint8_t **spki, size_t *spki_len);

// The notAfter of a certificate, Unix seconds. Returns 0, or -1 when it does not parse
// (including a time that is not YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ, or is before 1950).
int hw_cert_not_after(const uint8_t *der, size_t len, int64_t *out);

void hw_der_free(hw_der *d);

#endif
