/*
 * tests/test_cert.c - X.509 for WebTransport: the self-signed certificate (its structure, its
 * signature, and a pinned copy that OpenSSL accepted), certificates and keys made by OpenSSL
 * (checked in below, so the test needs no OpenSSL to run), refusals of RSA and P-384, strict PEM,
 * and every fixture truncated at every length and corrupted at every byte under the sanitizers.
 */
#include "holywisp/cert.h"
#include "holywisp/ecc.h"
#include "holywisp/hw.h"
#include "holywisp/sha256.h"

#include "test.h"

#include <stdlib.h>
#include <string.h>

// Made by hw_cert_selfsigned with SEC1_KEY, CN=localhost, valid from 1795000000 for 13 days. OpenSSL
// 3.5 parsed it (x509 -text) and verified its signature (verify -check_ss_sig -partial_chain).
static const char MINE_CERT[] = "-----BEGIN CERTIFICATE-----\n"
                                "MIIBXTCCAQKgAwIBAgIQZKMoJJYsGf4SfOd88WV+lzAKBggqhkjOPQQDAjAUMRIw\n"
                                "EAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYxMTE4MTEwNjQwWhcNMjYxMjAxMTEwNjQw\n"
                                "WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n"
                                "AASqvOSEFoixsZyobjzAIQJl5K59tYO+W/Tm9wvycdO5VBjHtDVJKjvEsnb4Kvxu\n"
                                "yb5exv1QQwrkBST3Wu8xoEN2ozYwNDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQE\n"
                                "AwIHgDAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAM8f\n"
                                "bg4pCxv0b+yoyJQQb2NTZv8q+7ii2ErZ7M9qMP2dAiEA0nQTYZLSBTz1SHuLX/oh\n"
                                "uxABWorRzkOzUEKw7Q45lDE=\n"
                                "-----END CERTIFICATE-----\n";

// openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 10 -subj /CN=fixture.test
//   -addext subjectAltName=DNS:fixture.test
static const char EC_CERT[] = "-----BEGIN CERTIFICATE-----\n"
                              "MIIBmzCCAUKgAwIBAgIUIvnLCNv+B99SZiKYdxLtnJ+JklQwCgYIKoZIzj0EAwIw\n"
                              "FzEVMBMGA1UEAwwMZml4dHVyZS50ZXN0MB4XDTI2MTExODIxNTUyMFoXDTI2MTEy\n"
                              "ODIxNTUyMFowFzEVMBMGA1UEAwwMZml4dHVyZS50ZXN0MFkwEwYHKoZIzj0CAQYI\n"
                              "KoZIzj0DAQcDQgAEI6UuPPfoRS3XJ5cCUxsHawmyfhCJrSQl20rf7uDSvhfCzB0H\n"
                              "fWDyEhoNA42Xu/yoNYjPvEaKNaCam55/5QmVfaNsMGowHQYDVR0OBBYEFCc88Nbc\n"
                              "Sq7GcsrsPOaP2VeCArnpMB8GA1UdIwQYMBaAFCc88NbcSq7GcsrsPOaP2VeCArnp\n"
                              "MA8GA1UdEwEB/wQFMAMBAf8wFwYDVR0RBBAwDoIMZml4dHVyZS50ZXN0MAoGCCqG\n"
                              "SM49BAMCA0cAMEQCIHvhVcZtio6Gd7ab+1evxJ/IvqfYO/YgfltE5d4UDcCZAiB0\n"
                              "1uOKGPnB2AvEOd9dI7CAmKZCOPDF11biKhp0FioLzg==\n"
                              "-----END CERTIFICATE-----\n";

// The key of EC_CERT, PKCS#8, as openssl req wrote it.
static const char EC_PKCS8_KEY[] = "-----BEGIN PRIVATE KEY-----\n"
                                   "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggcL7eOjCzIBkUgpf\n"
                                   "FheVYQvzHKg74SZCnl1gm2p4HdyhRANCAAQjpS489+hFLdcnlwJTGwdrCbJ+EImt\n"
                                   "JCXbSt/u4NK+F8LMHQd9YPISGg0DjZe7/Kg1iM+8Roo1oJqbnn/lCZV9\n"
                                   "-----END PRIVATE KEY-----\n";

// openssl ecparam -name prime256v1 -genkey: SEC 1, after an EC PARAMETERS block.
static const char SEC1_KEY[] = "-----BEGIN EC PARAMETERS-----\n"
                               "BggqhkjOPQMBBw==\n"
                               "-----END EC PARAMETERS-----\n"
                               "-----BEGIN EC PRIVATE KEY-----\n"
                               "MHcCAQEEIJdcYczIWzGf9u3vPE3NuKkXxxNfd7L105BEtXH1xLE/oAoGCCqGSM49\n"
                               "AwEHoUQDQgAEqrzkhBaIsbGcqG48wCECZeSufbWDvlv05vcL8nHTuVQYx7Q1SSo7\n"
                               "xLJ2+Cr8bsm+Xsb9UEMK5AUk91rvMaBDdg==\n"
                               "-----END EC PRIVATE KEY-----\n";

// openssl req -x509 -newkey rsa:2048 -nodes -days 10 -subj /CN=rsa.test
static const char RSA_CERT[] = "-----BEGIN CERTIFICATE-----\n"
                               "MIIDBzCCAe+gAwIBAgIUHuZ9tuV3Ksvo1WRqpecfygt2ZQswDQYJKoZIhvcNAQEL\n"
                               "BQAwEzERMA8GA1UEAwwIcnNhLnRlc3QwHhcNMjYxMTE4MjE1NTIwWhcNMjYxMTI4\n"
                               "MjE1NTIwWjATMREwDwYDVQQDDAhyc2EudGVzdDCCASIwDQYJKoZIhvcNAQEBBQAD\n"
                               "ggEPADCCAQoCggEBAJnfV3bLgM+0rMB4G81hN0nNX13jPUfNUUHjg7azBrBx9Wbm\n"
                               "O6IaWNgODielZw0uvfgDOtk7iO6ji9+SLQxLkD5d8HhEiIRqUMmFprb6mek283iE\n"
                               "qCXavm397IrasEWJKMdAvkaq6Z3EwkTP51AMb3g49WXSPoczjmrRPa3d+nrVLCjE\n"
                               "JRwagSvxTcrbcvbeNjm7XIriMKFEhEUZuiEYEvbAaMQrrQbubTDSaA0FuETh8krS\n"
                               "DswPfZ0bLHqV99srNR76oqSzLTCDXtBZERq0aDqFahObqV/LxFhyWPSxOz1UC5vR\n"
                               "XCD60jLvk6yb0oQSGVFMLLhHMZHd5DoGtiRSgy0CAwEAAaNTMFEwHQYDVR0OBBYE\n"
                               "FBQQ2X7y9PSRdzux4rdu12rBf6lMMB8GA1UdIwQYMBaAFBQQ2X7y9PSRdzux4rdu\n"
                               "12rBf6lMMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAA0kObuz\n"
                               "G1aDtl4XvcCb2sXIVISI7bh8N5cyHqNzh+q2OwENmjaBwPOpyQE+pDJ763jHLClc\n"
                               "lHF/yqc1E2qE26DDhX+o/340mtkozmdmT4dj84OyO2UNz9NCstYrXjutFqI30j/V\n"
                               "20VS4R93YTQZx5Q9hBdE/A4r4TFS901aT/zeogMUZ++nAlcGJCrHEtG4ZWDRonR7\n"
                               "otkSgleGMpmM9k4AYRerVBumBDdvfMI9TNChF5ZVryDsOBrjdCwmUaW6V0uhUinC\n"
                               "0f8Xiqzkv1TxFDR7TW8yIS+fytrIfhb/n01MH0bA9krZp8V0AEMEEFANi8J8szo0\n"
                               "Acmu0q5ktB8Rb9k=\n"
                               "-----END CERTIFICATE-----\n";

// The key of RSA_CERT, PKCS#8.
static const char RSA_PKCS8_KEY[] = "-----BEGIN PRIVATE KEY-----\n"
                                    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCZ31d2y4DPtKzA\n"
                                    "eBvNYTdJzV9d4z1HzVFB44O2swawcfVm5juiGljYDg4npWcNLr34AzrZO4juo4vf\n"
                                    "ki0MS5A+XfB4RIiEalDJhaa2+pnpNvN4hKgl2r5t/eyK2rBFiSjHQL5GqumdxMJE\n"
                                    "z+dQDG94OPVl0j6HM45q0T2t3fp61SwoxCUcGoEr8U3K23L23jY5u1yK4jChRIRF\n"
                                    "GbohGBL2wGjEK60G7m0w0mgNBbhE4fJK0g7MD32dGyx6lffbKzUe+qKksy0wg17Q\n"
                                    "WREatGg6hWoTm6lfy8RYclj0sTs9VAub0Vwg+tIy75Osm9KEEhlRTCy4RzGR3eQ6\n"
                                    "BrYkUoMtAgMBAAECggEAIQF7H7CFzCf3gV6SKiMfCq3qtbczcyYrtqwwmd07g1gi\n"
                                    "eWTL6Fjp80hKiX8NhJKg7aT1t9ixJe0/aODQWGmSAorAdO/Qb8TlWODaErhdEN04\n"
                                    "awLblake/XWBCoTf2D6UWG8/EWYCcBTfTgbhmXZdZ8ah/uoS/wnUU/3XkubBXpzr\n"
                                    "ow1GdyL96vxqJPx9rfwEDQHJCD5EzRZ58voskw+Q9PAPqmpai4dWTJr3lCmuQJO6\n"
                                    "blt4HX1UbSzNcNIWD2aT1UH+gsH8cKYNIhs1zyvwMzplzt5snsh/RsA3eU/PXFN8\n"
                                    "i4C1THW9fBlcT55fC24Ej+aHTsmG0QeO92tJtqlH4QKBgQDOR0ijMyl/I4J2auJE\n"
                                    "owsG/YbBhGEXFtVHOM129F+D++P1y8AQx2/eZCy9jvux1yCl6ddJ9333N02AIlj3\n"
                                    "4JadNXVvU3QQ4kF1OWNJ6vRE8p749bsrKWo/0T+hN+aik89acTGlyrQe4+Uq+gMH\n"
                                    "K1kLG1dx6p58fNDeBNioopM0TQKBgQC+9kRTEb9jO351haYL7GvvMVGLyYQeC8LY\n"
                                    "4aomlsENrhk9Hhavmn2EtQzqrYJr5LrUMkoXFXQs86HpOsS8GVzqMM8P8qNTDatQ\n"
                                    "lyr0XVc/Q1GD0+o3uXs+XgYqfIjhWOhImfj2IVZW++TWbQwZ0KpzZRaAg7xyHJsi\n"
                                    "oDLtHZt6YQKBgCMRASslNmeznKkO0HpEkUpV7QOWwn6PViBuapdPQbGJL56ITZVM\n"
                                    "ohrXQrfSx7zaymUKFJwxY4uULiubKy6wUkpVXSpYsIFyRRhtchCNzYqvCBFgjLnw\n"
                                    "p2xD4SJCA4YdxIEmfv8lL2uU6E9fAwbD+rYlpr7p2JlnCobDoiVAxe99AoGBAI0/\n"
                                    "JLx45SJmEBynVXF+VzueNB38WS/MLTw0dqGCYptWyi5NwiPzVqJBNKOk4VIi5hos\n"
                                    "dGbspHjXYExd/sTO0c4behzmsO2ur6e1mL0VCYKurW2f4p+DH2i7LT5hzPE5zN5e\n"
                                    "nSqY7/745IPCNvAlSt59yA4Y4ttY01riOajvfGAhAoGBAKWx4bVigUoZeEhBzO+S\n"
                                    "Q7zgSwmyijQKhCOGSkbZ7j+KPKDqxOrh/I6OnRWIBXaW5ixWd6gyv1vDbBXs11sb\n"
                                    "23Sz4JVPMKyA89lALA3XKgxfp7iGZkYIS3/bRxwH7JjpLW4SZkWpacZ1MWoxkF9X\n"
                                    "HAEh7c0dkjfoCjHcN7M+RNfM\n"
                                    "-----END PRIVATE KEY-----\n";

// The same key, openssl pkey -traditional.
static const char RSA_TRAD_KEY[] = "-----BEGIN RSA PRIVATE KEY-----\n"
                                   "MIIEpAIBAAKCAQEAmd9XdsuAz7SswHgbzWE3Sc1fXeM9R81RQeODtrMGsHH1ZuY7\n"
                                   "ohpY2A4OJ6VnDS69+AM62TuI7qOL35ItDEuQPl3weESIhGpQyYWmtvqZ6TbzeISo\n"
                                   "Jdq+bf3sitqwRYkox0C+RqrpncTCRM/nUAxveDj1ZdI+hzOOatE9rd36etUsKMQl\n"
                                   "HBqBK/FNytty9t42ObtciuIwoUSERRm6IRgS9sBoxCutBu5tMNJoDQW4ROHyStIO\n"
                                   "zA99nRssepX32ys1HvqipLMtMINe0FkRGrRoOoVqE5upX8vEWHJY9LE7PVQLm9Fc\n"
                                   "IPrSMu+TrJvShBIZUUwsuEcxkd3kOga2JFKDLQIDAQABAoIBACEBex+whcwn94Fe\n"
                                   "kiojHwqt6rW3M3MmK7asMJndO4NYInlky+hY6fNISol/DYSSoO2k9bfYsSXtP2jg\n"
                                   "0FhpkgKKwHTv0G/E5Vjg2hK4XRDdOGsC25WpHv11gQqE39g+lFhvPxFmAnAU304G\n"
                                   "4Zl2XWfGof7qEv8J1FP915LmwV6c66MNRnci/er8aiT8fa38BA0ByQg+RM0WefL6\n"
                                   "LJMPkPTwD6pqWouHVkya95QprkCTum5beB19VG0szXDSFg9mk9VB/oLB/HCmDSIb\n"
                                   "Nc8r8DM6Zc7ebJ7If0bAN3lPz1xTfIuAtUx1vXwZXE+eXwtuBI/mh07JhtEHjvdr\n"
                                   "SbapR+ECgYEAzkdIozMpfyOCdmriRKMLBv2GwYRhFxbVRzjNdvRfg/vj9cvAEMdv\n"
                                   "3mQsvY77sdcgpenXSfd99zdNgCJY9+CWnTV1b1N0EOJBdTljSer0RPKe+PW7Kylq\n"
                                   "P9E/oTfmopPPWnExpcq0HuPlKvoDBytZCxtXceqefHzQ3gTYqKKTNE0CgYEAvvZE\n"
                                   "UxG/Yzt+dYWmC+xr7zFRi8mEHgvC2OGqJpbBDa4ZPR4Wr5p9hLUM6q2Ca+S61DJK\n"
                                   "FxV0LPOh6TrEvBlc6jDPD/KjUw2rUJcq9F1XP0NRg9PqN7l7Pl4GKnyI4VjoSJn4\n"
                                   "9iFWVvvk1m0MGdCqc2UWgIO8chybIqAy7R2bemECgYAjEQErJTZns5ypDtB6RJFK\n"
                                   "Ve0DlsJ+j1YgbmqXT0GxiS+eiE2VTKIa10K30se82splChScMWOLlC4rmysusFJK\n"
                                   "VV0qWLCBckUYbXIQjc2KrwgRYIy58KdsQ+EiQgOGHcSBJn7/JS9rlOhPXwMGw/q2\n"
                                   "Jaa+6diZZwqGw6IlQMXvfQKBgQCNPyS8eOUiZhAcp1Vxflc7njQd/FkvzC08NHah\n"
                                   "gmKbVsouTcIj81aiQTSjpOFSIuYaLHRm7KR412BMXf7EztHOG3oc5rDtrq+ntZi9\n"
                                   "FQmCrq1tn+Kfgx9ouy0+YczxOczeXp0qmO/++OSDwjbwJUrefcgOGOLbWNNa4jmo\n"
                                   "73xgIQKBgQClseG1YoFKGXhIQczvkkO84EsJsoo0CoQjhkpG2e4/ijyg6sTq4fyO\n"
                                   "jp0ViAV2luYsVneoMr9bw2wV7NdbG9t0s+CVTzCsgPPZQCwN1yoMX6e4hmZGCEt/\n"
                                   "20ccB+yY6S1uEmZFqWnGdTFqMZBfVxwBIe3NHZI36Aox3DezPkTXzA==\n"
                                   "-----END RSA PRIVATE KEY-----\n";

// openssl ecparam -name secp384r1 -genkey -noout
static const char P384_SEC1_KEY[] = "-----BEGIN EC PRIVATE KEY-----\n"
                                    "MIGkAgEBBDAQJflHN0XgL+oPfDvxwAUu3gg9S2R9iQ1UcHC+Tzp0DKmOReDw/l5Z\n"
                                    "8Dd8gGhAjSKgBwYFK4EEACKhZANiAASadKXEHnwGfGmRn3WLD+FqeiaJqzYqvdM1\n"
                                    "n1P9jU3571cMZUpnE1MV604oGJUHomBv0lXGwsZ+XKxtofiUawu1Lnc16JRkRAz2\n"
                                    "C3Jg9Ya/2HIx6ZYhSGFYsQp1ZbHl9z8=\n"
                                    "-----END EC PRIVATE KEY-----\n";

// The same key, openssl pkcs8 -topk8 -nocrypt.
static const char P384_PKCS8_KEY[] = "-----BEGIN PRIVATE KEY-----\n"
                                     "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAQJflHN0XgL+oPfDvx\n"
                                     "wAUu3gg9S2R9iQ1UcHC+Tzp0DKmOReDw/l5Z8Dd8gGhAjSKhZANiAASadKXEHnwG\n"
                                     "fGmRn3WLD+FqeiaJqzYqvdM1n1P9jU3571cMZUpnE1MV604oGJUHomBv0lXGwsZ+\n"
                                     "XKxtofiUawu1Lnc16JRkRAz2C3Jg9Ya/2HIx6ZYhSGFYsQp1ZbHl9z8=\n"
                                     "-----END PRIVATE KEY-----\n";

// SEC1_KEY's private scalar and public point, and EC_CERT's (PKCS#8 key), from Python's cryptography.
static const char *const SEC1_PRIV = "975c61ccc85b319ff6edef3c4dcdb8a917c7135f77b2f5d39044b571f5c4b13f";
static const char *const SEC1_PUB = "04aabce4841688b1b19ca86e3cc0210265e4ae7db583be5bf4e6f70bf271d3b954"
                                    "18c7b435492a3bc4b276f82afc6ec9be5ec6fd50430ae40524f75aef31a04376";
static const char *const EC_PRIV = "81c2fb78e8c2cc8064520a5f161795610bf31ca83be126429e5d609b6a781ddc";
static const char *const EC_PUB = "0423a52e3cf7e8452dd7279702531b076b09b27e1089ad2425db4adfeee0d2be17"
                                  "c2cc1d077d60f2121a0d038d97bbfca83588cfbc468a35a09a9b9e7fe509957d";
#define EC_NOT_AFTER    1795902920LL // 2026-11-28T21:55:20Z
#define MINE_NOT_BEFORE 1795000000LL
#define MINE_NOT_AFTER  (MINE_NOT_BEFORE + 13 * 86400)

static int nibble(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static void hex(const char *s, uint8_t *out, size_t n) {
	CHECK(strlen(s) == 2 * n, "vector length %zu != %zu", strlen(s), 2 * n);
	for (size_t i = 0; i < n; i++) {
		int hi = nibble(s[2 * i]), lo = nibble(s[2 * i + 1]);
		CHECK(hi >= 0 && lo >= 0, "bad hex in %s", s);
		out[i] = (uint8_t)(hi << 4 | lo);
	}
}

// A TLV of a DER buffer the test trusts: the offset of its content and the content length.
static size_t tlv(const uint8_t *p, size_t *len) {
	size_t n = p[1], h = 2;
	if (n & 0x80) {
		size_t nb = n & 0x7f;
		n = 0;
		for (size_t i = 0; i < nb; i++) n = n << 8 | p[2 + i];
		h += nb;
	}
	*len = n;
	return h;
}

typedef struct {
	const uint8_t *tbs, *sig; // tbs is the whole TLV, sig the BIT STRING's content after its 0 byte
	size_t tbs_len, sig_len;
} cert_parts;

static void split(const hw_der *d, cert_parts *c) {
	size_t n, m;
	size_t h = tlv(d->der, &n);
	CHECK(d->der[0] == 0x30 && h + n == d->len, "outer SEQUENCE");
	const uint8_t *p = d->der + h;
	c->tbs = p;
	c->tbs_len = tlv(p, &m) + m;
	p += c->tbs_len;
	CHECK(p[0] == 0x30, "signatureAlgorithm");
	p += tlv(p, &m) + m;
	CHECK(p[0] == 0x03, "signatureValue");
	size_t bh = tlv(p, &m);
	CHECK(p[bh] == 0, "unused bits");
	c->sig = p + bh + 1;
	c->sig_len = m - 1;
	CHECK(c->sig + c->sig_len == d->der + d->len, "signatureValue ends the certificate");
}

static int signature_ok(const hw_der *d, const uint8_t pub[HW_P256_PUB_LEN]) {
	cert_parts c;
	split(d, &c);
	uint8_t digest[HW_SHA256_LEN];
	hw_sha256(c.tbs, c.tbs_len, digest);
	return hw_p256_verify(pub, digest, c.sig, c.sig_len);
}

static int contains(const hw_der *d, const uint8_t *needle, size_t n) {
	for (size_t i = 0; i + n <= d->len; i++) {
		if (memcmp(d->der + i, needle, n) == 0) return 1;
	}
	return 0;
}

static void load_one(const char *pem, hw_der *out) {
	hw_der chain[HW_CERT_CHAIN_MAX];
	size_t n = 99;
	CHECK(hw_cert_load_chain(pem, strlen(pem), chain, HW_CERT_CHAIN_MAX, &n) == 0, "load chain");
	CHECK_EQ(n, 1);
	*out = chain[0];
}

static void test_selfsigned(void) {
	uint8_t priv[32], pub[65], got[65];
	CHECK(hw_p256_keygen(priv, pub) == 0, "keygen");
	const int64_t nb = 1795000000, na = nb + 13 * 86400;
	hw_der a, b;
	CHECK(hw_cert_selfsigned(priv, pub, "localhost", nb, na, &a) == 0, "selfsigned");
	CHECK(hw_cert_selfsigned(priv, pub, "localhost", nb, na, &b) == 0, "selfsigned");
	CHECK(hw_cert_p256_pubkey(a.der, a.len, got) == 0 && memcmp(got, pub, 65) == 0, "public key");
	int64_t t = 0;
	CHECK(hw_cert_not_after(a.der, a.len, &t) == 0 && t == na, "not after %lld", (long long)t);
	CHECK(signature_ok(&a, pub) == 1, "signature");
	CHECK(signature_ok(&b, pub) == 1, "signature");

	cert_parts c;
	split(&a, &c);
	// [0] { INTEGER 2 }, then a 16-byte positive serial.
	size_t m, h = tlv(c.tbs, &m);
	static const uint8_t v3_serial[] = {0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10};
	CHECK(memcmp(c.tbs + h, v3_serial, sizeof(v3_serial)) == 0, "version 3 and a 16-byte serial");
	const uint8_t *serial = c.tbs + h + sizeof(v3_serial);
	CHECK((serial[0] & 0xc0) == 0x40, "serial positive and 16 bytes");
	cert_parts c2;
	split(&b, &c2);
	CHECK(memcmp(serial, c2.tbs + h + sizeof(v3_serial), 16) != 0, "two certificates, one serial");

	static const uint8_t alg[] = {0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
	static const uint8_t utc[] = {0x17, 0x0d, '2', '6', '1', '1', '1', '8', '1', '1', '0', '6', '4', '0', 'Z'};
	static const uint8_t basic[] = {0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00};
	static const uint8_t usage[] = {0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
	                                0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80};
	static const uint8_t san[] = {0x30, 0x14, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x0d, 0x30, 0x0b,
	                              0x82, 0x09, 'l',  'o',  'c',  'a',  'l',  'h',  'o',  's',  't'};
	CHECK(contains(&a, alg, sizeof(alg)), "ecdsa-with-SHA256");
	CHECK(contains(&a, utc, sizeof(utc)), "UTCTime notBefore");
	CHECK(contains(&a, basic, sizeof(basic)), "basicConstraints critical, CA:FALSE");
	CHECK(contains(&a, usage, sizeof(usage)), "keyUsage critical, digitalSignature");
	CHECK(contains(&a, san, sizeof(san)), "subjectAltName dNSName");
	hw_der_free(&a);
	hw_der_free(&b);
	CHECK(a.der == NULL && a.len == 0, "hw_der_free clears");
	hw_der_free(NULL);
}

static void test_selfsigned_refusals(void) {
	uint8_t priv[32], pub[65], other_priv[32], other_pub[65];
	CHECK(hw_p256_keygen(priv, pub) == 0 && hw_p256_keygen(other_priv, other_pub) == 0, "keygen");
	hw_der d;
	CHECK(hw_cert_selfsigned(priv, other_pub, "a.test", 0, 1, &d) == -1, "mismatched key pair");
	CHECK(d.der == NULL, "nothing returned on failure");
	CHECK(hw_cert_selfsigned(priv, pub, "", 0, 1, &d) == -1, "empty CN");
	CHECK(hw_cert_selfsigned(priv, pub, "a test", 0, 1, &d) == -1, "CN with a space");
	CHECK(hw_cert_selfsigned(priv, pub, "a\ntest", 0, 1, &d) == -1, "CN with a newline");
	CHECK(hw_cert_selfsigned(priv, pub, "caf\xc3\xa9", 0, 1, &d) == -1, "CN not ASCII");
	char long_cn[300];
	memset(long_cn, 'a', sizeof(long_cn));
	long_cn[256] = 0;
	CHECK(hw_cert_selfsigned(priv, pub, long_cn, 0, 1, &d) == -1, "CN of 256 bytes");
	long_cn[255] = 0;
	CHECK(hw_cert_selfsigned(priv, pub, long_cn, 0, 1, &d) == 0, "CN of 255 bytes");
	hw_der_free(&d);
	CHECK(hw_cert_selfsigned(priv, pub, "a.test", 10, 9, &d) == -1, "notAfter before notBefore");
	CHECK(hw_cert_selfsigned(priv, pub, "a.test", -631152001LL, 0, &d) == -1, "before 1950");
	CHECK(hw_cert_selfsigned(priv, pub, "a.test", 0, 253402300800LL, &d) == -1, "after 9999");
	uint8_t zero[32] = {0};
	CHECK(hw_cert_selfsigned(zero, pub, "a.test", 0, 1, &d) == -1, "private key 0");
	CHECK(hw_cert_selfsigned(priv, pub, NULL, 0, 1, &d) == -1, "NULL CN");
}

// The edges of UTCTime and GeneralizedTime, through hw_cert_not_after.
static void test_selfsigned_times(void) {
	uint8_t priv[32], pub[65];
	hex(SEC1_PRIV, priv, 32);
	hex(SEC1_PUB, pub, 65);
	static const int64_t times[] = {
	    -631152000LL,  // 1950-01-01T00:00:00Z, the first UTCTime
	    0,             // 1970
	    951782400LL,   // 2000-02-29, a leap day of a century leap year
	    2524607999LL,  // 2049-12-31T23:59:59Z, the last UTCTime
	    2524608000LL,  // 2050-01-01, the first GeneralizedTime
	    4107542400LL,  // 2100-03-01, after the 28-day February of a century
	    253402300799LL // 9999-12-31T23:59:59Z
	};
	for (size_t i = 0; i < HW_ARRAY_LEN(times); i++) {
		hw_der d;
		CHECK(hw_cert_selfsigned(priv, pub, "t.test", times[0], times[i], &d) == 0, "time %zu", i);
		int64_t t = 0;
		CHECK(hw_cert_not_after(d.der, d.len, &t) == 0, "parse %zu", i);
		CHECK(t == times[i], "time %zu: %lld != %lld", i, (long long)t, (long long)times[i]);
		uint8_t tag = times[i] < 2524608000LL ? 0x17 : 0x18;
		uint8_t want[2] = {tag, (uint8_t)(tag == 0x17 ? 13 : 15)};
		CHECK(contains(&d, want, 2), "time %zu tag", i);
		hw_der_free(&d);
	}
}

// The certificate OpenSSL accepted is still what hw_cert_selfsigned makes from the same input:
// the TBSCertificate differs only in the serial, and the signature (over that) verifies.
static void test_selfsigned_pinned(void) {
	uint8_t priv[32], pub[65], got[65];
	hex(SEC1_PRIV, priv, 32);
	hex(SEC1_PUB, pub, 65);
	hw_der pinned, fresh;
	load_one(MINE_CERT, &pinned);
	CHECK(hw_cert_p256_pubkey(pinned.der, pinned.len, got) == 0 && memcmp(got, pub, 65) == 0, "pinned key");
	int64_t t = 0;
	CHECK(hw_cert_not_after(pinned.der, pinned.len, &t) == 0 && t == MINE_NOT_AFTER, "pinned not after");
	CHECK(signature_ok(&pinned, pub) == 1, "pinned signature");
	CHECK(hw_cert_selfsigned(priv, pub, "localhost", MINE_NOT_BEFORE, MINE_NOT_AFTER, &fresh) == 0, "fresh");
	cert_parts a, b;
	split(&pinned, &a);
	split(&fresh, &b);
	CHECK_EQ(a.tbs_len, b.tbs_len);
	size_t m, h = tlv(a.tbs, &m);
	size_t serial = h + 7; // after [0] { 2 } and the serial's tag and length
	CHECK(memcmp(a.tbs, b.tbs, serial) == 0, "TBSCertificate before the serial");
	CHECK(memcmp(a.tbs + serial + 16, b.tbs + serial + 16, a.tbs_len - serial - 16) == 0,
	      "TBSCertificate after the serial");
	hw_der_free(&pinned);
	hw_der_free(&fresh);
}

static void test_openssl_fixtures(void) {
	uint8_t pub[65], want[65], priv[32], want_priv[32];
	hw_der d;
	load_one(EC_CERT, &d);
	hex(EC_PUB, want, 65);
	CHECK(hw_cert_p256_pubkey(d.der, d.len, pub) == 0 && memcmp(pub, want, 65) == 0, "openssl certificate key");
	int64_t t = 0;
	CHECK(hw_cert_not_after(d.der, d.len, &t) == 0 && t == EC_NOT_AFTER, "openssl not after %lld", (long long)t);
	CHECK(signature_ok(&d, pub) == 1, "openssl signature");
	hw_der_free(&d);

	CHECK(hw_cert_load_p256_key(EC_PKCS8_KEY, strlen(EC_PKCS8_KEY), priv) == 0, "PKCS#8 key");
	hex(EC_PRIV, want_priv, 32);
	CHECK(memcmp(priv, want_priv, 32) == 0, "PKCS#8 scalar");
	CHECK(hw_p256_public(priv, pub) == 0 && memcmp(pub, want, 65) == 0, "PKCS#8 key matches its certificate");

	CHECK(hw_cert_load_p256_key(SEC1_KEY, strlen(SEC1_KEY), priv) == 0, "SEC 1 key");
	hex(SEC1_PRIV, want_priv, 32);
	CHECK(memcmp(priv, want_priv, 32) == 0, "SEC 1 scalar");

	// A chain of two, and a key file in the middle of it, which is skipped.
	char chain[4096];
	snprintf(chain, sizeof(chain), "%s%s%s", EC_CERT, EC_PKCS8_KEY, MINE_CERT);
	hw_der certs[HW_CERT_CHAIN_MAX];
	size_t n = 0;
	CHECK(hw_cert_load_chain(chain, strlen(chain), certs, HW_CERT_CHAIN_MAX, &n) == 0 && n == 2, "chain of 2");
	CHECK(hw_cert_p256_pubkey(certs[0].der, certs[0].len, pub) == 0 && memcmp(pub, want, 65) == 0, "leaf first");
	for (size_t i = 0; i < n; i++) hw_der_free(&certs[i]);
	CHECK(hw_cert_load_chain(chain, strlen(chain), certs, 1, &n) == -1 && n == 0, "chain over max");
	CHECK(hw_cert_load_p256_key(chain, strlen(chain), priv) == 0, "key out of a combined file");
}

// The key pin is SHA-256 over the SubjectPublicKeyInfo as encoded, which is what openssl hashes in
// `openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256` (the
// vectors below), for any key type. A self-signed certificate's is the 91 bytes of its P-256 key,
// and two certificates for one key have one pin.
static void test_spki(void) {
	static const char *const ec_pin = "12dc539043981bfe5eacd6c9092f360e528186f79c4f2526edeca9050b6f7ad6";
	static const char *const rsa_pin = "5e1356e77d9334657b5ea899c294111f1e13db640c01afd6c1d155a60b3c4402";
	uint8_t want[32], got[32];
	const uint8_t *spki = NULL;
	size_t spki_len = 0;
	hw_der d;
	load_one(EC_CERT, &d);
	CHECK_EQ(hw_cert_spki(d.der, d.len, &spki, &spki_len), 0);
	CHECK(spki > d.der && spki + spki_len <= d.der + d.len, "points into the certificate");
	hw_sha256(spki, spki_len, got);
	hex(ec_pin, want, 32);
	CHECK(memcmp(got, want, 32) == 0, "openssl's pin of the P-256 fixture");
	for (size_t cut = 0; cut < d.len; cut += 7) {
		CHECK_EQ(hw_cert_spki(d.der, cut, &spki, &spki_len), -1);
	}
	hw_der_free(&d);
	load_one(RSA_CERT, &d);
	CHECK_EQ(hw_cert_spki(d.der, d.len, &spki, &spki_len), 0);
	hw_sha256(spki, spki_len, got);
	hex(rsa_pin, want, 32);
	CHECK(memcmp(got, want, 32) == 0, "openssl's pin of the RSA fixture");
	hw_der_free(&d);

	uint8_t priv[32], pub[65];
	CHECK_EQ(hw_p256_keygen(priv, pub), 0);
	hw_der a, b;
	CHECK_EQ(hw_cert_selfsigned(priv, pub, "a.example", 1700000000, 1700086400, &a), 0);
	CHECK_EQ(hw_cert_selfsigned(priv, pub, "b.example", 1700000000, 1700172800, &b), 0);
	const uint8_t *sa, *sb;
	size_t la, lb;
	CHECK(hw_cert_spki(a.der, a.len, &sa, &la) == 0 && hw_cert_spki(b.der, b.len, &sb, &lb) == 0, "parse");
	CHECK(la == 91 && memcmp(sa + 26, pub, 65) == 0, "a P-256 SubjectPublicKeyInfo of %zu bytes", la);
	CHECK(la == lb && memcmp(sa, sb, la) == 0, "one key, one pin");
	CHECK(a.len != b.len || memcmp(a.der, b.der, a.len) != 0, "two certificates");
	hw_der_free(&a);
	hw_der_free(&b);
	CHECK_EQ(hw_cert_spki(NULL, 0, &spki, &spki_len), -1);
}

static void test_refusals(void) {
	uint8_t pub[65], priv[32];
	hw_der d;
	load_one(RSA_CERT, &d);
	CHECK(hw_cert_p256_pubkey(d.der, d.len, pub) == -1, "RSA certificate key accepted");
	hw_der_free(&d);
	CHECK(hw_cert_load_p256_key(RSA_PKCS8_KEY, strlen(RSA_PKCS8_KEY), priv) == -1, "RSA PKCS#8 key");
	CHECK(hw_cert_load_p256_key(RSA_TRAD_KEY, strlen(RSA_TRAD_KEY), priv) == -1, "RSA PRIVATE KEY");
	CHECK(hw_cert_load_p256_key(P384_SEC1_KEY, strlen(P384_SEC1_KEY), priv) == -1, "P-384 SEC 1 key");
	CHECK(hw_cert_load_p256_key(P384_PKCS8_KEY, strlen(P384_PKCS8_KEY), priv) == -1, "P-384 PKCS#8 key");
	CHECK(hw_cert_load_p256_key(EC_CERT, strlen(EC_CERT), priv) == -1, "a certificate is not a key");

	hw_der certs[HW_CERT_CHAIN_MAX];
	size_t n = 7;
	CHECK(hw_cert_load_chain(SEC1_KEY, strlen(SEC1_KEY), certs, HW_CERT_CHAIN_MAX, &n) == -1 && n == 0, "no cert");
	CHECK(hw_cert_load_chain("", 0, certs, HW_CERT_CHAIN_MAX, &n) == -1, "empty");
	static const char *const bad[] = {
	    "-----BEGIN CERTIFICATE-----\nMIIB*mzCC\n-----END CERTIFICATE-----\n", // not the alphabet
	    "-----BEGIN CERTIFICATE-----\nMIIBmzC\n-----END CERTIFICATE-----\n",   // not a whole quantum
	    "-----BEGIN CERTIFICATE-----\nMA==MA==\n-----END CERTIFICATE-----\n",  // data after padding
	    "-----BEGIN CERTIFICATE-----\nMB==\n-----END CERTIFICATE-----\n",      // unused bits set
	    "-----BEGIN CERTIFICATE-----\nMAAA\n-----END CERTIFICATE-----\n",      // 30 00 00: a byte after it
	    "-----BEGIN CERTIFICATE-----\nMAA\n",                                  // no END
	    "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",            // empty
	    "-----BEGIN CERTIFICATE-----\n=MAA\n-----END CERTIFICATE-----\n",      // padding first
	    "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n",      // 30: no length
	    "-----BEGIN CERTIFICATE-----\nMIAA\n-----END CERTIFICATE-----\n",      // 30 80 00: indefinite
	    "-----BEGIN CERTIFICATE-----\nMIEA\n-----END CERTIFICATE-----\n",      // 30 81 00: not minimal
	};
	for (size_t i = 0; i < HW_ARRAY_LEN(bad); i++) {
		CHECK(hw_cert_load_chain(bad[i], strlen(bad[i]), certs, HW_CERT_CHAIN_MAX, &n) == -1, "bad PEM %zu", i);
	}
	// Whitespace of every kind anywhere in the Base64, even inside the padding.
	static const char spaced[] = "-----BEGIN CERTIFICATE-----\r\n M\tA A\r\n=\r\n-----END CERTIFICATE-----\r\n";
	CHECK(hw_cert_load_chain(spaced, strlen(spaced), certs, HW_CERT_CHAIN_MAX, &n) == 0 && n == 1, "whitespace");
	CHECK(certs[0].len == 2 && certs[0].der[0] == 0x30 && certs[0].der[1] == 0, "MAA= is 30 00");
	hw_der_free(&certs[0]);
}

// Runs every reader over a heap copy of exactly len bytes, so that ASan sees any read past it.
static void read_all(const char *text, size_t len) {
	char *p = malloc(len ? len : 1);
	CHECK(p != NULL, "malloc");
	memcpy(p, text, len);
	hw_der certs[HW_CERT_CHAIN_MAX];
	size_t n = 0;
	if (hw_cert_load_chain(p, len, certs, HW_CERT_CHAIN_MAX, &n) == 0) {
		for (size_t i = 0; i < n; i++) {
			uint8_t pub[65];
			int64_t t;
			(void)hw_cert_p256_pubkey(certs[i].der, certs[i].len, pub);
			(void)hw_cert_not_after(certs[i].der, certs[i].len, &t);
			hw_der_free(&certs[i]);
		}
	}
	uint8_t priv[32];
	(void)hw_cert_load_p256_key(p, len, priv);
	free(p);
}

static void read_der(const uint8_t *der, size_t len) {
	uint8_t *p = malloc(len ? len : 1);
	CHECK(p != NULL, "malloc");
	memcpy(p, der, len);
	uint8_t pub[65];
	int64_t t;
	(void)hw_cert_p256_pubkey(p, len, pub);
	(void)hw_cert_not_after(p, len, &t);
	free(p);
}

static void test_truncated_and_corrupted(void) {
	static const char *const pems[] = {MINE_CERT,     EC_CERT,      EC_PKCS8_KEY,  SEC1_KEY,      RSA_CERT,
	                                   RSA_PKCS8_KEY, RSA_TRAD_KEY, P384_SEC1_KEY, P384_PKCS8_KEY};
	for (size_t i = 0; i < HW_ARRAY_LEN(pems); i++) {
		size_t len = strlen(pems[i]);
		for (size_t l = 0; l <= len; l++) read_all(pems[i], l);
		CHECK(len > 0, "fixture %zu", i);
	}
	// The DER of each certificate: every truncation, every byte inverted, every length byte off
	// by one. A truncated certificate never parses.
	static const char *const certs[] = {MINE_CERT, EC_CERT, RSA_CERT};
	for (size_t i = 0; i < HW_ARRAY_LEN(certs); i++) {
		hw_der d;
		load_one(certs[i], &d);
		for (size_t l = 0; l < d.len; l++) {
			uint8_t pub[65];
			int64_t t;
			read_der(d.der, l);
			CHECK(hw_cert_p256_pubkey(d.der, l, pub) == -1 && hw_cert_not_after(d.der, l, &t) == -1,
			      "certificate %zu truncated to %zu parsed", i, l);
		}
		uint8_t *c = malloc(d.len);
		CHECK(c != NULL, "malloc");
		for (size_t b = 0; b < d.len; b++) {
			static const uint8_t flips[] = {0xff, 0x01, 0x80};
			for (size_t f = 0; f < sizeof(flips); f++) {
				memcpy(c, d.der, d.len);
				c[b] ^= flips[f];
				read_der(c, d.len);
			}
			memcpy(c, d.der, d.len);
			c[b]++;
			read_der(c, d.len);
		}
		free(c);
		hw_der_free(&d);
	}
	// Key PEM with each Base64 character replaced: either refused or a valid P-256 key.
	static const char *const keys[] = {EC_PKCS8_KEY, SEC1_KEY};
	for (size_t i = 0; i < HW_ARRAY_LEN(keys); i++) {
		size_t len = strlen(keys[i]);
		char *k = malloc(len);
		CHECK(k != NULL, "malloc");
		for (size_t b = 0; b < len; b++) {
			memcpy(k, keys[i], len);
			k[b] = k[b] == 'A' ? 'B' : 'A';
			read_all(k, len);
		}
		free(k);
	}
}

int main(void) {
	RUN(test_selfsigned);
	RUN(test_selfsigned_refusals);
	RUN(test_selfsigned_times);
	RUN(test_selfsigned_pinned);
	RUN(test_openssl_fixtures);
	RUN(test_spki);
	RUN(test_refusals);
	RUN(test_truncated_and_corrupted);
	return 0;
}
