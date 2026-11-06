#include "holywisp/dns.h"
#include "holywisp/hw.h"

#include "test.h"

#include <netdb.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

// Build a minimal DNS response: one A answer and one AAAA answer for the queried name, using a
// compression pointer back to the question name at offset 12.
static size_t build_response(uint8_t *out, uint16_t id, const uint8_t *query, size_t qlen) {
	memcpy(out, query, qlen);
	out[2] = 0x81; // QR + RD
	out[3] = 0x80; // RA, rcode 0
	out[6] = 0;
	out[7] = 2; // ANCOUNT = 2
	size_t o = qlen;
	// A record: name pointer, type 1, class 1, ttl 300, rdlen 4.
	uint8_t a[] = {0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 93, 184, 216, 34};
	memcpy(out + o, a, sizeof(a));
	o += sizeof(a);
	// AAAA record.
	uint8_t aaaa[] = {0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16, 0x20, 0x01, 0x0d, 0xb8,
	                  0,    0,    0, 0,  0, 0, 0, 0, 0, 0,  0, 0,  0,    0,    0,    1};
	memcpy(out + o, aaaa, sizeof(aaaa));
	o += sizeof(aaaa);
	(void)id;
	return o;
}

static void test_query_roundtrip(void) {
	uint8_t q[256];
	size_t qlen = hw_dns_build_query(q, sizeof(q), 0x1234, "example.com", 1);
	CHECK(qlen > 12, "query built");
	CHECK_EQ((q[0] << 8 | q[1]), 0x1234);
	CHECK_EQ(q[5], 1); // QDCOUNT
	// The name encodes as 7"example"3"com"0.
	CHECK_EQ(q[12], 7);
	CHECK(memcmp(q + 13, "example", 7) == 0, "label");

	uint8_t resp[512];
	size_t rlen = build_response(resp, 0x1234, q, qlen);
	hw_dns_result res;
	memset(&res, 0, sizeof(res));
	int rcode = -1;
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 0x1234, &res, &rcode), HW_OK);
	CHECK_EQ(rcode, 0);
	CHECK_EQ(res.count, 2);
	CHECK_EQ(res.ttl_s, 60); // smallest TTL (AAAA 60 < A 300)
	// Wrong id is rejected.
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 0x9999, &res, &rcode), HW_ERR_INVALID);
}

static void test_order(void) {
	hw_dns_result res;
	memset(&res, 0, sizeof(res));
	// Two v6 then one v4.
	struct sockaddr_in6 *a = (struct sockaddr_in6 *)&res.addrs[0];
	a->sin6_family = AF_INET6;
	res.lens[0] = sizeof(*a);
	struct sockaddr_in6 *b = (struct sockaddr_in6 *)&res.addrs[1];
	b->sin6_family = AF_INET6;
	res.lens[1] = sizeof(*b);
	struct sockaddr_in *c = (struct sockaddr_in *)&res.addrs[2];
	c->sin_family = AF_INET;
	res.lens[2] = sizeof(*c);
	res.count = 3;
	hw_dns_order(&res, HW_DNS_IPV4_FIRST);
	CHECK_EQ(res.addrs[0].ss_family, AF_INET);
	hw_dns_order(&res, HW_DNS_IPV6_FIRST);
	CHECK_EQ(res.addrs[0].ss_family, AF_INET6);
	CHECK_EQ(res.addrs[2].ss_family, AF_INET);
}

static void test_cache(void) {
	hw_dns_cache *c = hw_dns_cache_new(60, 5, 4);
	hw_dns_result res;
	memset(&res, 0, sizeof(res));
	res.count = 1;
	res.lens[0] = sizeof(struct sockaddr_in);
	((struct sockaddr_in *)&res.addrs[0])->sin_family = AF_INET;
	hw_dns_cache_put(c, "Example.com", &res, 0);
	hw_dns_result got;
	int err = -1;
	CHECK(hw_dns_cache_get(c, "example.com.", &got, &err), "case/dot-insensitive hit");
	CHECK_EQ(err, 0);
	CHECK_EQ(got.count, 1);
	CHECK(!hw_dns_cache_get(c, "other.com", &got, &err), "miss");
	// Negative caching.
	hw_dns_cache_put(c, "nope.invalid", NULL, EAI_NONAME);
	CHECK(hw_dns_cache_get(c, "nope.invalid", &got, &err), "negative hit");
	CHECK_EQ(err, EAI_NONAME);
	CHECK_EQ(hw_dns_cache_count(c), 2);
	hw_dns_cache_free(c);
}

int main(void) {
	RUN(test_query_roundtrip);
	RUN(test_order);
	RUN(test_cache);
	return 0;
}
