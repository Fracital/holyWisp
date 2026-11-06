#include "holywisp/filter.h"
#include "holywisp/net.h"

#include "test.h"

#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

static int match(const hw_hostlist *l, const char *h) {
	return hw_hostlist_match(l, h, strlen(h));
}

static void test_hostlist(void) {
	hw_hostlist l;
	memset(&l, 0, sizeof(l));
	CHECK_EQ(hw_hostlist_add(&l, "Example.COM"), 0); // normalized to lower
	CHECK_EQ(hw_hostlist_add(&l, "*.example.org"), 0);
	CHECK_EQ(hw_hostlist_add(&l, ".cdn.net"), 0);
	CHECK(match(&l, "example.com"), "exact");
	CHECK(match(&l, "EXAMPLE.COM"), "case insensitive");
	CHECK(match(&l, "example.com."), "trailing dot");
	CHECK(!match(&l, "evil.com"), "miss");
	CHECK(!match(&l, "notexample.com"), "no false suffix");
	CHECK(match(&l, "a.example.org"), "wildcard subdomain");
	CHECK(match(&l, "a.b.example.org"), "wildcard deep");
	CHECK(!match(&l, "example.org"), "wildcard excludes apex");
	CHECK(match(&l, "x.cdn.net"), "dot-prefix suffix");
	CHECK(!match(&l, "cdn.net"), "dot-prefix excludes apex");
	hw_hostlist empty;
	memset(&empty, 0, sizeof(empty));
	CHECK(!match(&empty, "anything"), "empty list matches nothing");
}

static void test_portset(void) {
	hw_portset s;
	memset(&s, 0, sizeof(s));
	CHECK_EQ(hw_portset_add(&s, "443"), 0);
	CHECK_EQ(hw_portset_add(&s, "8000-8002"), 0);
	CHECK_EQ(hw_portset_add(&s, "9000-8999"), 0); // reversed range tolerated
	CHECK(hw_portset_has(&s, 443), "single");
	CHECK(hw_portset_has(&s, 8000) && hw_portset_has(&s, 8001) && hw_portset_has(&s, 8002), "range");
	CHECK(!hw_portset_has(&s, 8003), "outside range");
	CHECK(hw_portset_has(&s, 8999) && hw_portset_has(&s, 9000), "reversed range");
	CHECK_EQ(hw_portset_add(&s, "0"), -1);
	CHECK_EQ(hw_portset_add(&s, "70000"), -1);
	CHECK_EQ(hw_portset_add(&s, "abc"), -1);
}

static int contains(const char *cidr, const char *ip) {
	hw_cidr c;
	CHECK_EQ(hw_cidr_parse(cidr, &c), 0);
	struct sockaddr_storage ss;
	socklen_t sl;
	CHECK_EQ(hw_addr_parse(ip, 0, &ss, &sl), 1);
	return hw_cidr_contains(&c, (struct sockaddr *)&ss);
}

static void test_cidr(void) {
	CHECK(contains("10.0.0.0/8", "10.1.2.3"), "v4 /8");
	CHECK(!contains("10.0.0.0/8", "11.0.0.1"), "v4 /8 miss");
	CHECK(contains("192.168.1.0/24", "192.168.1.255"), "v4 /24");
	CHECK(!contains("192.168.1.0/24", "192.168.2.0"), "v4 /24 miss");
	CHECK(contains("127.0.0.1", "127.0.0.1"), "v4 host");
	CHECK(!contains("127.0.0.1", "127.0.0.2"), "v4 host miss");
	CHECK(contains("2001:db8::/32", "2001:db8:1234::1"), "v6 /32");
	CHECK(!contains("2001:db8::/32", "2001:db9::1"), "v6 /32 miss");
	CHECK(contains("::1", "::1"), "v6 loopback");
	// An IPv4-mapped IPv6 peer matches an IPv4 CIDR.
	CHECK(contains("10.0.0.0/8", "::ffff:10.1.2.3"), "mapped v4 in v4 cidr");
	hw_cidr bad;
	CHECK_EQ(hw_cidr_parse("not-an-ip", &bad), -1);
	CHECK_EQ(hw_cidr_parse("10.0.0.0/40", &bad), -1);
}

static void test_real_ip(void) {
	struct sockaddr_storage peer;
	socklen_t sl;
	hw_cidr trusted[2];
	hw_cidr_parse("127.0.0.1", &trusted[0]);
	hw_cidr_parse("10.0.0.0/8", &trusted[1]);
	char out[HW_IP_STR_LEN];

	// Untrusted peer: headers ignored.
	hw_addr_parse("203.0.113.9", 0, &peer, &sl);
	const char *xff[] = {"1.2.3.4"};
	hw_real_ip((struct sockaddr *)&peer, trusted, 2, xff, 1, out);
	CHECK_STR(out, "203.0.113.9");

	// Trusted peer: right-most untrusted address in the list wins.
	hw_addr_parse("127.0.0.1", 0, &peer, &sl);
	const char *chain[] = {"9.9.9.9, 10.1.1.1, 10.2.2.2"};
	hw_real_ip((struct sockaddr *)&peer, trusted, 2, chain, 1, out);
	CHECK_STR(out, "9.9.9.9");

	// Trusted peer, single client address.
	const char *one[] = {"198.51.100.7"};
	hw_real_ip((struct sockaddr *)&peer, trusted, 2, one, 1, out);
	CHECK_STR(out, "198.51.100.7");

	// Trusted peer but no usable header: fall back to the peer.
	hw_real_ip((struct sockaddr *)&peer, trusted, 2, NULL, 0, out);
	CHECK_STR(out, "127.0.0.1");
}

int main(void) {
	RUN(test_hostlist);
	RUN(test_portset);
	RUN(test_cidr);
	RUN(test_real_ip);
	return 0;
}
