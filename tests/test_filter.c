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

#define NAME_MAX_LEN 600

// A name of `len` bytes made of labels of 'a' that ends in `tail`, and then `more` after it.
static void long_name(char out[NAME_MAX_LEN], size_t len, const char *tail, const char *more) {
	size_t pad = len - strlen(tail);
	for (size_t i = 0; i < pad; i++) out[i] = (i % 32) == 31 ? '.' : 'a';
	if (pad > 0 && out[pad - 1] == '.') out[pad - 1] = 'a';
	snprintf(out + pad, NAME_MAX_LEN - pad, "%s%s", tail, more);
}

// A host is compared whole. Cut at 127 bytes, a name whose first 127 bytes ended in an allowed
// suffix was allowed whatever came after them, and a long subdomain of a blocked one was not
// blocked.
static void test_hostlist_long_names(void) {
	static hw_hostlist allow, block;
	memset(&allow, 0, sizeof(allow));
	memset(&block, 0, sizeof(block));
	CHECK_EQ(hw_hostlist_add(&allow, "*.allowed.example"), 0);
	CHECK_EQ(hw_hostlist_add(&block, "*.blocked.example"), 0);
	char h[NAME_MAX_LEN];

	// 127 bytes that end in ".allowed.example", then the zone the name is really in.
	long_name(h, 127, ".allowed.example", "");
	CHECK_EQ(strlen(h), 127);
	CHECK_EQ(match(&allow, h), 1);
	long_name(h, 127, ".allowed.example", ".attacker.test");
	CHECK_EQ(strlen(h), 141);
	CHECK_EQ(match(&allow, h), 0);
	CHECK(!hw_hostlist_allows(&allow, h, strlen(h)), "a borrowed suffix is not allowed");
	// The same at every length a host can have.
	for (size_t len = 20; len <= 255 - strlen(".attacker.test"); len++) {
		long_name(h, len, ".allowed.example", "");
		CHECK(match(&allow, h) == 1, "length %zu not allowed", len);
		long_name(h, len, ".allowed.example", ".attacker.test");
		CHECK(match(&allow, h) == 0, "length %zu allowed with a foreign suffix", strlen(h));
	}
	// A blocked subdomain stays blocked however long it is.
	for (size_t len = 20; len <= 255; len++) {
		long_name(h, len, ".blocked.example", "");
		CHECK(match(&block, h) == 1, "length %zu not blocked", len);
		CHECK(hw_hostlist_blocks(&block, h, len), "length %zu not blocked", len);
	}
	// 255 bytes and a trailing dot is still that name.
	long_name(h, 255, ".blocked.example", ".");
	CHECK_EQ(match(&block, h), 1);

	// A name no CONNECT can carry cannot be compared: it is on no allow list and on every block
	// list, and the match itself says which of the two it was.
	long_name(h, 256, ".allowed.example", "");
	CHECK_EQ(match(&allow, h), -1);
	CHECK(!hw_hostlist_allows(&allow, h, strlen(h)), "too long to be allowed");
	long_name(h, 400, ".elsewhere.example", "");
	CHECK_EQ(match(&block, h), -1);
	CHECK(hw_hostlist_blocks(&block, h, strlen(h)), "too long not to be blocked");
	// An empty list has no opinion, on anything.
	static hw_hostlist empty;
	memset(&empty, 0, sizeof(empty));
	CHECK_EQ(match(&empty, h), 0);
	CHECK(!hw_hostlist_blocks(&empty, h, strlen(h)), "an empty block list blocks nothing");
	CHECK(!hw_hostlist_allows(&empty, "a.allowed.example", 17), "an empty allow list names nobody");

	// Patterns: one that fits is stored whole, one that does not is refused, never stored cut.
	char pattern[NAME_MAX_LEN];
	long_name(pattern, 255, ".example", "");
	pattern[0] = '*';
	pattern[1] = '.';
	CHECK_EQ(hw_hostlist_add(&block, pattern), 0); // stored as ".<253 bytes>"
	h[0] = 'x';
	memcpy(h + 1, pattern + 1, 255); // "x" and the stored pattern: 255 bytes and the NUL
	CHECK_EQ(strlen(h), 255);
	CHECK_EQ(match(&block, h), 1);
	long_name(pattern, 256, ".example", "");
	CHECK_EQ(hw_hostlist_add(&block, pattern), -1);
	char norm[8];
	CHECK_EQ(hw_hostname_normalize(norm, sizeof(norm), " Abc.De. ", 9), 0);
	CHECK_STR(norm, "abc.de");
	CHECK_EQ(hw_hostname_normalize(norm, sizeof(norm), "abcdefgh", 8), -1);
	CHECK_STR(norm, "abcdefg");
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

static hw_cidr g_trusted[2];

// hw_real_ip for a peer and one trusted header given as its instances (NULL-terminated).
static int real_ip(const char *peer_ip, const char *const *instances, char out[HW_IP_STR_LEN]) {
	struct sockaddr_storage peer;
	socklen_t sl;
	CHECK_EQ(hw_addr_parse(peer_ip, 0, &peer, &sl), 1);
	hw_real_ip_header h = {.values = instances, .count = 0};
	while (instances && instances[h.count]) h.count++;
	return hw_real_ip((struct sockaddr *)&peer, g_trusted, 2, &h, 1, out);
}

// The same for a header sent once.
static int real_ip1(const char *peer_ip, const char *value, char out[HW_IP_STR_LEN]) {
	const char *one[] = {value, NULL};
	return real_ip(peer_ip, one, out);
}

static void test_real_ip(void) {
	hw_cidr_parse("127.0.0.1", &g_trusted[0]);
	hw_cidr_parse("10.0.0.0/8", &g_trusted[1]);
	char out[HW_IP_STR_LEN];

	// Untrusted peer: headers ignored.
	CHECK_EQ(real_ip1("203.0.113.9", "1.2.3.4", out), 0);
	CHECK_STR(out, "203.0.113.9");

	// Trusted peer: right-most untrusted address in the list wins.
	CHECK_EQ(real_ip1("127.0.0.1", "9.9.9.9, 10.1.1.1, 10.2.2.2", out), 1);
	CHECK_STR(out, "9.9.9.9");
	// What the client put to the left of it is never read.
	CHECK_EQ(real_ip1("127.0.0.1", "6.6.6.6, 9.9.9.9", out), 1);
	CHECK_STR(out, "9.9.9.9");
	CHECK_EQ(real_ip1("127.0.0.1", "garbage, 6.6.6.6, 9.9.9.9, 10.1.1.1", out), 1);
	CHECK_STR(out, "9.9.9.9");

	// Trusted peer, single client address.
	CHECK_EQ(real_ip1("127.0.0.1", "198.51.100.7", out), 1);
	CHECK_STR(out, "198.51.100.7");

	// Trusted peer but no usable header: fall back to the peer.
	CHECK_EQ(real_ip("127.0.0.1", NULL, out), 0);
	CHECK_STR(out, "127.0.0.1");
	struct sockaddr_storage peer;
	socklen_t sl;
	hw_addr_parse("127.0.0.1", 0, &peer, &sl);
	CHECK_EQ(hw_real_ip((struct sockaddr *)&peer, g_trusted, 2, NULL, 0, out), 0);
	CHECK_STR(out, "127.0.0.1");
	// Only proxies in the list: nobody in it is the client.
	CHECK_EQ(real_ip1("127.0.0.1", "10.1.1.1, 10.2.2.2", out), 0);
	CHECK_STR(out, "127.0.0.1");
	// No trusted proxies configured at all.
	const char *xff[] = {"1.2.3.4"};
	hw_real_ip_header h = {.values = xff, .count = 1};
	CHECK_EQ(hw_real_ip((struct sockaddr *)&peer, g_trusted, 0, &h, 1, out), 0);
	CHECK_STR(out, "127.0.0.1");
}

// An entry the proxy appended with a port is still its address.
static void test_real_ip_ports(void) {
	char out[HW_IP_STR_LEN];
	CHECK_EQ(real_ip1("127.0.0.1", "6.6.6.6, 9.9.9.9:4711", out), 1);
	CHECK_STR(out, "9.9.9.9");
	CHECK_EQ(real_ip1("127.0.0.1", "6.6.6.6, [2001:4860::1]:443", out), 1);
	CHECK_STR(out, "2001:4860::1");
	CHECK_EQ(real_ip1("127.0.0.1", "6.6.6.6, [2001:4860::1]", out), 1);
	CHECK_STR(out, "2001:4860::1");
	CHECK_EQ(real_ip1("127.0.0.1", "6.6.6.6, 2001:4860::1", out), 1);
	CHECK_STR(out, "2001:4860::1");
	// A trusted proxy with a port is skipped like one without.
	CHECK_EQ(real_ip1("127.0.0.1", "9.9.9.9, 10.1.1.1:8080, [::ffff:10.2.2.2]:80", out), 1);
	CHECK_STR(out, "9.9.9.9");
	// IPv4-mapped is the IPv4 it wraps, in the answer and against the trusted list.
	CHECK_EQ(real_ip1("::ffff:127.0.0.1", "6.6.6.6, ::ffff:9.9.9.9, ::ffff:10.2.3.4", out), 1);
	CHECK_STR(out, "9.9.9.9");
	// Not ports.
	CHECK_EQ(real_ip1("127.0.0.1", "6.6.6.6, 9.9.9.9:", out), -1);
	CHECK_EQ(real_ip1("127.0.0.1", "6.6.6.6, 9.9.9.9:99999", out), -1);
	CHECK_EQ(real_ip1("127.0.0.1", "6.6.6.6, 9.9.9.9:80x", out), -1);
	CHECK_EQ(real_ip1("127.0.0.1", "6.6.6.6, [9.9.9.9]:80", out), -1);
	CHECK_EQ(real_ip1("127.0.0.1", "6.6.6.6, [2001:4860::1]x", out), -1);
	CHECK_EQ(real_ip1("127.0.0.1", "6.6.6.6, [2001:4860::1", out), -1);
	CHECK_STR(out, "127.0.0.1");
}

// Whatever cannot be read as an address ends the walk, and the answer is the peer: never the
// address to its left, which is the one the client supplied.
static void test_real_ip_stops(void) {
	char out[HW_IP_STR_LEN];
	static const char *const stops[] = {
	    "6.6.6.6, unknown",
	    "6.6.6.6, 10.1.1.1, unknown, 10.2.2.2",
	    "6.6.6.6, _hidden",
	    "6.6.6.6, proxy.example",
	    "6.6.6.6,",
	    "6.6.6.6, , 10.1.1.1",
	    "6.6.6.6, 9.9.9.9 8.8.8.8",
	    "6.6.6.6, 0x09090909",
	    "6.6.6.6, 9.9.9",
	    "6.6.6.6, fe80::1%eth0",
	    "6.6.6.6, for=9.9.9.9",
	    "",
	};
	for (size_t i = 0; i < sizeof(stops) / sizeof(stops[0]); i++) {
		CHECK(real_ip1("127.0.0.1", stops[i], out) == -1, "\"%s\" did not stop the walk", stops[i]);
		CHECK(strcmp(out, "127.0.0.1") == 0, "\"%s\" gave %s", stops[i], out);
	}
	// To the right of the client's address it changes nothing: the walk never gets there.
	CHECK_EQ(real_ip1("127.0.0.1", "unknown, 9.9.9.9, 10.1.1.1", out), 1);
	CHECK_STR(out, "9.9.9.9");
}

// A header sent more than once is one list, in the order it was sent. A proxy that adds its own
// line below the client's (HAProxy's forwardfor) is the last instance, not the first.
static void test_real_ip_instances(void) {
	char out[HW_IP_STR_LEN];
	const char *two[] = {"6.6.6.6", "203.0.113.9", NULL};
	CHECK_EQ(real_ip("127.0.0.1", two, out), 1);
	CHECK_STR(out, "203.0.113.9");
	const char *three[] = {"6.6.6.6, 7.7.7.7", "203.0.113.9, 10.1.1.1", "10.2.2.2", NULL};
	CHECK_EQ(real_ip("127.0.0.1", three, out), 1);
	CHECK_STR(out, "203.0.113.9");
	// The walk crosses from one instance into the one before it.
	const char *cross[] = {"6.6.6.6, 203.0.113.9", "10.1.1.1", "10.2.2.2", NULL};
	CHECK_EQ(real_ip("127.0.0.1", cross, out), 1);
	CHECK_STR(out, "203.0.113.9");
	const char *stop[] = {"6.6.6.6", "unknown", "10.1.1.1", NULL};
	CHECK_EQ(real_ip("127.0.0.1", stop, out), -1);
	CHECK_STR(out, "127.0.0.1");

	// Several trusted headers: the first one the request carries decides.
	struct sockaddr_storage peer;
	socklen_t sl;
	hw_addr_parse("10.9.9.9", 0, &peer, &sl);
	const char *cf[] = {"198.51.100.7"};
	const char *xff[] = {"6.6.6.6, 203.0.113.9"};
	hw_real_ip_header both[2] = {{.values = cf, .count = 1}, {.values = xff, .count = 1}};
	CHECK_EQ(hw_real_ip((struct sockaddr *)&peer, g_trusted, 2, both, 2, out), 1);
	CHECK_STR(out, "198.51.100.7");
	both[0].count = 0; // not in the request
	CHECK_EQ(hw_real_ip((struct sockaddr *)&peer, g_trusted, 2, both, 2, out), 1);
	CHECK_STR(out, "203.0.113.9");
	// One that names only proxies passes the question on; one that cannot be read ends it.
	const char *proxies[] = {"10.1.1.1"};
	const char *junk[] = {"unknown"};
	hw_real_ip_header pass[2] = {{.values = proxies, .count = 1}, {.values = xff, .count = 1}};
	CHECK_EQ(hw_real_ip((struct sockaddr *)&peer, g_trusted, 2, pass, 2, out), 1);
	CHECK_STR(out, "203.0.113.9");
	hw_real_ip_header end[2] = {{.values = junk, .count = 1}, {.values = xff, .count = 1}};
	CHECK_EQ(hw_real_ip((struct sockaddr *)&peer, g_trusted, 2, end, 2, out), -1);
	CHECK_STR(out, "10.9.9.9");
}

int main(void) {
	RUN(test_hostlist);
	RUN(test_hostlist_long_names);
	RUN(test_portset);
	RUN(test_cidr);
	RUN(test_real_ip);
	RUN(test_real_ip_ports);
	RUN(test_real_ip_stops);
	RUN(test_real_ip_instances);
	return 0;
}
