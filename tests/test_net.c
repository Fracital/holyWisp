#include "holywisp/hw.h"
#include "holywisp/net.h"

#include "test.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

static enum hw_addr_class classify(const char *ip) {
	struct sockaddr_storage ss;
	socklen_t sl;
	CHECK_EQ(hw_addr_parse(ip, 1, &ss, &sl), 1);
	return hw_addr_classify((struct sockaddr *)&ss);
}

static void test_parse_literals(void) {
	struct sockaddr_storage ss;
	socklen_t sl;
	CHECK_EQ(hw_addr_parse("192.168.1.2", 443, &ss, &sl), 1);
	CHECK_EQ(ss.ss_family, AF_INET);
	CHECK_EQ(hw_addr_port((struct sockaddr *)&ss), 443);
	CHECK_EQ(hw_addr_parse("::1", 53, &ss, &sl), 1);
	CHECK_EQ(ss.ss_family, AF_INET6);
	CHECK_EQ(hw_addr_parse("[2001:db8::1]", 53, &ss, &sl), 1);
	CHECK_EQ(ss.ss_family, AF_INET6);
	CHECK_EQ(hw_addr_parse("example.com", 80, &ss, &sl), 0);
	CHECK_EQ(hw_addr_parse("localhost", 80, &ss, &sl), 0);
	CHECK_EQ(hw_addr_parse("999.1.1.1", 80, &ss, &sl), -1);
	CHECK_EQ(hw_addr_parse("1.2.3", 80, &ss, &sl), -1);
	CHECK_EQ(hw_addr_parse("fe80::zz", 80, &ss, &sl), -1);
	char buf[HW_ADDR_STR_LEN];
	hw_addr_parse("10.0.0.1", 8080, &ss, &sl);
	CHECK_STR(hw_addr_str((struct sockaddr *)&ss, buf, sizeof(buf)), "10.0.0.1:8080");
	hw_addr_parse("::1", 8080, &ss, &sl);
	CHECK_STR(hw_addr_str((struct sockaddr *)&ss, buf, sizeof(buf)), "[::1]:8080");
}

// What a resolver would turn into an address by itself (inet_aton: one to four parts, decimal,
// octal or hexadecimal) is never handed to one as a name. Each of these reached getaddrinfo as a
// "hostname" and came back as the address in the comment, past allow-direct-ip = off.
static void test_parse_numeric_names(void) {
	struct sockaddr_storage ss;
	socklen_t sl;
	static const char *const numeric[] = {
	    "0x8.0x8.0x8.0x8", // 8.8.8.8
	    "0x08080808",      // 8.8.8.8
	    "0x7f.0.0.1",      // 127.0.0.1
	    "0x7f000001",      // 127.0.0.1
	    "0X7F.1",          // 127.0.0.1
	    "0xa9.0xfe.0xa9.0xfe",
	    "10.0x0.0.1",
	    "2130706433", // 127.0.0.1
	    "127.1",
	    "0177.0.0.1",
	    "127.000.000.001",
	    "127.0.0.1.",
	    "0x7f.1.",
	    "0",
	    "1.2.3.4.5",
	    "host.example.5", // no top-level label is a number
	    "example.0x10",
	    "0x7f.1 x", // classic inet_aton stops at the space
	    " 127.0.0.1",
	    "127.0.0.1 ",
	    "exam ple.com",
	    "example.com\t",
	    "exa\x7fmple.com",
	    "1.2.3.4:80",
	    "[127.0.0.1",
	    "[example.com]",
	};
	for (size_t i = 0; i < sizeof(numeric) / sizeof(numeric[0]); i++) {
		CHECK(hw_addr_parse(numeric[i], 80, &ss, &sl) == -1, "\"%s\" is not refused", numeric[i]);
	}
	// Names that only look a little like numbers are still names.
	static const char *const names[] = {
	    "example.com",           "example.com.",  "1.2.3.4x",  "0x8.example.com", "123.example", "4chan.org", "a.b0",
	    "xn--bcher-kva.example", "0xdeadbeef.io", "localhost", "x0x10",           "1e3",         "0x1g",
	};
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		CHECK(hw_addr_parse(names[i], 80, &ss, &sl) == 0, "\"%s\" is not a name", names[i]);
	}
	// And the canonical forms are still literals.
	CHECK_EQ(hw_addr_parse("8.8.8.8", 80, &ss, &sl), 1);
	CHECK_EQ(hw_addr_parse("0.0.0.0", 80, &ss, &sl), 1);
	CHECK_EQ(hw_addr_parse("::ffff:8.8.8.8", 80, &ss, &sl), 1);
}

static void test_classify_v4(void) {
	CHECK_EQ(classify("8.8.8.8"), HW_ADDR_PUBLIC);
	CHECK_EQ(classify("1.1.1.1"), HW_ADDR_PUBLIC);
	CHECK_EQ(classify("127.0.0.1"), HW_ADDR_LOOPBACK);
	CHECK_EQ(classify("127.255.255.254"), HW_ADDR_LOOPBACK);
	CHECK_EQ(classify("10.0.0.1"), HW_ADDR_PRIVATE);
	CHECK_EQ(classify("172.16.0.1"), HW_ADDR_PRIVATE);
	CHECK_EQ(classify("172.31.255.255"), HW_ADDR_PRIVATE);
	CHECK_EQ(classify("172.32.0.1"), HW_ADDR_PUBLIC);
	CHECK_EQ(classify("192.168.0.1"), HW_ADDR_PRIVATE);
	CHECK_EQ(classify("100.64.0.1"), HW_ADDR_PRIVATE);
	CHECK_EQ(classify("169.254.169.254"), HW_ADDR_LINK_LOCAL);
	CHECK_EQ(classify("0.0.0.0"), HW_ADDR_UNSPECIFIED);
	CHECK_EQ(classify("224.0.0.1"), HW_ADDR_MULTICAST);
	CHECK_EQ(classify("255.255.255.255"), HW_ADDR_MULTICAST);
	CHECK_EQ(classify("240.0.0.1"), HW_ADDR_RESERVED);
	CHECK_EQ(classify("192.0.2.1"), HW_ADDR_RESERVED);
	CHECK_EQ(classify("198.18.0.1"), HW_ADDR_RESERVED);
	CHECK_EQ(classify("192.88.99.1"), HW_ADDR_RESERVED); // 6to4 relay anycast
	CHECK_EQ(classify("192.88.98.1"), HW_ADDR_PUBLIC);
	CHECK_EQ(classify("192.88.100.1"), HW_ADDR_PUBLIC);
}

static void test_classify_v6(void) {
	CHECK_EQ(classify("2606:4700::1111"), HW_ADDR_PUBLIC);
	CHECK_EQ(classify("::1"), HW_ADDR_LOOPBACK);
	CHECK_EQ(classify("::"), HW_ADDR_UNSPECIFIED);
	CHECK_EQ(classify("fd00::1"), HW_ADDR_PRIVATE);
	CHECK_EQ(classify("fc00::1"), HW_ADDR_PRIVATE);
	CHECK_EQ(classify("fe80::1"), HW_ADDR_LINK_LOCAL);
	CHECK_EQ(classify("ff02::1"), HW_ADDR_MULTICAST);
	CHECK_EQ(classify("2001:db8::1"), HW_ADDR_RESERVED);
	// Wrapped IPv4 is classified as the IPv4 it wraps.
	CHECK_EQ(classify("::ffff:127.0.0.1"), HW_ADDR_LOOPBACK);
	CHECK_EQ(classify("::ffff:192.168.1.1"), HW_ADDR_PRIVATE);
	CHECK_EQ(classify("::ffff:8.8.8.8"), HW_ADDR_PUBLIC);
	CHECK_EQ(classify("64:ff9b::7f00:1"), HW_ADDR_LOOPBACK);
	CHECK_EQ(classify("2002:7f00:1::"), HW_ADDR_LOOPBACK);
	CHECK_EQ(classify("2002:0808:0808::"), HW_ADDR_RESERVED);
}

// Every way of writing an IPv4 address inside an IPv6 one is the IPv4 address to the policy.
static void test_classify_v6_wrapped(void) {
	// IPv4-translated, ::ffff:0:a.b.c.d (RFC 2765).
	CHECK_EQ(classify("::ffff:0:127.0.0.1"), HW_ADDR_LOOPBACK);
	CHECK_EQ(classify("::ffff:0:7f00:1"), HW_ADDR_LOOPBACK);
	CHECK_EQ(classify("::ffff:0:a9fe:a9fe"), HW_ADDR_LINK_LOCAL);
	CHECK_EQ(classify("::ffff:0:10.0.0.1"), HW_ADDR_PRIVATE);
	CHECK_EQ(classify("::ffff:0:8.8.8.8"), HW_ADDR_RESERVED);
	// An ISATAP interface id under a global, a link-local and a private prefix.
	CHECK_EQ(classify("2001:470:1:1:0:5efe:127.0.0.1"), HW_ADDR_LOOPBACK);
	CHECK_EQ(classify("2001:470:1:1:0:5efe:10.0.0.1"), HW_ADDR_PRIVATE);
	CHECK_EQ(classify("2001:470:1:1:200:5efe:169.254.169.254"), HW_ADDR_LINK_LOCAL);
	CHECK_EQ(classify("2001:470:1:1:200:5efe:192.168.1.1"), HW_ADDR_PRIVATE);
	CHECK_EQ(classify("2001:470:1:1:0:5efe:8.8.8.8"), HW_ADDR_RESERVED);
	CHECK_EQ(classify("fe80::5efe:127.0.0.1"), HW_ADDR_LOOPBACK);
	CHECK_EQ(classify("fe80::200:5efe:10.0.0.1"), HW_ADDR_PRIVATE);
	CHECK_EQ(classify("fd00::5efe:127.0.0.1"), HW_ADDR_LOOPBACK);
	// Not that interface id: the prefix decides.
	CHECK_EQ(classify("2001:470:1:1:100:5efe:127.0.0.1"), HW_ADDR_PUBLIC);
	CHECK_EQ(classify("2001:470:1:1:0:5eff:127.0.0.1"), HW_ADDR_PUBLIC);
	CHECK_EQ(classify("fe80::1:5efe:7f00:1"), HW_ADDR_LINK_LOCAL);
	// Local-use NAT64: where the IPv4 address sits depends on a prefix length we do not know.
	CHECK_EQ(classify("64:ff9b:1::127.0.0.1"), HW_ADDR_RESERVED);
	CHECK_EQ(classify("64:ff9b:1:7f00:1::"), HW_ADDR_RESERVED);
	CHECK_EQ(classify("64:ff9b:1::8.8.8.8"), HW_ADDR_RESERVED);
	// The forms that were already unwrapped still are.
	CHECK_EQ(classify("64:ff9b::a9fe:a9fe"), HW_ADDR_LINK_LOCAL);
	CHECK_EQ(classify("64:ff9b::8.8.8.8"), HW_ADDR_RESERVED);
	CHECK_EQ(classify("::127.0.0.1"), HW_ADDR_LOOPBACK);
	CHECK_EQ(classify("::10.0.0.1"), HW_ADDR_PRIVATE);
	CHECK_EQ(classify("2002:a9fe:a9fe::1"), HW_ADDR_LINK_LOCAL);
	CHECK_EQ(classify("2002:0a00:0001::1"), HW_ADDR_PRIVATE);
	CHECK_EQ(classify("::ffff:169.254.169.254"), HW_ADDR_LINK_LOCAL);
	CHECK_EQ(classify("::ffff:192.88.99.1"), HW_ADDR_RESERVED);
}

// IPv6 is public inside 2000::/3 only, and not everywhere in it.
static void test_classify_v6_reserved(void) {
	static const char *const reserved[] = {
	    "100::1",       // discard-only
	    "100::dead:1",  //
	    "2001::1",      // Teredo
	    "2001:2::1",    // benchmarking
	    "2001:10::1",   // ORCHID
	    "2001:1f::1",   //
	    "2001:20::1",   // ORCHIDv2
	    "2001:2f::1",   //
	    "2001:1ff::1",  // the end of 2001::/23
	    "3fff::1",      // documentation
	    "3fff:fff::1",  //
	    "5f00::1",      // SRv6 SIDs
	    "fec0::1",      // site-local
	    "1::",          // outside 2000::/3
	    "4000::1",      //
	    "8000::1",      //
	    "e000::1",      //
	    "::1:0:0:1",    //
	    "0:1::",        //
	    "1fff:ffff::1", //
	};
	for (size_t i = 0; i < sizeof(reserved) / sizeof(reserved[0]); i++) {
		CHECK(classify(reserved[i]) == HW_ADDR_RESERVED, "%s is %s", reserved[i],
		      hw_addr_class_str(classify(reserved[i])));
	}
	CHECK_EQ(classify("febf::1:2:3:4"), HW_ADDR_LINK_LOCAL);
	static const char *const pub[] = {
	    "2000::1",      "2001:200::1", "2001:4860:4860::8888", "2400:cb00::1", "2a00:1450:4001::1", "3ffe::1",
	    "3fff:1000::1", "2003::1",     "2001:db7::1",          "2001:db9::1",
	};
	for (size_t i = 0; i < sizeof(pub) / sizeof(pub[0]); i++) {
		CHECK(classify(pub[i]) == HW_ADDR_PUBLIC, "%s is %s", pub[i], hw_addr_class_str(classify(pub[i])));
	}
}

static void test_listen_and_connect(void) {
	uint16_t port = 0;
	int lfd = hw_listen_tcp("127.0.0.1", 0, 0, 16, &port);
	CHECK(lfd >= 0, "listen");
	CHECK(port != 0, "ephemeral port assigned");
	int cfd = hw_connect_tcp("127.0.0.1", port, 2000);
	CHECK(cfd >= 0, "connect");
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);
	int afd = hw_accept_nb(lfd, &ss, &sl);
	CHECK(afd >= 0, "accept");
	CHECK_EQ(hw_addr_classify((struct sockaddr *)&ss), HW_ADDR_LOOPBACK);
	close(afd);
	close(cfd);
	close(lfd);
	// Nothing listens here any more: connect must fail with ECONNREFUSED. At once on most systems;
	// Windows sends the SYN twice more first, which takes it two seconds, so the timeout is longer.
	CHECK(hw_connect_tcp("127.0.0.1", port, 10000) < 0, "refused");
	CHECK_EQ(errno, ECONNREFUSED);
}

#define HOLE_FILL 8

// A listener whose accept queue is full and never read. Linux drops the SYNs that reach it, so a
// connect to it hangs as one to an address without a route does; another system may refuse them,
// which the cases below allow. fill[] holds the connections that filled the queue. The backlog is
// 1, a queue of two on Linux and macOS, and not 0: macOS takes 0 for its maximum (somaxconn, 128),
// which the fill did not come near, and the "silent" address answered at once.
static int black_hole(struct sockaddr_in *addr, int fill[HOLE_FILL]) {
	uint16_t port = 0;
	int lfd = hw_listen_tcp("127.0.0.1", 0, 0, 1, &port);
	CHECK(lfd >= 0, "listen");
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);
	addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	for (int i = 0; i < HOLE_FILL; i++) {
		fill[i] = hw_socket_nb(AF_INET, SOCK_STREAM, 0);
		CHECK(fill[i] >= 0, "socket");
		// Non-blocking: in progress, done, or refused by a system that refuses past the queue.
		int rc = connect(fill[i], (struct sockaddr *)addr, sizeof(*addr));
		CHECK(rc == 0 || errno == EINPROGRESS || errno == ECONNREFUSED || errno == EWOULDBLOCK, "connect");
	}
	struct pollfd none;
	poll(&none, 0, 50); // the handshakes that will complete have completed
	return lfd;
}

static struct addrinfo ai_of(struct sockaddr_in *addr, struct addrinfo *next) {
	struct addrinfo ai;
	memset(&ai, 0, sizeof(ai));
	ai.ai_family = AF_INET;
	ai.ai_socktype = SOCK_STREAM;
	ai.ai_addr = (struct sockaddr *)addr;
	ai.ai_addrlen = sizeof(*addr);
	ai.ai_next = next;
	return ai;
}

static uint16_t peer_port(int fd) {
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);
	CHECK(getpeername(fd, (struct sockaddr *)&ss, &sl) == 0, "getpeername: %s", strerror(errno));
	return hw_addr_port((struct sockaddr *)&ss);
}

// An address that never answers costs the next one a stagger, not the whole timeout: with one
// timeout for each address in turn, a host whose IPv6 has no route waited it out on every name
// before its IPv4 was tried. The socket that wins is blocking, and the timeout bounds the list.
static void test_connect_moves_past_a_silent_address(void) {
	int fill[HOLE_FILL];
	struct sockaddr_in hole, good, refused;
	int hfd = black_hole(&hole, fill);
	uint16_t port = 0;
	int lfd = hw_listen_tcp("127.0.0.1", 0, 0, 16, &port);
	CHECK(lfd >= 0, "listen");
	good = hole;
	good.sin_port = htons(port);
	int rfd = hw_listen_tcp("127.0.0.1", 0, 0, 16, &port);
	CHECK(rfd >= 0, "listen");
	close(rfd); // nothing listens here: refused
	refused = good;
	refused.sin_port = htons(port);

	struct addrinfo second = ai_of(&good, NULL);
	struct addrinfo first = ai_of(&hole, &second);
	uint64_t t0 = hw_now_ms();
	int fd = hw_connect_tcp_list(&first, 5000);
	uint64_t took = hw_now_ms() - t0;
	CHECK(fd >= 0, "connect past a silent address: %s", strerror(errno));
	CHECK(took < 2000, "the second address connected after %llu ms of a 5000 ms timeout", (unsigned long long)took);
	CHECK_EQ(peer_port(fd), ntohs(good.sin_port));
	CHECK_EQ(fcntl(fd, F_GETFL, 0) & O_NONBLOCK, 0);
	close(fd);

	// A refused address hands over at once, or after a stagger where the refusal is slow (Windows).
	first = ai_of(&refused, &second);
	fd = hw_connect_tcp_list(&first, 5000);
	CHECK(fd >= 0, "connect past a refused address: %s", strerror(errno));
	CHECK_EQ(peer_port(fd), ntohs(good.sin_port));
	close(fd);

	// Silence alone: the timeout is the bound, and it says so.
	first = ai_of(&hole, NULL);
	t0 = hw_now_ms();
	fd = hw_connect_tcp_list(&first, 300);
	took = hw_now_ms() - t0;
	CHECK(fd < 0, "connected to a full accept queue");
	if (errno == ETIMEDOUT) {
		CHECK(took >= 250 && took < 1500, "a 300 ms connect took %llu ms", (unsigned long long)took);
	}
	first = ai_of(&hole, &second);
	second = ai_of(&hole, NULL);
	t0 = hw_now_ms();
	fd = hw_connect_tcp_list(&first, 400);
	took = hw_now_ms() - t0;
	CHECK(fd < 0, "connected to a full accept queue");
	if (errno == ETIMEDOUT) {
		CHECK(took >= 350 && took < 1500, "a 400 ms connect over two addresses took %llu ms", (unsigned long long)took);
	}
	CHECK(hw_connect_tcp_list(NULL, 300) < 0, "an empty list");
	for (int i = 0; i < HOLE_FILL; i++) close(fill[i]);
	close(hfd);
	close(lfd);
}

int main(void) {
	RUN(test_parse_literals);
	RUN(test_parse_numeric_names);
	RUN(test_classify_v4);
	RUN(test_classify_v6);
	RUN(test_classify_v6_wrapped);
	RUN(test_classify_v6_reserved);
	RUN(test_listen_and_connect);
	RUN(test_connect_moves_past_a_silent_address);
	return 0;
}
