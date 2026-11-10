#include "holywisp/net.h"

#include "test.h"

#include <errno.h>
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

int main(void) {
	RUN(test_parse_literals);
	RUN(test_classify_v4);
	RUN(test_classify_v6);
	RUN(test_listen_and_connect);
	return 0;
}
