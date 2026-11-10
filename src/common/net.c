/*
 * holywisp/net.h implementation: sockets and address classification. The resolver is resolver.c.
 */
#include "holywisp/net.h"

#include "holywisp/hw.h"
#include "holywisp/sys.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int hw_socket_nb(int domain, int type, int protocol) {
	return hw_sys_socket(domain, type, protocol, 1);
}

int hw_accept_nb(int listen_fd, struct sockaddr_storage *addr, socklen_t *addr_len) {
	return hw_sys_accept(listen_fd, (struct sockaddr *)addr, addr_len);
}

int hw_listen_tcp(const char *host, uint16_t port, int reuseport, int backlog, uint16_t *bound_port) {
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	if (!host || !*host) {
		hints.ai_flags |= AI_ADDRCONFIG;
		host = NULL;
	}
	char service[8];
	snprintf(service, sizeof(service), "%u", port);
	struct addrinfo *res = NULL;
	int gai = getaddrinfo(host, service, &hints, &res);
	if (gai != 0) {
		errno = gai == EAI_SYSTEM ? errno : EINVAL;
		return -1;
	}
	// Prefer an IPv6 wildcard (dual-stack) when binding to every interface.
	struct addrinfo *pick = res;
	if (!host) {
		for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
			if (ai->ai_family == AF_INET6) {
				pick = ai;
				break;
			}
		}
	}
	int fd = -1;
	int saved = 0;
	for (struct addrinfo *ai = pick; ai; ai = ai->ai_next) {
		fd = hw_socket_nb(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0) {
			saved = errno;
			continue;
		}
		int one = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		if (reuseport) setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
		if (ai->ai_family == AF_INET6) {
			int zero = 0;
			setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
		}
		if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && listen(fd, backlog) == 0) break;
		saved = errno;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0) {
		errno = saved ? saved : EADDRNOTAVAIL;
		return -1;
	}
	if (bound_port) {
		struct sockaddr_storage ss;
		memset(&ss, 0, sizeof(ss));
		socklen_t sl = sizeof(ss);
		if (getsockname(fd, (struct sockaddr *)&ss, &sl) == 0) *bound_port = hw_addr_port((struct sockaddr *)&ss);
	}
	return fd;
}

int hw_connect_tcp(const char *host, uint16_t port, int timeout_ms) {
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;
	char service[8];
	snprintf(service, sizeof(service), "%u", port);
	struct addrinfo *res = NULL;
	if (getaddrinfo(host, service, &hints, &res) != 0) {
		errno = EHOSTUNREACH;
		return -1;
	}
	int fd = -1;
	int saved = ECONNREFUSED;
	for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
		fd = hw_socket_nb(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0) {
			saved = errno;
			continue;
		}
		int r = connect(fd, ai->ai_addr, ai->ai_addrlen);
		if (r != 0 && errno == EINPROGRESS) {
			struct pollfd pfd = {.fd = fd, .events = POLLOUT};
			r = poll(&pfd, 1, timeout_ms);
			if (r == 0) {
				saved = ETIMEDOUT;
				r = -1;
			} else if (r > 0) {
				int err = 0;
				socklen_t el = sizeof(err);
				getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
				r = err ? -1 : 0;
				if (err) saved = err;
			} else {
				saved = errno;
			}
		} else if (r != 0) {
			saved = errno;
		}
		if (r == 0) break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0) {
		errno = saved;
		return -1;
	}
	// The client is blocking by design; the socket came back non-blocking from hw_socket_nb.
	int fl = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
	return fd;
}

static int digits_and_dots(const char *s) {
	for (; *s; s++) {
		if (*s != '.' && (*s < '0' || *s > '9')) return 0;
	}
	return 1;
}

int hw_addr_parse(const char *host, uint16_t port, struct sockaddr_storage *out, socklen_t *out_len) {
	char tmp[INET6_ADDRSTRLEN + 2];
	size_t n = strlen(host);
	int bracketed = 0;
	if (n >= 2 && host[0] == '[' && host[n - 1] == ']') {
		if (n - 2 >= sizeof(tmp)) return -1;
		memcpy(tmp, host + 1, n - 2);
		tmp[n - 2] = '\0';
		host = tmp;
		bracketed = 1;
	}
	struct sockaddr_in *v4 = (struct sockaddr_in *)out;
	struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)out;
	memset(out, 0, sizeof(*out));
	if (inet_pton(AF_INET, host, &v4->sin_addr) == 1) {
		v4->sin_family = AF_INET;
		v4->sin_port = htons(port);
		*out_len = sizeof(*v4);
		return 1;
	}
	if (inet_pton(AF_INET6, host, &v6->sin6_addr) == 1) {
		v6->sin6_family = AF_INET6;
		v6->sin6_port = htons(port);
		*out_len = sizeof(*v6);
		return 1;
	}
	// Brackets around something that is not an IPv6 literal, or digits and dots that inet_pton
	// rejected, or a stray colon: a malformed literal rather than a hostname.
	if (bracketed) return -1;
	if (n > 0 && digits_and_dots(host)) return -1;
	if (strchr(host, ':')) return -1;
	return 0;
}

uint16_t hw_addr_port(const struct sockaddr *sa) {
	if (sa->sa_family == AF_INET) return ntohs(((const struct sockaddr_in *)sa)->sin_port);
	if (sa->sa_family == AF_INET6) return ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
	return 0;
}

const char *hw_addr_str(const struct sockaddr *sa, char *buf, size_t cap) {
	char ip[INET6_ADDRSTRLEN] = "?";
	if (sa->sa_family == AF_INET) {
		inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr, ip, sizeof(ip));
		snprintf(buf, cap, "%s:%u", ip, hw_addr_port(sa));
	} else if (sa->sa_family == AF_INET6) {
		inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr, ip, sizeof(ip));
		snprintf(buf, cap, "[%s]:%u", ip, hw_addr_port(sa));
	} else {
		snprintf(buf, cap, "<af %d>", sa->sa_family);
	}
	return buf;
}

static enum hw_addr_class classify_v4(uint32_t a) {
	uint8_t b0 = (uint8_t)(a >> 24), b1 = (uint8_t)(a >> 16), b2 = (uint8_t)(a >> 8);
	if (a == 0xFFFFFFFFu) return HW_ADDR_MULTICAST; // limited broadcast
	if (b0 == 0) return HW_ADDR_UNSPECIFIED;
	if (b0 == 127) return HW_ADDR_LOOPBACK;
	if (b0 == 10) return HW_ADDR_PRIVATE;
	if (b0 == 172 && (b1 & 0xF0) == 16) return HW_ADDR_PRIVATE;
	if (b0 == 192 && b1 == 168) return HW_ADDR_PRIVATE;
	if (b0 == 100 && (b1 & 0xC0) == 64) return HW_ADDR_PRIVATE; // CGNAT
	if (b0 == 169 && b1 == 254) return HW_ADDR_LINK_LOCAL;
	if (b0 >= 224 && b0 <= 239) return HW_ADDR_MULTICAST;
	if (b0 >= 240) return HW_ADDR_RESERVED;
	if (b0 == 192 && b1 == 0 && b2 == 0) return HW_ADDR_RESERVED;     // IETF protocol assignments
	if (b0 == 192 && b1 == 0 && b2 == 2) return HW_ADDR_RESERVED;     // TEST-NET-1
	if (b0 == 198 && b1 == 51 && b2 == 100) return HW_ADDR_RESERVED;  // TEST-NET-2
	if (b0 == 203 && b1 == 0 && b2 == 113) return HW_ADDR_RESERVED;   // TEST-NET-3
	if (b0 == 198 && (b1 == 18 || b1 == 19)) return HW_ADDR_RESERVED; // benchmarking
	return HW_ADDR_PUBLIC;
}

enum hw_addr_class hw_addr_classify(const struct sockaddr *sa) {
	if (sa->sa_family == AF_INET) {
		return classify_v4(ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr));
	}
	if (sa->sa_family != AF_INET6) return HW_ADDR_RESERVED;
	const uint8_t *a = ((const struct sockaddr_in6 *)sa)->sin6_addr.s6_addr;
	static const uint8_t zero[15] = {0};
	if (memcmp(a, zero, 15) == 0) return a[15] == 1 ? HW_ADDR_LOOPBACK : HW_ADDR_UNSPECIFIED;
	// ::ffff:a.b.c.d
	static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
	if (memcmp(a, mapped, 12) == 0) {
		uint32_t v4 = (uint32_t)a[12] << 24 | (uint32_t)a[13] << 16 | (uint32_t)a[14] << 8 | a[15];
		return classify_v4(v4);
	}
	// 64:ff9b::/96 (NAT64) and ::a.b.c.d (deprecated compat) also wrap an IPv4 address.
	static const uint8_t nat64[12] = {0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0};
	if (memcmp(a, nat64, 12) == 0 || memcmp(a, zero, 12) == 0) {
		uint32_t v4 = (uint32_t)a[12] << 24 | (uint32_t)a[13] << 16 | (uint32_t)a[14] << 8 | a[15];
		enum hw_addr_class c = classify_v4(v4);
		return c == HW_ADDR_PUBLIC ? HW_ADDR_RESERVED : c;
	}
	if (a[0] == 0xff) return HW_ADDR_MULTICAST;
	if ((a[0] & 0xfe) == 0xfc) return HW_ADDR_PRIVATE;                                         // fc00::/7 ULA
	if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return HW_ADDR_LINK_LOCAL;                      // fe80::/10
	if (a[0] == 0xfe && (a[1] & 0xc0) == 0xc0) return HW_ADDR_RESERVED;                        // fec0::/10 site-local
	if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0d && a[3] == 0xb8) return HW_ADDR_RESERVED; // 2001:db8::/32
	if (a[0] == 0x20 && a[1] == 0x02) {                                                        // 6to4
		uint32_t v4 = (uint32_t)a[2] << 24 | (uint32_t)a[3] << 16 | (uint32_t)a[4] << 8 | a[5];
		enum hw_addr_class c = classify_v4(v4);
		return c == HW_ADDR_PUBLIC ? HW_ADDR_RESERVED : c;
	}
	if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0 && a[3] == 0) return HW_ADDR_RESERVED; // Teredo
	return HW_ADDR_PUBLIC;
}

const char *hw_addr_class_str(enum hw_addr_class c) {
	switch (c) {
	case HW_ADDR_PUBLIC:
		return "public";
	case HW_ADDR_LOOPBACK:
		return "loopback";
	case HW_ADDR_PRIVATE:
		return "private";
	case HW_ADDR_LINK_LOCAL:
		return "link-local";
	case HW_ADDR_UNSPECIFIED:
		return "unspecified";
	case HW_ADDR_MULTICAST:
		return "multicast";
	case HW_ADDR_RESERVED:
		return "reserved";
	}
	return "?";
}

void hw_tcp_tune(int fd, int nodelay) {
	int one = 1;
	if (nodelay) setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
	hw_sys_keepalive(fd, 60, 15, 4);
}
