/*
 * holywisp/net.h - sockets, addresses and the asynchronous resolver.
 */
#ifndef HOLYWISP_NET_H
#define HOLYWISP_NET_H

#include "holywisp/loop.h"

#include <netdb.h>
#include <stdint.h>

#include <sys/socket.h>

#define HW_ADDR_STR_LEN 64 // "[v6]:port" with room to spare

// Non-blocking, close-on-exec socket(2) / accept(2). -1 with errno on failure.
int hw_socket_nb(int domain, int type, int protocol);
int hw_accept_nb(int listen_fd, struct sockaddr_storage *addr, socklen_t *addr_len);

// Bind + listen a TCP socket. host NULL or "" means every interface (dual-stack when possible).
// port 0 picks one; the chosen port is written to bound_port when non-NULL.
int hw_listen_tcp(const char *host, uint16_t port, int reuseport, int backlog, uint16_t *bound_port);

// Blocking connect with a timeout, for the client. Resolves host synchronously.
int hw_connect_tcp(const char *host, uint16_t port, int timeout_ms);

// Literal IPv4/IPv6 address ("1.2.3.4", "::1", "[::1]") into a sockaddr. 1 when host was a literal,
// 0 when it is a name (out untouched), -1 when it looks like a literal but is malformed.
int hw_addr_parse(const char *host, uint16_t port, struct sockaddr_storage *out, socklen_t *out_len);
// "ip:port" / "[v6]:port" into buf. Returns buf.
const char *hw_addr_str(const struct sockaddr *sa, char *buf, size_t cap);
uint16_t hw_addr_port(const struct sockaddr *sa);

// Where an address points. IPv4-mapped IPv6 is classified as its IPv4 address.
enum hw_addr_class {
	HW_ADDR_PUBLIC = 0,
	HW_ADDR_LOOPBACK,
	HW_ADDR_PRIVATE,     // RFC 1918, fc00::/7, 100.64/10 (CGNAT)
	HW_ADDR_LINK_LOCAL,  // 169.254/16, fe80::/10
	HW_ADDR_UNSPECIFIED, // 0.0.0.0, ::
	HW_ADDR_MULTICAST,   // 224/4, ff00::/8, 255.255.255.255
	HW_ADDR_RESERVED     // 240/4, 192.0.0/24, documentation, benchmarking, 6to4 etc.
};
enum hw_addr_class hw_addr_classify(const struct sockaddr *sa);
const char *hw_addr_class_str(enum hw_addr_class c);

// Set TCP_NODELAY (and keepalive) on a connected TCP socket.
void hw_tcp_tune(int fd, int nodelay);

// Resolver: getaddrinfo on a small thread pool, completion delivered on the requesting loop's
// thread. One resolver per process; it is shared by every worker.
typedef struct hw_resolver hw_resolver;
typedef struct hw_resolve_req hw_resolve_req;
// gai_err is 0 and res is the (owned by the resolver, freed after the callback) addrinfo list on
// success; otherwise gai_err is the getaddrinfo(3) error and res is NULL.
typedef void (*hw_resolve_cb)(hw_loop *loop, int gai_err, struct addrinfo *res, void *ud);

hw_resolver *hw_resolver_new(int threads);
// Joins the workers. Any request not yet delivered is dropped without a callback.
void hw_resolver_free(hw_resolver *r);
// Queue a lookup. socktype is SOCK_STREAM or SOCK_DGRAM. NULL (ENOMEM) on failure.
hw_resolve_req *hw_resolve(hw_resolver *r, hw_loop *loop, const char *host, uint16_t port, int socktype,
                           hw_resolve_cb cb, void *ud);
// From the loop thread: the callback will not run. The request is released by the resolver.
void hw_resolve_cancel(hw_resolve_req *req);

#endif
