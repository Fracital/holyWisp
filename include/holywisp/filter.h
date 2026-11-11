/*
 * holywisp/filter.h - hostname and port allow/block lists, CIDR matching, real client IP.
 *
 * Plain data, no allocation, so they can live inside hw_server_config and be copied with it.
 */
#ifndef HOLYWISP_FILTER_H
#define HOLYWISP_FILTER_H

#include <stddef.h>
#include <stdint.h>

#include <sys/socket.h>

#define HW_MAX_FILTER_HOSTS 256
#define HW_FILTER_HOST_LEN  256 // the longest host a CONNECT can carry (255 bytes), and its NUL
#define HW_MAX_CIDRS        64

// Hostnames, lowercased, trailing dot stripped. "*.example.com" and ".example.com" match every
// subdomain (not the apex); "example.com" matches exactly.
typedef struct hw_hostlist {
	char entries[HW_MAX_FILTER_HOSTS][HW_FILTER_HOST_LEN];
	int count;
} hw_hostlist;

// -1 when the list is full or the pattern is empty or longer than an entry holds: a pattern is
// never stored cut, because a cut pattern is another pattern.
int hw_hostlist_add(hw_hostlist *l, const char *pattern);
// Whether host is on the list: 1 when an entry matches it, 0 when none does, and -1 when the
// host is too long to be compared at all (more than HW_FILTER_HOST_LEN - 1 bytes once
// normalized) and the list is not empty. A host is compared whole or not at all: matching the
// part that fits would let a long name borrow an allowed suffix or shed a blocked one. What -1
// means is the caller's policy, and there are only two that are safe, so they have names below.
int hw_hostlist_match(const hw_hostlist *l, const char *host, size_t host_len);
// The question an allow list is asked: is this host one of them? A host that cannot be compared
// is not.
static inline int hw_hostlist_allows(const hw_hostlist *l, const char *host, size_t host_len) {
	return hw_hostlist_match(l, host, host_len) == 1;
}
// The question a block list is asked: is this host to be refused? A host that cannot be compared
// is, unless the list is empty and refuses nobody.
static inline int hw_hostlist_blocks(const hw_hostlist *l, const char *host, size_t host_len) {
	return hw_hostlist_match(l, host, host_len) != 0;
}
// Lowercase src into dst without the whitespace around it and without trailing dots. 0, or -1
// when it does not fit in cap bytes; dst then holds the part that did, which is good for a log
// line and for nothing else.
int hw_hostname_normalize(char *dst, size_t cap, const char *src, size_t src_len);

// Ports as a 65536-bit set. Specs are "443" or "8000-8999".
typedef struct hw_portset {
	uint8_t bits[8192];
	int count;
} hw_portset;

int hw_portset_add(hw_portset *s, const char *spec); // -1 invalid
static inline int hw_portset_has(const hw_portset *s, uint16_t port) {
	return (s->bits[port >> 3] >> (port & 7)) & 1;
}

typedef struct hw_cidr {
	int family; // AF_INET or AF_INET6
	uint8_t addr[16];
	int bits;
} hw_cidr;

// "10.0.0.0/8", "::1", "2001:db8::/32"; a bare address gets a full-length mask.
int hw_cidr_parse(const char *text, hw_cidr *out);
int hw_cidr_contains(const hw_cidr *c, const struct sockaddr *sa); // IPv4-mapped IPv6 matches IPv4 rules
int hw_cidr_any_contains(const hw_cidr *list, int n, const struct sockaddr *sa);

// One header that is trusted to carry the client's address: every instance of it in the
// request, in the order they were sent (hw_http_header_all). A proxy that appends to the header
// may do so on the same line or on a line of its own, so the instances are read as one list.
typedef struct hw_real_ip_header {
	const char *const *values; // comma lists
	int count;                 // 0 when the request did not carry the header
} hw_real_ip_header;

// The client IP the policy should see: the peer, unless the peer is a trusted proxy, in which
// case it is read from the first of `headers` (they are in the order of preference) that the
// request carries. That header's list is walked from the right, the end the nearest proxy wrote:
// addresses of trusted proxies are skipped and the first address that is not one is the client.
// Nothing to the left of that address is looked at, since the client wrote it. An entry may be
// "ip", "ip:port", "[v6]" or "[v6]:port". Any other entry (a name, "unknown", an empty one) ends
// the walk and the answer is the peer itself: what stands to the left of something a trusted
// proxy did not write is never the client. A header that holds only trusted proxies leaves the
// answer to the next header.
//
// out gets the IP without a port, IPv4-mapped IPv6 as the IPv4 it wraps. The result says where
// it came from: 1 a header, 0 the peer (not a trusted proxy, or nothing in the headers), -1 the
// peer because a header held something that is not an address.
//
// The caller must not pass a header of which any instance was cut (hw_http_header_all's `cut`):
// the end of that list is missing, and the end is the part the proxy wrote.
#define HW_IP_STR_LEN 48
int hw_real_ip(const struct sockaddr *peer, const hw_cidr *trusted, int ntrusted, const hw_real_ip_header *headers,
               int nheaders, char out[HW_IP_STR_LEN]);
// IP without port.
const char *hw_addr_ip_str(const struct sockaddr *sa, char *buf, size_t cap);

#endif
