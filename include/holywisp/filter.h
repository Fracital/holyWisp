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
#define HW_FILTER_HOST_LEN  128
#define HW_MAX_CIDRS        64

// Hostnames, lowercased, trailing dot stripped. "*.example.com" and ".example.com" match every
// subdomain (not the apex); "example.com" matches exactly.
typedef struct hw_hostlist {
	char entries[HW_MAX_FILTER_HOSTS][HW_FILTER_HOST_LEN];
	int count;
} hw_hostlist;

int hw_hostlist_add(hw_hostlist *l, const char *pattern); // -1 full or invalid
int hw_hostlist_match(const hw_hostlist *l, const char *host, size_t host_len);
void hw_hostname_normalize(char *dst, size_t cap, const char *src, size_t src_len);

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

// The client IP the policy should see: the peer, unless the peer is a trusted proxy, in which
// case the right-most address in the trusted headers (in header order) that is not itself a
// trusted proxy. header_values are the raw header values (comma lists allowed). out gets the IP
// without a port.
#define HW_IP_STR_LEN 48
void hw_real_ip(const struct sockaddr *peer, const hw_cidr *trusted, int ntrusted, const char *const *header_values,
                int nvalues, char out[HW_IP_STR_LEN]);
// IP without port.
const char *hw_addr_ip_str(const struct sockaddr *sa, char *buf, size_t cap);

#endif
