/*
 * holywisp/dns.h - a small DNS client and a result cache.
 *
 * The client sends A and AAAA queries over UDP to the configured servers (RFC 1035, with
 * compression pointers and CNAME chains inside one response), retrying across servers. It is
 * blocking and used from the resolver's threads only. The cache is shared and locked.
 */
#ifndef HOLYWISP_DNS_H
#define HOLYWISP_DNS_H

#include <stddef.h>
#include <stdint.h>

#include <sys/socket.h>

#define HW_DNS_MAX_SERVERS 8
#define HW_DNS_MAX_ADDRS   16

enum hw_dns_order {
	HW_DNS_IPV4_FIRST = 0,
	HW_DNS_IPV6_FIRST,
	HW_DNS_VERBATIM
};

typedef struct hw_dns_result {
	struct sockaddr_storage addrs[HW_DNS_MAX_ADDRS];
	socklen_t lens[HW_DNS_MAX_ADDRS];
	int count;
	uint32_t ttl_s; // smallest TTL seen, 0 when unknown
} hw_dns_result;

// Query every configured server in turn for A and AAAA records of host. 0 on success with at
// least one address, otherwise a getaddrinfo-style error (EAI_NONAME, EAI_AGAIN, EAI_FAIL).
int hw_dns_query(const struct sockaddr_storage *servers, const socklen_t *server_lens, int nservers, const char *host,
                 int timeout_ms, hw_dns_result *out);

// Build a query message; returns its length or 0. qtype 1 = A, 28 = AAAA. Exposed for tests.
size_t hw_dns_build_query(uint8_t *out, size_t cap, uint16_t id, const char *host, uint16_t qtype);
// Parse a response for the given id; appends addresses with the right port to res. Returns 0,
// or a negative HW_ERR. rcode_out receives the RCODE. Exposed for tests.
int hw_dns_parse_response(const uint8_t *msg, size_t len, uint16_t id, hw_dns_result *res, int *rcode_out);

// Put addresses in the requested family order; stable within a family.
void hw_dns_order(hw_dns_result *res, enum hw_dns_order order);
void hw_dns_set_port(hw_dns_result *res, uint16_t port);

// Cache keyed by lowercase hostname. Negative results are cached too.
typedef struct hw_dns_cache hw_dns_cache;
hw_dns_cache *hw_dns_cache_new(uint32_t ttl_s, uint32_t negative_ttl_s, size_t max_entries);
void hw_dns_cache_free(hw_dns_cache *c);
// 1 hit (res or err filled), 0 miss.
int hw_dns_cache_get(hw_dns_cache *c, const char *host, hw_dns_result *res, int *err);
void hw_dns_cache_put(hw_dns_cache *c, const char *host, const hw_dns_result *res, int err);
void hw_dns_cache_expire(hw_dns_cache *c);
size_t hw_dns_cache_count(hw_dns_cache *c);

#endif
