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
	uint32_t ttl_s; // smallest TTL of the records the answer is made of, when ttl_known
	int ttl_known;  // 0: the answer came without one (getaddrinfo), and ttl_s says nothing
} hw_dns_result;

// Query every configured server in turn for A and AAAA records of host. 0 on success with at
// least one address, otherwise a getaddrinfo-style error (EAI_NONAME, EAI_AGAIN, EAI_FAIL).
int hw_dns_query(const struct sockaddr_storage *servers, const socklen_t *server_lens, int nservers, const char *host,
                 int timeout_ms, hw_dns_result *out);

// Build a query message; returns its length or 0. qtype 1 = A, 28 = AAAA. 0 also for a host that
// is not a host name: an empty or overlong label, or a byte outside [A-Za-z0-9_-] in one. Exposed
// for tests.
size_t hw_dns_build_query(uint8_t *out, size_t cap, uint16_t id, const char *host, uint16_t qtype);
// Parse a response to the question (host, qtype) sent under `id`; appends addresses to res and
// notes the smallest TTL. Returns 0, HW_ERR_INVALID when the message is not an answer to that
// question (another id, another or no question, malformed) and HW_ERR_AGAIN when it is one but
// was truncated. rcode_out receives the RCODE. Exposed for tests.
int hw_dns_parse_response(const uint8_t *msg, size_t len, uint16_t id, const char *host, uint16_t qtype,
                          hw_dns_result *res, int *rcode_out);

// Put addresses in the requested family order; stable within a family.
void hw_dns_order(hw_dns_result *res, enum hw_dns_order order);
void hw_dns_set_port(hw_dns_result *res, uint16_t port);

// Cache keyed by lowercase hostname. Negative results are cached too. An entry lives for the
// configured time or the answer's own TTL, whichever is shorter; an answer with a TTL of 0 is
// not stored.
typedef struct hw_dns_cache hw_dns_cache;
hw_dns_cache *hw_dns_cache_new(uint32_t ttl_s, uint32_t negative_ttl_s, size_t max_entries);
void hw_dns_cache_free(hw_dns_cache *c);
// 1 hit (res or err filled), 0 miss.
int hw_dns_cache_get(hw_dns_cache *c, const char *host, hw_dns_result *res, int *err);
void hw_dns_cache_put(hw_dns_cache *c, const char *host, const hw_dns_result *res, int err);
void hw_dns_cache_expire(hw_dns_cache *c);
size_t hw_dns_cache_count(hw_dns_cache *c);

#endif
