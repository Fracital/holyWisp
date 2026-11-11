/*
 * holywisp/dns.h implementation.
 */
#include "holywisp/dns.h"

#include "holywisp/hw.h"
#include "holywisp/smap.h"
#include "holywisp/sys.h"

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>

#define DNS_MAX_MSG    4096
#define DNS_MAX_NAME   253
#define DNS_TYPE_A     1
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_AAAA  28

// ---------------------------------------------------------------------------------- messages

size_t hw_dns_build_query(uint8_t *out, size_t cap, uint16_t id, const char *host, uint16_t qtype) {
	size_t hl = strlen(host);
	if (hl == 0 || hl > DNS_MAX_NAME || cap < 12 + hl + 2 + 4) return 0;
	out[0] = (uint8_t)(id >> 8);
	out[1] = (uint8_t)id;
	out[2] = 0x01; // RD
	out[3] = 0x00;
	out[4] = 0;
	out[5] = 1; // QDCOUNT
	memset(out + 6, 0, 6);
	size_t o = 12;
	const char *p = host;
	while (*p) {
		const char *dot = strchr(p, '.');
		size_t label = dot ? (size_t)(dot - p) : strlen(p);
		if (label == 0 || label > 63) return 0;
		// Letters, digits, hyphen and underscore are all a host name is made of. Anything else
		// in a label (a space, a control byte, a byte of another alphabet that should have come
		// as punycode) is not asked for.
		for (size_t i = 0; i < label; i++) {
			if (!isalnum((unsigned char)p[i]) && p[i] != '-' && p[i] != '_') return 0;
		}
		out[o++] = (uint8_t)label;
		memcpy(out + o, p, label);
		o += label;
		p += label;
		if (*p == '.') p++;
	}
	out[o++] = 0;
	out[o++] = (uint8_t)(qtype >> 8);
	out[o++] = (uint8_t)qtype;
	out[o++] = 0;
	out[o++] = 1; // IN
	return o;
}

// Skip a (possibly compressed) name starting at off. Returns the offset after it or 0 on error.
static size_t skip_name(const uint8_t *msg, size_t len, size_t off) {
	int hops = 0;
	for (;;) {
		if (off >= len) return 0;
		uint8_t l = msg[off];
		if (l == 0) return off + 1;
		if ((l & 0xC0) == 0xC0) {
			if (off + 1 >= len) return 0;
			return off + 2;
		}
		if (l > 63) return 0;
		off += 1 + l;
		if (++hops > 128) return 0;
	}
}

static int add_addr(hw_dns_result *res, int family, const uint8_t *rdata, uint16_t rdlen) {
	if (res->count >= HW_DNS_MAX_ADDRS) return 0;
	struct sockaddr_storage *ss = &res->addrs[res->count];
	memset(ss, 0, sizeof(*ss));
	if (family == AF_INET) {
		if (rdlen != 4) return 0;
		struct sockaddr_in *v4 = (struct sockaddr_in *)ss;
		v4->sin_family = AF_INET;
		memcpy(&v4->sin_addr, rdata, 4);
		res->lens[res->count] = sizeof(*v4);
	} else {
		if (rdlen != 16) return 0;
		struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)ss;
		v6->sin6_family = AF_INET6;
		memcpy(&v6->sin6_addr, rdata, 16);
		res->lens[res->count] = sizeof(*v6);
	}
	res->count++;
	return 1;
}

// A record's TTL bounds how long the whole answer may be kept: the smallest one counts, a
// CNAME's like an address's, and 0 is a TTL like any other (do not keep it at all).
static void note_ttl(hw_dns_result *res, uint32_t ttl) {
	if (!res->ttl_known || ttl < res->ttl_s) res->ttl_s = ttl;
	res->ttl_known = 1;
}

// Whether the question section of a response is the one question that was asked: this name
// (letters compared without case), this type, class IN. Returns the offset after it, or 0.
static size_t match_question(const uint8_t *msg, size_t len, const char *host, uint16_t qtype) {
	uint8_t want[DNS_MAX_NAME + 18];
	size_t wl = hw_dns_build_query(want, sizeof(want), 0, host, qtype);
	if (wl == 0 || len < wl) return 0;
	if (msg[4] != 0 || msg[5] != 1) return 0; // QDCOUNT is 1
	for (size_t i = 12; i < wl; i++) {
		// A length byte is below 64 and so never a letter: lowering both sides compares the
		// labels without case and everything else exactly.
		if (tolower(msg[i]) != tolower(want[i])) return 0;
	}
	return wl;
}

int hw_dns_parse_response(const uint8_t *msg, size_t len, uint16_t id, const char *host, uint16_t qtype,
                          hw_dns_result *res, int *rcode_out) {
	if (len < 12) return HW_ERR_INVALID;
	if (((uint16_t)msg[0] << 8 | msg[1]) != id) return HW_ERR_INVALID;
	if (!(msg[2] & 0x80)) return HW_ERR_INVALID; // not a response
	// The id is 16 bits, and whoever can send to our port can try all of them. The echoed
	// question is what ties an answer to what was asked: without it, an answer for any name,
	// from anyone who guessed the id, would be cached under this one.
	size_t off = match_question(msg, len, host, qtype);
	if (!off) return HW_ERR_INVALID;
	if (msg[2] & 0x02) return HW_ERR_AGAIN; // truncated: caller may retry over another server
	*rcode_out = msg[3] & 0x0F;
	uint16_t an = (uint16_t)(msg[6] << 8 | msg[7]);
	for (uint16_t i = 0; i < an; i++) {
		off = skip_name(msg, len, off);
		if (!off || off + 10 > len) return HW_ERR_INVALID;
		uint16_t type = (uint16_t)(msg[off] << 8 | msg[off + 1]);
		uint32_t ttl = (uint32_t)msg[off + 4] << 24 | (uint32_t)msg[off + 5] << 16 | (uint32_t)msg[off + 6] << 8 |
		               msg[off + 7];
		uint16_t rdlen = (uint16_t)(msg[off + 8] << 8 | msg[off + 9]);
		off += 10;
		if (off + rdlen > len) return HW_ERR_INVALID;
		// CNAMEs in the answer section are followed by the target's records, which we take as
		// they come; no name matching is needed for a client that asked one question.
		int used = type == DNS_TYPE_CNAME;
		if (type == DNS_TYPE_A) used = add_addr(res, AF_INET, msg + off, rdlen);
		if (type == DNS_TYPE_AAAA) used = add_addr(res, AF_INET6, msg + off, rdlen);
		if (used) note_ttl(res, ttl);
		off += rdlen;
	}
	return HW_OK;
}

void hw_dns_order(hw_dns_result *res, enum hw_dns_order order) {
	if (order == HW_DNS_VERBATIM || res->count <= 1) return;
	hw_dns_result tmp = *res;
	int first = order == HW_DNS_IPV4_FIRST ? AF_INET : AF_INET6;
	int n = 0;
	for (int pass = 0; pass < 2; pass++) {
		for (int i = 0; i < tmp.count; i++) {
			int fam = tmp.addrs[i].ss_family;
			if ((pass == 0) == (fam == first)) {
				res->addrs[n] = tmp.addrs[i];
				res->lens[n] = tmp.lens[i];
				n++;
			}
		}
	}
}

void hw_dns_set_port(hw_dns_result *res, uint16_t port) {
	for (int i = 0; i < res->count; i++) {
		if (res->addrs[i].ss_family == AF_INET) {
			((struct sockaddr_in *)&res->addrs[i])->sin_port = htons(port);
		} else {
			((struct sockaddr_in6 *)&res->addrs[i])->sin6_port = htons(port);
		}
	}
}

// ---------------------------------------------------------------------------------- transport

// The transaction id is the one secret in a query besides its source port, so it comes from the
// kernel's random source: an id that follows from a counter, the pid and the clock is an id an
// off-path sender can predict.
static uint16_t next_id(void) {
	uint16_t id;
	if (hw_sys_random(&id, sizeof(id)) == 0) return id;
	// No random source. Better a guessable id than no lookups at all; the question match and the
	// connected socket still stand.
	static _Atomic uint32_t counter;
	uint32_t c = atomic_fetch_add(&counter, 0x9E37u);
	return (uint16_t)(c ^ (uint32_t)getpid() ^ (uint32_t)hw_now_ms());
}

// One question to one server. 0 ok (res appended), >0 getaddrinfo error.
static int query_one(const struct sockaddr *server, socklen_t slen, const char *host, uint16_t qtype, int timeout_ms,
                     hw_dns_result *res) {
	uint8_t q[512];
	uint16_t id = next_id();
	size_t qlen = hw_dns_build_query(q, sizeof(q), id, host, qtype);
	if (!qlen) return EAI_NONAME;
	int fd = hw_sys_socket(server->sa_family, SOCK_DGRAM, 0, 0);
	if (fd < 0) return EAI_SYSTEM;
	if (connect(fd, server, slen) != 0 || send(fd, q, qlen, 0) != (ssize_t)qlen) {
		close(fd);
		return EAI_AGAIN;
	}
	uint8_t buf[DNS_MAX_MSG];
	uint64_t deadline = hw_now_ms() + (uint64_t)timeout_ms;
	for (;;) {
		uint64_t now = hw_now_ms();
		if (now >= deadline) {
			close(fd);
			return EAI_AGAIN;
		}
		struct pollfd pfd = {.fd = fd, .events = POLLIN};
		int r = poll(&pfd, 1, (int)(deadline - now));
		if (r < 0 && errno == EINTR) continue;
		if (r <= 0) {
			close(fd);
			return EAI_AGAIN;
		}
		ssize_t n = recv(fd, buf, sizeof(buf), 0);
		if (n < 0) {
			close(fd);
			return EAI_AGAIN;
		}
		int rcode = 0;
		int pr = hw_dns_parse_response(buf, (size_t)n, id, host, qtype, res, &rcode);
		if (pr == HW_ERR_INVALID) continue; // not ours; keep waiting
		close(fd);
		if (pr == HW_ERR_AGAIN) return EAI_AGAIN;
		if (rcode == 3) return EAI_NONAME;
		if (rcode != 0) return EAI_FAIL;
		return 0;
	}
}

int hw_dns_query(const struct sockaddr_storage *servers, const socklen_t *server_lens, int nservers, const char *host,
                 int timeout_ms, hw_dns_result *out) {
	memset(out, 0, sizeof(*out));
	if (nservers <= 0) return EAI_FAIL;
	int last = EAI_AGAIN;
	for (int s = 0; s < nservers; s++) {
		hw_dns_result res;
		memset(&res, 0, sizeof(res));
		const struct sockaddr *sa = (const struct sockaddr *)&servers[s];
		int ra = query_one(sa, server_lens[s], host, DNS_TYPE_A, timeout_ms, &res);
		int raaaa = query_one(sa, server_lens[s], host, DNS_TYPE_AAAA, timeout_ms, &res);
		if (res.count > 0) {
			*out = res;
			return 0;
		}
		if (ra == EAI_NONAME && raaaa == EAI_NONAME) return EAI_NONAME;
		if (ra == 0 && raaaa == 0) return EAI_NODATA;
		last = ra != 0 ? ra : raaaa;
	}
	return last;
}

// ---------------------------------------------------------------------------------- cache

typedef struct cache_entry {
	hw_dns_result res;
	int err;
	uint64_t expires_ms;
} cache_entry;

struct hw_dns_cache {
	uint32_t ttl_s;
	uint32_t negative_ttl_s;
	size_t max_entries;
	pthread_mutex_t lock;
	hw_smap entries;
};

hw_dns_cache *hw_dns_cache_new(uint32_t ttl_s, uint32_t negative_ttl_s, size_t max_entries) {
	hw_dns_cache *c = calloc(1, sizeof(*c));
	if (!c) return NULL;
	c->ttl_s = ttl_s;
	c->negative_ttl_s = negative_ttl_s;
	c->max_entries = max_entries ? max_entries : 65536;
	pthread_mutex_init(&c->lock, NULL);
	hw_smap_init(&c->entries);
	return c;
}

static int free_visit(const char *key, void *value, void *ud) {
	free(value);
	return 0;
}

void hw_dns_cache_free(hw_dns_cache *c) {
	if (!c) return;
	hw_smap_each(&c->entries, free_visit, NULL);
	hw_smap_free(&c->entries);
	pthread_mutex_destroy(&c->lock);
	free(c);
}

static void lower(char *dst, size_t cap, const char *src) {
	size_t i = 0;
	for (; src[i] && i + 1 < cap; i++) dst[i] = (char)tolower((unsigned char)src[i]);
	dst[i] = '\0';
	if (i > 1 && dst[i - 1] == '.') dst[i - 1] = '\0';
}

int hw_dns_cache_get(hw_dns_cache *c, const char *host, hw_dns_result *res, int *err) {
	if (!c) return 0;
	char key[256];
	lower(key, sizeof(key), host);
	pthread_mutex_lock(&c->lock);
	cache_entry *e = hw_smap_get(&c->entries, key);
	int hit = 0;
	if (e) {
		if (hw_now_ms() < e->expires_ms) {
			*res = e->res;
			*err = e->err;
			hit = 1;
		} else {
			hw_smap_remove(&c->entries, key);
			free(e);
		}
	}
	pthread_mutex_unlock(&c->lock);
	return hit;
}

void hw_dns_cache_put(hw_dns_cache *c, const char *host, const hw_dns_result *res, int err) {
	if (!c) return;
	uint32_t ttl = err ? c->negative_ttl_s : c->ttl_s;
	// The configured lifetime is a cap. An answer that came with a TTL is kept no longer than
	// that, and one that came with a TTL of 0 is not kept at all: its owner said so, typically
	// because the address is about to change.
	if (!err && res->ttl_known && res->ttl_s < ttl) ttl = res->ttl_s;
	if (ttl == 0) return;
	char key[256];
	lower(key, sizeof(key), host);
	cache_entry *e = calloc(1, sizeof(*e));
	if (!e) return;
	if (res) e->res = *res;
	e->err = err;
	e->expires_ms = hw_now_ms() + (uint64_t)ttl * 1000;
	pthread_mutex_lock(&c->lock);
	if (hw_smap_count(&c->entries) >= c->max_entries) {
		pthread_mutex_unlock(&c->lock);
		hw_dns_cache_expire(c);
		pthread_mutex_lock(&c->lock);
		if (hw_smap_count(&c->entries) >= c->max_entries) {
			pthread_mutex_unlock(&c->lock);
			free(e);
			return;
		}
	}
	cache_entry *old = hw_smap_remove(&c->entries, key);
	free(old);
	if (hw_smap_put(&c->entries, key, e) != 0) free(e);
	pthread_mutex_unlock(&c->lock);
}

typedef struct expire_ctx {
	hw_smap *map;
	uint64_t now;
} expire_ctx;

static int expire_visit(const char *key, void *value, void *ud) {
	expire_ctx *ctx = ud;
	cache_entry *e = value;
	if (e->expires_ms <= ctx->now) {
		hw_smap_remove(ctx->map, key);
		free(e);
	}
	return 0;
}

void hw_dns_cache_expire(hw_dns_cache *c) {
	if (!c) return;
	expire_ctx ctx = {.map = &c->entries, .now = hw_now_ms()};
	pthread_mutex_lock(&c->lock);
	hw_smap_each(&c->entries, expire_visit, &ctx);
	pthread_mutex_unlock(&c->lock);
}

size_t hw_dns_cache_count(hw_dns_cache *c) {
	if (!c) return 0;
	pthread_mutex_lock(&c->lock);
	size_t n = hw_smap_count(&c->entries);
	pthread_mutex_unlock(&c->lock);
	return n;
}
