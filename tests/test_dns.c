#include "holywisp/dns.h"
#include "holywisp/hw.h"
#include "holywisp/loop.h"
#include "holywisp/net.h"
#include "holywisp/sys.h"

#include "test.h"

#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

// Build a minimal DNS response: one A answer and one AAAA answer for the queried name, using a
// compression pointer back to the question name at offset 12.
static size_t build_response(uint8_t *out, uint16_t id, const uint8_t *query, size_t qlen) {
	memcpy(out, query, qlen);
	out[2] = 0x81; // QR + RD
	out[3] = 0x80; // RA, rcode 0
	out[6] = 0;
	out[7] = 2; // ANCOUNT = 2
	size_t o = qlen;
	// A record: name pointer, type 1, class 1, ttl 300, rdlen 4.
	uint8_t a[] = {0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 93, 184, 216, 34};
	memcpy(out + o, a, sizeof(a));
	o += sizeof(a);
	// AAAA record.
	uint8_t aaaa[] = {0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16, 0x20, 0x01, 0x0d, 0xb8,
	                  0,    0,    0, 0,  0, 0, 0, 0, 0, 0,  0, 0,  0,    0,    0,    1};
	memcpy(out + o, aaaa, sizeof(aaaa));
	o += sizeof(aaaa);
	(void)id;
	return o;
}

static void test_query_roundtrip(void) {
	uint8_t q[256];
	size_t qlen = hw_dns_build_query(q, sizeof(q), 0x1234, "example.com", 1);
	CHECK(qlen > 12, "query built");
	CHECK_EQ((q[0] << 8 | q[1]), 0x1234);
	CHECK_EQ(q[5], 1); // QDCOUNT
	// The name encodes as 7"example"3"com"0.
	CHECK_EQ(q[12], 7);
	CHECK(memcmp(q + 13, "example", 7) == 0, "label");

	uint8_t resp[512];
	size_t rlen = build_response(resp, 0x1234, q, qlen);
	hw_dns_result res;
	memset(&res, 0, sizeof(res));
	int rcode = -1;
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 0x1234, "example.com", 1, &res, &rcode), HW_OK);
	CHECK_EQ(rcode, 0);
	CHECK_EQ(res.count, 2);
	CHECK_EQ(res.ttl_known, 1);
	CHECK_EQ(res.ttl_s, 60); // smallest TTL (AAAA 60 < A 300)
	// Wrong id is rejected.
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 0x9999, "example.com", 1, &res, &rcode), HW_ERR_INVALID);
}

// An answer counts only when it echoes the question that was asked. The id alone is 16 bits.
static void test_question_must_match(void) {
	uint8_t q[256], resp[512];
	hw_dns_result res;
	int rcode = -1;
	// The audit's case: a response about another name, with the right id, was taken as the answer.
	size_t qlen = hw_dns_build_query(q, sizeof(q), 7, "other.test", 1);
	size_t rlen = build_response(resp, 7, q, qlen);
	memset(&res, 0, sizeof(res));
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 7, "victim.example", 1, &res, &rcode), HW_ERR_INVALID);
	CHECK_EQ(res.count, 0);
	// A name that only starts or ends the same.
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 7, "other.tes", 1, &res, &rcode), HW_ERR_INVALID);
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 7, "other.testing", 1, &res, &rcode), HW_ERR_INVALID);
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 7, "another.test", 1, &res, &rcode), HW_ERR_INVALID);
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 7, "othe.rtest", 1, &res, &rcode), HW_ERR_INVALID);
	// The right name, another type.
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 7, "other.test", 28, &res, &rcode), HW_ERR_INVALID);
	CHECK_EQ(res.count, 0);
	// The right question: letters compare without case (servers may echo either), and a trailing
	// dot on our side is the same name.
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 7, "other.test", 1, &res, &rcode), HW_OK);
	CHECK_EQ(res.count, 2);
	memset(&res, 0, sizeof(res));
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 7, "OTHER.Test.", 1, &res, &rcode), HW_OK);
	CHECK_EQ(res.count, 2);
	memcpy(resp + 13, "OtHeR", 5);
	memset(&res, 0, sizeof(res));
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 7, "other.test", 1, &res, &rcode), HW_OK);
	// No question at all, two questions, another class.
	resp[5] = 0;
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 7, "other.test", 1, &res, &rcode), HW_ERR_INVALID);
	resp[5] = 2;
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 7, "other.test", 1, &res, &rcode), HW_ERR_INVALID);
	resp[5] = 1;
	resp[qlen - 1] = 3; // class CHAOS
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 7, "other.test", 1, &res, &rcode), HW_ERR_INVALID);
	// A message that ends inside the question.
	CHECK_EQ(hw_dns_parse_response(resp, qlen - 3, 7, "other.test", 1, &res, &rcode), HW_ERR_INVALID);
}

// A label is letters, digits, hyphens and underscores. Nothing else goes into a query.
static void test_query_label_bytes(void) {
	uint8_t q[512];
	static const char *const bad[] = {
	    "exa mple.com",  "example.com\n",  "a\rb.com",     "ex\x01.com",  "caf\xc3\xa9.fr", "a.b/c",
	    "user@host.com", "a..b",           ".example.com", "exam\x7fple", "a.b*",           "a,b.com",
	    "ex\\ample.com", "\"quoted\".com", "a.b:53",       "[::1]",       "a.%00.com",      " ",
	};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		CHECK(hw_dns_build_query(q, sizeof(q), 1, bad[i], 1) == 0, "built a query for \"%s\"", bad[i]);
	}
	static const char *const good[] = {
	    "example.com", "example.com.", "xn--bcher-kva.example", "_dmarc.example.com", "a-b.c_d.E9",
	    "localhost",   "0.1.2",
	};
	for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
		CHECK(hw_dns_build_query(q, sizeof(q), 1, good[i], 1) > 12, "no query for \"%s\"", good[i]);
	}
	char label64[80];
	memset(label64, 'a', 64);
	memcpy(label64 + 64, ".com", 5);
	CHECK_EQ(hw_dns_build_query(q, sizeof(q), 1, label64, 1), 0);
}

// One answer record for the name at offset 12: an A record with the given TTL.
static size_t build_a_response(uint8_t *out, const uint8_t *query, size_t qlen, uint32_t ttl) {
	memcpy(out, query, qlen);
	out[2] = 0x81;
	out[3] = 0x80;
	out[7] = 1;
	uint8_t a[] = {
	    0xC0, 0x0C, 0,  1,   0,   1, (uint8_t)(ttl >> 24), (uint8_t)(ttl >> 16), (uint8_t)(ttl >> 8), (uint8_t)ttl,
	    0,    4,    93, 184, 216, 34};
	memcpy(out + qlen, a, sizeof(a));
	return qlen + sizeof(a);
}

// A TTL of 0 means "do not keep this". It used to mean "unknown" and the answer was kept for the
// whole dns-ttl-s.
static void test_ttl_zero_is_not_cached(void) {
	uint8_t q[256], resp[512];
	size_t qlen = hw_dns_build_query(q, sizeof(q), 9, "rebind.test", 1);
	hw_dns_result res;
	int rcode = -1;
	memset(&res, 0, sizeof(res));
	size_t rlen = build_a_response(resp, q, qlen, 0);
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 9, "rebind.test", 1, &res, &rcode), HW_OK);
	CHECK_EQ(res.count, 1);
	CHECK_EQ(res.ttl_known, 1);
	CHECK_EQ(res.ttl_s, 0);
	// A later record with a longer TTL does not lift it.
	rlen = build_a_response(resp, q, qlen, 3600);
	CHECK_EQ(hw_dns_parse_response(resp, rlen, 9, "rebind.test", 1, &res, &rcode), HW_OK);
	CHECK_EQ(res.count, 2);
	CHECK_EQ(res.ttl_s, 0);

	hw_dns_cache *c = hw_dns_cache_new(120, 5, 16);
	hw_dns_result got;
	int err = -1;
	hw_dns_cache_put(c, "rebind.test", &res, 0);
	CHECK_EQ(hw_dns_cache_count(c), 0);
	CHECK(!hw_dns_cache_get(c, "rebind.test", &got, &err), "an answer with TTL 0 was cached");
	// With a TTL it is kept, and without one too (getaddrinfo gives none): for the configured time.
	res.ttl_s = 30;
	hw_dns_cache_put(c, "ttl.test", &res, 0);
	CHECK(hw_dns_cache_get(c, "ttl.test", &got, &err), "an answer with a TTL is cached");
	res.ttl_known = 0;
	res.ttl_s = 0;
	hw_dns_cache_put(c, "system.test", &res, 0);
	CHECK(hw_dns_cache_get(c, "system.test", &got, &err), "an answer without a TTL is cached");
	CHECK_EQ(hw_dns_cache_count(c), 2);
	hw_dns_cache_free(c);
}

static void test_order(void) {
	hw_dns_result res;
	memset(&res, 0, sizeof(res));
	// Two v6 then one v4.
	struct sockaddr_in6 *a = (struct sockaddr_in6 *)&res.addrs[0];
	a->sin6_family = AF_INET6;
	res.lens[0] = sizeof(*a);
	struct sockaddr_in6 *b = (struct sockaddr_in6 *)&res.addrs[1];
	b->sin6_family = AF_INET6;
	res.lens[1] = sizeof(*b);
	struct sockaddr_in *c = (struct sockaddr_in *)&res.addrs[2];
	c->sin_family = AF_INET;
	res.lens[2] = sizeof(*c);
	res.count = 3;
	hw_dns_order(&res, HW_DNS_IPV4_FIRST);
	CHECK_EQ(res.addrs[0].ss_family, AF_INET);
	hw_dns_order(&res, HW_DNS_IPV6_FIRST);
	CHECK_EQ(res.addrs[0].ss_family, AF_INET6);
	CHECK_EQ(res.addrs[2].ss_family, AF_INET);
}

static void test_cache(void) {
	hw_dns_cache *c = hw_dns_cache_new(60, 5, 4);
	hw_dns_result res;
	memset(&res, 0, sizeof(res));
	res.count = 1;
	res.lens[0] = sizeof(struct sockaddr_in);
	((struct sockaddr_in *)&res.addrs[0])->sin_family = AF_INET;
	hw_dns_cache_put(c, "Example.com", &res, 0);
	hw_dns_result got;
	int err = -1;
	CHECK(hw_dns_cache_get(c, "example.com.", &got, &err), "case/dot-insensitive hit");
	CHECK_EQ(err, 0);
	CHECK_EQ(got.count, 1);
	CHECK(!hw_dns_cache_get(c, "other.com", &got, &err), "miss");
	// Negative caching.
	hw_dns_cache_put(c, "nope.invalid", NULL, EAI_NONAME);
	CHECK(hw_dns_cache_get(c, "nope.invalid", &got, &err), "negative hit");
	CHECK_EQ(err, EAI_NONAME);
	CHECK_EQ(hw_dns_cache_count(c), 2);
	hw_dns_cache_free(c);
}

// ---------------------------------------------------------------------------------- a DNS stub

// A DNS server on a loopback UDP port: it notes every name it is asked for and, when `answer` is
// set, answers A questions with 192.0.2.1 (a question for `slow_name` only after slow_ms).
#define STUB_MAX_ASKED 64
typedef struct dns_stub {
	int fd;
	uint16_t port;
	int answer;
	const char *slow_name;
	int slow_ms;
	pthread_t thread;
	atomic_int stop;
	pthread_mutex_t lock;
	char asked[STUB_MAX_ASKED][64];
	uint16_t ids[STUB_MAX_ASKED];
	int nasked;
} dns_stub;

static void *stub_main(void *arg) {
	dns_stub *st = arg;
	while (!atomic_load(&st->stop)) {
		struct pollfd pfd = {.fd = st->fd, .events = POLLIN};
		if (poll(&pfd, 1, 20) <= 0) continue;
		uint8_t q[512];
		struct sockaddr_storage from;
		socklen_t fl = sizeof(from);
		ssize_t n = recvfrom(st->fd, q, sizeof(q), 0, (struct sockaddr *)&from, &fl);
		if (n < 17) continue;
		// The question name, as dotted text.
		char name[64];
		size_t o = 12, k = 0;
		while (o < (size_t)n && q[o] != 0 && k + q[o] + 2 < sizeof(name)) {
			if (k) name[k++] = '.';
			memcpy(name + k, q + o + 1, q[o]);
			k += q[o];
			o += (size_t)q[o] + 1;
		}
		name[k] = '\0';
		size_t qend = o + 5;
		if (qend > (size_t)n) continue;
		pthread_mutex_lock(&st->lock);
		if (st->nasked < STUB_MAX_ASKED) {
			snprintf(st->asked[st->nasked], sizeof(st->asked[0]), "%s", name);
			st->ids[st->nasked] = (uint16_t)(q[0] << 8 | q[1]);
			st->nasked++;
		}
		pthread_mutex_unlock(&st->lock);
		if (!st->answer) continue;
		if (st->slow_name && strcmp(name, st->slow_name) == 0) usleep((unsigned)st->slow_ms * 1000);
		uint8_t resp[600];
		size_t rlen = qend;
		memcpy(resp, q, qend);
		resp[2] = 0x81;
		resp[3] = 0x80;
		memset(resp + 6, 0, 6);
		if (q[o + 2] == 1) rlen = build_a_response(resp, q, qend, 60);
		sendto(st->fd, resp, rlen, 0, (struct sockaddr *)&from, fl);
	}
	return NULL;
}

static void stub_start(dns_stub *st, int answer) {
	memset(st, 0, sizeof(*st));
	st->answer = answer;
	st->fd = hw_sys_socket(AF_INET, SOCK_DGRAM, 0, 0);
	CHECK(st->fd >= 0, "stub socket");
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	CHECK_EQ(bind(st->fd, (struct sockaddr *)&sin, sizeof(sin)), 0);
	socklen_t sl = sizeof(sin);
	CHECK_EQ(getsockname(st->fd, (struct sockaddr *)&sin, &sl), 0);
	st->port = ntohs(sin.sin_port);
	pthread_mutex_init(&st->lock, NULL);
}

static void stub_run(dns_stub *st) {
	CHECK_EQ(pthread_create(&st->thread, NULL, stub_main, st), 0);
}

static void stub_stop(dns_stub *st, int running) {
	atomic_store(&st->stop, 1);
	if (running) pthread_join(st->thread, NULL);
	close(st->fd);
	pthread_mutex_destroy(&st->lock);
}

static int stub_asked(dns_stub *st, const char *name) {
	int n = 0;
	pthread_mutex_lock(&st->lock);
	for (int i = 0; i < st->nasked; i++) n += strcmp(st->asked[i], name) == 0;
	pthread_mutex_unlock(&st->lock);
	return n;
}

static void stub_server(const dns_stub *st, struct sockaddr_storage *ss, socklen_t *sl) {
	CHECK_EQ(hw_addr_parse("127.0.0.1", st->port, ss, sl), 1);
}

// The transaction id comes from the kernel's random source. It used to be a counter mixed with
// the pid and the clock, which is to say something a sender who knows roughly when a lookup
// happens can compute: this test computes it, and must be wrong. It has to run before any other
// test that sends a query, because the old counter started at 0.
static void test_query_ids_are_random(void) {
	enum {
		LOOKUPS = 6
	};
	dns_stub st;
	stub_start(&st, 0); // nobody reads the socket: the queries wait in its buffer
	struct sockaddr_storage server;
	socklen_t sl;
	stub_server(&st, &server, &sl);
	int predicted = 0, distinct = 0;
	uint16_t seen[LOOKUPS * 2];
	for (int i = 0; i < LOOKUPS; i++) {
		uint64_t t0 = hw_now_ms();
		hw_dns_result res;
		CHECK_EQ(hw_dns_query(&server, &sl, 1, "id.test", 30, &res), EAI_AGAIN);
		uint64_t t1 = hw_now_ms();
		for (int k = 0; k < 2; k++) {
			uint8_t q[512];
			struct pollfd pfd = {.fd = st.fd, .events = POLLIN};
			CHECK_EQ(poll(&pfd, 1, 2000), 1);
			CHECK(recv(st.fd, q, sizeof(q), 0) > 12, "a query");
			uint16_t id = (uint16_t)(q[0] << 8 | q[1]);
			// What the old scheme would have sent as query number 2i+k of this process.
			uint32_t counter = (uint32_t)(2 * i + k) * 0x9E37u;
			for (uint64_t t = t0; t <= t1; t++) {
				if (id == (uint16_t)(counter ^ (uint32_t)getpid() ^ (uint32_t)t)) {
					predicted++;
					break;
				}
			}
			int fresh = 1;
			for (int j = 0; j < 2 * i + k; j++) fresh &= seen[j] != id;
			distinct += fresh;
			seen[2 * i + k] = id;
		}
	}
	// By chance about one id in a thousand lands in the predicted window; the old scheme put all
	// twelve there.
	CHECK(predicted <= 2, "%d of %d query ids follow from the counter, the pid and the clock", predicted, LOOKUPS * 2);
	CHECK(distinct >= LOOKUPS * 2 - 1, "only %d distinct ids in %d queries", distinct, LOOKUPS * 2);
	stub_stop(&st, 0);
}

// ---------------------------------------------------------------------------------- the pool

typedef struct lookup {
	int done;  // the callback ran
	int order; // as which callback of the test, from 1
	int err;
	int count;
	uint16_t port;
} lookup;

static int g_order;

static void lookup_cb(hw_loop *loop, int gai_err, const hw_dns_result *res, void *ud) {
	lookup *l = ud;
	l->done = 1;
	l->order = ++g_order;
	l->err = gai_err;
	l->count = res ? res->count : 0;
	l->port = res && res->count ? hw_addr_port((const struct sockaddr *)&res->addrs[0]) : 0;
}

// Run the loop until *flag is set, or for at most ms.
static void run_until(hw_loop *loop, const int *flag, int ms) {
	uint64_t deadline = hw_now_ms() + (uint64_t)ms;
	while (!*flag && hw_now_ms() < deadline) hw_loop_run_once(loop, 10);
}

static hw_resolver *pool_new(const dns_stub *st, int timeout_ms, hw_dns_cache *cache) {
	hw_resolver_config rc;
	memset(&rc, 0, sizeof(rc));
	rc.threads = 1; // one thread: whatever is slow blocks everything behind it
	stub_server(st, &rc.servers[0], &rc.server_lens[0]);
	rc.nservers = 1;
	rc.timeout_ms = timeout_ms;
	rc.cache = cache;
	hw_resolver *r = hw_resolver_new(&rc);
	CHECK(r != NULL, "resolver");
	return r;
}

// A name the cache knows does not wait for a thread. With the pool's only thread stuck on a
// server that never answers, it used to wait until that lookup had timed out.
static void test_pool_cached_name_skips_queue(void) {
	dns_stub st;
	stub_start(&st, 0);
	stub_run(&st);
	hw_dns_cache *cache = hw_dns_cache_new(60, 5, 16);
	hw_dns_result known;
	memset(&known, 0, sizeof(known));
	struct sockaddr_storage addr;
	socklen_t al;
	CHECK_EQ(hw_addr_parse("192.0.2.7", 0, &addr, &al), 1);
	known.addrs[0] = addr;
	known.lens[0] = al;
	known.count = 1;
	hw_dns_cache_put(cache, "cached.test", &known, 0);
	hw_dns_cache_put(cache, "gone.test", NULL, EAI_NONAME);
	hw_resolver *r = pool_new(&st, 200, cache);
	hw_loop *loop = hw_loop_new();
	g_order = 0;

	lookup slow = {0}, cached = {0}, gone = {0};
	CHECK(hw_resolve(r, loop, "slow.test", 80, lookup_cb, &slow) != NULL, "queued");
	CHECK(hw_resolve(r, loop, "Cached.Test", 443, lookup_cb, &cached) != NULL, "queued");
	CHECK(hw_resolve(r, loop, "gone.test", 443, lookup_cb, &gone) != NULL, "queued");
	CHECK(!cached.done, "the callback never runs inside hw_resolve");
	run_until(loop, &slow.done, 5000);
	CHECK(slow.done && cached.done && gone.done, "all three answered");
	CHECK(cached.order < slow.order, "the cached name waited behind the slow one");
	CHECK(gone.order < slow.order, "the cached failure waited behind the slow one");
	CHECK_EQ(cached.err, 0);
	CHECK_EQ(cached.count, 1);
	CHECK_EQ(cached.port, 443);
	CHECK_EQ(gone.err, EAI_NONAME);
	CHECK_EQ(slow.err, EAI_AGAIN);
	CHECK_EQ(stub_asked(&st, "cached.test"), 0);
	CHECK(stub_asked(&st, "slow.test") > 0, "the slow name was asked for");

	hw_resolver_free(r);
	hw_loop_free(loop);
	hw_dns_cache_free(cache);
	stub_stop(&st, 1);
}

// A request cancelled while it waits for a thread is never looked up. A client that opens
// streams and closes them at once used to buy a full lookup with each.
static void test_pool_skips_cancelled(void) {
	dns_stub st;
	stub_start(&st, 1);
	st.slow_name = "slow.test";
	st.slow_ms = 120;
	stub_run(&st);
	hw_resolver *r = pool_new(&st, 2000, NULL);
	hw_loop *loop = hw_loop_new();
	g_order = 0;

	lookup slow = {0}, cancelled = {0}, after = {0};
	CHECK(hw_resolve(r, loop, "slow.test", 80, lookup_cb, &slow) != NULL, "queued");
	hw_resolve_req *req = hw_resolve(r, loop, "cancelme.test", 80, lookup_cb, &cancelled);
	CHECK(req != NULL, "queued");
	CHECK(hw_resolve(r, loop, "after.test", 80, lookup_cb, &after) != NULL, "queued");
	hw_resolve_cancel(req);
	run_until(loop, &after.done, 5000);
	CHECK(slow.done && after.done, "the others are answered");
	CHECK_EQ(slow.err, 0);
	CHECK_EQ(after.err, 0);
	CHECK_EQ(after.count, 1);
	CHECK_EQ(after.port, 80);
	CHECK(!cancelled.done, "a cancelled request has no callback");
	CHECK_EQ(stub_asked(&st, "cancelme.test"), 0);
	CHECK_EQ(stub_asked(&st, "after.test"), 2); // A and AAAA

	hw_resolver_free(r);
	hw_loop_free(loop);
	stub_stop(&st, 1);
}

// The queue has an end. Past it a lookup fails at once, as a temporary failure, instead of
// waiting behind thousands that will each take a thread for seconds.
static void test_pool_queue_is_bounded(void) {
	enum {
		EXTRA = 40
	};
	dns_stub st;
	stub_start(&st, 0);
	stub_run(&st);
	hw_resolver *r = pool_new(&st, 300, NULL);
	hw_loop *loop = hw_loop_new();
	g_order = 0;

	static lookup lookups[HW_RESOLVER_QUEUE_MAX + EXTRA];
	memset(lookups, 0, sizeof(lookups));
	for (int i = 0; i < HW_RESOLVER_QUEUE_MAX + EXTRA; i++) {
		char name[32];
		snprintf(name, sizeof(name), "q%d.test", i);
		CHECK(hw_resolve(r, loop, name, 80, lookup_cb, &lookups[i]) != NULL, "request %d", i);
	}
	// The one thread is in its first lookup for the next 600 ms. Whatever is answered before
	// that was answered without it.
	run_until(loop, &lookups[HW_RESOLVER_QUEUE_MAX + EXTRA - 1].done, 200);
	int refused = 0;
	for (int i = 0; i < HW_RESOLVER_QUEUE_MAX + EXTRA; i++) {
		if (!lookups[i].done) continue;
		refused++;
		CHECK(i >= HW_RESOLVER_QUEUE_MAX, "request %d was answered before the queue was full", i);
		CHECK_EQ(lookups[i].err, EAI_AGAIN);
	}
	// The thread may have taken the first request off the queue while it filled, or not yet.
	CHECK(refused == EXTRA || refused == EXTRA - 1, "%d requests past the limit were refused, not %d", refused, EXTRA);

	hw_resolver_free(r); // drops the 4096 that still wait
	hw_loop_free(loop);
	stub_stop(&st, 1);
}

int main(void) {
	RUN(test_query_ids_are_random);
	RUN(test_query_roundtrip);
	RUN(test_question_must_match);
	RUN(test_query_label_bytes);
	RUN(test_ttl_zero_is_not_cached);
	RUN(test_order);
	RUN(test_cache);
	RUN(test_pool_cached_name_skips_queue);
	RUN(test_pool_skips_cancelled);
	RUN(test_pool_queue_is_bounded);
	return 0;
}
