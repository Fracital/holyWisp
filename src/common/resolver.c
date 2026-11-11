/*
 * holywisp/net.h resolver: a fixed pool of threads doing blocking lookups, completions posted back
 * to the requesting loop.
 *
 * Ownership: the resolver owns every request from hw_resolve() until the delivery task has run on
 * the loop (or hw_resolver_free drops it), and frees it nowhere else: the caller keeps the pointer
 * to cancel through. Cancellation only sets a flag. The loop thread reads it in that same
 * delivery task, which is what keeps the callback from running; a pool thread reads it when it
 * takes the request off the queue, to skip a lookup nobody is waiting for, and still hands the
 * request to the delivery task to be freed. The flag is atomic and nothing else about a request
 * crosses threads except through the queue.
 *
 * The pool is small and every lookup in it can take as long as the resolver's timeout, so what
 * one client can make it do is bounded three ways: a name the cache knows is answered by
 * hw_resolve itself and never takes a thread, a request cancelled while it waited costs no
 * lookup, and the queue has a length (HW_RESOLVER_QUEUE_MAX) past which a request fails at once
 * with EAI_AGAIN instead of waiting behind thousands of others.
 */
#include "holywisp/hw.h"
#include "holywisp/net.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct hw_resolve_req {
	hw_resolver *resolver;
	hw_loop *loop;
	char *host;
	uint16_t port;
	hw_resolve_cb cb;
	void *ud;
	atomic_int cancelled; // set on the loop thread, read there and by the pool thread that dequeues it
	int gai_err;
	hw_dns_result res;
	struct hw_resolve_req *next;     // pending queue
	struct hw_resolve_req *all_prev; // every live request, for hw_resolver_free
	struct hw_resolve_req *all_next;
};

struct hw_resolver {
	hw_resolver_config cfg;
	pthread_t *threads;
	int nthreads;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	hw_resolve_req *head;
	hw_resolve_req *tail;
	hw_resolve_req *all;
	size_t pending; // length of the head..tail queue
	int stop;
};

static void req_free(hw_resolve_req *req) {
	free(req->host);
	free(req);
}

static void all_unlink(hw_resolver *r, hw_resolve_req *req) {
	if (req->all_prev) {
		req->all_prev->all_next = req->all_next;
	} else {
		r->all = req->all_next;
	}
	if (req->all_next) req->all_next->all_prev = req->all_prev;
	req->all_prev = req->all_next = NULL;
}

// Loop thread.
static void deliver_cb(hw_loop *loop, void *ud) {
	hw_resolve_req *req = ud;
	hw_resolver *r = req->resolver;
	pthread_mutex_lock(&r->lock);
	all_unlink(r, req);
	pthread_mutex_unlock(&r->lock);
	if (!atomic_load(&req->cancelled)) req->cb(loop, req->gai_err, req->gai_err ? NULL : &req->res, req->ud);
	req_free(req);
}

// getaddrinfo into an hw_dns_result, dropping duplicates.
static int lookup_system(const char *host, hw_dns_result *res) {
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;
	struct addrinfo *list = NULL;
	int err = getaddrinfo(host, NULL, &hints, &list);
	if (err != 0) return err;
	for (struct addrinfo *ai = list; ai && res->count < HW_DNS_MAX_ADDRS; ai = ai->ai_next) {
		if (ai->ai_addrlen > sizeof(res->addrs[0])) continue;
		int dup = 0;
		for (int i = 0; i < res->count && !dup; i++) {
			// ai_addrlen is a socklen_t in POSIX and a size_t in Winsock.
			dup = res->lens[i] == (socklen_t)ai->ai_addrlen && memcmp(&res->addrs[i], ai->ai_addr, ai->ai_addrlen) == 0;
		}
		if (dup) continue;
		memcpy(&res->addrs[res->count], ai->ai_addr, ai->ai_addrlen);
		res->lens[res->count] = ai->ai_addrlen;
		res->count++;
	}
	freeaddrinfo(list);
	return res->count ? 0 : EAI_NODATA;
}

// Worker thread: resolve one request, cache aware.
static void resolve_one(hw_resolver *r, hw_resolve_req *req) {
	hw_dns_result res;
	memset(&res, 0, sizeof(res));
	int err = 0;
	if (!r->cfg.cache || !hw_dns_cache_get(r->cfg.cache, req->host, &res, &err)) {
		if (r->cfg.nservers > 0) {
			err = hw_dns_query(r->cfg.servers, r->cfg.server_lens, r->cfg.nservers, req->host, r->cfg.timeout_ms, &res);
		} else {
			err = lookup_system(req->host, &res);
		}
		if (err == 0) hw_dns_order(&res, r->cfg.order);
		// Cache after ordering, before the port is set, so one entry serves every port.
		if (r->cfg.cache && err != EAI_AGAIN && err != EAI_SYSTEM) hw_dns_cache_put(r->cfg.cache, req->host, &res, err);
	}
	if (err == 0) hw_dns_set_port(&res, req->port);
	req->gai_err = err;
	req->res = res;
}

static void *worker_main(void *arg) {
	hw_resolver *r = arg;
	for (;;) {
		pthread_mutex_lock(&r->lock);
		while (!r->head && !r->stop) pthread_cond_wait(&r->cond, &r->lock);
		if (r->stop && !r->head) {
			pthread_mutex_unlock(&r->lock);
			return NULL;
		}
		hw_resolve_req *req = r->head;
		r->head = req->next;
		if (!r->head) r->tail = NULL;
		r->pending--;
		pthread_mutex_unlock(&r->lock);

		// A request whose stream is gone is not looked up: a client that opens streams and closes
		// them at once would otherwise keep every thread busy with names nobody wants. Its
		// delivery task still runs, to free it. (Cancelled a moment later, it is looked up and
		// the answer dropped, as before.)
		if (atomic_load(&req->cancelled)) {
			req->gai_err = EAI_AGAIN;
		} else {
			resolve_one(r, req);
		}

		// Out of memory for the task: the answer is lost, and the caller waits until it cancels.
		// The request is not freed here, because the caller still holds it and will write its
		// cancel flag: it stays on the `all` list for hw_resolver_free.
		(void)hw_loop_post(req->loop, deliver_cb, req);
	}
}

hw_resolver *hw_resolver_new(const hw_resolver_config *cfg) {
	int threads = cfg->threads > 0 ? cfg->threads : 4;
	hw_resolver *r = calloc(1, sizeof(*r));
	if (!r) return NULL;
	r->cfg = *cfg;
	if (r->cfg.timeout_ms <= 0) r->cfg.timeout_ms = 3000;
	r->threads = calloc((size_t)threads, sizeof(pthread_t));
	if (!r->threads) {
		free(r);
		return NULL;
	}
	pthread_mutex_init(&r->lock, NULL);
	pthread_cond_init(&r->cond, NULL);
	for (int i = 0; i < threads; i++) {
		if (pthread_create(&r->threads[i], NULL, worker_main, r) != 0) break;
		r->nthreads++;
	}
	if (r->nthreads == 0) {
		hw_resolver_free(r);
		return NULL;
	}
	return r;
}

void hw_resolver_free(hw_resolver *r) {
	if (!r) return;
	pthread_mutex_lock(&r->lock);
	r->stop = 1;
	hw_resolve_req *req = r->head;
	r->head = r->tail = NULL;
	r->pending = 0;
	while (req) {
		hw_resolve_req *next = req->next;
		all_unlink(r, req);
		req_free(req);
		req = next;
	}
	pthread_cond_broadcast(&r->cond);
	pthread_mutex_unlock(&r->lock);
	for (int i = 0; i < r->nthreads; i++) pthread_join(r->threads[i], NULL);
	req = r->all;
	while (req) {
		hw_resolve_req *next = req->all_next;
		req_free(req);
		req = next;
	}
	pthread_cond_destroy(&r->cond);
	pthread_mutex_destroy(&r->lock);
	free(r->threads);
	free(r);
}

hw_resolve_req *hw_resolve(hw_resolver *r, hw_loop *loop, const char *host, uint16_t port, hw_resolve_cb cb, void *ud) {
	hw_resolve_req *req = calloc(1, sizeof(*req));
	if (!req) return NULL;
	req->host = strdup(host);
	if (!req->host) {
		free(req);
		errno = ENOMEM;
		return NULL;
	}
	req->resolver = r;
	req->loop = loop;
	req->port = port;
	req->cb = cb;
	req->ud = ud;
	// A name the cache knows needs no thread: it is answered from here, through the loop like
	// every other answer, so it never waits behind the slow lookups of somebody else.
	int answered = r->cfg.cache && hw_dns_cache_get(r->cfg.cache, host, &req->res, &req->gai_err);
	if (answered && req->gai_err == 0) hw_dns_set_port(&req->res, port);

	pthread_mutex_lock(&r->lock);
	if (!answered && r->pending >= HW_RESOLVER_QUEUE_MAX) {
		// The queue is as long as it gets. Waiting in it would take longer than the caller's
		// connect timeout anyway: fail now, as a temporary failure, which is never cached.
		req->gai_err = EAI_AGAIN;
		answered = 1;
	}
	req->all_next = r->all;
	if (r->all) r->all->all_prev = req;
	r->all = req;
	if (!answered) {
		if (r->tail) {
			r->tail->next = req;
		} else {
			r->head = req;
		}
		r->tail = req;
		r->pending++;
		pthread_cond_signal(&r->cond);
	}
	pthread_mutex_unlock(&r->lock);
	if (answered && hw_loop_post(loop, deliver_cb, req) != 0) {
		// Nobody has the pointer yet, so unlike a pool thread in this position we can take the
		// request back and report the failure to the caller.
		pthread_mutex_lock(&r->lock);
		all_unlink(r, req);
		pthread_mutex_unlock(&r->lock);
		req_free(req);
		errno = ENOMEM;
		return NULL;
	}
	return req;
}

void hw_resolve_cancel(hw_resolve_req *req) {
	if (req) atomic_store(&req->cancelled, 1);
}
