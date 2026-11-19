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
 * one client can make it do is bounded: a name the cache knows is answered by hw_resolve itself
 * and never takes a thread, a request cancelled while it waited costs no lookup, and the queue
 * has a length (HW_RESOLVER_QUEUE_MAX) past which a request fails at once with EAI_AGAIN instead
 * of waiting behind thousands of others.
 *
 * And the pool is shared by its users, not by one of them. A request carries its caller's key
 * (the server's is the client's address), and each key has a queue of its own. A free thread
 * takes the oldest request of the next key in turn (a key the pool was doing nothing for goes ahead of
 * the keys that have had a turn), and never lets one key hold more than all threads but one at
 * once: so a client whose names never resolve cannot hold every thread, and another client's
 * lookup waits for a thread at most as long as one lookup takes, never for the first client's
 * queue to drain. A key holds at most max_pending_per_key requests (waiting,
 * running, or answered and not yet delivered); one more is refused at hw_resolve.
 */
#include "holywisp/hw.h"
#include "holywisp/net.h"
#include "holywisp/smap.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct resolve_key resolve_key;

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
	resolve_key *key;                // the share it counts in; NULL for an answer that took no thread
	struct hw_resolve_req *next;     // the key's queue
	struct hw_resolve_req *all_prev; // every live request, for hw_resolver_free
	struct hw_resolve_req *all_next;
};

// One caller's share of the pool, under the resolver's lock. It exists while it holds a request
// and is in the ring while it has one waiting.
struct resolve_key {
	hw_resolve_req *head; // waiting for a thread, oldest first
	hw_resolve_req *tail;
	int running; // lookups a thread is doing for it now
	int held;    // its requests from hw_resolve until their delivery task frees them
	resolve_key *ring_next;
	char name[]; // "" for the shared key
};

struct hw_resolver {
	hw_resolver_config cfg;
	pthread_t *threads;
	int nthreads;
	int per_key_threads; // how many threads one key may hold at once
	pthread_mutex_t lock;
	pthread_cond_t cond;
	hw_smap keys;        // name -> resolve_key, every key but the shared one
	resolve_key *shared; // callers without a key, and keys there was no memory for: never capped
	resolve_key *ring;   // keys with requests waiting, in the order they get a thread
	resolve_key *ring_tail;
	resolve_key *fresh_tail; // the last of the fresh keys, which lead the ring; NULL: none
	hw_resolve_req *all;
	size_t pending; // requests waiting in all the keys' queues
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

// Under the lock. The key of that name, made on first use; the shared one when there is no name,
// or no memory for another (fail open: a client that cannot be counted is not refused).
static resolve_key *key_get(hw_resolver *r, const char *name) {
	if (!name || !*name) return r->shared;
	resolve_key *k = hw_smap_get(&r->keys, name);
	if (k) return k;
	size_t len = strlen(name);
	k = calloc(1, sizeof(*k) + len + 1);
	if (!k) return r->shared;
	memcpy(k->name, name, len + 1);
	if (hw_smap_put(&r->keys, name, k) != 0) {
		free(k);
		return r->shared;
	}
	return k;
}

// Under the lock: a key that holds nothing is forgotten.
static void key_put(hw_resolver *r, resolve_key *k) {
	if (k == r->shared || k->held > 0) return;
	hw_smap_remove(&r->keys, k->name);
	free(k);
}

// A key that has had its turn goes to the back of the ring.
static void ring_append(hw_resolver *r, resolve_key *k) {
	k->ring_next = NULL;
	if (r->ring_tail) {
		r->ring_tail->ring_next = k;
	} else {
		r->ring = k;
	}
	r->ring_tail = k;
}

// A key the pool was doing nothing for goes ahead of every key that has had a turn since it joined,
// behind the other fresh ones: a client with one lookup is not put behind another client's next
// one of thousands, which the plain back of the ring would do every time the other got a thread
// just before it came.
static void ring_join(hw_resolver *r, resolve_key *k) {
	if (r->fresh_tail) {
		k->ring_next = r->fresh_tail->ring_next;
		r->fresh_tail->ring_next = k;
	} else {
		k->ring_next = r->ring;
		r->ring = k;
	}
	if (!k->ring_next) r->ring_tail = k;
	r->fresh_tail = k;
}

// Under the lock: the request a free thread takes, or NULL when there is none it may. That is
// the oldest of the first key in the ring with a thread to spare, and the key goes to the back of
// the ring, so the keys take turns. Only a key at its thread limit is passed over, and each of
// those holds a thread, so the walk is never longer than the pool.
static hw_resolve_req *pool_take(hw_resolver *r) {
	resolve_key *prev = NULL;
	for (resolve_key *k = r->ring; k; prev = k, k = k->ring_next) {
		if (k->running >= r->per_key_threads) continue;
		hw_resolve_req *req = k->head;
		k->head = req->next;
		req->next = NULL;
		if (!k->head) k->tail = NULL;
		if (prev) {
			prev->ring_next = k->ring_next;
		} else {
			r->ring = k->ring_next;
		}
		if (r->ring_tail == k) r->ring_tail = prev;
		// Everything ahead of the last fresh key is fresh too, so its predecessor is the new last.
		if (r->fresh_tail == k) r->fresh_tail = prev;
		if (k->head) ring_append(r, k);
		k->running++;
		r->pending--;
		return req;
	}
	return NULL;
}

// Loop thread.
static void deliver_cb(hw_loop *loop, void *ud) {
	hw_resolve_req *req = ud;
	hw_resolver *r = req->resolver;
	pthread_mutex_lock(&r->lock);
	all_unlink(r, req);
	if (req->key) {
		req->key->held--;
		key_put(r, req->key);
	}
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
		hw_resolve_req *req;
		while (!(req = pool_take(r)) && !r->stop) pthread_cond_wait(&r->cond, &r->lock);
		pthread_mutex_unlock(&r->lock);
		if (!req) return NULL;

		// A request whose stream is gone is not looked up: a client that opens streams and closes
		// them at once would otherwise keep every thread busy with names nobody wants. Its
		// delivery task still runs, to free it. (Cancelled a moment later, it is looked up and
		// the answer dropped, as before.)
		if (atomic_load(&req->cancelled)) {
			req->gai_err = EAI_AGAIN;
		} else {
			resolve_one(r, req);
		}

		pthread_mutex_lock(&r->lock);
		req->key->running--;
		// The key may have been at its thread limit with requests waiting, and the other threads
		// asleep for want of anything they could take.
		if (req->key->head) pthread_cond_signal(&r->cond);
		pthread_mutex_unlock(&r->lock);

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
	r->shared = calloc(1, sizeof(*r->shared) + 1);
	if (!r->threads || !r->shared) {
		free(r->threads);
		free(r->shared);
		free(r);
		return NULL;
	}
	hw_smap_init(&r->keys);
	pthread_mutex_init(&r->lock, NULL);
	pthread_cond_init(&r->cond, NULL);
	// Set before any thread runs; only what was started counts, below.
	r->per_key_threads = threads > 1 ? threads - 1 : 1;
	for (int i = 0; i < threads; i++) {
		if (pthread_create(&r->threads[i], NULL, worker_main, r) != 0) break;
		r->nthreads++;
	}
	if (r->nthreads == 0) {
		hw_resolver_free(r);
		return NULL;
	}
	pthread_mutex_lock(&r->lock);
	r->per_key_threads = r->nthreads > 1 ? r->nthreads - 1 : 1;
	pthread_mutex_unlock(&r->lock);
	return r;
}

static int key_free_visit(const char *name, void *value, void *ud) {
	(void)name;
	(void)ud;
	free(value);
	return 0;
}

void hw_resolver_free(hw_resolver *r) {
	if (!r) return;
	pthread_mutex_lock(&r->lock);
	r->stop = 1;
	// Every key with a request waiting is in the ring.
	for (resolve_key *k = r->ring; k; k = k->ring_next) {
		hw_resolve_req *req = k->head;
		while (req) {
			hw_resolve_req *next = req->next;
			all_unlink(r, req);
			req_free(req);
			req = next;
		}
		k->head = k->tail = NULL;
	}
	r->ring = r->ring_tail = r->fresh_tail = NULL;
	r->pending = 0;
	pthread_cond_broadcast(&r->cond);
	pthread_mutex_unlock(&r->lock);
	for (int i = 0; i < r->nthreads; i++) pthread_join(r->threads[i], NULL);
	hw_resolve_req *req = r->all;
	while (req) {
		hw_resolve_req *next = req->all_next;
		req_free(req);
		req = next;
	}
	hw_smap_each(&r->keys, key_free_visit, NULL);
	hw_smap_free(&r->keys);
	free(r->shared);
	pthread_cond_destroy(&r->cond);
	pthread_mutex_destroy(&r->lock);
	free(r->threads);
	free(r);
}

hw_resolve_req *hw_resolve(hw_resolver *r, hw_loop *loop, const char *host, uint16_t port, const char *key,
                           hw_resolve_cb cb, void *ud) {
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
	// every other answer, so it never waits behind the slow lookups of somebody else, and it is
	// not counted against the caller's share.
	int answered = r->cfg.cache && hw_dns_cache_get(r->cfg.cache, host, &req->res, &req->gai_err);
	if (answered && req->gai_err == 0) hw_dns_set_port(&req->res, port);

	pthread_mutex_lock(&r->lock);
	if (!answered) {
		resolve_key *k = key_get(r, key);
		if (k != r->shared && r->cfg.max_pending_per_key > 0 && k->held >= r->cfg.max_pending_per_key) {
			// This caller's share is full. That is the caller's own doing, and the caller is
			// told so apart from every other failure.
			pthread_mutex_unlock(&r->lock);
			req_free(req);
			errno = EAGAIN;
			return NULL;
		}
		if (r->pending >= HW_RESOLVER_QUEUE_MAX) {
			// The queue is as long as it gets. Waiting in it would take longer than the caller's
			// connect timeout anyway: fail now, as a temporary failure, which is never cached.
			req->gai_err = EAI_AGAIN;
			answered = 1;
			key_put(r, k);
		} else {
			req->key = k;
			k->held++;
			if (k->tail) {
				k->tail->next = req;
			} else {
				k->head = req;
				// It had nothing waiting, so it was not in the ring. With a lookup running it has
				// had its turn; only a key the pool is doing nothing for is new.
				if (k->running > 0) {
					ring_append(r, k);
				} else {
					ring_join(r, k);
				}
			}
			k->tail = req;
			r->pending++;
			pthread_cond_signal(&r->cond);
		}
	}
	req->all_next = r->all;
	if (r->all) r->all->all_prev = req;
	r->all = req;
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
