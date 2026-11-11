/*
 * Hashed-password checks, off the event loops.
 *
 * crypt(3) is slow on purpose: tens or hundreds of milliseconds for a modern method. Run on a
 * worker's loop, as it was, every wrong password from anybody stopped every client of that worker
 * for that long. Here it runs on a small pool of threads of its own and the answer is posted back
 * to the loop that asked, the way the resolver does it.
 *
 * Ownership is the resolver's too: the pool owns a request from auth_check() until its delivery
 * task has run on the loop (or auth_free drops it); the connection keeps the pointer only to
 * cancel through, and cancelling flips a flag that the loop thread alone reads and writes.
 */
#include "holywisp/hw.h"
#include "holywisp/sys.h"

#include "internal.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define AUTH_THREADS   2
#define AUTH_QUEUE_MAX 64 // checks waiting their turn; past it a login is turned away, not queued

struct hw_auth_req {
	hw_auth *auth;
	hw_loop *loop;
	hw_auth_cb cb;
	void *ud;
	int cancelled; // loop thread only
	int known;     // 0: the user does not exist; the hash is computed all the same and never matches
	int ok;
	char pass[256];
	char stored[256];
	struct hw_auth_req *next;     // pending queue
	struct hw_auth_req *all_prev; // every live request, for auth_free
	struct hw_auth_req *all_next;
};

struct hw_auth {
	pthread_t threads[AUTH_THREADS];
	int nthreads;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	hw_auth_req *head;
	hw_auth_req *tail;
	hw_auth_req *all;
	int pending;
	int stop;
};

// A password is not left in freed memory. Through a volatile pointer, so it is not optimised away.
static void wipe(void *p, size_t n) {
	volatile unsigned char *b = p;
	while (n--) *b++ = 0;
}

static void req_free(hw_auth_req *req) {
	wipe(req->pass, sizeof(req->pass));
	free(req);
}

static void all_unlink(hw_auth *a, hw_auth_req *req) {
	if (req->all_prev) {
		req->all_prev->all_next = req->all_next;
	} else {
		a->all = req->all_next;
	}
	if (req->all_next) req->all_next->all_prev = req->all_prev;
	req->all_prev = req->all_next = NULL;
}

// Loop thread.
static void deliver_cb(hw_loop *loop, void *ud) {
	hw_auth_req *req = ud;
	hw_auth *a = req->auth;
	pthread_mutex_lock(&a->lock);
	all_unlink(a, req);
	pthread_mutex_unlock(&a->lock);
	if (!req->cancelled) req->cb(loop, req->ok, req->ud);
	req_free(req);
}

static int same(const char *x, const char *y, size_t n) {
	unsigned char diff = 0;
	for (size_t i = 0; i < n; i++) diff |= (unsigned char)(x[i] ^ y[i]);
	return diff == 0;
}

static void *auth_main(void *arg) {
	hw_auth *a = arg;
	for (;;) {
		pthread_mutex_lock(&a->lock);
		while (!a->head && !a->stop) pthread_cond_wait(&a->cond, &a->lock);
		if (a->stop && !a->head) {
			pthread_mutex_unlock(&a->lock);
			return NULL;
		}
		hw_auth_req *req = a->head;
		a->head = req->next;
		if (!a->head) a->tail = NULL;
		a->pending--;
		pthread_mutex_unlock(&a->lock);

		char got[256];
		int hashed = hw_sys_crypt(req->pass, req->stored, got, sizeof(got)) == 0;
		size_t gl = hashed ? strlen(got) : 0;
		size_t sl = strlen(req->stored);
		req->ok = hashed && req->known && gl == sl && same(got, req->stored, gl);
		wipe(req->pass, sizeof(req->pass));
		wipe(got, sizeof(got));

		// No memory for the task: the answer is lost and the connection's handshake timer ends the
		// wait. The request stays on the `all` list, because the connection still holds it.
		(void)hw_loop_post(req->loop, deliver_cb, req);
	}
}

hw_auth *auth_new(void) {
	hw_auth *a = calloc(1, sizeof(*a));
	if (!a) return NULL;
	pthread_mutex_init(&a->lock, NULL);
	pthread_cond_init(&a->cond, NULL);
	for (int i = 0; i < AUTH_THREADS; i++) {
		if (pthread_create(&a->threads[i], NULL, auth_main, a) != 0) break;
		a->nthreads++;
	}
	if (a->nthreads == 0) {
		auth_free(a);
		return NULL;
	}
	return a;
}

void auth_free(hw_auth *a) {
	if (!a) return;
	pthread_mutex_lock(&a->lock);
	a->stop = 1;
	hw_auth_req *req = a->head;
	a->head = a->tail = NULL;
	while (req) {
		hw_auth_req *next = req->next;
		all_unlink(a, req);
		req_free(req);
		req = next;
	}
	pthread_cond_broadcast(&a->cond);
	pthread_mutex_unlock(&a->lock);
	for (int i = 0; i < a->nthreads; i++) pthread_join(a->threads[i], NULL);
	req = a->all;
	while (req) {
		hw_auth_req *next = req->all_next;
		req_free(req);
		req = next;
	}
	pthread_cond_destroy(&a->cond);
	pthread_mutex_destroy(&a->lock);
	free(a);
}

hw_auth_req *auth_check(hw_auth *a, hw_loop *loop, const char *pass, const char *stored, int known, hw_auth_cb cb,
                        void *ud) {
	if (strlen(pass) >= sizeof(((hw_auth_req *)0)->pass) || strlen(stored) >= sizeof(((hw_auth_req *)0)->stored)) {
		return NULL;
	}
	hw_auth_req *req = calloc(1, sizeof(*req));
	if (!req) return NULL;
	req->auth = a;
	req->loop = loop;
	req->cb = cb;
	req->ud = ud;
	req->known = known;
	memcpy(req->pass, pass, strlen(pass) + 1);
	memcpy(req->stored, stored, strlen(stored) + 1);
	pthread_mutex_lock(&a->lock);
	if (a->pending >= AUTH_QUEUE_MAX) {
		pthread_mutex_unlock(&a->lock);
		req_free(req);
		return NULL;
	}
	a->pending++;
	req->all_next = a->all;
	if (a->all) a->all->all_prev = req;
	a->all = req;
	if (a->tail) {
		a->tail->next = req;
	} else {
		a->head = req;
	}
	a->tail = req;
	pthread_cond_signal(&a->cond);
	pthread_mutex_unlock(&a->lock);
	return req;
}

void auth_cancel(hw_auth_req *req) {
	if (req) req->cancelled = 1;
}
