/*
 * holywisp/limits.h implementation.
 */
#include "holywisp/limits.h"

#include "holywisp/hw.h"
#include "holywisp/smap.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

// ---------------------------------------------------------------------------------- window

typedef struct window_entry {
	uint64_t start;
	int count;
} window_entry;

struct hw_window {
	int limit;
	uint64_t window_ms;
	pthread_mutex_t lock;
	hw_smap entries;
};

hw_window *hw_window_new(int limit, uint64_t window_ms) {
	hw_window *w = calloc(1, sizeof(*w));
	if (!w) return NULL;
	w->limit = limit;
	w->window_ms = window_ms ? window_ms : 1000;
	pthread_mutex_init(&w->lock, NULL);
	hw_smap_init(&w->entries);
	return w;
}

static int free_entry_visit(const char *key, void *value, void *ud) {
	free(value);
	return 0;
}

void hw_window_free(hw_window *w) {
	if (!w) return;
	hw_smap_each(&w->entries, free_entry_visit, NULL);
	hw_smap_free(&w->entries);
	pthread_mutex_destroy(&w->lock);
	free(w);
}

int hw_window_allow(hw_window *w, const char *key) {
	if (!w || w->limit <= 0) return 1;
	uint64_t now = hw_now_ms();
	pthread_mutex_lock(&w->lock);
	window_entry *e = hw_smap_get(&w->entries, key);
	if (!e) {
		e = calloc(1, sizeof(*e));
		if (!e || hw_smap_put(&w->entries, key, e) != 0) {
			free(e);
			pthread_mutex_unlock(&w->lock);
			return 1; // out of memory: fail open rather than refuse everyone
		}
		e->start = now;
		e->count = 0;
	}
	if (now - e->start >= w->window_ms) {
		e->start = now;
		e->count = 0;
	}
	e->count++;
	int allowed = e->count <= w->limit;
	pthread_mutex_unlock(&w->lock);
	return allowed;
}

typedef struct evict_ctx {
	hw_smap *map;
	uint64_t cutoff;
} evict_ctx;

static int window_evict_visit(const char *key, void *value, void *ud) {
	evict_ctx *ctx = ud;
	window_entry *e = value;
	if (e->start < ctx->cutoff) {
		hw_smap_remove(ctx->map, key);
		free(e);
	}
	return 0;
}

void hw_window_evict(hw_window *w, uint64_t idle_ms) {
	if (!w) return;
	uint64_t now = hw_now_ms();
	evict_ctx ctx = {.map = &w->entries, .cutoff = now > idle_ms ? now - idle_ms : 0};
	pthread_mutex_lock(&w->lock);
	hw_smap_each(&w->entries, window_evict_visit, &ctx);
	pthread_mutex_unlock(&w->lock);
}

size_t hw_window_count(hw_window *w) {
	if (!w) return 0;
	pthread_mutex_lock(&w->lock);
	size_t n = hw_smap_count(&w->entries);
	pthread_mutex_unlock(&w->lock);
	return n;
}

// ---------------------------------------------------------------------------------- semaphore

void hw_semaphore_init(hw_semaphore *s, int64_t max) {
	atomic_store(&s->current, 0);
	s->max = max;
}

int hw_semaphore_try(hw_semaphore *s) {
	if (s->max <= 0) return 1;
	int64_t cur = atomic_load(&s->current);
	for (;;) {
		if (cur >= s->max) return 0;
		if (atomic_compare_exchange_weak(&s->current, &cur, cur + 1)) return 1;
	}
}

void hw_semaphore_release(hw_semaphore *s) {
	if (s->max <= 0) return;
	atomic_fetch_sub(&s->current, 1);
}

int64_t hw_semaphore_value(const hw_semaphore *s) {
	return atomic_load(&s->current);
}

// ---------------------------------------------------------------------------------- bandwidth

typedef struct bw_bucket {
	uint64_t next_us;   // when the key's virtual clock lets the next byte through
	uint64_t last_seen; // ms
} bw_bucket;

struct hw_bandwidth {
	uint64_t bytes_per_second;
	pthread_mutex_t lock;
	hw_smap buckets;
};

hw_bandwidth *hw_bandwidth_new(uint64_t bytes_per_second) {
	if (bytes_per_second == 0) return NULL;
	hw_bandwidth *b = calloc(1, sizeof(*b));
	if (!b) return NULL;
	b->bytes_per_second = bytes_per_second;
	pthread_mutex_init(&b->lock, NULL);
	hw_smap_init(&b->buckets);
	return b;
}

void hw_bandwidth_free(hw_bandwidth *b) {
	if (!b) return;
	hw_smap_each(&b->buckets, free_entry_visit, NULL);
	hw_smap_free(&b->buckets);
	pthread_mutex_destroy(&b->lock);
	free(b);
}

uint64_t hw_bandwidth_charge(hw_bandwidth *b, const char *key, size_t bytes) {
	if (!b || bytes == 0) return 0;
	uint64_t now_ms = hw_now_ms();
	uint64_t now_us = now_ms * 1000;
	uint64_t cost_us = (uint64_t)bytes * 1000000u / b->bytes_per_second;
	pthread_mutex_lock(&b->lock);
	bw_bucket *k = hw_smap_get(&b->buckets, key);
	if (!k) {
		k = calloc(1, sizeof(*k));
		if (!k || hw_smap_put(&b->buckets, key, k) != 0) {
			free(k);
			pthread_mutex_unlock(&b->lock);
			return 0;
		}
	}
	// A burst of one second is always free: the clock never lags more than that behind now.
	uint64_t earliest = now_us > 1000000u ? now_us - 1000000u : 0;
	uint64_t start = k->next_us > earliest ? k->next_us : earliest;
	uint64_t finish = start + cost_us;
	k->next_us = finish;
	k->last_seen = now_ms;
	pthread_mutex_unlock(&b->lock);
	if (finish <= now_us) return 0;
	return (finish - now_us + 999) / 1000;
}

static int bw_evict_visit(const char *key, void *value, void *ud) {
	evict_ctx *ctx = ud;
	bw_bucket *k = value;
	if (k->last_seen < ctx->cutoff) {
		hw_smap_remove(ctx->map, key);
		free(k);
	}
	return 0;
}

void hw_bandwidth_evict(hw_bandwidth *b, uint64_t idle_ms) {
	if (!b) return;
	uint64_t now = hw_now_ms();
	evict_ctx ctx = {.map = &b->buckets, .cutoff = now > idle_ms ? now - idle_ms : 0};
	pthread_mutex_lock(&b->lock);
	hw_smap_each(&b->buckets, bw_evict_visit, &ctx);
	pthread_mutex_unlock(&b->lock);
}

// ---------------------------------------------------------------------------------- signature

void hw_sigdet_record(hw_sigdet *d, int ok, uint64_t now_ms, uint64_t window_ms) {
	d->at[d->head] = now_ms;
	d->ok[d->head] = ok ? 1 : 0;
	d->head = (d->head + 1) % HW_SIGDET_RING;
	if (d->count < HW_SIGDET_RING) d->count++;
	// Age out samples older than the window from the tail.
	uint64_t cutoff = now_ms > window_ms ? now_ms - window_ms : 0;
	while (d->count > 0) {
		int tail = (d->head - d->count + HW_SIGDET_RING) % HW_SIGDET_RING;
		if (d->at[tail] >= cutoff) break;
		d->count--;
	}
}

int hw_sigdet_match(const hw_sigdet *d, int min_samples, double failed_ratio) {
	if (min_samples <= 0 || d->count < min_samples) return 0;
	int failed = 0;
	for (int i = 0; i < d->count; i++) {
		int idx = (d->head - 1 - i + HW_SIGDET_RING) % HW_SIGDET_RING;
		if (!d->ok[idx]) failed++;
	}
	return (double)failed / (double)d->count >= failed_ratio;
}
