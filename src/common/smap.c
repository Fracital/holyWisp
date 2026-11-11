/*
 * holywisp/smap.h implementation.
 */
#include "holywisp/smap.h"

#include "holywisp/hw.h"
#include "holywisp/sys.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SMAP_MIN_CAP 16
static char TOMB_STORAGE;
#define HW_SMAP_TOMB (&TOMB_STORAGE)

// The hash is keyed. Keys here are chosen by clients (addresses, "ip:port" strings), and with a
// hash anyone can compute, a client picks keys that all land in one probe chain and every lookup
// of a limiter walks it. SipHash-1-3 under a key drawn once per process from the kernel leaves
// nothing to aim at: which keys collide is different in every process and cannot be worked out
// from outside it.
static pthread_once_t g_key_once = PTHREAD_ONCE_INIT;
static uint64_t g_key[2];

static uint64_t mix64(uint64_t x) {
	x += 0x9E3779B97F4A7C15u;
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9u;
	x = (x ^ (x >> 27)) * 0x94D049BB133111EBu;
	return x ^ (x >> 31);
}

static void key_init(void) {
	if (hw_sys_random(g_key, sizeof(g_key)) == 0) return;
	// No random source: what is left is the clocks, the pid and where the loader put us. Guessable
	// with effort, but still not the same in any two processes.
	g_key[0] = mix64((uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32) ^ hw_now_ms());
	g_key[1] = mix64(g_key[0] ^ (uint64_t)(uintptr_t)&g_key);
}

static uint64_t rotl64(uint64_t x, int b) {
	return x << b | x >> (64 - b);
}

static void sip_round(uint64_t v[4]) {
	v[0] += v[1];
	v[1] = rotl64(v[1], 13);
	v[1] ^= v[0];
	v[0] = rotl64(v[0], 32);
	v[2] += v[3];
	v[3] = rotl64(v[3], 16);
	v[3] ^= v[2];
	v[0] += v[3];
	v[3] = rotl64(v[3], 21);
	v[3] ^= v[0];
	v[2] += v[1];
	v[1] = rotl64(v[1], 17);
	v[1] ^= v[2];
	v[2] = rotl64(v[2], 32);
}

// SipHash-1-3 (one round per word, three to finish) of len bytes under the key k0, k1.
static uint64_t siphash13(const uint8_t *in, size_t len, uint64_t k0, uint64_t k1) {
	uint64_t v[4] = {k0 ^ 0x736f6d6570736575u, k1 ^ 0x646f72616e646f6du, k0 ^ 0x6c7967656e657261u,
	                 k1 ^ 0x7465646279746573u};
	size_t whole = len & ~(size_t)7;
	for (size_t i = 0; i < whole; i += 8) {
		uint64_t m = 0;
		for (int k = 7; k >= 0; k--) m = m << 8 | in[i + (size_t)k];
		v[3] ^= m;
		sip_round(v);
		v[0] ^= m;
	}
	uint64_t last = (uint64_t)len << 56;
	for (size_t i = len; i > whole; i--) last |= (uint64_t)in[i - 1] << (8 * (i - 1 - whole));
	v[3] ^= last;
	sip_round(v);
	v[0] ^= last;
	v[2] ^= 0xff;
	sip_round(v);
	sip_round(v);
	sip_round(v);
	return v[0] ^ v[1] ^ v[2] ^ v[3];
}

uint32_t hw_str_hash(const char *s) {
	pthread_once(&g_key_once, key_init);
	uint64_t h = siphash13((const uint8_t *)s, strlen(s), g_key[0], g_key[1]);
	uint32_t folded = (uint32_t)(h ^ h >> 32);
	return folded ? folded : 1;
}

void hw_smap_init(hw_smap *m) {
	memset(m, 0, sizeof(*m));
}

void hw_smap_free(hw_smap *m) {
	for (size_t i = 0; i < m->cap; i++) {
		if (m->slots[i].key && m->slots[i].key != HW_SMAP_TOMB) free(m->slots[i].key);
	}
	free(m->slots);
	hw_smap_init(m);
}

static int rehash(hw_smap *m, size_t new_cap) {
	hw_smap_slot *slots = calloc(new_cap, sizeof(*slots));
	if (!slots) {
		errno = ENOMEM;
		return -1;
	}
	hw_smap old = *m;
	m->slots = slots;
	m->cap = new_cap;
	m->count = 0;
	m->used = 0;
	for (size_t i = 0; i < old.cap; i++) {
		hw_smap_slot *s = &old.slots[i];
		if (!s->key || s->key == HW_SMAP_TOMB) continue;
		size_t idx = s->hash & (m->cap - 1);
		while (m->slots[idx].key) idx = (idx + 1) & (m->cap - 1);
		m->slots[idx] = *s;
		m->count++;
		m->used++;
	}
	free(old.slots);
	return 0;
}

static hw_smap_slot *find(const hw_smap *m, const char *key, uint32_t hash) {
	if (m->cap == 0) return NULL;
	size_t idx = hash & (m->cap - 1);
	for (;;) {
		hw_smap_slot *s = &m->slots[idx];
		if (!s->key) return NULL;
		if (s->key != HW_SMAP_TOMB && s->hash == hash && strcmp(s->key, key) == 0) return s;
		idx = (idx + 1) & (m->cap - 1);
	}
}

int hw_smap_put(hw_smap *m, const char *key, void *value) {
	uint32_t hash = hw_str_hash(key);
	if (find(m, key, hash)) return 1;
	if (m->cap == 0 && rehash(m, SMAP_MIN_CAP) != 0) return -1;
	if ((m->used + 1) * 10 > m->cap * 7) {
		size_t new_cap = m->count * 2 > m->cap ? m->cap * 2 : m->cap;
		if (rehash(m, new_cap) != 0) return -1;
	}
	char *copy = strdup(key);
	if (!copy) {
		errno = ENOMEM;
		return -1;
	}
	size_t idx = hash & (m->cap - 1);
	hw_smap_slot *tomb = NULL;
	for (;;) {
		hw_smap_slot *s = &m->slots[idx];
		if (!s->key) break;
		if (s->key == HW_SMAP_TOMB && !tomb) tomb = s;
		idx = (idx + 1) & (m->cap - 1);
	}
	hw_smap_slot *dst = tomb ? tomb : &m->slots[idx];
	if (!tomb) m->used++;
	dst->key = copy;
	dst->hash = hash;
	dst->value = value;
	m->count++;
	return 0;
}

void *hw_smap_get(const hw_smap *m, const char *key) {
	hw_smap_slot *s = find(m, key, hw_str_hash(key));
	return s ? s->value : NULL;
}

void *hw_smap_remove(hw_smap *m, const char *key) {
	hw_smap_slot *s = find(m, key, hw_str_hash(key));
	if (!s) return NULL;
	void *v = s->value;
	free(s->key);
	s->key = HW_SMAP_TOMB;
	s->value = NULL;
	m->count--;
	return v;
}

void hw_smap_each(hw_smap *m, hw_smap_visit cb, void *ud) {
	for (size_t i = 0; i < m->cap; i++) {
		hw_smap_slot *s = &m->slots[i];
		if (!s->key || s->key == HW_SMAP_TOMB) continue;
		if (cb(s->key, s->value, ud) != 0) return;
	}
}
