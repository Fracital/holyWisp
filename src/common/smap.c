/*
 * holywisp/smap.h implementation.
 */
#include "holywisp/smap.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define SMAP_MIN_CAP 16
static char TOMB_STORAGE;
#define HW_SMAP_TOMB (&TOMB_STORAGE)

uint32_t hw_str_hash(const char *s) {
	uint32_t h = 2166136261u;
	for (; *s; s++) {
		h ^= (uint8_t)*s;
		h *= 16777619u;
	}
	return h ? h : 1;
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
