/*
 * holywisp/map.h implementation: linear probing, power-of-two table, Fibonacci hashing of the key.
 */
#include "holywisp/map.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define SLOT_EMPTY  0
#define SLOT_USED   1
#define SLOT_TOMB   2
#define MAP_MIN_CAP 16

static size_t slot_index(const hw_map *m, uint32_t key) {
	// Stream ids are usually small sequential integers; the multiply spreads them over the table.
	uint64_t h = (uint64_t)key * 0x9E3779B97F4A7C15ull;
	return (size_t)(h >> 32) & (m->cap - 1);
}

void hw_map_init(hw_map *m) {
	m->slots = NULL;
	m->cap = 0;
	m->count = 0;
	m->used = 0;
}

void hw_map_free(hw_map *m) {
	free(m->slots);
	hw_map_init(m);
}

static int map_rehash(hw_map *m, size_t new_cap) {
	hw_map_slot *slots = calloc(new_cap, sizeof(*slots));
	if (!slots) {
		errno = ENOMEM;
		return -1;
	}
	hw_map old = *m;
	m->slots = slots;
	m->cap = new_cap;
	m->count = 0;
	m->used = 0;
	for (size_t i = 0; i < old.cap; i++) {
		if (old.slots[i].state != SLOT_USED) continue;
		size_t idx = slot_index(m, old.slots[i].key);
		while (m->slots[idx].state == SLOT_USED) idx = (idx + 1) & (m->cap - 1);
		m->slots[idx] = old.slots[i];
		m->count++;
		m->used++;
	}
	free(old.slots);
	return 0;
}

int hw_map_put(hw_map *m, uint32_t key, void *value) {
	if (m->cap == 0 && map_rehash(m, MAP_MIN_CAP) != 0) return -1;
	// Grow at 70% (counting tombstones) so probe chains stay short.
	if ((m->used + 1) * 10 > m->cap * 7) {
		size_t new_cap = m->count * 2 > m->cap ? m->cap * 2 : m->cap;
		if (new_cap < MAP_MIN_CAP) new_cap = MAP_MIN_CAP;
		if (map_rehash(m, new_cap) != 0) return -1;
	}
	size_t idx = slot_index(m, key);
	hw_map_slot *tomb = NULL;
	for (;;) {
		hw_map_slot *s = &m->slots[idx];
		if (s->state == SLOT_EMPTY) break;
		if (s->state == SLOT_USED && s->key == key) return 1;
		if (s->state == SLOT_TOMB && !tomb) tomb = s;
		idx = (idx + 1) & (m->cap - 1);
	}
	hw_map_slot *dst = tomb ? tomb : &m->slots[idx];
	if (!tomb) m->used++;
	dst->key = key;
	dst->state = SLOT_USED;
	dst->value = value;
	m->count++;
	return 0;
}

static hw_map_slot *map_find(const hw_map *m, uint32_t key) {
	if (m->cap == 0) return NULL;
	size_t idx = slot_index(m, key);
	for (;;) {
		hw_map_slot *s = &m->slots[idx];
		if (s->state == SLOT_EMPTY) return NULL;
		if (s->state == SLOT_USED && s->key == key) return s;
		idx = (idx + 1) & (m->cap - 1);
	}
}

void *hw_map_get(const hw_map *m, uint32_t key) {
	hw_map_slot *s = map_find(m, key);
	return s ? s->value : NULL;
}

void *hw_map_remove(hw_map *m, uint32_t key) {
	hw_map_slot *s = map_find(m, key);
	if (!s) return NULL;
	void *v = s->value;
	s->state = SLOT_TOMB;
	s->value = NULL;
	m->count--;
	return v;
}

void hw_map_each(hw_map *m, hw_map_visit cb, void *ud) {
	for (size_t i = 0; i < m->cap; i++) {
		hw_map_slot *s = &m->slots[i];
		if (s->state != SLOT_USED) continue;
		if (cb(s->key, s->value, ud) != 0) return;
	}
}
