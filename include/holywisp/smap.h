/*
 * holywisp/smap.h - open-addressing hash map from a NUL-terminated string to a pointer.
 *
 * Keys are copied and owned by the map. Not thread-safe; the rate limiters that use it hold their
 * own lock. Deletion uses tombstones, like hw_map.
 */
#ifndef HOLYWISP_SMAP_H
#define HOLYWISP_SMAP_H

#include <stddef.h>
#include <stdint.h>

typedef struct hw_smap_slot {
	char *key; // NULL = empty; HW_SMAP_TOMB = deleted
	uint32_t hash;
	void *value;
} hw_smap_slot;

typedef struct hw_smap {
	hw_smap_slot *slots;
	size_t cap;
	size_t count;
	size_t used;
} hw_smap;

// FNV-1a over the string, also usable on its own for conn-local tables.
uint32_t hw_str_hash(const char *s);

void hw_smap_init(hw_smap *m);
// Frees the keys; the values are the caller's.
void hw_smap_free(hw_smap *m);
// 0 inserted, 1 key existed (unchanged), -1 ENOMEM.
int hw_smap_put(hw_smap *m, const char *key, void *value);
void *hw_smap_get(const hw_smap *m, const char *key);
void *hw_smap_remove(hw_smap *m, const char *key);
static inline size_t hw_smap_count(const hw_smap *m) {
	return m->count;
}
// Visit every entry; cb may remove the entry it is given. Non-zero stops the walk.
typedef int (*hw_smap_visit)(const char *key, void *value, void *ud);
void hw_smap_each(hw_smap *m, hw_smap_visit cb, void *ud);

#endif
