/*
 * holywisp/map.h - open-addressing hash map from uint32_t to a pointer. Not thread-safe.
 *
 * Used per connection for stream_id -> stream. Keys are arbitrary (clients pick them), values are
 * non-NULL pointers. Deletion uses tombstones; the table rehashes when it gets crowded.
 */
#ifndef HOLYWISP_MAP_H
#define HOLYWISP_MAP_H

#include <stddef.h>
#include <stdint.h>

typedef struct hw_map_slot {
	uint32_t key;
	uint8_t state; // 0 empty, 1 used, 2 tombstone
	void *value;
} hw_map_slot;

typedef struct hw_map {
	hw_map_slot *slots;
	size_t cap; // power of two or 0
	size_t count;
	size_t used; // count + tombstones
} hw_map;

void hw_map_init(hw_map *m);
void hw_map_free(hw_map *m);
// 0 on success, -1 (ENOMEM) on allocation failure, 1 when the key already exists (nothing changed).
int hw_map_put(hw_map *m, uint32_t key, void *value);
void *hw_map_get(const hw_map *m, uint32_t key);
// Returns the removed value or NULL.
void *hw_map_remove(hw_map *m, uint32_t key);
static inline size_t hw_map_count(const hw_map *m) {
	return m->count;
}
// Visit every entry. cb may remove the entry it is given; returning non-zero stops the walk.
typedef int (*hw_map_visit)(uint32_t key, void *value, void *ud);
void hw_map_each(hw_map *m, hw_map_visit cb, void *ud);

#endif
