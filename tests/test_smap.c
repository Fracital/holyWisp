#include "holywisp/smap.h"

#include "test.h"

#include <stdint.h>
#include <stdio.h>

static int count_visit(const char *key, void *value, void *ud) {
	(*(int *)ud)++;
	return 0;
}

static void test_put_get_remove(void) {
	hw_smap m;
	hw_smap_init(&m);
	char keys[2000][16];
	int values[2000];
	for (int i = 0; i < 2000; i++) {
		snprintf(keys[i], sizeof(keys[i]), "key-%d", i);
		values[i] = i;
		CHECK_EQ(hw_smap_put(&m, keys[i], &values[i]), 0);
	}
	CHECK_EQ(hw_smap_count(&m), 2000);
	for (int i = 0; i < 2000; i++) CHECK(hw_smap_get(&m, keys[i]) == &values[i], "get %d", i);
	CHECK(hw_smap_get(&m, "absent") == NULL, "missing");
	CHECK_EQ(hw_smap_put(&m, "key-0", &values[1]), 1); // duplicate
	CHECK(hw_smap_get(&m, "key-0") == &values[0], "duplicate keeps first");
	CHECK(hw_smap_remove(&m, "key-0") == &values[0], "remove returns value");
	CHECK(hw_smap_remove(&m, "key-0") == NULL, "second remove");
	CHECK_EQ(hw_smap_count(&m), 1999);
	hw_smap_free(&m);
}

static void test_tombstone_churn(void) {
	hw_smap m;
	hw_smap_init(&m);
	int v = 1;
	for (int i = 0; i < 100000; i++) {
		char key[16];
		snprintf(key, sizeof(key), "k%d", i % 32);
		if (!hw_smap_get(&m, key)) CHECK_EQ(hw_smap_put(&m, key, &v), 0);
		hw_smap_remove(&m, key);
	}
	CHECK_EQ(hw_smap_count(&m), 0);
	CHECK(m.cap <= 64, "capacity %zu stayed bounded", m.cap);
	hw_smap_free(&m);
}

static void test_each_and_hash(void) {
	hw_smap m;
	hw_smap_init(&m);
	int v = 0;
	for (int i = 0; i < 50; i++) {
		char key[16];
		snprintf(key, sizeof(key), "e%d", i);
		hw_smap_put(&m, key, &v);
	}
	int n = 0;
	hw_smap_each(&m, count_visit, &n);
	CHECK_EQ(n, 50);
	CHECK(hw_str_hash("abc") == hw_str_hash("abc"), "hash is stable");
	CHECK(hw_str_hash("abc") != 0, "hash is never zero");
	hw_smap_free(&m);
}

// The hash anyone can compute: FNV-1a, which is what the map used before it was keyed.
static uint32_t fnv1a(const char *s) {
	uint32_t h = 2166136261u;
	for (; *s; s++) {
		h ^= (uint8_t)*s;
		h *= 16777619u;
	}
	return h;
}

// A client that chooses the keys ("ip:port" destinations) must not be able to choose their slots.
// These are keys picked to share the low 16 bits of an unkeyed FNV-1a, so that every one of them
// starts its probe in the same slot of a 65536-slot table. Under the keyed hash they scatter.
static void test_hash_is_keyed(void) {
	enum {
		KEYS = 32
	};
	static char keys[KEYS][24];
	int found = 0;
	for (unsigned i = 0; found < KEYS && i < 100000000u; i++) {
		char k[24];
		snprintf(k, sizeof(k), "198.51.%u.%u:%u", i >> 24 & 255, i >> 16 & 255, i & 65535);
		if ((fnv1a(k) & 0xffff) == 0x1234) memcpy(keys[found++], k, sizeof(k));
	}
	CHECK_EQ(found, KEYS);
	int same_slot = 0, same_hash = 0;
	for (int i = 0; i < KEYS; i++) {
		if ((hw_str_hash(keys[i]) & 0xffff) == (hw_str_hash(keys[0]) & 0xffff)) same_slot++;
		if (hw_str_hash(keys[i]) == fnv1a(keys[i])) same_hash++;
	}
	// By chance one other key in 65536 shares a slot with the first; all 32 never do.
	CHECK(same_slot <= 4, "%d of %d chosen keys still share a slot", same_slot, KEYS);
	CHECK(same_hash <= 1, "%d of %d hashes are plain FNV-1a", same_hash, KEYS);
	// And the map still finds every one of them.
	hw_smap m;
	hw_smap_init(&m);
	for (int i = 0; i < KEYS; i++) CHECK_EQ(hw_smap_put(&m, keys[i], keys[i]), 0);
	for (int i = 0; i < KEYS; i++) CHECK(hw_smap_get(&m, keys[i]) == keys[i], "get %s", keys[i]);
	hw_smap_free(&m);
}

int main(void) {
	RUN(test_put_get_remove);
	RUN(test_tombstone_churn);
	RUN(test_each_and_hash);
	RUN(test_hash_is_keyed);
	return 0;
}
