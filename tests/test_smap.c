#include "holywisp/smap.h"

#include "test.h"

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

int main(void) {
	RUN(test_put_get_remove);
	RUN(test_tombstone_churn);
	RUN(test_each_and_hash);
	return 0;
}
