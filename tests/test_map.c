#include "holywisp/map.h"

#include "test.h"

static int count_visit(uint32_t key, void *value, void *ud) {
	(*(int *)ud)++;
	return 0;
}

static int remove_odd_visit(uint32_t key, void *value, void *ud) {
	if (key & 1) hw_map_remove(ud, key);
	return 0;
}

static void test_put_get_remove(void) {
	hw_map m;
	hw_map_init(&m);
	int values[10000];
	for (uint32_t i = 0; i < 10000; i++) {
		values[i] = (int)i;
		CHECK_EQ(hw_map_put(&m, (i + 1) * 2654435761u, &values[i]), 0);
	}
	CHECK_EQ(hw_map_count(&m), 10000);
	for (uint32_t i = 0; i < 10000; i++) CHECK(hw_map_get(&m, (i + 1) * 2654435761u) == &values[i], "get %u", i);
	CHECK(hw_map_get(&m, 12345) == NULL, "missing key");
	CHECK_EQ(hw_map_put(&m, 0, &values[0]), 0);
	CHECK_EQ(hw_map_put(&m, 0, &values[1]), 1);
	CHECK(hw_map_get(&m, 0) == &values[0], "duplicate put does not replace");
	CHECK(hw_map_remove(&m, 0) == &values[0], "remove returns value");
	CHECK(hw_map_remove(&m, 0) == NULL, "second remove");
	for (uint32_t i = 0; i < 5000; i++) CHECK(hw_map_remove(&m, (i + 1) * 2654435761u) == &values[i], "remove %u", i);
	CHECK_EQ(hw_map_count(&m), 5000);
	for (uint32_t i = 5000; i < 10000; i++) {
		CHECK(hw_map_get(&m, (i + 1) * 2654435761u) == &values[i], "survived %u", i);
	}
	hw_map_free(&m);
}

static void test_tombstone_churn(void) {
	// Insert/remove the same small set many times: tombstones must not fill the table.
	hw_map m;
	hw_map_init(&m);
	int v = 1;
	for (uint32_t round = 0; round < 100000; round++) {
		CHECK_EQ(hw_map_put(&m, round, &v), 0);
		CHECK(hw_map_remove(&m, round) == &v, "round %u", round);
	}
	CHECK_EQ(hw_map_count(&m), 0);
	CHECK(m.cap <= 64, "capacity %zu after churn", m.cap);
	hw_map_free(&m);
}

static void test_each(void) {
	hw_map m;
	hw_map_init(&m);
	int v = 1;
	for (uint32_t i = 1; i <= 100; i++) hw_map_put(&m, i, &v);
	int n = 0;
	hw_map_each(&m, count_visit, &n);
	CHECK_EQ(n, 100);
	hw_map_each(&m, remove_odd_visit, &m);
	CHECK_EQ(hw_map_count(&m), 50);
	for (uint32_t i = 1; i <= 100; i++) CHECK((hw_map_get(&m, i) != NULL) == !(i & 1), "key %u", i);
	hw_map_free(&m);
}

int main(void) {
	RUN(test_put_get_remove);
	RUN(test_tombstone_churn);
	RUN(test_each);
	return 0;
}
