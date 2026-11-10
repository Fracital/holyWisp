#include "holywisp/buf.h"

#include "test.h"

static void test_append_consume(void) {
	hw_buf b;
	hw_buf_init(&b);
	CHECK_EQ(hw_buf_avail(&b), 0);
	CHECK_EQ(hw_buf_append(&b, "hello", 5), 0);
	CHECK_EQ(hw_buf_append(&b, " world", 6), 0);
	CHECK_EQ(hw_buf_avail(&b), 11);
	CHECK(memcmp(hw_buf_head(&b), "hello world", 11) == 0, "content");
	hw_buf_consume(&b, 6);
	CHECK_EQ(hw_buf_avail(&b), 5);
	CHECK(memcmp(hw_buf_head(&b), "world", 5) == 0, "after consume");
	hw_buf_consume(&b, 5);
	CHECK_EQ(hw_buf_avail(&b), 0);
	CHECK_EQ(b.off, 0);
	CHECK_EQ(b.len, 0);
	hw_buf_free(&b);
	CHECK(b.data == NULL, "freed");
}

static void test_reserve_and_tail(void) {
	hw_buf b;
	hw_buf_init(&b);
	CHECK_EQ(hw_buf_reserve(&b, 1000), 0);
	CHECK(hw_buf_room(&b) >= 1000, "room %zu", hw_buf_room(&b));
	memset(hw_buf_tail(&b), 'x', 1000);
	hw_buf_commit(&b, 1000);
	CHECK_EQ(hw_buf_avail(&b), 1000);
	// Consuming most of it then reserving must reuse the front instead of growing.
	hw_buf_consume(&b, 900);
	size_t cap = b.cap;
	CHECK_EQ(hw_buf_reserve(&b, cap - 200), 0);
	CHECK_EQ(b.cap, cap);
	CHECK_EQ(b.off, 0);
	CHECK_EQ(hw_buf_avail(&b), 100);
	hw_buf_free(&b);
}

static void test_compaction_keeps_data(void) {
	hw_buf b;
	hw_buf_init(&b);
	uint8_t pattern[4096];
	for (size_t i = 0; i < sizeof(pattern); i++) pattern[i] = (uint8_t)(i * 7);
	size_t written = 0, read = 0;
	for (int round = 0; round < 200; round++) {
		CHECK_EQ(hw_buf_append(&b, pattern + (written % 4096),
		                       1000 <= 4096 - (written % 4096) ? 1000 : 4096 - (written % 4096)),
		         0);
		size_t n = 1000 <= 4096 - (written % 4096) ? 1000 : 4096 - (written % 4096);
		written += n;
		size_t take = hw_buf_avail(&b) > 700 ? 700 : hw_buf_avail(&b);
		for (size_t i = 0; i < take; i++) {
			CHECK(hw_buf_head(&b)[i] == pattern[(read + i) % 4096], "byte %zu", read + i);
		}
		hw_buf_consume(&b, take);
		read += take;
	}
	CHECK_EQ(hw_buf_avail(&b), written - read);
	CHECK(b.cap < 1 << 20, "capacity stayed bounded: %zu", b.cap);
	hw_buf_free(&b);
}

static void test_clear(void) {
	hw_buf b;
	hw_buf_init(&b);
	hw_buf_append(&b, "abc", 3);
	size_t cap = b.cap;
	hw_buf_clear(&b);
	CHECK_EQ(hw_buf_avail(&b), 0);
	CHECK_EQ(b.cap, cap);
	CHECK_EQ(hw_buf_append_u8(&b, 0x42), 0);
	CHECK_EQ(hw_buf_head(&b)[0], 0x42);
	hw_buf_free(&b);
}

static void test_shrink(void) {
	hw_buf b;
	hw_buf_init(&b);
	CHECK_EQ(hw_buf_reserve(&b, 1 << 20), 0);
	CHECK(b.cap >= 1 << 20, "grew");
	CHECK_EQ(hw_buf_append(&b, "abc", 3), 0);
	size_t cap = b.cap;
	hw_buf_shrink(&b, 4096);
	CHECK_EQ(b.cap, cap); // not empty: untouched
	CHECK(memcmp(hw_buf_head(&b), "abc", 3) == 0, "data kept");
	hw_buf_consume(&b, 3);
	CHECK_EQ(b.cap, cap); // consume alone never reallocates
	hw_buf_shrink(&b, 4096);
	CHECK_EQ(b.cap, 4096);
	hw_buf_shrink(&b, 8192); // already at or below keep: no-op
	CHECK_EQ(b.cap, 4096);
	CHECK_EQ(hw_buf_append(&b, "xyz", 3), 0);
	CHECK(memcmp(hw_buf_head(&b), "xyz", 3) == 0, "usable after shrink");
	hw_buf_consume(&b, 3);
	hw_buf_shrink(&b, 0);
	CHECK_EQ(b.cap, 0);
	CHECK(b.data == NULL, "freed");
	CHECK_EQ(hw_buf_append(&b, "q", 1), 0);
	hw_buf_free(&b);
}

int main(void) {
	RUN(test_append_consume);
	RUN(test_reserve_and_tail);
	RUN(test_compaction_keeps_data);
	RUN(test_shrink);
	RUN(test_clear);
	return 0;
}
