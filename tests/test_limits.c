#include "holywisp/hw.h"
#include "holywisp/limits.h"

#include "test.h"

#include <unistd.h>

static void test_window(void) {
	hw_window *w = hw_window_new(3, 100); // 3 per 100 ms
	CHECK(w != NULL, "new");
	for (int i = 0; i < 3; i++) CHECK(hw_window_allow(w, "a"), "allow %d", i);
	CHECK(!hw_window_allow(w, "a"), "fourth blocked");
	CHECK(hw_window_allow(w, "b"), "other key independent");
	CHECK_EQ(hw_window_count(w), 2);
	usleep(120000);
	CHECK(hw_window_allow(w, "a"), "window reset after expiry");
	hw_window_evict(w, 50); // everything older than 50 ms gone
	CHECK(hw_window_count(w) <= 1, "evicted");
	hw_window_free(w);
	// A zero limit is unlimited.
	hw_window *z = hw_window_new(0, 1000);
	for (int i = 0; i < 1000; i++) CHECK(hw_window_allow(z, "x"), "unlimited");
	hw_window_free(z);
}

static void test_semaphore(void) {
	hw_semaphore s;
	hw_semaphore_init(&s, 2);
	CHECK(hw_semaphore_try(&s), "1");
	CHECK(hw_semaphore_try(&s), "2");
	CHECK(!hw_semaphore_try(&s), "3 blocked");
	CHECK_EQ(hw_semaphore_value(&s), 2);
	hw_semaphore_release(&s);
	CHECK(hw_semaphore_try(&s), "after release");
	hw_semaphore_release(&s);
	hw_semaphore_release(&s);
	CHECK_EQ(hw_semaphore_value(&s), 0);
	// max <= 0 is unlimited.
	hw_semaphore u;
	hw_semaphore_init(&u, 0);
	for (int i = 0; i < 1000; i++) CHECK(hw_semaphore_try(&u), "unlimited");
}

static void test_gauge(void) {
	hw_gauge *g = hw_gauge_new(2);
	CHECK(g != NULL, "new");
	CHECK_EQ(hw_gauge_acquire(g, "a"), 1);
	CHECK_EQ(hw_gauge_acquire(g, "a"), 1);
	CHECK_EQ(hw_gauge_acquire(g, "a"), 0);
	CHECK_EQ(hw_gauge_value(g, "a"), 2);
	// Another key has its own count.
	CHECK_EQ(hw_gauge_acquire(g, "b"), 1);
	hw_gauge_release(g, "a");
	CHECK_EQ(hw_gauge_acquire(g, "a"), 1);
	hw_gauge_release(g, "a");
	hw_gauge_release(g, "a");
	CHECK_EQ(hw_gauge_value(g, "a"), 0);
	// A release nobody holds does not go below zero, and does not lend the next holder a slot.
	hw_gauge_release(g, "a");
	CHECK_EQ(hw_gauge_acquire(g, "a"), 1);
	CHECK_EQ(hw_gauge_acquire(g, "a"), 1);
	CHECK_EQ(hw_gauge_acquire(g, "a"), 0);
	hw_gauge_free(g);
	// No limit, or no gauge at all: let through, nothing to release.
	hw_gauge *u = hw_gauge_new(0);
	CHECK_EQ(hw_gauge_acquire(u, "a"), -1);
	hw_gauge_free(u);
	CHECK_EQ(hw_gauge_acquire(NULL, "a"), -1);
	hw_gauge_release(NULL, "a");
}

static void test_bandwidth(void) {
	// 1 MiB/s. The first second is a free burst, then charges accrue.
	hw_bandwidth *b = hw_bandwidth_new(1024 * 1024);
	CHECK(b != NULL, "new");
	// Spend the burst plus a second's worth; the next charge must demand a wait.
	uint64_t total_wait = 0;
	for (int i = 0; i < 8; i++) total_wait += hw_bandwidth_charge(b, "ip", 1024 * 1024);
	CHECK(total_wait > 0, "a wait was required after the burst");
	// A different key has its own budget and its own free burst.
	CHECK_EQ(hw_bandwidth_charge(b, "other", 1024), 0);
	hw_bandwidth_free(b);
	CHECK(hw_bandwidth_new(0) == NULL, "zero rate disables");
}

static void test_sigdet(void) {
	hw_sigdet d;
	memset(&d, 0, sizeof(d));
	uint64_t t = 1000;
	// Below min_samples: never matches.
	for (int i = 0; i < 10; i++) hw_sigdet_record(&d, 0, t++, 2000);
	CHECK(!hw_sigdet_match(&d, 20, 0.5), "not enough samples");
	// 40 failures out of 50: ratio 0.8.
	memset(&d, 0, sizeof(d));
	t = 1000;
	for (int i = 0; i < 50; i++) hw_sigdet_record(&d, i < 10, t++, 100000);
	CHECK(hw_sigdet_match(&d, 20, 0.75), "high failure ratio matches");
	CHECK(!hw_sigdet_match(&d, 20, 0.95), "below the demanded ratio");
	// Old samples age out of the window.
	memset(&d, 0, sizeof(d));
	for (int i = 0; i < 40; i++) hw_sigdet_record(&d, 0, 1000, 500); // all at t=1000
	hw_sigdet_record(&d, 1, 2000, 500);                              // 1000 ms later: the rest expire
	CHECK(!hw_sigdet_match(&d, 10, 0.5), "stale failures dropped");
	CHECK_EQ(hw_sigdet_last(&d), 2000);
	memset(&d, 0, sizeof(d));
	CHECK_EQ(hw_sigdet_last(&d), 0);
}

int main(void) {
	RUN(test_window);
	RUN(test_semaphore);
	RUN(test_gauge);
	RUN(test_bandwidth);
	RUN(test_sigdet);
	return 0;
}
