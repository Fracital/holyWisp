/*
 * holywisp/limits.h - the rate-limiting primitives behind flood protection.
 *
 * Everything here is shared by all workers and is therefore locked; each call takes the lock
 * once, does O(1) work and releases it. None of these block: the bandwidth limiter returns how
 * long the caller should pause, and the caller (a worker loop) sets a timer.
 */
#ifndef HOLYWISP_LIMITS_H
#define HOLYWISP_LIMITS_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

// Fixed-window counter per key: `limit` events per `window_ms`, the window starting at the first
// event. 0 limit = unlimited.
typedef struct hw_window hw_window;
hw_window *hw_window_new(int limit, uint64_t window_ms);
void hw_window_free(hw_window *w);
int hw_window_allow(hw_window *w, const char *key); // 1 allowed, 0 over the limit
// Drop keys whose window started more than idle_ms ago.
void hw_window_evict(hw_window *w, uint64_t idle_ms);
size_t hw_window_count(hw_window *w);

// Counting semaphore. max <= 0 = unlimited.
typedef struct hw_semaphore {
	_Atomic int64_t current;
	int64_t max;
} hw_semaphore;
void hw_semaphore_init(hw_semaphore *s, int64_t max);
int hw_semaphore_try(hw_semaphore *s); // 1 acquired
void hw_semaphore_release(hw_semaphore *s);
int64_t hw_semaphore_value(const hw_semaphore *s);

// Per-key bandwidth: a virtual clock per key advances by bytes / rate; a one-second burst is
// free. Returns the milliseconds the caller should wait before moving more bytes (0 = none).
typedef struct hw_bandwidth hw_bandwidth;
hw_bandwidth *hw_bandwidth_new(uint64_t bytes_per_second);
void hw_bandwidth_free(hw_bandwidth *b);
uint64_t hw_bandwidth_charge(hw_bandwidth *b, const char *key, size_t bytes);
void hw_bandwidth_evict(hw_bandwidth *b, uint64_t idle_ms);

// SYN-flood signature: a ring of recent connect outcomes to one destination from one client.
// Lives inside the connection (single-threaded), so no lock.
#define HW_SIGDET_RING 64
typedef struct hw_sigdet {
	uint64_t at[HW_SIGDET_RING];
	uint8_t ok[HW_SIGDET_RING];
	int head;
	int count;
} hw_sigdet;
void hw_sigdet_record(hw_sigdet *d, int ok, uint64_t now_ms, uint64_t window_ms);
// 1 when at least min_samples are in the window and the failed share is >= ratio.
int hw_sigdet_match(const hw_sigdet *d, int min_samples, double failed_ratio);

#endif
