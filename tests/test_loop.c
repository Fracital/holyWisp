#include "holywisp/hw.h"
#include "holywisp/loop.h"
#include "holywisp/net.h"
#include "holywisp/sys.h"

#include "test.h"

#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>

static int g_order[8];
static int g_norder;

static void record_cb(hw_loop *loop, void *ud) {
	g_order[g_norder++] = (int)(intptr_t)ud;
	if (g_norder == 3) hw_loop_stop(loop);
}

// The two clocks are one: microseconds over 1000 are the milliseconds, and they tick finer.
static void test_clock_us(void) {
	int fine = 0;
	for (int i = 0; i < 1000; i++) {
		uint64_t ms0 = hw_now_ms(), us = hw_now_us(), ms1 = hw_now_ms();
		CHECK(ms0 <= us / 1000 && us / 1000 <= ms1, "%llu ms, %llu us, %llu ms", (unsigned long long)ms0,
		      (unsigned long long)us, (unsigned long long)ms1);
		fine |= us % 1000 != 0;
	}
	CHECK(fine, "every reading was a whole millisecond");
	uint64_t a = hw_now_us(), b = a;
	while (b - a < 2000) b = hw_now_us();
	CHECK(b - a < 1000000, "2 ms took %llu us", (unsigned long long)(b - a));
}

static void test_timers_fire_in_order(void) {
	hw_loop *loop = hw_loop_new();
	CHECK(loop != NULL, "loop");
	g_norder = 0;
	hw_loop_add_timer(loop, 30, 0, record_cb, (void *)3);
	hw_loop_add_timer(loop, 10, 0, record_cb, (void *)1);
	hw_timer *cancelled = hw_loop_add_timer(loop, 15, 0, record_cb, (void *)9);
	hw_loop_add_timer(loop, 20, 0, record_cb, (void *)2);
	hw_loop_cancel_timer(loop, cancelled);
	uint64_t start = hw_now_ms();
	CHECK_EQ(hw_loop_run(loop), 0);
	CHECK_EQ(g_norder, 3);
	CHECK_EQ(g_order[0], 1);
	CHECK_EQ(g_order[1], 2);
	CHECK_EQ(g_order[2], 3);
	CHECK(hw_now_ms() - start >= 25, "waited for the 30 ms timer");
	hw_loop_free(loop);
}

static int g_repeats;
static hw_timer *g_repeat_timer;

static void repeat_cb(hw_loop *loop, void *ud) {
	if (++g_repeats == 5) {
		// Cancelling a repeating timer from inside its own callback is allowed.
		hw_loop_cancel_timer(loop, g_repeat_timer);
		g_repeat_timer = NULL;
		hw_loop_stop(loop);
	}
}

static void test_repeating_timer_cancels_itself(void) {
	hw_loop *loop = hw_loop_new();
	g_repeats = 0;
	g_repeat_timer = hw_loop_add_timer(loop, 1, 2, repeat_cb, NULL);
	CHECK_EQ(hw_loop_run(loop), 0);
	CHECK_EQ(g_repeats, 5);
	CHECK(g_repeat_timer == NULL, "cancelled");
	hw_loop_free(loop);
}

// When a timer fired (hw_now_us), for the microsecond timer tests.
static uint64_t g_fired_us;
static int g_us_order[8];
static int g_us_norder;

static void fired_cb(hw_loop *loop, void *ud) {
	g_fired_us = hw_now_us();
	hw_loop_stop(loop);
}

static void us_order_cb(hw_loop *loop, void *ud) {
	g_us_order[g_us_norder++] = (int)(intptr_t)ud;
	if (g_us_norder == 4) hw_loop_stop(loop);
}

static int cmp_u64(const void *a, const void *b) {
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return x < y ? -1 : x > y;
}

// A microsecond timer fires no earlier than its delay, and where the loop's waits keep microseconds
// (hw_loop_timer_resolution_us 1) well within a millisecond of it: a pacer releasing a few
// datagrams every hundred microseconds is woken for each release, not on the next millisecond.
// Judged by the median of 25 tries, so that a busy machine's odd late wakeup does not fail it.
static void test_timer_us_resolution(void) {
	hw_loop *loop = hw_loop_new();
	unsigned res = hw_loop_timer_resolution_us(loop);
	CHECK(res == 1 || res == 1000, "resolution %u", res);
	enum {
		TRIES = 25,
		DELAY_US = 300
	};
	uint64_t late[TRIES];
	for (int i = 0; i < TRIES; i++) {
		uint64_t set = hw_now_us();
		CHECK(hw_loop_add_timer_us(loop, DELAY_US, 0, fired_cb, NULL) != NULL, "add");
		CHECK_EQ(hw_loop_run(loop), 0);
		// hw_loop_run returns at once on a stopped loop; a fresh one per try would do as well.
		hw_loop_free(loop);
		loop = hw_loop_new();
		CHECK(g_fired_us >= set + DELAY_US, "try %d fired %llu us after it was set, delay %d", i,
		      (unsigned long long)(g_fired_us - set), DELAY_US);
		late[i] = g_fired_us - set - DELAY_US;
	}
	qsort(late, TRIES, sizeof(late[0]), cmp_u64);
	printf("  a %d us timer fired late by %llu us (median), %llu us (worst of %d)\n", DELAY_US,
	       (unsigned long long)late[TRIES / 2], (unsigned long long)late[TRIES - 1], TRIES);
	if (res == 1) {
		CHECK(late[TRIES / 2] < 500, "median lateness %llu us on a loop that waits in microseconds",
		      (unsigned long long)late[TRIES / 2]);
	}
	hw_loop_free(loop);
}

// Microsecond and millisecond timers share one heap and fire in the order they are due, and a
// repeating microsecond timer repeats at its period.
static int g_us_repeats;
static hw_timer *g_us_repeat_timer;

static void us_repeat_cb(hw_loop *loop, void *ud) {
	if (++g_us_repeats == 10) {
		hw_loop_cancel_timer(loop, g_us_repeat_timer);
		hw_loop_stop(loop);
	}
}

static void test_timer_us_mixed(void) {
	hw_loop *loop = hw_loop_new();
	g_us_norder = 0;
	// A millisecond timer of n is due between n - 1 and n ms from now (on a tick): 2 between 1000
	// and 2000 us, 4 between 3000 and 4000.
	hw_loop_add_timer(loop, 4, 0, us_order_cb, (void *)4);
	hw_loop_add_timer_us(loop, 2500, 0, us_order_cb, (void *)3);
	hw_loop_add_timer(loop, 2, 0, us_order_cb, (void *)2);
	hw_loop_add_timer_us(loop, 200, 0, us_order_cb, (void *)1);
	CHECK_EQ(hw_loop_run(loop), 0);
	CHECK_EQ(g_us_norder, 4);
	for (int i = 0; i < 4; i++) CHECK(g_us_order[i] == i + 1, "fired %d as %d", g_us_order[i], i + 1);
	hw_loop_free(loop);

	loop = hw_loop_new();
	g_us_repeats = 0;
	uint64_t start = hw_now_us();
	g_us_repeat_timer = hw_loop_add_timer_us(loop, 100, 200, us_repeat_cb, NULL);
	CHECK_EQ(hw_loop_run(loop), 0);
	CHECK_EQ(g_us_repeats, 10);
	uint64_t took = hw_now_us() - start;
	CHECK(took >= 100 + 9 * 200, "ten repeats took %llu us", (unsigned long long)took);
	hw_loop_free(loop);
}

// A millisecond timer is due on a tick of hw_now_ms, as before the heap was in microseconds: one
// of 2 ms fires once hw_now_ms has moved on by 2, never before.
static void test_timer_ms_ticks(void) {
	hw_loop *loop = hw_loop_new();
	for (int i = 0; i < 5; i++) {
		uint64_t set_ms = hw_now_ms();
		hw_loop_add_timer(loop, 2, 0, fired_cb, NULL);
		CHECK_EQ(hw_loop_run(loop), 0);
		hw_loop_free(loop);
		loop = hw_loop_new();
		CHECK(g_fired_us / 1000 >= set_ms + 2, "fired at %llu us, set at %llu ms", (unsigned long long)g_fired_us,
		      (unsigned long long)set_ms);
	}
	hw_loop_free(loop);
}

static void wake_once_cb(hw_loop *loop, int fd, unsigned events, void *ud) {
	char c;
	ssize_t r = read(fd, &c, 1);
	(void)r;
}

// Busy polling never makes a timer late: one due sooner than the polling would end fires on time.
// The polling used to run its whole course before the loop looked at the timers again, which with
// a millisecond's waits was within the tick, and with a pacer's 300 us is ten times late.
static void test_busy_poll_keeps_timers(void) {
	hw_loop *loop = hw_loop_new();
	hw_loop_set_busy_poll(loop, 20000);
	int p[2];
	CHECK_EQ(pipe(p), 0);
	hw_set_nonblock(p[0]);
	CHECK_EQ(hw_loop_add_fd(loop, p[0], HW_EV_READ, wake_once_cb, NULL), 0);
	// An event, so that the next iteration polls.
	CHECK_EQ(write(p[1], "x", 1), 1);
	CHECK_EQ(hw_loop_run_once(loop, 0), 0);
	uint64_t set = hw_now_us();
	hw_loop_add_timer_us(loop, 500, 0, fired_cb, NULL);
	g_fired_us = 0;
	while (!hw_loop_stopped(loop) && hw_now_us() - set < 1000000) CHECK_EQ(hw_loop_run_once(loop, -1), 0);
	CHECK(g_fired_us >= set + 500, "fired early");
	CHECK(g_fired_us - set < 10000, "a 500 us timer fired after %llu us of a 20 ms busy poll",
	      (unsigned long long)(g_fired_us - set));
	hw_loop_del_fd(loop, p[0]);
	close(p[0]);
	close(p[1]);
	hw_loop_free(loop);
}

static void *poster(void *arg);

static void test_post_from_other_thread(void) {
	hw_loop *loop = hw_loop_new();
	g_norder = 0;
	pthread_t th;
	CHECK_EQ(pthread_create(&th, NULL, poster, loop), 0);
	CHECK_EQ(hw_loop_run(loop), 0);
	pthread_join(th, NULL);
	CHECK_EQ(g_norder, 3);
	CHECK_EQ(g_order[0], 1);
	CHECK_EQ(g_order[2], 3);
	hw_loop_free(loop);
}

static void *poster(void *arg) {
	hw_loop *loop = arg;
	usleep(10000);
	for (int i = 1; i <= 3; i++) hw_loop_post(loop, record_cb, (void *)(intptr_t)i);
	return NULL;
}

static void *stopper(void *arg) {
	usleep(10000);
	hw_loop_stop(arg);
	return NULL;
}

// A loop is not stopped until hw_loop_stop, from its own thread or another, and then it stays so.
static void test_loop_stopped(void) {
	hw_loop *loop = hw_loop_new();
	CHECK(loop != NULL, "loop");
	CHECK_EQ(hw_loop_stopped(loop), 0);
	CHECK_EQ(hw_loop_run_once(loop, 0), 0);
	CHECK_EQ(hw_loop_stopped(loop), 0);
	pthread_t th;
	CHECK_EQ(pthread_create(&th, NULL, stopper, loop), 0);
	CHECK_EQ(hw_loop_run(loop), 0);
	pthread_join(th, NULL);
	CHECK_EQ(hw_loop_stopped(loop), 1);
	CHECK_EQ(hw_loop_run_once(loop, 0), 0);
	CHECK_EQ(hw_loop_stopped(loop), 1);
	// Running a stopped loop returns at once.
	uint64_t start = hw_now_ms();
	CHECK_EQ(hw_loop_run(loop), 0);
	CHECK(hw_now_ms() - start < 1000, "run on a stopped loop returned after %llu ms",
	      (unsigned long long)(hw_now_ms() - start));
	hw_loop_free(loop);

	loop = hw_loop_new();
	hw_loop_stop(loop);
	CHECK_EQ(hw_loop_stopped(loop), 1);
	hw_loop_stop(loop);
	CHECK_EQ(hw_loop_stopped(loop), 1);
	hw_loop_free(loop);
}

static int g_pipe_bytes;

static void pipe_cb(hw_loop *loop, int fd, unsigned events, void *ud) {
	char buf[16];
	ssize_t n = read(fd, buf, sizeof(buf));
	if (n > 0) g_pipe_bytes += (int)n;
	if (g_pipe_bytes >= 5) {
		hw_loop_del_fd(loop, fd);
		hw_loop_stop(loop);
	}
}

static void test_fd_events(void) {
	hw_loop *loop = hw_loop_new();
	int p[2];
	CHECK_EQ(pipe(p), 0);
	hw_set_nonblock(p[0]);
	g_pipe_bytes = 0;
	CHECK_EQ(hw_loop_add_fd(loop, p[0], HW_EV_READ, pipe_cb, NULL), 0);
	CHECK(hw_loop_add_fd(loop, p[0], HW_EV_READ, pipe_cb, NULL) != 0, "double add rejected");
	CHECK_EQ(write(p[1], "hello", 5), 5);
	CHECK_EQ(hw_loop_run(loop), 0);
	CHECK_EQ(g_pipe_bytes, 5);
	CHECK(hw_loop_mod_fd(loop, p[0], HW_EV_WRITE) != 0, "mod after del fails");
	close(p[0]);
	close(p[1]);
	hw_loop_free(loop);
}

static int g_batch_ends;
static int g_batch_seen_at_timer;

static void batch_end_cb(hw_loop *loop, void *ud) {
	g_batch_ends++;
}

static void batch_timer_cb(hw_loop *loop, void *ud) {
	g_batch_seen_at_timer = g_batch_ends;
	hw_loop_stop(loop);
}

static void batch_task_cb(hw_loop *loop, void *ud) {
	*(int *)ud = g_batch_ends;
}

// The hook runs after the posted tasks and again after the events and timers of an iteration, so
// nothing a callback queued is still waiting when the loop goes to sleep.
static void test_batch_end_hook(void) {
	hw_loop *loop = hw_loop_new();
	g_batch_ends = 0;
	g_batch_seen_at_timer = -1;
	hw_loop_set_batch_end(loop, batch_end_cb, NULL);
	int at_task = -1;
	CHECK_EQ(hw_loop_post(loop, batch_task_cb, &at_task), 0);
	CHECK_EQ(hw_loop_run_once(loop, 0), 0);
	CHECK_EQ(at_task, 0);      // the task ran before any hook call
	CHECK_EQ(g_batch_ends, 2); // once after the tasks, once after the (empty) dispatch
	hw_loop_add_timer(loop, 5, 0, batch_timer_cb, NULL);
	CHECK_EQ(hw_loop_run(loop), 0);
	CHECK(g_batch_seen_at_timer >= 2, "hook count at timer: %d", g_batch_seen_at_timer);
	CHECK(g_batch_ends > g_batch_seen_at_timer, "hook ran after the timer: %d", g_batch_ends);
	int before = g_batch_ends;
	hw_loop_set_batch_end(loop, NULL, NULL);
	CHECK_EQ(hw_loop_run_once(loop, 0), 0);
	CHECK_EQ(g_batch_ends, before);
	hw_loop_free(loop);
}

static int g_poll_reads;

static void poll_pipe_cb(hw_loop *loop, int fd, unsigned events, void *ud) {
	char c;
	if (read(fd, &c, 1) == 1) g_poll_reads++;
	if (g_poll_reads >= 3) hw_loop_stop(loop);
}

static void *slow_writer(void *arg) {
	int fd = *(int *)arg;
	for (int i = 0; i < 3; i++) {
		usleep(2000);
		ssize_t r = write(fd, "x", 1);
		(void)r;
	}
	return NULL;
}

// Busy polling changes when the loop sleeps, never what it delivers: events that arrive while it
// polls and events that arrive after it gave up and blocked are all dispatched, and timers fire.
static void test_busy_poll(void) {
	hw_loop *loop = hw_loop_new();
	hw_loop_set_busy_poll(loop, 500);
	int p[2];
	CHECK_EQ(pipe(p), 0);
	hw_set_nonblock(p[0]);
	g_poll_reads = 0;
	CHECK_EQ(hw_loop_add_fd(loop, p[0], HW_EV_READ, poll_pipe_cb, NULL), 0);
	pthread_t th;
	CHECK_EQ(pthread_create(&th, NULL, slow_writer, &p[1]), 0);
	uint64_t start = hw_now_ms();
	CHECK_EQ(hw_loop_run(loop), 0);
	pthread_join(th, NULL);
	CHECK_EQ(g_poll_reads, 3);
	CHECK(hw_now_ms() - start < 2000, "took %llu ms", (unsigned long long)(hw_now_ms() - start));
	hw_loop_del_fd(loop, p[0]);
	close(p[0]);
	close(p[1]);
	hw_loop_free(loop);
}

static int g_quiet_events;

static void quiet_cb(hw_loop *loop, int fd, unsigned events, void *ud) {
	g_quiet_events++;
}

// An fd that is watched for nothing is not woken by its peer's half-close. The condition never
// clears, so a backend that reported it there would turn every paused socket whose peer finished
// into a busy loop. With reading wanted again, the half-close is readable.
static void test_half_close_needs_read_interest(void) {
	hw_loop *loop = hw_loop_new();
	uint16_t port = 0;
	int lfd = hw_listen_tcp("127.0.0.1", 0, 0, 4, &port);
	CHECK(lfd >= 0, "listen");
	int peer = hw_connect_tcp("127.0.0.1", port, 2000);
	CHECK(peer >= 0, "connect");
	struct pollfd pfd = {.fd = lfd, .events = POLLIN};
	CHECK_EQ(poll(&pfd, 1, 2000), 1);
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);
	int fd = hw_sys_accept(lfd, (struct sockaddr *)&ss, &sl);
	CHECK(fd >= 0, "accept");
	close(lfd);

	g_quiet_events = 0;
	CHECK_EQ(hw_loop_add_fd(loop, fd, HW_EV_READ, quiet_cb, NULL), 0);
	CHECK_EQ(hw_loop_mod_fd(loop, fd, 0), 0);
	CHECK_EQ(shutdown(peer, SHUT_WR), 0);
	CHECK_EQ(hw_loop_run_once(loop, 100), 0);
	CHECK_EQ(g_quiet_events, 0);

	CHECK_EQ(hw_loop_mod_fd(loop, fd, HW_EV_READ), 0);
	CHECK_EQ(hw_loop_run_once(loop, 2000), 0);
	CHECK_EQ(g_quiet_events, 1);
	char byte;
	CHECK_EQ(recv(fd, &byte, 1, 0), 0);

	hw_loop_del_fd(loop, fd);
	close(fd);
	close(peer);
	hw_loop_free(loop);
}

int main(void) {
	RUN(test_clock_us);
	RUN(test_timers_fire_in_order);
	RUN(test_repeating_timer_cancels_itself);
	RUN(test_timer_us_resolution);
	RUN(test_timer_us_mixed);
	RUN(test_timer_ms_ticks);
	RUN(test_busy_poll_keeps_timers);
	RUN(test_post_from_other_thread);
	RUN(test_loop_stopped);
	RUN(test_fd_events);
	RUN(test_batch_end_hook);
	RUN(test_busy_poll);
	RUN(test_half_close_needs_read_interest);
	return 0;
}
