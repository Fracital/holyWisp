#include "holywisp/hw.h"
#include "holywisp/loop.h"

#include "test.h"

#include <pthread.h>
#include <unistd.h>

static int g_order[8];
static int g_norder;

static void record_cb(hw_loop *loop, void *ud) {
	g_order[g_norder++] = (int)(intptr_t)ud;
	if (g_norder == 3) hw_loop_stop(loop);
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

int main(void) {
	RUN(test_timers_fire_in_order);
	RUN(test_repeating_timer_cancels_itself);
	RUN(test_post_from_other_thread);
	RUN(test_fd_events);
	RUN(test_batch_end_hook);
	RUN(test_busy_poll);
	return 0;
}
