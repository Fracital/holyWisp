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

int main(void) {
	RUN(test_timers_fire_in_order);
	RUN(test_repeating_timer_cancels_itself);
	RUN(test_post_from_other_thread);
	RUN(test_fd_events);
	return 0;
}
