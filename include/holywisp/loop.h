/*
 * holywisp/loop.h - single-threaded epoll event loop.
 *
 * Every worker thread owns one hw_loop and all the fds, timers and objects registered on it. Only
 * hw_loop_post() and hw_loop_stop() may be called from another thread; both wake the loop through
 * an eventfd. Callbacks may add, modify and remove fds and timers freely, including their own.
 *
 * Events are delivered with the fd's generation checked, so an fd closed and reused inside the
 * same dispatch batch is never handed to a stale watcher.
 */
#ifndef HOLYWISP_LOOP_H
#define HOLYWISP_LOOP_H

#include <stdint.h>

typedef struct hw_loop hw_loop;
typedef struct hw_timer hw_timer;

enum {
	HW_EV_READ = 1u << 0,
	HW_EV_WRITE = 1u << 1,
	HW_EV_ERROR = 1u << 2, // reported only
	HW_EV_HUP = 1u << 3    // reported only
};

typedef void (*hw_io_cb)(hw_loop *loop, int fd, unsigned events, void *ud);
typedef void (*hw_timer_cb)(hw_loop *loop, void *ud);
typedef void (*hw_task_cb)(hw_loop *loop, void *ud);

hw_loop *hw_loop_new(void);
// Does not close registered fds. Pending posted tasks are dropped, not run.
void hw_loop_free(hw_loop *loop);

// One watcher per fd. The fd must be non-blocking.
int hw_loop_add_fd(hw_loop *loop, int fd, unsigned events, hw_io_cb cb, void *ud);
int hw_loop_mod_fd(hw_loop *loop, int fd, unsigned events);
void hw_loop_del_fd(hw_loop *loop, int fd);

// Timers in monotonic milliseconds. repeat_ms 0 = one shot: the handle is invalid once the
// callback has run, so forget it there. Cancelling a timer from inside its own callback is fine.
hw_timer *hw_loop_add_timer(hw_loop *loop, uint64_t delay_ms, uint64_t repeat_ms, hw_timer_cb cb, void *ud);
void hw_loop_cancel_timer(hw_loop *loop, hw_timer *t);

// Run cb on the loop thread at the start of its next iteration. Thread-safe.
int hw_loop_post(hw_loop *loop, hw_task_cb cb, void *ud);

// Run until hw_loop_stop(). Returns 0, or -1 on a fatal backend error.
int hw_loop_run(hw_loop *loop);
// One iteration: wait up to timeout_ms (-1 = until something happens) and dispatch.
int hw_loop_run_once(hw_loop *loop, int timeout_ms);
void hw_loop_stop(hw_loop *loop); // thread-safe
int hw_loop_stopped(const hw_loop *loop);

#endif
