/*
 * holywisp/loop.h - single-threaded event loop (epoll on Linux, kqueue on macOS, select on Windows).
 *
 * Every worker thread owns one hw_loop and all the fds, timers and objects registered on it. Only
 * hw_loop_post() and hw_loop_stop() may be called from another thread; both wake the loop through
 * a descriptor it watches. Callbacks may add, modify and remove fds and timers freely, including their own.
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
typedef void (*hw_batch_cb)(hw_loop *loop, void *ud);

hw_loop *hw_loop_new(void);
// Does not close registered fds. Pending posted tasks are dropped, not run.
void hw_loop_free(hw_loop *loop);

// One watcher per fd. The fd must be non-blocking.
int hw_loop_add_fd(hw_loop *loop, int fd, unsigned events, hw_io_cb cb, void *ud);
int hw_loop_mod_fd(hw_loop *loop, int fd, unsigned events);
void hw_loop_del_fd(hw_loop *loop, int fd);

// Timers in monotonic milliseconds. repeat_ms 0 = one shot: the timer is freed before its callback
// runs, so the callback forgets the handle and never cancels it. A repeating timer may be cancelled
// from inside its own callback.
hw_timer *hw_loop_add_timer(hw_loop *loop, uint64_t delay_ms, uint64_t repeat_ms, hw_timer_cb cb, void *ud);
void hw_loop_cancel_timer(hw_loop *loop, hw_timer *t);

// Run cb on the loop thread at the start of its next iteration. Thread-safe.
int hw_loop_post(hw_loop *loop, hw_task_cb cb, void *ud);

// One hook per loop, called on the loop thread each time a batch of callbacks is over: once after
// the posted tasks of an iteration have run, and once after its fd events and timers. It is the
// place for work that is cheaper done once per batch than once per callback, like writing what
// several callbacks queued for the same socket. Nothing posted, armed or queued by the callbacks
// of a batch is left waiting across a sleep: the hook always runs before the loop blocks. NULL
// clears it.
void hw_loop_set_batch_end(hw_loop *loop, hw_batch_cb cb, void *ud);

// After an iteration that delivered events, poll without sleeping for up to `us` microseconds
// before blocking. A relay between two busy peers is woken again within microseconds, and going to
// sleep and being woken costs more than waiting that long; an idle loop never spins. 0 (the
// default) always blocks.
void hw_loop_set_busy_poll(hw_loop *loop, unsigned us);

// Run until hw_loop_stop(). Returns 0, or -1 on a fatal backend error.
int hw_loop_run(hw_loop *loop);
// One iteration: wait up to timeout_ms (-1 = until something happens) and dispatch.
int hw_loop_run_once(hw_loop *loop, int timeout_ms);
void hw_loop_stop(hw_loop *loop); // thread-safe
int hw_loop_stopped(const hw_loop *loop);

#endif
