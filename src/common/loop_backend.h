/*
 * The kernel half of the event loop: readiness for a set of fds. loop.c owns everything else (the
 * fd table and its generations, timers, posted tasks, the batch hook) and is the same on every
 * platform; loop_epoll.c, loop_kqueue.c and loop_select.c each implement these five calls.
 *
 * Readiness is level-triggered: an fd is reported for as long as the condition holds and the
 * interest is registered. A backend may report an fd more than once in a batch, and may report
 * an event the interest no longer covers if it changed inside the batch; callbacks already have
 * to cope with a socket that turns out not to be ready.
 */
#ifndef HOLYWISP_LOOP_BACKEND_H
#define HOLYWISP_LOOP_BACKEND_H

#include <stdint.h>

typedef struct hw_poll_event {
	int fd;
	uint32_t gen;    // the generation the fd was registered with
	unsigned events; // HW_EV_*
} hw_poll_event;

// A new poller, close-on-exec. It is a descriptor: close(2) frees it. -1 with errno on failure.
int hw_poller_open(void);

// What hw_loop_post() and hw_loop_stop() wake the loop through: fds[0] is watched for reading,
// writing eight bytes to fds[1] makes it readable, and both are non-blocking. They may be the
// same descriptor. 0, or -1 with errno.
int hw_poller_wake_open(int fds[2]);

// Set the interest in fd to `events` (HW_EV_READ | HW_EV_WRITE, or 0 for errors and hang-ups only
// where the kernel reports those unasked). `old` is the interest it has now; `fresh` is nonzero
// when the fd is not in the poller yet. 0, or -1 with errno.
int hw_poller_set(int poller, int fd, int fresh, unsigned old, unsigned events, uint32_t gen);

// Forget fd, which had interest `events`. Harmless when the fd is already closed.
void hw_poller_del(int poller, int fd, unsigned events);

// Wait up to timeout_ms (-1 = forever, 0 = poll) and fill out[0..max). The count, 0 on timeout,
// or -1 with errno (EINTR included).
int hw_poller_wait(int poller, hw_poll_event *out, int max, int timeout_ms);

#endif
