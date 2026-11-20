/*
 * loop_backend.h on kqueue (macOS, the BSDs). Reading and writing are two filters on an fd, each
 * added and deleted as the interest changes and each reported as its own event; the generation
 * rides in the filter's user data. The wakeup is a pipe, whose write(2) is safe from a signal
 * handler.
 *
 * Unlike epoll, kqueue says nothing about an fd with no filter: a socket that is neither read nor
 * written learns of a reset when it is next watched. Nothing is lost by that; it is found later.
 *
 * A timed wait does not end on kevent's own timeout. Darwin gives that deadline leeway by the
 * waiting thread's QoS (timer_compute_leeway in xnu's timer_call.c): an eighth of the wait up to
 * 1 ms for an ordinary thread, and up to four times the wait for a lower latency tier, which is
 * what a CI runner or a launchd job may run at. A 300 us wait ended 1.1 ms late at the median on
 * the macOS CI runner, and the WebTransport pacer, told that the loop waits in microseconds,
 * would have released its bursts a millisecond apart. So the wait is a one-shot EVFILT_TIMER of
 * NOTE_USECONDS with NOTE_CRITICAL, which takes the real-time coalescing parameters, whose leeway
 * is 0. It is armed in the kevent call that waits (the change list is applied first), and the
 * next call re-arms it, or disables it for a wait without end: a timer that is armed again never
 * delivers the expiry of the arming before (filt_timertouch). Where that timer cannot be added,
 * the wait is kevent's timeout and the resolution reported is 1000, the leeway's bound.
 */
#include "holywisp/hw.h"
#include "holywisp/loop.h"

#include "loop_backend.h"

#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>

#include <sys/event.h>
#include <sys/types.h>

#define KQUEUE_BATCH 256

// The wait's timer. Timer idents are their own namespace, apart from the descriptors'.
#define WAIT_TIMER_IDENT  1
#define WAIT_TIMER_FFLAGS (NOTE_USECONDS | NOTE_CRITICAL)
// What the timer is set to while disabled: it is never delivered, and its callout runs once an hour.
#define WAIT_TIMER_IDLE_US 3600000000LL

// Set once a poller could not take the wait's timer: from then on a timed wait is kevent's timeout.
static _Atomic int g_timer_off;

static int timer_off(void) {
	return atomic_load_explicit(&g_timer_off, memory_order_relaxed);
}

// The change that arms the wait's timer for timeout_us (> 0), or disables it for a wait without
// end (-1), so that an arming for an earlier wait cannot end this one.
static void wait_timer(struct kevent *ch, int64_t timeout_us) {
	if (timeout_us > 0) {
		EV_SET(ch, WAIT_TIMER_IDENT, EVFILT_TIMER, EV_ADD | EV_ENABLE | EV_ONESHOT, WAIT_TIMER_FFLAGS,
		       (intptr_t)timeout_us, NULL);
	} else {
		EV_SET(ch, WAIT_TIMER_IDENT, EVFILT_TIMER, EV_ADD | EV_DISABLE | EV_ONESHOT, WAIT_TIMER_FFLAGS,
		       (intptr_t)WAIT_TIMER_IDLE_US, NULL);
	}
}

int hw_poller_open(void) {
	int kq = kqueue();
	if (kq < 0) return -1;
	if (hw_set_cloexec(kq) != 0) {
		int saved = errno;
		close(kq);
		errno = saved;
		return -1;
	}
	if (!timer_off()) {
		// Whether the timer can be had is known before the first wait, so that a caller sizing what
		// it does to the timers' resolution (the WebTransport pacer) knows it from the start.
		struct kevent ch;
		wait_timer(&ch, -1);
		if (kevent(kq, &ch, 1, NULL, 0, NULL) < 0) atomic_store_explicit(&g_timer_off, 1, memory_order_relaxed);
	}
	return kq;
}

unsigned hw_poller_resolution_us(void) {
	// A timer of microseconds without leeway, or else kevent's timeout, which Darwin may end up to a
	// millisecond late on an ordinary thread (above).
	return timer_off() ? 1000 : 1;
}

int hw_poller_wake_open(int fds[2]) {
	if (pipe(fds) != 0) return -1;
	for (int i = 0; i < 2; i++) {
		if (hw_set_nonblock(fds[i]) != 0 || hw_set_cloexec(fds[i]) != 0) {
			int saved = errno;
			close(fds[0]);
			close(fds[1]);
			errno = saved;
			return -1;
		}
	}
	return 0;
}

int hw_poller_set(int poller, int fd, int fresh, unsigned old, unsigned events, uint32_t gen) {
	struct kevent changes[2];
	int n = 0;
	if (fresh) old = 0;
	static const struct {
		unsigned bit;
		short filter;
	} filters[] = {{HW_EV_READ, EVFILT_READ}, {HW_EV_WRITE, EVFILT_WRITE}};
	for (int i = 0; i < 2; i++) {
		unsigned was = old & filters[i].bit;
		unsigned now = events & filters[i].bit;
		if (was == now) continue;
		EV_SET(&changes[n], (uintptr_t)fd, filters[i].filter, now ? EV_ADD : EV_DELETE, 0, 0, (void *)(uintptr_t)gen);
		n++;
	}
	if (n == 0) return 0;
	return kevent(poller, changes, n, NULL, 0, NULL) < 0 ? -1 : 0;
}

void hw_poller_del(int poller, int fd, unsigned events) {
	// Closing an fd drops its filters, so a failure here only means it was closed first.
	hw_poller_set(poller, fd, 0, events, 0, 0);
}

int hw_poller_wait(int poller, hw_poll_event *out, int max, int64_t timeout_us) {
	struct kevent events[KQUEUE_BATCH];
	int cap = max < KQUEUE_BATCH ? max : KQUEUE_BATCH;
	uint64_t end = timeout_us > 0 ? hw_now_us() + (uint64_t)timeout_us : 0;
	for (;;) {
		struct kevent change;
		int nchanges = 0;
		struct timespec ts;
		struct timespec *wait = NULL;
		if (timeout_us == 0 || (timeout_us > 0 && timer_off())) {
			// kevent's timeout is a timespec: microseconds are kept as they are (and given leeway).
			ts.tv_sec = (time_t)(timeout_us / 1000000);
			ts.tv_nsec = (long)(timeout_us % 1000000) * 1000L;
			wait = &ts;
		} else if (!timer_off()) {
			wait_timer(&change, timeout_us);
			nchanges = 1;
		}
		int n = kevent(poller, nchanges ? &change : NULL, nchanges, events, cap, wait);
		if (n < 0) return -1;
		int got = 0;
		for (int i = 0; i < n; i++) {
			const struct kevent *e = &events[i];
			if (e->filter == EVFILT_TIMER) {
				// The wait's own timer, whose expiry is the timeout. A change that failed comes back
				// as an error at once: from then on a timed wait is kevent's timeout.
				if (e->flags & EV_ERROR) atomic_store_explicit(&g_timer_off, 1, memory_order_relaxed);
				continue;
			}
			unsigned ev = e->filter == EVFILT_WRITE ? HW_EV_WRITE : HW_EV_READ;
			if (e->flags & EV_EOF) {
				// End of input is readable (the read returns 0), as it is under epoll. A socket that
				// can no longer be written has hung up, and fflags holds its error if it had one.
				if (e->filter == EVFILT_WRITE) ev |= HW_EV_HUP;
				if (e->fflags != 0) ev |= HW_EV_ERROR;
			}
			if (e->flags & EV_ERROR) ev |= HW_EV_ERROR;
			out[got].fd = (int)e->ident;
			out[got].gen = (uint32_t)(uintptr_t)e->udata;
			out[got].events = ev;
			got++;
		}
		if (got > 0 || timeout_us == 0) return got;
		// Nothing but the timer, or nothing at all. A timeout is never cut short: had it ended
		// early (a failed arming, a stale expiry), what is left of the wait is waited for.
		if (timeout_us > 0) {
			uint64_t now = hw_now_us();
			if (now >= end) return 0;
			timeout_us = (int64_t)(end - now);
		}
	}
}
