/*
 * loop_backend.h on kqueue (macOS, the BSDs). Reading and writing are two filters on an fd, each
 * added and deleted as the interest changes and each reported as its own event; the generation
 * rides in the filter's user data. The wakeup is a pipe, whose write(2) is safe from a signal
 * handler.
 *
 * Unlike epoll, kqueue says nothing about an fd with no filter: a socket that is neither read nor
 * written learns of a reset when it is next watched. Nothing is lost by that; it is found later.
 */
#include "holywisp/hw.h"
#include "holywisp/loop.h"

#include "loop_backend.h"

#include <errno.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>

#include <sys/event.h>
#include <sys/types.h>

#define KQUEUE_BATCH 256

int hw_poller_open(void) {
	int kq = kqueue();
	if (kq >= 0 && hw_set_cloexec(kq) != 0) {
		int saved = errno;
		close(kq);
		errno = saved;
		return -1;
	}
	return kq;
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

int hw_poller_wait(int poller, hw_poll_event *out, int max, int timeout_ms) {
	struct kevent events[KQUEUE_BATCH];
	struct timespec ts;
	struct timespec *wait = NULL;
	if (timeout_ms >= 0) {
		ts.tv_sec = timeout_ms / 1000;
		ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
		wait = &ts;
	}
	int n = kevent(poller, NULL, 0, events, max < KQUEUE_BATCH ? max : KQUEUE_BATCH, wait);
	for (int i = 0; i < n; i++) {
		const struct kevent *e = &events[i];
		unsigned ev = e->filter == EVFILT_WRITE ? HW_EV_WRITE : HW_EV_READ;
		if (e->flags & EV_EOF) {
			// End of input is readable (the read returns 0), as it is under epoll. A socket that can
			// no longer be written has hung up, and fflags holds its error if it had one.
			if (e->filter == EVFILT_WRITE) ev |= HW_EV_HUP;
			if (e->fflags != 0) ev |= HW_EV_ERROR;
		}
		if (e->flags & EV_ERROR) ev |= HW_EV_ERROR;
		out[i].fd = (int)e->ident;
		out[i].gen = (uint32_t)(uintptr_t)e->udata;
		out[i].events = ev;
	}
	return n;
}
