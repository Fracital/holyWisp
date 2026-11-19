/*
 * loop_backend.h on epoll (Linux). An event carries (fd, generation) in its user data, and the
 * wakeup is an eventfd. A wait shorter than forever and longer than nothing is epoll_pwait2's
 * (Linux 5.11), whose timeout is a timespec: epoll_wait's is in milliseconds, and a pacer that
 * releases a few datagrams every hundred microseconds cannot wait for one of those.
 */
#include "holywisp/loop.h"

#include "loop_backend.h"

#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>

#define EPOLL_BATCH 256

// Called by number: glibc wraps it from 2.35 and musl not at all. The number is one of those every
// architecture shares (after 424); a C library older than its kernel lacks the name.
#ifndef SYS_epoll_pwait2
#define SYS_epoll_pwait2 441
#endif

// Set once epoll_pwait2 is missing: ENOSYS from a kernel before 5.11, EPERM from a seccomp filter
// that does not know it (systemd's @system-service before v249, with SystemCallErrorNumber=EPERM
// as in our unit). From then on a wait is epoll_wait's, rounded up to a millisecond.
static _Atomic int g_pwait2_off;

int hw_poller_open(void) {
	int ep = epoll_create1(EPOLL_CLOEXEC);
	if (ep >= 0 && !atomic_load_explicit(&g_pwait2_off, memory_order_relaxed)) {
		// Whether epoll_pwait2 is there is known before the first wait, so that a caller sizing
		// what it does to the timers' resolution (the WebTransport pacer) knows it from the start.
		struct epoll_event ev;
		struct timespec zero = {0, 0};
		if (syscall(SYS_epoll_pwait2, ep, &ev, 1, &zero, NULL, 0) < 0 && (errno == ENOSYS || errno == EPERM)) {
			atomic_store_explicit(&g_pwait2_off, 1, memory_order_relaxed);
		}
	}
	return ep;
}

unsigned hw_poller_resolution_us(void) {
	return atomic_load_explicit(&g_pwait2_off, memory_order_relaxed) ? 1000 : 1;
}

int hw_poller_wake_open(int fds[2]) {
	int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (fd < 0) return -1;
	fds[0] = fd;
	fds[1] = fd;
	return 0;
}

int hw_poller_set(int poller, int fd, int fresh, unsigned old, unsigned events, uint32_t gen) {
	struct epoll_event ev;
	// A peer's half-close is reported as readable, because reading is how it is noticed, and so
	// only while reading is wanted: the condition never clears, and an fd whose reads are paused
	// would otherwise wake the loop for as long as the pause lasts.
	ev.events = 0;
	if (events & HW_EV_READ) ev.events |= EPOLLIN | EPOLLRDHUP;
	if (events & HW_EV_WRITE) ev.events |= EPOLLOUT;
	ev.data.u64 = (uint64_t)fd << 32 | gen;
	return epoll_ctl(poller, fresh ? EPOLL_CTL_ADD : EPOLL_CTL_MOD, fd, &ev);
}

void hw_poller_del(int poller, int fd, unsigned events) {
	epoll_ctl(poller, EPOLL_CTL_DEL, fd, NULL);
}

static int poller_epoll_wait(int poller, struct epoll_event *events, int max, int64_t timeout_us) {
	if (timeout_us > 0 && !atomic_load_explicit(&g_pwait2_off, memory_order_relaxed)) {
		struct timespec ts = {.tv_sec = (time_t)(timeout_us / 1000000), .tv_nsec = (long)(timeout_us % 1000000) * 1000};
		int n = (int)syscall(SYS_epoll_pwait2, poller, events, max, &ts, NULL, 0);
		if (n >= 0 || (errno != ENOSYS && errno != EPERM)) return n;
		atomic_store_explicit(&g_pwait2_off, 1, memory_order_relaxed);
	}
	int ms = timeout_us < 0 ? -1 : (int)((timeout_us + 999) / 1000);
	return epoll_wait(poller, events, max, ms);
}

int hw_poller_wait(int poller, hw_poll_event *out, int max, int64_t timeout_us) {
	struct epoll_event events[EPOLL_BATCH];
	int n = poller_epoll_wait(poller, events, max < EPOLL_BATCH ? max : EPOLL_BATCH, timeout_us);
	for (int i = 0; i < n; i++) {
		uint32_t e = events[i].events;
		unsigned ev = 0;
		if (e & (EPOLLIN | EPOLLRDHUP)) ev |= HW_EV_READ;
		if (e & EPOLLOUT) ev |= HW_EV_WRITE;
		if (e & EPOLLERR) ev |= HW_EV_ERROR;
		if (e & EPOLLHUP) ev |= HW_EV_HUP;
		out[i].fd = (int)(events[i].data.u64 >> 32);
		out[i].gen = (uint32_t)events[i].data.u64;
		out[i].events = ev;
	}
	return n;
}
