/*
 * loop_backend.h on epoll (Linux). An event carries (fd, generation) in its user data, and the
 * wakeup is an eventfd.
 */
#include "holywisp/loop.h"

#include "loop_backend.h"

#include <stddef.h>

#include <sys/epoll.h>
#include <sys/eventfd.h>

#define EPOLL_BATCH 256

int hw_poller_open(void) {
	return epoll_create1(EPOLL_CLOEXEC);
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

int hw_poller_wait(int poller, hw_poll_event *out, int max, int timeout_ms) {
	struct epoll_event events[EPOLL_BATCH];
	int n = epoll_wait(poller, events, max < EPOLL_BATCH ? max : EPOLL_BATCH, timeout_ms);
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
