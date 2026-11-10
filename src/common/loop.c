/*
 * holywisp/loop.h implementation.
 *
 * Fds live in a table indexed by fd with a generation counter: events carry (fd, gen) so an fd
 * closed and reused inside the same dispatch batch is never handed to the wrong watcher. Timers
 * are a binary min-heap of heap-allocated nodes that know their index, so cancel is O(log n).
 * Posted tasks sit on a mutex-protected queue and wake the loop through a descriptor it watches.
 *
 * Waiting for readiness is the kernel's part and lives behind loop_backend.h (loop_epoll.c on
 * Linux, loop_kqueue.c on macOS, loop_select.c on Windows); nothing in this file is specific to
 * any of them.
 */
#include "holywisp/loop.h"

#include "holywisp/hw.h"

#include "loop_backend.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define LOOP_MAX_EVENTS 256

typedef struct fd_watch {
	hw_io_cb cb;
	void *ud;
	unsigned events;
	uint32_t gen;
	int active;
} fd_watch;

struct hw_timer {
	uint64_t when;
	uint64_t repeat;
	size_t index; // position in the heap
	hw_timer_cb cb;
	void *ud;
};

typedef struct task {
	hw_task_cb cb;
	void *ud;
	struct task *next;
} task;

struct hw_loop {
	int poller;
	int wake_rd; // watched; readable once something was written to wake_wr
	int wake_wr; // may be the same descriptor
	fd_watch *fds;
	int fd_cap;

	hw_timer **timers; // heap
	size_t ntimers;
	size_t timer_cap;

	pthread_mutex_t task_lock;
	task *task_head;
	task *task_tail;

	hw_batch_cb batch_cb;
	void *batch_ud;
	unsigned busy_poll_us;
	int was_busy; // the previous iteration delivered events

	_Atomic int stop;
};

// ---------------------------------------------------------------------------------- hw.h helpers

static uint64_t now_us(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

uint64_t hw_now_ms(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

int hw_set_nonblock(int fd) {
	int fl = fcntl(fd, F_GETFL, 0);
	return (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) ? -1 : 0;
}

int hw_set_cloexec(int fd) {
	int fl = fcntl(fd, F_GETFD, 0);
	return (fl < 0 || fcntl(fd, F_SETFD, fl | FD_CLOEXEC) < 0) ? -1 : 0;
}

// ---------------------------------------------------------------------------------- lifecycle

static void wake_cb(hw_loop *loop, int fd, unsigned events, void *ud) {
	// Empty it: an eventfd in one read, a pipe in as many as it holds wakeups.
	uint64_t v[8];
	while (read(fd, v, sizeof(v)) == (ssize_t)sizeof(v)) {
	}
}

static void wake(hw_loop *loop) {
	uint64_t one = 1;
	ssize_t r = write(loop->wake_wr, &one, sizeof(one));
	(void)r; // full means a wakeup is already pending
}

hw_loop *hw_loop_new(void) {
	hw_loop *loop = calloc(1, sizeof(*loop));
	if (!loop) return NULL;
	int wakefds[2] = {-1, -1};
	loop->poller = hw_poller_open();
	if (loop->poller < 0 || hw_poller_wake_open(wakefds) != 0) goto fail;
	loop->wake_rd = wakefds[0];
	loop->wake_wr = wakefds[1];
	pthread_mutex_init(&loop->task_lock, NULL);
	if (hw_loop_add_fd(loop, loop->wake_rd, HW_EV_READ, wake_cb, NULL) != 0) {
		pthread_mutex_destroy(&loop->task_lock);
		goto fail;
	}
	return loop;
fail:
	if (loop->poller >= 0) close(loop->poller);
	if (wakefds[0] >= 0) close(wakefds[0]);
	if (wakefds[1] >= 0 && wakefds[1] != wakefds[0]) close(wakefds[1]);
	free(loop->fds);
	free(loop);
	return NULL;
}

void hw_loop_free(hw_loop *loop) {
	if (!loop) return;
	for (size_t i = 0; i < loop->ntimers; i++) free(loop->timers[i]);
	free(loop->timers);
	task *t = loop->task_head;
	while (t) {
		task *next = t->next;
		free(t);
		t = next;
	}
	pthread_mutex_destroy(&loop->task_lock);
	close(loop->wake_rd);
	if (loop->wake_wr != loop->wake_rd) close(loop->wake_wr);
	close(loop->poller);
	free(loop->fds);
	free(loop);
}

// ---------------------------------------------------------------------------------- fds

static int fd_table_grow(hw_loop *loop, int fd) {
	if (fd < loop->fd_cap) return 0;
	int cap = loop->fd_cap ? loop->fd_cap : 64;
	while (cap <= fd) cap *= 2;
	fd_watch *p = realloc(loop->fds, (size_t)cap * sizeof(*p));
	if (!p) {
		errno = ENOMEM;
		return -1;
	}
	memset(p + loop->fd_cap, 0, (size_t)(cap - loop->fd_cap) * sizeof(*p));
	loop->fds = p;
	loop->fd_cap = cap;
	return 0;
}

int hw_loop_add_fd(hw_loop *loop, int fd, unsigned events, hw_io_cb cb, void *ud) {
	if (fd < 0 || fd_table_grow(loop, fd) != 0) return -1;
	fd_watch *w = &loop->fds[fd];
	if (w->active) {
		errno = EEXIST;
		return -1;
	}
	w->cb = cb;
	w->ud = ud;
	w->events = events;
	w->gen++;
	w->active = 1;
	if (hw_poller_set(loop->poller, fd, 1, 0, events, w->gen) != 0) {
		w->active = 0;
		return -1;
	}
	return 0;
}

int hw_loop_mod_fd(hw_loop *loop, int fd, unsigned events) {
	if (fd < 0 || fd >= loop->fd_cap || !loop->fds[fd].active) {
		errno = ENOENT;
		return -1;
	}
	fd_watch *w = &loop->fds[fd];
	if (w->events == events) return 0;
	if (hw_poller_set(loop->poller, fd, 0, w->events, events, w->gen) != 0) return -1;
	w->events = events;
	return 0;
}

void hw_loop_del_fd(hw_loop *loop, int fd) {
	if (fd < 0 || fd >= loop->fd_cap || !loop->fds[fd].active) return;
	loop->fds[fd].active = 0;
	loop->fds[fd].cb = NULL;
	hw_poller_del(loop->poller, fd, loop->fds[fd].events);
}

// ---------------------------------------------------------------------------------- timers

static void heap_swap(hw_loop *loop, size_t a, size_t b) {
	hw_timer *t = loop->timers[a];
	loop->timers[a] = loop->timers[b];
	loop->timers[b] = t;
	loop->timers[a]->index = a;
	loop->timers[b]->index = b;
}

static void heap_up(hw_loop *loop, size_t i) {
	while (i > 0) {
		size_t parent = (i - 1) / 2;
		if (loop->timers[parent]->when <= loop->timers[i]->when) break;
		heap_swap(loop, parent, i);
		i = parent;
	}
}

static void heap_down(hw_loop *loop, size_t i) {
	for (;;) {
		size_t l = 2 * i + 1;
		size_t r = l + 1;
		size_t m = i;
		if (l < loop->ntimers && loop->timers[l]->when < loop->timers[m]->when) m = l;
		if (r < loop->ntimers && loop->timers[r]->when < loop->timers[m]->when) m = r;
		if (m == i) return;
		heap_swap(loop, i, m);
		i = m;
	}
}

static void heap_remove(hw_loop *loop, size_t i) {
	size_t last = loop->ntimers - 1;
	if (i != last) {
		heap_swap(loop, i, last);
	}
	loop->ntimers--;
	if (i < loop->ntimers) {
		heap_up(loop, i);
		heap_down(loop, i);
	}
}

hw_timer *hw_loop_add_timer(hw_loop *loop, uint64_t delay_ms, uint64_t repeat_ms, hw_timer_cb cb, void *ud) {
	if (loop->ntimers == loop->timer_cap) {
		size_t cap = loop->timer_cap ? loop->timer_cap * 2 : 32;
		hw_timer **p = realloc(loop->timers, cap * sizeof(*p));
		if (!p) return NULL;
		loop->timers = p;
		loop->timer_cap = cap;
	}
	hw_timer *t = malloc(sizeof(*t));
	if (!t) return NULL;
	t->when = hw_now_ms() + delay_ms;
	t->repeat = repeat_ms;
	t->cb = cb;
	t->ud = ud;
	t->index = loop->ntimers;
	loop->timers[loop->ntimers++] = t;
	heap_up(loop, t->index);
	return t;
}

void hw_loop_cancel_timer(hw_loop *loop, hw_timer *t) {
	if (!t) return;
	heap_remove(loop, t->index);
	free(t);
}

static void timers_run(hw_loop *loop) {
	uint64_t now = hw_now_ms();
	while (loop->ntimers > 0 && loop->timers[0]->when <= now) {
		hw_timer *t = loop->timers[0];
		hw_timer_cb cb = t->cb;
		void *ud = t->ud;
		if (t->repeat) {
			t->when = now + t->repeat;
			heap_down(loop, 0);
		} else {
			heap_remove(loop, 0);
			free(t);
		}
		cb(loop, ud);
	}
}

static int timers_next_ms(const hw_loop *loop) {
	if (loop->ntimers == 0) return -1;
	uint64_t now = hw_now_ms();
	uint64_t when = loop->timers[0]->when;
	if (when <= now) return 0;
	uint64_t d = when - now;
	return d > 1000000 ? 1000000 : (int)d;
}

// ---------------------------------------------------------------------------------- tasks

int hw_loop_post(hw_loop *loop, hw_task_cb cb, void *ud) {
	task *t = malloc(sizeof(*t));
	if (!t) {
		errno = ENOMEM;
		return -1;
	}
	t->cb = cb;
	t->ud = ud;
	t->next = NULL;
	pthread_mutex_lock(&loop->task_lock);
	int was_empty = loop->task_head == NULL;
	if (loop->task_tail) {
		loop->task_tail->next = t;
	} else {
		loop->task_head = t;
	}
	loop->task_tail = t;
	pthread_mutex_unlock(&loop->task_lock);
	if (was_empty) wake(loop);
	return 0;
}

static void tasks_run(hw_loop *loop) {
	pthread_mutex_lock(&loop->task_lock);
	task *t = loop->task_head;
	loop->task_head = NULL;
	loop->task_tail = NULL;
	pthread_mutex_unlock(&loop->task_lock);
	while (t) {
		task *next = t->next;
		t->cb(loop, t->ud);
		free(t);
		t = next;
	}
}

static int tasks_pending(hw_loop *loop) {
	pthread_mutex_lock(&loop->task_lock);
	int pending = loop->task_head != NULL;
	pthread_mutex_unlock(&loop->task_lock);
	return pending;
}

// ---------------------------------------------------------------------------------- run

void hw_loop_set_batch_end(hw_loop *loop, hw_batch_cb cb, void *ud) {
	loop->batch_cb = cb;
	loop->batch_ud = ud;
}

void hw_loop_set_busy_poll(hw_loop *loop, unsigned us) {
	loop->busy_poll_us = us;
}

int hw_loop_run_once(hw_loop *loop, int timeout_ms) {
	tasks_run(loop);
	if (loop->batch_cb) loop->batch_cb(loop, loop->batch_ud);
	int next = timers_next_ms(loop);
	if (next >= 0 && (timeout_ms < 0 || next < timeout_ms)) timeout_ms = next;
	if (tasks_pending(loop) || atomic_load(&loop->stop)) timeout_ms = 0;

	hw_poll_event events[LOOP_MAX_EVENTS];
	int n = 0;
	if (loop->busy_poll_us > 0 && loop->was_busy && timeout_ms != 0) {
		// The peer that was just served usually answers before a sleep and a wakeup would be over.
		uint64_t until = now_us() + loop->busy_poll_us;
		do {
			n = hw_poller_wait(loop->poller, events, LOOP_MAX_EVENTS, 0);
		} while (n == 0 && now_us() < until && !atomic_load(&loop->stop));
	}
	if (n == 0) n = hw_poller_wait(loop->poller, events, LOOP_MAX_EVENTS, timeout_ms);
	if (n < 0) {
		loop->was_busy = 0;
		if (errno == EINTR) return 0;
		return -1;
	}
	loop->was_busy = n > 0;
	for (int i = 0; i < n; i++) {
		int fd = events[i].fd;
		if (fd < 0 || fd >= loop->fd_cap) continue;
		fd_watch *w = &loop->fds[fd];
		if (!w->active || w->gen != events[i].gen || !w->cb) continue;
		w->cb(loop, fd, events[i].events, w->ud);
	}
	timers_run(loop);
	if (loop->batch_cb) loop->batch_cb(loop, loop->batch_ud);
	return 0;
}

int hw_loop_run(hw_loop *loop) {
	while (!atomic_load(&loop->stop)) {
		if (hw_loop_run_once(loop, -1) != 0) return -1;
	}
	// Give posted tasks (deferred frees) one last chance so nothing leaks on shutdown.
	tasks_run(loop);
	return 0;
}

void hw_loop_stop(hw_loop *loop) {
	atomic_store(&loop->stop, 1);
	wake(loop);
}

int hw_loop_stopped(const hw_loop *loop) {
	return atomic_load(&loop->stop);
}
