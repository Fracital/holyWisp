/*
 * bench/echo.c - counting TCP echo service for the benchmark harness.
 *
 * Every byte read is written straight back. Every 100 ms the main thread prints
 * "<monotonic_ns> <bytes_echoed>" on stdout so the harness can measure the exact number of bytes
 * that crossed the echo port in a window, independent of which client produced them (the same
 * idea as wispmark's iftop counter, without needing root).
 *
 * A connection starts on its port's event loop and gets a thread of its own once it has echoed
 * SMALL bytes. A bulk stream is on its thread after its first packet, as it always was. A stream
 * that echoes one byte and closes never costs a thread: with one thread and one megabyte mapped
 * per connection, the churn scenario measured this process queueing on its own address space
 * lock (the servers under test sat half idle), not the server.
 *
 *   echo PORT [COUNT]
 *
 * With COUNT it listens on PORT .. PORT+COUNT-1 and counts them together. The churn scenario needs
 * that: a server that dials one address and port tens of thousands of times a second runs the
 * kernel out of local ports for that destination, and the test then measures connect()'s search
 * for a free one instead of the server.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#define BUF   (1024 * 1024)
#define SMALL (64 * 1024)

static _Atomic uint64_t g_bytes;
static _Atomic uint64_t g_conns;

static void *serve(void *arg) {
	int fd = (int)(intptr_t)arg;
	uint8_t *buf = malloc(BUF);
	if (!buf) {
		close(fd);
		return NULL;
	}
	for (;;) {
		ssize_t n = read(fd, buf, BUF);
		if (n <= 0) break;
		atomic_fetch_add_explicit(&g_bytes, (uint64_t)n, memory_order_relaxed);
		size_t off = 0;
		while (off < (size_t)n) {
			ssize_t w = write(fd, buf + off, (size_t)n - off);
			if (w < 0) {
				if (errno == EINTR) continue;
				goto out;
			}
			off += (size_t)w;
		}
	}
out:
	close(fd);
	free(buf);
	return NULL;
}

static void *reporter(void *arg) {
	(void)arg;
	for (;;) {
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		uint64_t ns = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
		printf("%llu %llu %llu\n", (unsigned long long)ns,
		       (unsigned long long)atomic_load_explicit(&g_bytes, memory_order_relaxed),
		       (unsigned long long)atomic_load_explicit(&g_conns, memory_order_relaxed));
		fflush(stdout);
		usleep(100 * 1000);
	}
	return NULL;
}

static void spawn_serve(int fd) {
	pthread_t t;
	pthread_attr_t at;
	pthread_attr_init(&at);
	pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&at, 256 * 1024);
	if (pthread_create(&t, &at, serve, (void *)(intptr_t)fd) != 0) close(fd);
	pthread_attr_destroy(&at);
}

// Echo what is readable on a young connection. Returns the bytes echoed, or -1 when it is over.
static ssize_t echo_small(int fd, uint8_t *buf) {
	ssize_t n = recv(fd, buf, SMALL, 0);
	if (n < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
	if (n <= 0) return -1;
	size_t off = 0;
	while (off < (size_t)n) {
		ssize_t w = send(fd, buf + off, (size_t)n - off, MSG_NOSIGNAL);
		if (w >= 0) {
			off += (size_t)w;
		} else if (errno == EAGAIN) {
			struct pollfd pfd = {.fd = fd, .events = POLLOUT};
			poll(&pfd, 1, -1);
		} else if (errno != EINTR) {
			return -1;
		}
	}
	return n;
}

// One port: accept, echo the small connections here, hand the busy ones to a thread each.
static void *acceptor(void *arg) {
	int ls = (int)(intptr_t)arg;
	int one = 1;
	int ep = epoll_create1(EPOLL_CLOEXEC);
	uint8_t *buf = malloc(SMALL);
	uint32_t *seen = NULL; // bytes echoed so far, by descriptor
	int seen_cap = 0;
	struct epoll_event ev = {.events = EPOLLIN, .data.fd = ls};
	if (ep < 0 || !buf || fcntl(ls, F_SETFL, O_NONBLOCK) != 0 || epoll_ctl(ep, EPOLL_CTL_ADD, ls, &ev) != 0) {
		perror("echo: event loop");
		exit(1);
	}
	for (;;) {
		struct epoll_event evs[256];
		int n = epoll_wait(ep, evs, 256, -1);
		for (int i = 0; i < n; i++) {
			int fd = evs[i].data.fd;
			if (fd != ls) {
				ssize_t got = echo_small(fd, buf);
				if (got < 0) {
					close(fd); // which also takes it out of the epoll set
					continue;
				}
				atomic_fetch_add_explicit(&g_bytes, (uint64_t)got, memory_order_relaxed);
				seen[fd] += (uint32_t)got;
				if (seen[fd] >= SMALL) {
					epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL);
					fcntl(fd, F_SETFL, 0); // blocking again for its thread
					spawn_serve(fd);
				}
				continue;
			}
			for (;;) {
				int c = accept4(ls, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
				if (c < 0) {
					if (errno == EINTR || errno == ECONNABORTED) continue;
					if (errno == EAGAIN) break;
					perror("accept");
					exit(1);
				}
				setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
				atomic_fetch_add_explicit(&g_conns, 1, memory_order_relaxed);
				if (c >= seen_cap) {
					int cap = seen_cap ? seen_cap : 1024;
					while (cap <= c) cap *= 2;
					uint32_t *grown = realloc(seen, (size_t)cap * sizeof(*seen));
					if (!grown) {
						perror("echo: realloc");
						exit(1);
					}
					seen = grown;
					seen_cap = cap;
				}
				seen[c] = 0;
				struct epoll_event cev = {.events = EPOLLIN, .data.fd = c};
				if (epoll_ctl(ep, EPOLL_CTL_ADD, c, &cev) != 0) close(c);
			}
		}
	}
	return NULL;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "usage: echo PORT [COUNT]\n");
		return 2;
	}
	int port = atoi(argv[1]);
	int count = argc > 2 ? atoi(argv[2]) : 1;
	if (count < 1 || port < 1 || port + count > 65536) {
		fprintf(stderr, "echo: bad port range\n");
		return 2;
	}
	signal(SIGPIPE, SIG_IGN);
	pthread_t rt;
	pthread_create(&rt, NULL, reporter, NULL);
	pthread_detach(rt);
	int last = -1;
	for (int i = 0; i < count; i++) {
		int ls = socket(AF_INET, SOCK_STREAM, 0);
		int one = 1;
		setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
		struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons((uint16_t)(port + i))};
		sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (ls < 0 || bind(ls, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(ls, 4096) != 0) {
			perror("bind/listen");
			return 1;
		}
		if (i + 1 < count) {
			pthread_t t;
			if (pthread_create(&t, NULL, acceptor, (void *)(intptr_t)ls) != 0) {
				perror("pthread_create");
				return 1;
			}
			pthread_detach(t);
		} else {
			last = ls;
		}
	}
	acceptor((void *)(intptr_t)last);
	return 0;
}
