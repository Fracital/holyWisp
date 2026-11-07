/*
 * bench/echo.c - counting TCP echo service for the benchmark harness.
 *
 * One thread per connection; every byte read is written straight back. Every 100 ms the main
 * thread prints "<monotonic_ns> <bytes_echoed>" on stdout so the harness can measure the exact
 * number of bytes that crossed the echo port in a window, independent of which client produced
 * them (the same idea as wispmark's iftop counter, without needing root).
 *
 *   echo PORT
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
#include <netinet/tcp.h>
#include <sys/socket.h>

#define BUF (1024 * 1024)

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

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "usage: echo PORT\n");
		return 2;
	}
	signal(SIGPIPE, SIG_IGN);
	int ls = socket(AF_INET, SOCK_STREAM, 0);
	int one = 1;
	setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons((uint16_t)atoi(argv[1]))};
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(ls, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(ls, 4096) != 0) {
		perror("bind/listen");
		return 1;
	}
	pthread_t rt;
	pthread_create(&rt, NULL, reporter, NULL);
	pthread_detach(rt);
	for (;;) {
		int fd = accept4(ls, NULL, NULL, SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno == EINTR) continue;
			perror("accept");
			return 1;
		}
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
		atomic_fetch_add_explicit(&g_conns, 1, memory_order_relaxed);
		pthread_t t;
		pthread_attr_t at;
		pthread_attr_init(&at);
		pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
		pthread_attr_setstacksize(&at, 256 * 1024);
		if (pthread_create(&t, &at, serve, (void *)(intptr_t)fd) != 0) close(fd);
		pthread_attr_destroy(&at);
	}
}
