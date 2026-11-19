/*
 * holywisp/sys.h: the same promises on every platform, whichever kernel call keeps them.
 */
#include "holywisp/hw.h"
#include "holywisp/net.h"
#include "holywisp/sys.h"

#include "test.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

static int is_cloexec(int fd) {
	return (fcntl(fd, F_GETFD, 0) & FD_CLOEXEC) != 0;
}

static int is_nonblock(int fd) {
	return (fcntl(fd, F_GETFL, 0) & O_NONBLOCK) != 0;
}

// hw_set_cloexec adds close-on-exec to what the descriptor has and changes nothing else about it.
static void test_set_cloexec(void) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(fd >= 0, "socket: errno %d", errno);
	CHECK_EQ(fcntl(fd, F_SETFD, 0), 0);
	CHECK(!is_cloexec(fd), "inherited to begin with");
	CHECK_EQ(hw_set_nonblock(fd), 0);
	CHECK_EQ(hw_set_cloexec(fd), 0);
	CHECK(is_cloexec(fd), "close-on-exec");
	CHECK(is_nonblock(fd), "the status flags are as they were");
	CHECK_EQ(hw_set_cloexec(fd), 0); // a second time is no different
	CHECK(is_cloexec(fd), "still close-on-exec");
	close(fd);
	errno = 0;
	CHECK_EQ(hw_set_cloexec(fd), -1);
	CHECK_EQ(errno, EBADF);
}

static void test_socket_flags(void) {
	int nb = hw_sys_socket(AF_INET, SOCK_STREAM, 0, 1);
	int blocking = hw_sys_socket(AF_INET, SOCK_DGRAM, 0, 0);
	CHECK(nb >= 0 && blocking >= 0, "sockets");
	CHECK(is_cloexec(nb) && is_cloexec(blocking), "close-on-exec");
	CHECK(is_nonblock(nb), "non-blocking when asked");
	CHECK(!is_nonblock(blocking), "blocking when not");
	close(nb);
	close(blocking);
}

// A connected pair over loopback: *client is blocking, the return value came from hw_sys_accept.
static int tcp_pair(int *client) {
	uint16_t port = 0;
	int lfd = hw_listen_tcp("127.0.0.1", 0, 0, 4, &port);
	CHECK(lfd >= 0, "listen");
	*client = hw_connect_tcp("127.0.0.1", port, 2000);
	CHECK(*client >= 0, "connect");
	struct pollfd pfd = {.fd = lfd, .events = POLLIN};
	CHECK_EQ(poll(&pfd, 1, 2000), 1);
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);
	int afd = hw_sys_accept(lfd, (struct sockaddr *)&ss, &sl);
	CHECK(afd >= 0, "accept");
	close(lfd);
	return afd;
}

static void test_accept_flags_and_no_sigpipe(void) {
	int client;
	int afd = tcp_pair(&client);
	CHECK(is_cloexec(afd), "accepted socket is close-on-exec");
	CHECK(is_nonblock(afd), "accepted socket is non-blocking");

	// Writing to a peer that has gone is an error to handle, never a signal: SIGPIPE is left at
	// its default here, so a signal would end the test.
	close(client);
	ssize_t r = 0;
	for (int i = 0; i < 200 && r >= 0; i++) {
		r = send(afd, "x", 1, HW_MSG_NOSIGNAL);
		if (r >= 0) usleep(5000);
	}
	CHECK(r < 0, "send to a closed peer fails");
	CHECK(errno == EPIPE || errno == ECONNRESET, "with EPIPE or ECONNRESET, got %d", errno);
	close(afd);
}

static void test_keepalive(void) {
	int client;
	int afd = tcp_pair(&client);
	int one = 1;
	CHECK_EQ(setsockopt(afd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)), 0);
	hw_sys_keepalive(afd, 60, 15, 4);
	// The two options that have one name everywhere read back what was set.
	int interval = 0, count = 0;
	socklen_t len = sizeof(interval);
	CHECK_EQ(getsockopt(afd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, &len), 0);
	len = sizeof(count);
	CHECK_EQ(getsockopt(afd, IPPROTO_TCP, TCP_KEEPCNT, &count, &len), 0);
	CHECK_EQ(interval, 15);
	CHECK_EQ(count, 4);
	close(afd);
	close(client);
}

static void test_listen_more(void) {
	uint16_t port = 0;
	int first = hw_listen_tcp("127.0.0.1", 0, 1, 16, &port);
	CHECK(first >= 0, "first listener");
	int second = hw_sys_listen_more(first, "127.0.0.1", port, 16);
	CHECK(second >= 0 && second != first, "second listener");
	CHECK(is_cloexec(second) && is_nonblock(second), "second listener flags");

	// Every connection is accepted by one of the two, whichever way the kernel shares them out.
	enum {
		CONNS = 8
	};
	int clients[CONNS];
	for (int i = 0; i < CONNS; i++) {
		clients[i] = hw_connect_tcp("127.0.0.1", port, 2000);
		CHECK(clients[i] >= 0, "connect %d", i);
	}
	int accepted = 0;
	for (int spins = 0; accepted < CONNS && spins < 400; spins++) {
		struct pollfd pfds[2] = {{.fd = first, .events = POLLIN}, {.fd = second, .events = POLLIN}};
		if (poll(pfds, 2, 50) <= 0) continue;
		for (int i = 0; i < 2; i++) {
			struct sockaddr_storage ss;
			socklen_t sl = sizeof(ss);
			int fd = hw_sys_accept(pfds[i].fd, (struct sockaddr *)&ss, &sl);
			if (fd < 0) continue;
			accepted++;
			close(fd);
		}
	}
	CHECK_EQ(accepted, CONNS);
	for (int i = 0; i < CONNS; i++) close(clients[i]);

	// Closing the first leaves the second listening.
	close(first);
	int late = hw_connect_tcp("127.0.0.1", port, 2000);
	CHECK(late >= 0, "connect after the first listener closed");
	close(late);
	close(second);
}

// The server's workers: one thread per listener, each accepting when its own is readable.
enum {
	SHARE_THREADS = 4,
	SHARE_CONNS = 200
};

static struct {
	int fds[SHARE_THREADS];
	_Atomic int accepted;
	_Atomic int exited;
	_Atomic int done;
} g_share;

static void *share_main(void *arg) {
	int fd = g_share.fds[(int)(intptr_t)arg];
	while (!atomic_load(&g_share.done)) {
		struct pollfd pfd = {.fd = fd, .events = POLLIN};
		if (poll(&pfd, 1, 20) <= 0) continue;
		struct sockaddr_storage ss;
		socklen_t sl = sizeof(ss);
		int c = hw_sys_accept(fd, (struct sockaddr *)&ss, &sl);
		if (c < 0) continue;
		close(c);
		atomic_fetch_add(&g_share.accepted, 1);
	}
	atomic_fetch_add(&g_share.exited, 1);
	return NULL;
}

static int share_wait(_Atomic int *counter, int want, int timeout_ms) {
	for (int waited = 0; atomic_load(counter) < want && waited < timeout_ms; waited += 5) usleep(5000);
	return atomic_load(counter);
}

// Where the listeners are one socket, every thread is woken for a connection only one of them
// gets. The rest must be told there is nothing, at once: a thread that waits in accept for the
// next connection is deaf to everything else its loop watches.
static void test_shared_accept_never_blocks(void) {
	uint16_t port = 0;
	g_share.fds[0] = hw_listen_tcp("127.0.0.1", 0, 1, 64, &port);
	CHECK(g_share.fds[0] >= 0, "first listener");
	for (int i = 1; i < SHARE_THREADS; i++) {
		g_share.fds[i] = hw_sys_listen_more(g_share.fds[0], "127.0.0.1", port, 64);
		CHECK(g_share.fds[i] >= 0, "listener %d", i);
	}
	atomic_store(&g_share.accepted, 0);
	atomic_store(&g_share.exited, 0);
	atomic_store(&g_share.done, 0);
	pthread_t threads[SHARE_THREADS];
	for (int i = 0; i < SHARE_THREADS; i++) {
		CHECK_EQ(pthread_create(&threads[i], NULL, share_main, (void *)(intptr_t)i), 0);
	}
	for (int i = 0; i < SHARE_CONNS; i++) {
		int c = hw_connect_tcp("127.0.0.1", port, 10000);
		CHECK(c >= 0, "connect %d", i);
		close(c);
	}
	CHECK_EQ(share_wait(&g_share.accepted, SHARE_CONNS, 10000), SHARE_CONNS);
	// Nothing is left to accept, so every thread is back in its poll and sees the flag.
	atomic_store(&g_share.done, 1);
	int exited = share_wait(&g_share.exited, SHARE_THREADS, 3000);
	CHECK(exited == SHARE_THREADS, "%d of %d threads are still inside accept", SHARE_THREADS - exited, SHARE_THREADS);
	for (int i = 0; i < SHARE_THREADS; i++) {
		pthread_join(threads[i], NULL);
		close(g_share.fds[i]);
	}
}

static void test_relay_pipe(void) {
	int fds[2];
	size_t size = 0;
	if (hw_sys_relay_pipe(fds, 1024 * 1024, 64 * 1024, &size) != 0) {
		// No pipe to be had is a legitimate answer (a kernel that does not splice, or the user's
		// pipe memory is spent): the server copies then. It has to say which.
		CHECK(errno == ENOTSUP || errno == ENOBUFS || errno == EMFILE || errno == ENFILE, "errno %d", errno);
		return;
	}
	CHECK(size >= 64 * 1024, "at least the minimum, got %zu", size);
	CHECK(is_cloexec(fds[0]) && is_cloexec(fds[1]), "pipe is close-on-exec");
	CHECK(is_nonblock(fds[0]) && is_nonblock(fds[1]), "pipe is non-blocking");

	// socket -> pipe -> socket, the route a bulk stream's payload takes.
	int remote_peer, client_peer;
	int remote = tcp_pair(&remote_peer);
	int client = tcp_pair(&client_peer);
	CHECK_EQ(hw_sys_splice(remote, fds[1], 4096), -1);
	CHECK(errno == EAGAIN || errno == EWOULDBLOCK, "nothing to move yet: errno %d", errno);

	char sent[3000];
	for (size_t i = 0; i < sizeof(sent); i++) sent[i] = (char)(i * 7);
	CHECK_EQ(write(remote_peer, sent, sizeof(sent)), (ssize_t)sizeof(sent));
	size_t in = 0;
	for (int spins = 0; in < sizeof(sent) && spins < 400; spins++) {
		ssize_t n = hw_sys_splice(remote, fds[1], sizeof(sent) - in);
		if (n > 0) {
			in += (size_t)n;
		} else {
			usleep(5000);
		}
	}
	CHECK_EQ(in, sizeof(sent));
	size_t out = 0;
	while (out < in) {
		ssize_t n = hw_sys_splice(fds[0], client, in - out);
		CHECK(n > 0, "pipe to socket: errno %d", errno);
		out += (size_t)n;
	}
	char got[sizeof(sent)];
	size_t have = 0;
	while (have < sizeof(got)) {
		ssize_t r = read(client_peer, got + have, sizeof(got) - have);
		CHECK(r > 0, "read back: errno %d", errno);
		have += (size_t)r;
	}
	CHECK(memcmp(sent, got, sizeof(sent)) == 0, "payload intact");

	// End of input is 0, not an error.
	close(remote_peer);
	ssize_t n = -1;
	for (int spins = 0; spins < 400; spins++) {
		n = hw_sys_splice(remote, fds[1], 4096);
		if (n >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) break;
		usleep(5000);
	}
	CHECK_EQ(n, 0);
	close(remote);
	close(client);
	close(client_peer);
	close(fds[0]);
	close(fds[1]);
}

// One read, waiting up to five seconds for it: the count, 0 at the end of the stream, -1 with errno.
static ssize_t read_wait(int fd, void *buf, size_t cap) {
	struct pollfd pfd = {.fd = fd, .events = POLLIN};
	if (poll(&pfd, 1, 5000) <= 0) {
		errno = ETIMEDOUT;
		return -1;
	}
	return read(fd, buf, cap);
}

static void test_close_reset(void) {
	// Bytes the peer has not acknowledged are never given up for a reset. The peer here reads
	// nothing until the socket is closed, so most of what was written is still on this side: it
	// must all arrive, followed by the end of the stream and not by an error.
	int client;
	int afd = tcp_pair(&client);
	static uint8_t chunk[65536];
	memset(chunk, 0x5a, sizeof(chunk));
	size_t sent = 0;
	for (;;) {
		ssize_t w = send(afd, chunk, sizeof(chunk), HW_MSG_NOSIGNAL);
		if (w < 0) break;
		sent += (size_t)w;
	}
	CHECK(errno == EAGAIN || errno == EWOULDBLOCK, "the send buffer filled, got %d", errno);
	CHECK(sent > 0, "something was written");
	CHECK_EQ(hw_sys_close_reset(afd), 0);
	size_t got = 0;
	ssize_t n;
	while ((n = read_wait(client, chunk, sizeof(chunk))) > 0) got += (size_t)n;
	CHECK(n == 0, "the stream ends cleanly, got errno %d", errno);
	CHECK(got == sent, "all %zu bytes arrived, got %zu", sent, got);
	close(client);

	// With everything acknowledged (the peer's reply carries the acknowledgement) the close is a
	// reset where the platform has one, and what was written before it had arrived either way.
	afd = tcp_pair(&client);
	char buf[8];
	CHECK_EQ(send(afd, "hello", 5, HW_MSG_NOSIGNAL), 5);
	CHECK_EQ(read_wait(client, buf, sizeof(buf)), 5);
	CHECK_EQ(send(client, "ok", 2, HW_MSG_NOSIGNAL), 2);
	CHECK_EQ(read_wait(afd, buf, sizeof(buf)), 2);
	int reset = hw_sys_close_reset(afd);
	CHECK_EQ(reset, hw_sys_has_close_reset());
	n = read_wait(client, buf, sizeof(buf));
	if (reset) {
		CHECK(n < 0 && errno == ECONNRESET, "the peer sees a reset, got %zd errno %d", n, errno);
	} else {
		CHECK(n == 0, "the peer sees the end of the stream, got %zd errno %d", n, errno);
	}
	close(client);
}

static void test_crypt(void) {
	// Whatever method the C library reads this setting as, it is a function of key and setting.
	char a[128], b[128], c[128], tiny[4];
	if (!hw_sys_has_crypt()) {
		// Then nothing hashes, whatever the method: a stored hash can only ever not match.
		CHECK_EQ(hw_sys_crypt("hunter2", "$6$holywispsalt$", a, sizeof(a)), -1);
		CHECK_EQ(hw_sys_crypt("hunter2", "ab", a, sizeof(a)), -1);
		return;
	}
	CHECK_EQ(hw_sys_crypt("hunter2", "$6$holywispsalt$", a, sizeof(a)), 0);
	CHECK_EQ(hw_sys_crypt("hunter2", "$6$holywispsalt$", b, sizeof(b)), 0);
	CHECK_EQ(hw_sys_crypt("hunter3", "$6$holywispsalt$", c, sizeof(c)), 0);
	CHECK(strlen(a) >= 13, "a hash, got \"%s\"", a);
	CHECK_STR(a, b);
	CHECK(strcmp(a, c) != 0, "another key, another hash");
	// The stored hash is its own setting: that is how a password is checked.
	CHECK_EQ(hw_sys_crypt("hunter2", a, b, sizeof(b)), 0);
	CHECK_STR(a, b);
	CHECK_EQ(hw_sys_crypt("hunter2", "$6$holywispsalt$", tiny, sizeof(tiny)), -1);
}

// Random bytes that are fit for keys: the whole buffer is written, and no two calls agree.
static void test_random(void) {
	uint8_t a[64], b[64], zero[64];
	memset(a, 0, sizeof(a));
	memset(b, 0, sizeof(b));
	memset(zero, 0, sizeof(zero));
	CHECK_EQ(hw_sys_random(a, sizeof(a)), 0);
	CHECK_EQ(hw_sys_random(b, sizeof(b)), 0);
	CHECK(memcmp(a, zero, sizeof(a)) != 0, "the buffer was filled");
	CHECK(memcmp(a, b, sizeof(a)) != 0, "two calls differ");
	// Every position is written, not only the first word: over 32 calls no byte stays the same.
	// (One that did by chance would be 1 in 256^31.)
	uint8_t first[37], changed[37];
	CHECK_EQ(hw_sys_random(first, sizeof(first)), 0);
	memset(changed, 0, sizeof(changed));
	for (int i = 0; i < 32; i++) {
		uint8_t next[37];
		CHECK_EQ(hw_sys_random(next, sizeof(next)), 0);
		for (size_t k = 0; k < sizeof(next); k++) changed[k] |= (uint8_t)(next[k] != first[k]);
	}
	for (size_t k = 0; k < sizeof(changed); k++) CHECK(changed[k], "byte %zu never changes", k);
	CHECK_EQ(hw_sys_random(a, 0), 0);
}

// Read from a pty master until `want` shows up or the terminal ends. What was read is in buf.
static int pty_expect(int master, char *buf, size_t cap, const char *want) {
	size_t got = 0;
	buf[0] = '\0';
	while (got < cap - 1) {
		struct pollfd pfd = {.fd = master, .events = POLLIN};
		if (poll(&pfd, 1, 5000) <= 0) break;
		ssize_t n = read(master, buf + got, cap - 1 - got);
		if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
		if (n <= 0) break; // EIO once the child has gone
		got += (size_t)n;
		buf[got] = '\0';
		if (strstr(buf, want)) return 1;
	}
	return 0;
}

// A datagram to a port nothing listens on: where the platform reports it, the connected socket
// that sent it gets ECONNREFUSED from its next send or receive; where it does not, nothing on the
// socket ever says so.
static void test_udp_unreachable(void) {
	int probe = hw_sys_socket(AF_INET, SOCK_DGRAM, 0, 0);
	CHECK(probe >= 0, "socket: errno %d", errno);
	struct sockaddr_in a;
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	CHECK_EQ(bind(probe, (struct sockaddr *)&a, sizeof(a)), 0);
	socklen_t al = sizeof(a);
	CHECK_EQ(getsockname(probe, (struct sockaddr *)&a, &al), 0);
	close(probe);

	int fd = hw_sys_socket(AF_INET, SOCK_DGRAM, 0, 1);
	CHECK(fd >= 0, "socket: errno %d", errno);
	CHECK_EQ(connect(fd, (struct sockaddr *)&a, sizeof(a)), 0);
	int refused = 0;
	for (int i = 0; i < 4 && !refused; i++) {
		if (send(fd, "u", 1, HW_MSG_NOSIGNAL) < 0) {
			CHECK(errno == ECONNREFUSED, "send: errno %d", errno);
			refused = 1;
			break;
		}
		struct pollfd p = {fd, POLLIN, 0};
		if (poll(&p, 1, 200) > 0) {
			// Nothing ever answers, so a receive fails. A readiness with nothing behind it (Wine
			// has them) is no report either.
			char c;
			ssize_t n = recv(fd, &c, 1, 0);
			CHECK(n < 0, "recv: %zd", n);
			if (errno == ECONNREFUSED) {
				refused = 1;
			} else {
				CHECK(errno == EAGAIN || errno == EWOULDBLOCK, "recv: errno %d", errno);
			}
		}
	}
	CHECK_EQ(refused, hw_sys_has_udp_unreachable());
	close(fd);
}

// A UDP socket on 127.0.0.1:port (0: an ephemeral one, written back), in the SO_REUSEPORT group
// there when `group`.
static int udp_bound(uint16_t *port, int group) {
	int fd = hw_sys_socket(AF_INET, SOCK_DGRAM, 0, 1);
	CHECK(fd >= 0, "socket: errno %d", errno);
	int one = 1;
	if (group) CHECK_EQ(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)), 0);
	struct sockaddr_in a;
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	a.sin_port = htons(*port);
	CHECK(bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0, "bind: errno %d", errno);
	socklen_t al = sizeof(a);
	CHECK_EQ(getsockname(fd, (struct sockaddr *)&a, &al), 0);
	*port = ntohs(a.sin_port);
	return fd;
}

static struct sockaddr_in loopback_to(uint16_t port) {
	struct sockaddr_in a;
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	a.sin_port = htons(port);
	return a;
}

#define STEER_N 4

// Which of the group's sockets the next datagram arrives on (its first 4 bytes after the header
// bytes are a tag, checked against `tag`), or -1 when none gets one within the time.
static int steer_which(const int fds[STEER_N], uint32_t tag, size_t tag_at) {
	struct pollfd p[STEER_N];
	for (int i = 0; i < STEER_N; i++) p[i] = (struct pollfd){fds[i], POLLIN, 0};
	if (poll(p, STEER_N, 2000) <= 0) return -1;
	for (int i = 0; i < STEER_N; i++) {
		if (!(p[i].revents & POLLIN)) continue;
		uint8_t buf[64];
		ssize_t n = recv(fds[i], buf, sizeof(buf), 0);
		CHECK(n >= (ssize_t)(tag_at + 4), "recv on %d: %zd errno %d", i, n, errno);
		uint32_t got;
		memcpy(&got, buf + tag_at, 4);
		CHECK_EQ(got, tag);
		return i;
	}
	return -1;
}

// The promise of hw_sys_udp_steer: a datagram whose connection ID starts with i reaches socket i,
// for short headers and for long headers with an 8-byte DCID, and anything else (an index past the
// group, a client's own longer DCID, a runt) reaches exactly one socket, the same one for every
// datagram from one address, and the kernel's hash spreads different addresses over the group.
// That fallback is the kernel's behaviour, not ours, so it is checked here on the kernel that runs.
static void test_udp_steer(void) {
	if (!hw_sys_has_udp_steer()) {
		int fd = 3;
		errno = 0;
		CHECK_EQ(hw_sys_udp_steer(&fd, 1), -1);
		CHECK_EQ(errno, ENOTSUP);
		return;
	}
	uint16_t port = 0;
	int fds[STEER_N];
	for (int i = 0; i < STEER_N; i++) fds[i] = udp_bound(&port, 1);
	CHECK(hw_sys_udp_steer(fds, STEER_N) == 0, "steer: errno %d", errno);
	struct sockaddr_in to = loopback_to(port);
	int tx = hw_sys_socket(AF_INET, SOCK_DGRAM, 0, 0);
	CHECK(tx >= 0, "socket");
	uint32_t tag = 1;
	for (int round = 0; round < 3; round++) {
		for (int i = 0; i < STEER_N; i++) {
			uint8_t pkt[32];
			memset(pkt, 0xab, sizeof(pkt));
			// Short header: flags, DCID (8 bytes, the first the index), then the rest.
			pkt[0] = 0x40;
			pkt[1] = (uint8_t)i;
			memcpy(pkt + 12, &tag, 4);
			CHECK_EQ(sendto(tx, pkt, sizeof(pkt), 0, (struct sockaddr *)&to, sizeof(to)), (ssize_t)sizeof(pkt));
			CHECK_EQ(steer_which(fds, tag, 12), i);
			tag++;
			// Long header: flags, version, DCID length 8, DCID.
			uint8_t lh[1200];
			memset(lh, 0, sizeof(lh));
			lh[0] = 0xc0;
			lh[4] = 1;
			lh[5] = 8;
			lh[6] = (uint8_t)i;
			memcpy(lh + 12, &tag, 4);
			CHECK_EQ(sendto(tx, lh, sizeof(lh), 0, (struct sockaddr *)&to, sizeof(to)), (ssize_t)sizeof(lh));
			CHECK_EQ(steer_which(fds, tag, 12), i);
			tag++;
		}
	}
	close(tx);

	// The fallback: senders on 32 ports, three kinds of datagram the program cannot steer, three
	// of each per sender.
	int seen[STEER_N] = {0};
	for (int s = 0; s < 32; s++) {
		int from = hw_sys_socket(AF_INET, SOCK_DGRAM, 0, 0);
		CHECK(from >= 0, "socket");
		int where = -1;
		for (int k = 0; k < 9; k++) {
			uint8_t pkt[1200];
			memset(pkt, 0, sizeof(pkt));
			size_t len = sizeof(pkt);
			size_t tag_at = 24;
			if (k % 3 == 0) { // a short header whose index is past the group
				pkt[0] = 0x40;
				pkt[1] = 0xff;
				len = 64;
			} else if (k % 3 == 1) { // an Initial with an 18-byte DCID of the client's choosing
				pkt[0] = 0xc0;
				pkt[4] = 1;
				pkt[5] = 18;
				pkt[6] = 1; // would be a valid index, were the DCID 8 bytes
			} else {        // a runt: too short to read an index from
				len = 6;
				tag_at = 2;
				pkt[0] = 0x40;
				pkt[1] = 1;
			}
			memcpy(pkt + tag_at, &tag, len - tag_at < 4 ? len - tag_at : 4);
			if (len - tag_at < 4) memset(pkt + tag_at, 0, 4); // runts carry no whole tag
			CHECK_EQ(sendto(from, pkt, len, 0, (struct sockaddr *)&to, sizeof(to)), (ssize_t)len);
			int got;
			if (len - tag_at < 4) {
				struct pollfd p[STEER_N];
				for (int i = 0; i < STEER_N; i++) p[i] = (struct pollfd){fds[i], POLLIN, 0};
				CHECK(poll(p, STEER_N, 2000) > 0, "runt delivered");
				got = -1;
				for (int i = 0; i < STEER_N && got < 0; i++) {
					if (!(p[i].revents & POLLIN)) continue;
					uint8_t buf[16];
					CHECK_EQ(recv(fds[i], buf, sizeof(buf), 0), (ssize_t)len);
					got = i;
				}
			} else {
				got = steer_which(fds, tag, tag_at);
			}
			CHECK(got >= 0, "sender %d datagram %d delivered", s, k);
			if (where < 0) where = got;
			CHECK(got == where, "sender %d: datagram %d went to %d, earlier ones to %d", s, k, got, where);
			tag++;
		}
		seen[where]++;
		close(from);
	}
	int used = 0;
	for (int i = 0; i < STEER_N; i++) used += seen[i] > 0;
	CHECK(used >= 2, "32 senders all hashed to one socket: %d %d %d %d", seen[0], seen[1], seen[2], seen[3]);
	// Nothing was delivered twice.
	for (int i = 0; i < STEER_N; i++) {
		uint8_t b[8];
		CHECK(recv(fds[i], b, sizeof(b), MSG_DONTWAIT) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
		      "socket %d holds a datagram nobody sent it", i);
		close(fds[i]);
	}
}

// hw_sys_send_batch sends in order and says how many went; hw_sys_recv_batch takes what is
// waiting, with each sender's address, never waits, and reports a datagram cut by its buffer as
// length 0.
static void test_udp_batch(void) {
	uint16_t rport = 0, sport = 0;
	int rx = udp_bound(&rport, 0);
	int tx = udp_bound(&sport, 0);
	hw_sys_dgram d[HW_SYS_BATCH_MAX];
	memset(d, 0, sizeof(d));
	uint8_t bufs[8][256];
	errno = 0;
	d[0].buf = bufs[0];
	d[0].cap = sizeof(bufs[0]);
	CHECK_EQ(hw_sys_recv_batch(rx, d, 1), -1);
	CHECK(errno == EAGAIN || errno == EWOULDBLOCK, "nothing waiting: errno %d", errno);

	struct sockaddr_in to = loopback_to(rport);
	for (int i = 0; i < 8; i++) {
		memset(bufs[i], 'a' + i, sizeof(bufs[i]));
		d[i].buf = bufs[i];
		d[i].len = 10 + (size_t)i * 30; // 10 .. 220
		memcpy(&d[i].addr, &to, sizeof(to));
		d[i].addr_len = sizeof(to);
	}
	d[7].len = 200; // longer than the buffer it will be received into
	int sent = 0;
	while (sent < 8) {
		int r = hw_sys_send_batch(tx, d + sent, (size_t)(8 - sent));
		CHECK(r >= 1, "send_batch: %d errno %d", r, errno);
		sent += r;
	}
	uint8_t in[8][256];
	hw_sys_dgram rd[8];
	int got = 0;
	uint64_t until = hw_now_ms() + 2000;
	while (got < 8 && hw_now_ms() < until) {
		for (int i = got; i < 8; i++) {
			rd[i].buf = in[i];
			rd[i].cap = i == 7 ? 100 : sizeof(in[i]);
			rd[i].len = 12345;
		}
		struct pollfd p = {rx, POLLIN, 0};
		poll(&p, 1, 200);
		int r = hw_sys_recv_batch(rx, rd + got, (size_t)(8 - got));
		if (r < 0) {
			CHECK(errno == EAGAIN || errno == EWOULDBLOCK, "recv_batch: errno %d", errno);
			continue;
		}
		CHECK(r >= 1 && r <= 8 - got, "recv_batch: %d", r);
		got += r;
	}
	CHECK_EQ(got, 8);
	for (int i = 0; i < 7; i++) {
		CHECK_EQ(rd[i].len, d[i].len);
		CHECK(rd[i].buf[0] == 'a' + i && rd[i].buf[rd[i].len - 1] == 'a' + i, "datagram %d in order", i);
		const struct sockaddr_in *from = (const struct sockaddr_in *)&rd[i].addr;
		CHECK_EQ(rd[i].addr_len, (socklen_t)sizeof(*from));
		CHECK_EQ(ntohs(from->sin_port), sport);
	}
	CHECK_EQ(rd[7].len, 0); // 200 bytes into 100: cut, and said so
	close(rx);
	close(tx);
}

#define CO_LEN   1000
#define CO_TOTAL 32

// Fills the stack below the caller, where the next call's frame will be, with a word that read
// as a length is 2^64 - 2^44: added to a pointer it wraps round to 16 TiB below it, under any
// end it is compared with, and what is there is not mapped. Called through a pointer so that it is
// never inlined into the caller's own frame.
static void stack_poison(void) {
	volatile uint64_t junk[4096];
	for (size_t i = 0; i < sizeof(junk) / sizeof(junk[0]); i++) junk[i] = 0xfffff00000000000ull;
}
static void (*volatile g_stack_poison_fn)(void) = stack_poison;

// The datagrams waiting on rx, taken apart where a read holds several (hw_sys_udp_gro), into
// lens/tags (each datagram's first byte) in order. How many there were. The receive finds its
// stack poisoned (stack_poison): past the last control message a read would take that for a
// length that wraps a pointer round the end of the buffer, which once crashed a worker.
static int coalesced_take(int rx, size_t cap, int want, size_t lens[], uint8_t tags[]) {
	uint8_t *room = malloc(HW_SYS_BATCH_MAX * cap);
	CHECK(room != NULL, "malloc");
	hw_sys_dgram rd[HW_SYS_BATCH_MAX];
	int got = 0;
	uint64_t until = hw_now_ms() + 2000;
	while (got < want && hw_now_ms() < until) {
		for (int i = 0; i < HW_SYS_BATCH_MAX; i++) {
			rd[i].buf = room + (size_t)i * cap;
			rd[i].cap = cap;
		}
		struct pollfd p = {rx, POLLIN, 0};
		poll(&p, 1, 200);
		g_stack_poison_fn();
		int r = hw_sys_recv_batch(rx, rd, HW_SYS_BATCH_MAX);
		if (r < 0) {
			CHECK(errno == EAGAIN || errno == EWOULDBLOCK, "recv_batch: errno %d", errno);
			continue;
		}
		for (int i = 0; i < r; i++) {
			CHECK(rd[i].len > 0 && rd[i].segment > 0 && rd[i].segment <= rd[i].len, "read %d: len %zu segment %zu", i,
			      rd[i].len, rd[i].segment);
			for (size_t off = 0; off < rd[i].len; off += rd[i].segment) {
				CHECK(got < CO_TOTAL + 8, "more datagrams than were sent");
				lens[got] = HW_MIN(rd[i].segment, rd[i].len - off);
				tags[got] = rd[i].buf[off];
				CHECK(rd[i].buf[off + lens[got] - 1] == tags[got], "datagram %d whole", got);
				got++;
			}
		}
	}
	free(room);
	return got;
}

// Whatever the kernel does with a run (one write cut up again, or a write per datagram) and with
// what it receives (one read of several, or one each), the datagrams on the other side are the
// ones sent: each whole, in order, to the address it was sent to. A batch that mixes addresses and
// lengths, a run longer than the kernel may take as one, and a connected socket's send (addr_len 0)
// all keep that promise.
static void test_udp_coalesce(void) {
	uint16_t rport = 0, r2port = 0, sport = 0;
	int rx = udp_bound(&rport, 0);
	int rx2 = udp_bound(&r2port, 0);
	int tx = udp_bound(&sport, 0);
	int gro = hw_sys_udp_gro(rx);
	CHECK(gro == 0 || gro == 1, "gro %d", gro);
	size_t cap = gro ? HW_SYS_GRO_SLOT : 2048;
	struct sockaddr_in to = loopback_to(rport), to2 = loopback_to(r2port);

	// 20 of CO_LEN and a shorter one to rx, 3 to rx2, then 8 more of CO_LEN to rx: 32 in one batch.
	static uint8_t bufs[CO_TOTAL][CO_LEN];
	hw_sys_dgram d[CO_TOTAL];
	memset(d, 0, sizeof(d));
	size_t want_len[CO_TOTAL];
	int n1 = 0;
	for (int i = 0; i < CO_TOTAL; i++) {
		int second = i >= 21 && i < 24;
		size_t len = i == 20 ? 300 : second ? 100 : CO_LEN;
		memset(bufs[i], 'A' + i, len);
		d[i].buf = bufs[i];
		d[i].len = len;
		memcpy(&d[i].addr, second ? &to2 : &to, sizeof(to));
		d[i].addr_len = sizeof(to);
		if (!second) want_len[n1++] = len;
	}
	int sent = 0;
	while (sent < CO_TOTAL) {
		int r = hw_sys_send_batch(tx, d + sent, (size_t)(CO_TOTAL - sent));
		CHECK(r >= 1, "send_batch: %d errno %d", r, errno);
		sent += r;
	}
	size_t lens[CO_TOTAL + 8];
	uint8_t tags[CO_TOTAL + 8];
	int got = coalesced_take(rx, cap, n1, lens, tags);
	CHECK_EQ(got, n1);
	for (int i = 0, k = 0; i < CO_TOTAL; i++) {
		if (i >= 21 && i < 24) continue;
		CHECK_EQ(lens[k], want_len[k]);
		CHECK(tags[k] == 'A' + i, "datagram %d in order: got %c", k, tags[k]);
		k++;
	}
	got = coalesced_take(rx2, 2048, 3, lens, tags);
	CHECK_EQ(got, 3);
	for (int i = 0; i < 3; i++) CHECK(lens[i] == 100 && tags[i] == 'A' + 21 + i, "rx2 datagram %d", i);

	// A connected socket: no address at all.
	struct sockaddr_in back = loopback_to(rport);
	CHECK_EQ(connect(tx, (struct sockaddr *)&back, sizeof(back)), 0);
	for (int i = 0; i < 10; i++) {
		d[i].len = CO_LEN;
		memset(bufs[i], 'a' + i, CO_LEN);
		d[i].addr_len = 0;
	}
	sent = 0;
	while (sent < 10) {
		int r = hw_sys_send_batch(tx, d + sent, (size_t)(10 - sent));
		CHECK(r >= 1, "connected send_batch: %d errno %d", r, errno);
		sent += r;
	}
	got = coalesced_take(rx, cap, 10, lens, tags);
	CHECK_EQ(got, 10);
	for (int i = 0; i < 10; i++) CHECK(lens[i] == CO_LEN && tags[i] == 'a' + i, "connected datagram %d", i);
	close(rx);
	close(rx2);
	close(tx);
}

// A coalesced read and then a single datagram in one batch: the single one has no control
// message, so its slot holds what the stack held (stack_poison), and the walk over the
// coalesced read's message must end at its last byte rather than read that as a length. It read
// it once, made a pointer that wrapped round the end check, and took a worker down.
static void test_udp_gro_then_single(void) {
	uint16_t rport = 0, sport = 0, s2port = 0;
	int rx = udp_bound(&rport, 0);
	int tx = udp_bound(&sport, 0);
	int tx2 = udp_bound(&s2port, 0);
	if (hw_sys_udp_gro(rx) != 1) {
		close(rx);
		close(tx);
		close(tx2);
		return; // no GRO here: nothing is coalesced and there is no control message to walk
	}
	struct sockaddr_in to = loopback_to(rport);
	static uint8_t bufs[8][CO_LEN];
	hw_sys_dgram d[8];
	memset(d, 0, sizeof(d));
	for (int i = 0; i < 8; i++) {
		memset(bufs[i], 'A' + i, CO_LEN);
		d[i].buf = bufs[i];
		d[i].len = CO_LEN;
		memcpy(&d[i].addr, &to, sizeof(to));
		d[i].addr_len = sizeof(to);
	}
	for (int sent = 0; sent < 8;) {
		int r = hw_sys_send_batch(tx, d + sent, (size_t)(8 - sent));
		CHECK(r >= 1, "send_batch: %d errno %d", r, errno);
		sent += r;
	}
	uint8_t one[500];
	memset(one, 'z', sizeof(one));
	CHECK_EQ(sendto(tx2, one, sizeof(one), 0, (struct sockaddr *)&to, sizeof(to)), (ssize_t)sizeof(one));
	size_t lens[CO_TOTAL + 8];
	uint8_t tags[CO_TOTAL + 8];
	CHECK_EQ(coalesced_take(rx, HW_SYS_GRO_SLOT, 9, lens, tags), 9);
	for (int i = 0; i < 8; i++) CHECK(lens[i] == CO_LEN && tags[i] == 'A' + i, "datagram %d", i);
	CHECK(lens[8] == sizeof(one) && tags[8] == 'z', "the single datagram");
	close(rx);
	close(tx);
	close(tx2);
}

// hw_sys_poll_us never returns before its timeout when nothing is ready, keeps a timeout under a
// millisecond to its resolution (1 us, or a whole millisecond where it rounds up), and returns at
// once for a descriptor that is ready.
static void test_poll_us(void) {
	unsigned res = hw_sys_poll_resolution_us();
	CHECK(res == 1 || res == 1000, "resolution %u", res);
	uint16_t port = 0;
	int fd = udp_bound(&port, 0);
	struct pollfd p = {fd, POLLIN, 0};
	CHECK_EQ(hw_sys_poll_us(&p, 1, 0), 0);
	uint64_t late[9];
	for (int i = 0; i < 9; i++) {
		uint64_t t0 = hw_now_us();
		CHECK_EQ(hw_sys_poll_us(&p, 1, 300), 0);
		uint64_t took = hw_now_us() - t0;
		CHECK(took >= 300, "returned after %llu us of 300", (unsigned long long)took);
		late[i] = took - 300;
	}
	// The median, against a machine that is busy now and then: a millisecond poll waits 1000.
	for (int i = 0; i < 9; i++) {
		for (int j = i + 1; j < 9; j++) {
			if (late[j] < late[i]) {
				uint64_t t = late[i];
				late[i] = late[j];
				late[j] = t;
			}
		}
	}
	if (res == 1) CHECK(late[4] < 500, "a poll of 300 us took %llu us more", (unsigned long long)late[4]);
	if (res == 1000) CHECK(late[4] >= 600, "rounded up to a millisecond: %llu us late", (unsigned long long)late[4]);
	uint16_t txport = 0;
	int tx = udp_bound(&txport, 0);
	struct sockaddr_in to = loopback_to(port);
	CHECK_EQ(sendto(tx, "x", 1, 0, (struct sockaddr *)&to, sizeof(to)), 1);
	CHECK_EQ(hw_sys_poll_us(&p, 1, 2000000), 1);
	CHECK(p.revents & POLLIN, "readable");
	close(tx);
	close(fd);
}

// A run never spans run_start: a datagram that starts a run (a pacer's release) is not sent in
// one write with the ones before it, where the kernel would put them on the wire back to back.
// Received with GRO on loopback, a write arrives as one read, so no read may hold datagrams of two
// releases. Where nothing is coalesced (no GSO or no GRO) every read is one datagram and that holds.
static void test_udp_run_start(void) {
	enum {
		N = 12,
		RELEASE = 4
	};
	uint16_t rport = 0, sport = 0;
	int rx = udp_bound(&rport, 0);
	int tx = udp_bound(&sport, 0);
	int gro = hw_sys_udp_gro(rx);
	size_t cap = gro == 1 ? HW_SYS_GRO_SLOT : 2048;
	struct sockaddr_in to = loopback_to(rport);
	static uint8_t bufs[N][CO_LEN];
	hw_sys_dgram d[N];
	memset(d, 0, sizeof(d));
	for (int i = 0; i < N; i++) {
		memset(bufs[i], 'A' + i, CO_LEN);
		d[i].buf = bufs[i];
		d[i].len = CO_LEN;
		d[i].run_start = i % RELEASE == 0;
		memcpy(&d[i].addr, &to, sizeof(to));
		d[i].addr_len = sizeof(to);
	}
	for (int sent = 0; sent < N;) {
		int r = hw_sys_send_batch(tx, d + sent, (size_t)(N - sent));
		CHECK(r >= 1, "send_batch: %d errno %d", r, errno);
		sent += r;
	}
	uint8_t *room = malloc(HW_SYS_BATCH_MAX * cap);
	CHECK(room != NULL, "malloc");
	hw_sys_dgram rd[HW_SYS_BATCH_MAX];
	int got = 0, most = 0;
	uint64_t until = hw_now_ms() + 2000;
	while (got < N && hw_now_ms() < until) {
		for (int i = 0; i < HW_SYS_BATCH_MAX; i++) {
			rd[i].buf = room + (size_t)i * cap;
			rd[i].cap = cap;
		}
		struct pollfd p = {rx, POLLIN, 0};
		poll(&p, 1, 200);
		int r = hw_sys_recv_batch(rx, rd, HW_SYS_BATCH_MAX);
		if (r < 0) continue;
		for (int i = 0; i < r; i++) {
			CHECK(rd[i].segment > 0 && rd[i].len % rd[i].segment == 0, "read %zu of %zu", rd[i].len, rd[i].segment);
			int first = rd[i].buf[0] - 'A', in = (int)(rd[i].len / rd[i].segment);
			int last = rd[i].buf[rd[i].len - 1] - 'A';
			CHECK(first == got && last == got + in - 1, "datagrams %d..%d in order: got %d", first, last, got);
			CHECK(first / RELEASE == last / RELEASE, "one read holds datagrams %d to %d, of two releases", first, last);
			if (in > most) most = in;
			got += in;
		}
	}
	CHECK_EQ(got, N);
	if (gro == 1) CHECK(most > 1, "nothing was coalesced: the test shows nothing here");
	free(room);
	close(rx);
	close(tx);
}

// The buffers asked for are what the socket reports afterwards, whatever the cap made of them.
static void test_udp_buffers(void) {
	uint16_t port = 0;
	int fd = udp_bound(&port, 0);
	size_t got = hw_sys_udp_buffers(fd, 1024 * 1024);
	int now = 0;
	socklen_t nl = sizeof(now);
	CHECK_EQ(getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &now, &nl), 0);
	CHECK(got > 0 && got == (size_t)now, "granted %zu, the socket says %d", got, now);
	close(fd);
}

// Don't-fragment takes on an IPv4 and an IPv6 socket, and a datagram the path carries still
// arrives whole: the loopback's MTU holds 9000 bytes, so nothing here is lost or cut.
static void test_udp_no_fragment(void) {
	uint16_t port = 0;
	int rx = udp_bound(&port, 0);
	int tx = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(tx >= 0, "socket: errno %d", errno);
	CHECK_EQ(hw_sys_udp_no_fragment(tx), 0);
	struct sockaddr_in to;
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_port = htons(port);
	to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	static uint8_t buf[9000], got[9100];
	const size_t sizes[] = {1200, 1452, 9000};
	for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		memset(buf, (int)i + 1, sizes[i]);
		CHECK_EQ(sendto(tx, (const char *)buf, sizes[i], 0, (struct sockaddr *)&to, sizeof(to)), (ssize_t)sizes[i]);
		struct pollfd pfd = {.fd = rx, .events = POLLIN};
		CHECK_EQ(poll(&pfd, 1, 2000), 1);
		ssize_t n = recv(rx, (char *)got, sizeof(got), 0);
		CHECK(n == (ssize_t)sizes[i] && got[0] == (uint8_t)(i + 1), "%zu bytes: got %zd", sizes[i], n);
	}
	close(tx);
	close(rx);
	int six = socket(AF_INET6, SOCK_DGRAM, 0);
	if (six >= 0) {
		struct sockaddr_in6 any;
		memset(&any, 0, sizeof(any));
		any.sin6_family = AF_INET6;
		any.sin6_addr = in6addr_loopback;
		if (bind(six, (struct sockaddr *)&any, sizeof(any)) == 0) CHECK_EQ(hw_sys_udp_no_fragment(six), 0);
		close(six);
	}
	CHECK(hw_sys_udp_no_fragment(-1) != 0, "a descriptor that is none");
}

// A mark is set or refused, and a refused one leaves the socket as it was: with the capability the
// mark takes; without it (the usual case here, an unprivileged test) the call says EPERM. Either
// way the socket still sends. Without marks at all the answer is ENOTSUP.
static void test_mark(void) {
	int rx = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(rx >= 0, "socket: errno %d", errno);
	struct sockaddr_in a;
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	CHECK_EQ(bind(rx, (struct sockaddr *)&a, sizeof(a)), 0);
	socklen_t al = sizeof(a);
	CHECK_EQ(getsockname(rx, (struct sockaddr *)&a, &al), 0);
	int tx = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(tx >= 0, "socket: errno %d", errno);
	errno = 0;
	int r = hw_sys_set_mark(tx, 0x7701);
	if (!hw_sys_has_mark()) {
		CHECK_EQ(r, -1);
		CHECK_EQ(errno, ENOTSUP);
	} else {
		CHECK(r == 0 || errno == EPERM, "set_mark: %d, errno %d", r, errno);
	}
	// A marked socket may route elsewhere; only an unmarked one must still reach loopback here.
	if (r != 0) {
		CHECK_EQ(connect(tx, (struct sockaddr *)&a, sizeof(a)), 0);
		CHECK_EQ(send(tx, "m", 1, 0), 1);
		struct pollfd p = {rx, POLLIN, 0};
		CHECK_EQ(poll(&p, 1, 2000), 1);
		char c = 0;
		CHECK_EQ(recv(rx, &c, 1, 0), 1);
		CHECK_EQ(c, 'm');
	}
	close(tx);
	close(rx);
}

static void test_pty(void) {
	char sh[] = "sh", dash_c[] = "-c";
	char script[] = "test -t 0 && echo on a tty && read line && stty size && sleep 30";
	char *argv[] = {sh, dash_c, script, NULL};
	int master = -1;
	if (!hw_sys_has_pty()) {
		errno = 0;
		CHECK(hw_sys_pty_spawn(argv, &master) < 0, "no pty, but a spawn worked");
		CHECK_EQ(errno, ENOTSUP);
		return;
	}
	pid_t pid = hw_sys_pty_spawn(argv, &master);
	CHECK(pid > 0, "pty_spawn: errno %d", errno);
	CHECK(master >= 0, "master %d", master);
	// The child's stdio is the terminal, and the master is ours to poll.
	char buf[256];
	CHECK(pty_expect(master, buf, sizeof(buf), "on a tty"), "read \"%s\"", buf);
	char none;
	CHECK(read(master, &none, 1) < 0 && errno == EAGAIN, "the master is non-blocking");
	// The size we set is the size the child's terminal reports.
	hw_sys_pty_resize(master, 41, 107);
	CHECK_EQ(write(master, "\n", 1), 1);
	CHECK(pty_expect(master, buf, sizeof(buf), "41 107"), "read \"%s\"", buf);
	// It is now in `sleep 30`. Ending it does not wait for that, and the terminal closes.
	uint64_t t0 = hw_now_ms();
	hw_sys_pty_end(pid);
	CHECK(hw_now_ms() - t0 < 5000, "pty_end waited for the child");
	CHECK(!pty_expect(master, buf, sizeof(buf), "never printed"), "read \"%s\"", buf);
	close(master);

	// A caller that ignores SIGPIPE (the server does) does not pass that on: the command gets the
	// default, under which the signal ends it. Ignored, the shell would live to print the word.
	void (*before)(int) = signal(SIGPIPE, SIG_IGN);
	char pipe_script[] = "echo started; kill -PIPE $$; echo survived";
	char *pipe_argv[] = {sh, dash_c, pipe_script, NULL};
	pid = hw_sys_pty_spawn(pipe_argv, &master);
	signal(SIGPIPE, before);
	CHECK(pid > 0, "pty_spawn: errno %d", errno);
	CHECK(!pty_expect(master, buf, sizeof(buf), "survived"), "read \"%s\"", buf);
	CHECK(strstr(buf, "started") != NULL, "read \"%s\"", buf);
	hw_sys_pty_end(pid);
	close(master);
}

int main(void) {
	RUN(test_set_cloexec);
	RUN(test_socket_flags);
	RUN(test_accept_flags_and_no_sigpipe);
	RUN(test_keepalive);
	RUN(test_listen_more);
	RUN(test_shared_accept_never_blocks);
	RUN(test_relay_pipe);
	RUN(test_close_reset);
	RUN(test_crypt);
	RUN(test_random);
	RUN(test_udp_unreachable);
	RUN(test_udp_steer);
	RUN(test_udp_batch);
	RUN(test_udp_coalesce);
	RUN(test_udp_gro_then_single);
	RUN(test_poll_us);
	RUN(test_udp_run_start);
	RUN(test_udp_buffers);
	RUN(test_udp_no_fragment);
	RUN(test_mark);
	RUN(test_pty);
	return 0;
}
