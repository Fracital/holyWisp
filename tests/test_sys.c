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
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

static int is_cloexec(int fd) {
	return (fcntl(fd, F_GETFD, 0) & FD_CLOEXEC) != 0;
}

static int is_nonblock(int fd) {
	return (fcntl(fd, F_GETFL, 0) & O_NONBLOCK) != 0;
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
}

int main(void) {
	RUN(test_socket_flags);
	RUN(test_accept_flags_and_no_sigpipe);
	RUN(test_keepalive);
	RUN(test_listen_more);
	RUN(test_relay_pipe);
	RUN(test_crypt);
	RUN(test_pty);
	return 0;
}
