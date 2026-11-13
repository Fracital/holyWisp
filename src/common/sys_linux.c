/*
 * holywisp/sys.h for Linux: every call here is the kernel's own.
 */
#include "holywisp/hw.h"
#include "holywisp/net.h"
#include "holywisp/sys.h"

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/sockios.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/wait.h>

int hw_sys_socket(int domain, int type, int protocol, int nonblock) {
	return socket(domain, type | SOCK_CLOEXEC | (nonblock ? SOCK_NONBLOCK : 0), protocol);
}

int hw_sys_accept(int listen_fd, struct sockaddr *addr, socklen_t *addr_len) {
	return accept4(listen_fd, addr, addr_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
}

void hw_sys_keepalive(int fd, int idle_s, int interval_s, int count) {
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle_s, sizeof(idle_s));
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval_s, sizeof(interval_s));
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
}

int hw_sys_listen_more(int first, const char *host, uint16_t port, int backlog) {
	return hw_listen_tcp(host, port, 1, backlog, NULL);
}

int hw_sys_relay_pipe(int fds[2], size_t want, size_t min, size_t *size) {
	if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0) return -1;
	// Past fs.pipe-user-pages-soft the kernel hands out two-page pipes that cannot be enlarged.
	long sz = fcntl(fds[1], F_SETPIPE_SZ, (int)want);
	if (sz < (long)min) sz = fcntl(fds[1], F_SETPIPE_SZ, (int)min);
	if (sz < (long)min) {
		// EPERM is the same limit refusing an unprivileged resize outright: ENOBUFS, as promised.
		int saved = sz >= 0 || errno == EPERM ? ENOBUFS : errno;
		close(fds[0]);
		close(fds[1]);
		errno = saved;
		return -1;
	}
	*size = (size_t)sz;
	return 0;
}

ssize_t hw_sys_splice(int from, int to, size_t n) {
	return splice(from, NULL, to, NULL, n, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
}

int hw_sys_has_close_reset(void) {
	return 1;
}

int hw_sys_close_reset(int fd) {
	// SIOCOUTQ counts what the peer has not acknowledged, sent or not. A close with a zero linger
	// time resets the connection and discards exactly that, so it is asked for only at zero.
	int queued = 1;
	struct linger lg = {.l_onoff = 1, .l_linger = 0};
	int reset = ioctl(fd, SIOCOUTQ, &queued) == 0 && queued == 0 &&
	            setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg)) == 0;
	close(fd);
	return reset;
}

int hw_sys_random(void *buf, size_t len) {
	uint8_t *p = buf;
	while (len > 0) {
		ssize_t n = getrandom(p, len, 0);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) return -1;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

int hw_sys_has_crypt(void) {
	return 1;
}

int hw_sys_crypt(const char *key, const char *setting, char *out, size_t out_cap) {
	struct crypt_data data;
	memset(&data, 0, sizeof(data));
	const char *got = crypt_r(key, setting, &data);
	// A failure token ("*0", "*1") is not a hash: it must never compare equal to a stored value.
	if (!got || got[0] == '*') return -1;
	size_t n = strlen(got);
	if (n >= out_cap) return -1;
	memcpy(out, got, n + 1);
	return 0;
}

int hw_sys_has_pty(void) {
	return 1;
}

pid_t hw_sys_pty_spawn(char *const argv[], int *master) {
	pid_t pid = forkpty(master, NULL, NULL, NULL);
	if (pid < 0) return -1;
	if (pid == 0) {
		// The server ignores SIGPIPE and an ignored signal stays ignored across exec, where a
		// shell cannot even set it back: `yes | head` would never end.
		signal(SIGPIPE, SIG_DFL);
		setenv("TERM", "xterm-256color", 1);
		execvp(argv[0], argv);
		_exit(127); // exec failed; the master sees the end at once
	}
	if (hw_set_nonblock(*master) != 0 || hw_set_cloexec(*master) != 0) {
		int saved = errno;
		close(*master);
		hw_sys_pty_end(pid);
		errno = saved;
		return -1;
	}
	return pid;
}

void hw_sys_pty_resize(int master, uint16_t rows, uint16_t cols) {
	struct winsize ws;
	memset(&ws, 0, sizeof(ws));
	ws.ws_row = rows;
	ws.ws_col = cols;
	ioctl(master, TIOCSWINSZ, &ws);
}

void hw_sys_pty_end(pid_t pid) {
	// A hang-up on its controlling terminal ends a shell promptly. What ignores it is killed: the
	// caller is a loop thread and cannot wait out a grace period.
	kill(pid, SIGHUP);
	if (waitpid(pid, NULL, WNOHANG) == 0) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
	}
}
