/*
 * holywisp/sys.h for macOS. A development port: correct, not tuned. Nothing is spliced (remote
 * payloads are copied, the path every small read takes on Linux too) and the workers share one
 * listening socket.
 */
#include "holywisp/hw.h"
#include "holywisp/sys.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

// <util.h> declares this, and the SDK subset a cross-compiler carries may not have that header.
// The function itself is in libSystem.
struct termios;
pid_t forkpty(int *master, char *name, struct termios *termp, struct winsize *winp);

// No MSG_NOSIGNAL here: the socket carries the property instead.
static int socket_prepare(int fd, int nonblock) {
	int one = 1;
	if (hw_set_cloexec(fd) != 0 || (nonblock && hw_set_nonblock(fd) != 0) ||
	    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) != 0) {
		int saved = errno;
		close(fd);
		errno = saved;
		return -1;
	}
	return fd;
}

int hw_sys_socket(int domain, int type, int protocol, int nonblock) {
	int fd = socket(domain, type, protocol);
	return fd < 0 ? -1 : socket_prepare(fd, nonblock);
}

int hw_sys_accept(int listen_fd, struct sockaddr *addr, socklen_t *addr_len) {
	int fd = accept(listen_fd, addr, addr_len);
	return fd < 0 ? -1 : socket_prepare(fd, 1);
}

void hw_sys_keepalive(int fd, int idle_s, int interval_s, int count) {
	// The idle time goes by another name here.
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &idle_s, sizeof(idle_s));
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval_s, sizeof(interval_s));
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
}

int hw_sys_listen_more(int first, const char *host, uint16_t port, int backlog) {
	// The duplicate shares the listening socket and its non-blocking mode.
	return fcntl(first, F_DUPFD_CLOEXEC, 0);
}

int hw_sys_relay_pipe(int fds[2], size_t want, size_t min, size_t *size) {
	errno = ENOTSUP;
	return -1;
}

ssize_t hw_sys_splice(int from, int to, size_t n) {
	errno = ENOSYS;
	return -1;
}

int hw_sys_has_close_reset(void) {
	return 0;
}

int hw_sys_close_reset(int fd) {
	close(fd);
	return 0;
}

int hw_sys_random(void *buf, size_t len) {
	// Seeded from the kernel and reseeded by it; it cannot fail.
	arc4random_buf(buf, len);
	return 0;
}

// macOS has no socket marks for policy routing.
int hw_sys_has_mark(void) {
	return 0;
}

int hw_sys_set_mark(int fd, uint32_t mark) {
	(void)fd;
	(void)mark;
	errno = ENOTSUP;
	return -1;
}

int hw_sys_has_crypt(void) {
	return 1;
}

int hw_sys_crypt(const char *key, const char *setting, char *out, size_t out_cap) {
	// crypt(3) returns a static buffer; auth is far from the data path, so one lock is enough.
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	int r = -1;
	pthread_mutex_lock(&lock);
	const char *got = crypt(key, setting);
	if (got && got[0] != '*') {
		size_t n = strlen(got);
		if (n > 0 && n < out_cap) {
			memcpy(out, got, n + 1);
			r = 0;
		}
	}
	pthread_mutex_unlock(&lock);
	return r;
}

int hw_sys_has_pty(void) {
	return 1;
}

pid_t hw_sys_pty_spawn(char *const argv[], int *master) {
	pid_t pid = forkpty(master, NULL, NULL, NULL);
	if (pid < 0) return -1;
	if (pid == 0) {
		// Nothing of the server's goes into the command. A descriptor is made close-on-exec in a
		// second call here (hw_sys_socket and friends), and a fork on another thread between the
		// two would hand the child a client's socket or the listener: close everything above the
		// terminal's three, whatever its flags.
		int top = getdtablesize();
		for (int fd = 3; fd < top; fd++) close(fd);
		// An ignored signal stays ignored across exec, where a shell cannot even set it back.
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
