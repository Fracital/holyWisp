/*
 * holywisp/sys.h for Windows, a port for development machines like the macOS one.
 *
 * The sockets are Winsock's behind the descriptors of src/compat/win32 (see hw_w32.h there), so
 * most of this file reads like the other two. What Windows does not have is said so plainly: no
 * relay pipes or splice (bulk streams are copied), no SO_REUSEPORT (the workers share one
 * listening socket), no crypt(3) (a hashed password never matches) and no pseudo-terminal that a
 * readiness loop can watch (Twisp is refused when the server starts).
 */
// rand_s is declared by <stdlib.h> only when this is defined before the first header.
#define _CRT_RAND_S

#include "holywisp/hw.h"
#include "holywisp/net.h"
#include "holywisp/sys.h"

#include "hw_w32.h"

#include <errno.h>
#include <fcntl.h>
#include <mstcpip.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

int hw_sys_socket(int domain, int type, int protocol, int nonblock) {
	// Never inheritable, and there is no SIGPIPE to raise: both are how a socket is made here.
	int fd = socket(domain, type, protocol);
	if (fd >= 0 && nonblock && hw_set_nonblock(fd) != 0) {
		int saved = errno;
		close(fd);
		errno = saved;
		return -1;
	}
	return fd;
}

int hw_sys_accept(int listen_fd, struct sockaddr *addr, socklen_t *addr_len) {
	int fd = accept(listen_fd, addr, addr_len);
	if (fd >= 0 && hw_set_nonblock(fd) != 0) {
		int saved = errno;
		close(fd);
		errno = saved;
		return -1;
	}
	return fd;
}

void hw_sys_keepalive(int fd, int idle_s, int interval_s, int count) {
	// The per-socket options exist from Windows 10 1709. Before that only the two times can be
	// set, in one ioctl, and the probe count is the system's.
	if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle_s, sizeof(idle_s)) == 0 &&
	    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval_s, sizeof(interval_s)) == 0) {
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
		return;
	}
	struct tcp_keepalive ka = {
	    .onoff = 1, .keepalivetime = (u_long)idle_s * 1000, .keepaliveinterval = (u_long)interval_s * 1000};
	DWORD ignored = 0;
	WSAIoctl(hw_w32_sock(fd), SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &ignored, NULL, NULL);
}

int hw_sys_listen_more(int first, const char *host, uint16_t port, int backlog) {
	// A second socket bound to the port would not share its connections, it would take them all
	// or none. So, as on macOS: one listening socket, and a descriptor of its own for each worker.
	SOCKET sock = hw_w32_sock(first);
	if (sock == INVALID_SOCKET) return -1;
	WSAPROTOCOL_INFOW info;
	if (WSADuplicateSocketW(sock, GetCurrentProcessId(), &info) != 0) return hw_w32_fail();
	SOCKET dup = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &info, 0,
	                        WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
	if (dup == INVALID_SOCKET) return hw_w32_fail();
	// Blocking or not is a property of the socket, not of the handle: it is what `first` is.
	int fd = hw_w32_adopt(dup, (fcntl(first, F_GETFL, 0) & O_NONBLOCK) != 0);
	if (fd >= 0) hw_w32_same_socket(fd, first);
	return fd;
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
	// The runtime's rand_s is the system generator (RtlGenRandom), one unsigned int at a time.
	uint8_t *p = buf;
	while (len > 0) {
		unsigned int word;
		if (rand_s(&word) != 0) return -1;
		size_t n = len < sizeof(word) ? len : sizeof(word);
		memcpy(p, &word, n);
		p += n;
		len -= n;
	}
	return 0;
}

// Windows has no socket marks for policy routing.
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
	return 0;
}

int hw_sys_crypt(const char *key, const char *setting, char *out, size_t out_cap) {
	return -1;
}

int hw_sys_has_pty(void) {
	return 0;
}

pid_t hw_sys_pty_spawn(char *const argv[], int *master) {
	errno = ENOTSUP;
	return -1;
}

void hw_sys_pty_resize(int master, uint16_t rows, uint16_t cols) {
}

void hw_sys_pty_end(pid_t pid) {
}
