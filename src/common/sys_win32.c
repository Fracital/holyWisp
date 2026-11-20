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
#include <limits.h>
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

ssize_t hw_sys_send_now(int fd, const void *buf, size_t len) {
	// The compat layer keeps MSG_DONTWAIT's promise on a blocking socket (posix.c, dontwait_begin).
	return send(fd, buf, len, MSG_DONTWAIT);
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

// Winsock would report it, but the compat layer turns that off for every datagram socket
// (SIO_UDP_CONNRESET in src/compat/win32/posix.c), so a datagram to a closed port is lost.
int hw_sys_has_udp_unreachable(void) {
	return 0;
}

// Windows has no socket marks for policy routing.
size_t hw_sys_udp_buffers(int fd, int bytes) {
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
	int got = 0;
	socklen_t gl = sizeof(got);
	return getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &got, &gl) == 0 && got > 0 ? (size_t)got : 0;
}

int hw_sys_has_mark(void) {
	return 0;
}

int hw_sys_set_mark(int fd, uint32_t mark) {
	(void)fd;
	(void)mark;
	errno = ENOTSUP;
	return -1;
}

// No SO_REUSEPORT groups here (see hw_sys_listen_more): one socket, one worker.
int hw_sys_has_udp_steer(void) {
	return 0;
}

int hw_sys_udp_steer(const int fds[], size_t n) {
	(void)fds;
	(void)n;
	errno = ENOTSUP;
	return -1;
}

int hw_sys_recv_batch(int fd, hw_sys_dgram *d, size_t n) {
	if (n > HW_SYS_BATCH_MAX) n = HW_SYS_BATCH_MAX;
	size_t got = 0;
	while (got < n) {
		socklen_t al = sizeof(d[got].addr);
		ssize_t r = recvfrom(fd, d[got].buf, d[got].cap, MSG_DONTWAIT, (struct sockaddr *)&d[got].addr, &al);
		if (r < 0 && errno == EINTR) continue;
		// Winsock reports a datagram larger than the buffer as an error, and has taken it.
		if (r < 0 && errno == EMSGSIZE) r = 0;
		if (r < 0) break;
		d[got].len = (size_t)r;
		d[got].segment = d[got].len;
		d[got].addr_len = al;
		got++;
	}
	return got > 0 ? (int)got : -1;
}

int hw_sys_send_batch(int fd, const hw_sys_dgram *d, size_t n) {
	if (n > HW_SYS_BATCH_MAX) n = HW_SYS_BATCH_MAX;
	size_t sent = 0;
	while (sent < n) {
		ssize_t r = d[sent].addr_len ? sendto(fd, d[sent].buf, d[sent].len, MSG_DONTWAIT,
		                                      (const struct sockaddr *)&d[sent].addr, d[sent].addr_len)
		                             : send(fd, d[sent].buf, d[sent].len, MSG_DONTWAIT);
		if (r < 0 && errno == EINTR) continue;
		if (r < 0) break;
		sent++;
	}
	return sent > 0 ? (int)sent : -1;
}

// No segmentation offload: every datagram is a write and a read of its own.
int hw_sys_has_udp_gso(void) {
	return 0;
}

int hw_sys_udp_gro(int fd) {
	(void)fd;
	return 0;
}

int hw_sys_has_crypt(const char *setting) {
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

#ifndef IP_DONTFRAGMENT
#define IP_DONTFRAGMENT 14
#endif
#ifndef IPV6_DONTFRAG
#define IPV6_DONTFRAG 14
#endif

int hw_sys_udp_no_fragment(int fd) {
	// The family decides which option must take; a socket not bound yet has none to tell (Windows
	// refuses getsockname then), and takes whichever applies. A dual-stack socket's IPv4 datagrams
	// follow the IPv4 option, so an IPv6 socket gets both.
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(ss));
	socklen_t sl = sizeof(ss);
	int family = getsockname(fd, (struct sockaddr *)&ss, &sl) == 0 ? ss.ss_family : AF_UNSPEC;
	int v4 = 1, v6 = 1;
	int r4 = setsockopt(fd, IPPROTO_IP, IP_DONTFRAGMENT, (const void *)&v4, sizeof(v4));
	if (family == AF_INET) return r4 == 0 ? 0 : -1;
	int r6 = setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, (const void *)&v6, sizeof(v6));
	if (family == AF_INET6) return r6 == 0 ? 0 : -1;
	return r4 == 0 || r6 == 0 ? 0 : -1;
}

int hw_sys_poll_us(struct pollfd *fds, nfds_t n, int64_t timeout_us) {
	if (timeout_us <= 0) return poll(fds, n, timeout_us < 0 ? -1 : 0);
	// Winsock's wait can expire early relative to the monotonic clock, even with the timeout
	// rounded up. Wait out the rounded interval without delaying readiness or errors.
	uint64_t duration = ((uint64_t)timeout_us + 999) / 1000 * 1000;
	uint64_t start = hw_now_us();
	uint64_t left = duration;
	for (;;) {
		uint64_t ms = (left + 999) / 1000;
		int r = poll(fds, n, ms > INT_MAX ? INT_MAX : (int)ms);
		if (r != 0) return r;
		uint64_t elapsed = hw_now_us() - start;
		if (elapsed >= duration) return 0;
		left = duration - elapsed;
	}
}

unsigned hw_sys_poll_resolution_us(void) {
	return 1000;
}

// Windows has no user signals; a console sends only the two that stop the server.
int hw_sys_user_signals(void (*fn)(int which)) {
	(void)fn;
	errno = ENOTSUP;
	return -1;
}
