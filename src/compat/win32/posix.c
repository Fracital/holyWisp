/*
 * The POSIX calls the headers under include/ declare, over Winsock and the C runtime.
 *
 * The descriptor table is the centre of it. A socket gets a number at or above HW_W32_FD_BASE; the
 * slot holds its SOCKET and whether it is non-blocking (Winsock can set that but not report it).
 * Slots live in chunks that are allocated once and never move, so a lookup takes no lock: only
 * handing a number out and taking it back do. Freed numbers are reused newest-first, which keeps
 * them small, and the event loop's table is indexed by them.
 *
 * One Winsock habit is corrected rather than passed on. A non-blocking send to a stream socket
 * that has any room at all takes the whole buffer, however large, and only the next call is
 * refused; POSIX takes what fits. The server's flow control rests on the POSIX behaviour (what the
 * kernel did not take is what it counts as queued), so a non-blocking send here hands the kernel
 * at most one send buffer's worth and reports a short write for the rest. A blocking send has the
 * same habit: with room in the buffer it returns at once, the whole of a large write held by the
 * kernel. Here it goes out a send buffer at a time, so it returns when the peer has taken all but
 * that much, which is what a sender that waits for its peer is relying on.
 */
#define HW_W32_NO_MACROS

#include "hw_w32.h"

#include <direct.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <windows.h>
#include <ws2tcpip.h>

#include <sys/socket.h>
#include <sys/stat.h>

// ---------------------------------------------------------------------------------- start-up

// Winsock has to be started before its first call. Every program that uses a socket links this
// file, so this runs before main in all of them.
__attribute__((constructor)) static void w32_start(void) {
	WSADATA data;
	if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
		fputs("holywisp: WSAStartup failed\n", stderr);
		abort();
	}
}

// ---------------------------------------------------------------------------------- errors

int hw_w32_error(int wsa_error) {
	switch (wsa_error) {
	case 0:
		return 0;
	case WSAEWOULDBLOCK:
		return EAGAIN;
	case WSAEINPROGRESS:
		return EINPROGRESS;
	case WSAEALREADY:
		return EALREADY;
	case WSAEINTR:
		return EINTR;
	case WSAEBADF:
	case WSAENOTSOCK:
		return EBADF;
	case WSAEACCES:
		return EACCES;
	case WSAEFAULT:
		return EFAULT;
	case WSAEINVAL:
		return EINVAL;
	case WSAEMFILE:
		return EMFILE;
	case WSAEMSGSIZE:
		return EMSGSIZE;
	case WSAEPROTOTYPE:
		return EPROTOTYPE;
	case WSAENOPROTOOPT:
		return ENOPROTOOPT;
	case WSAEPROTONOSUPPORT:
		return EPROTONOSUPPORT;
	case WSAEOPNOTSUPP:
		return EOPNOTSUPP;
	case WSAEAFNOSUPPORT:
		return EAFNOSUPPORT;
	case WSAEADDRINUSE:
		return EADDRINUSE;
	case WSAEADDRNOTAVAIL:
		return EADDRNOTAVAIL;
	case WSAENETDOWN:
		return ENETDOWN;
	case WSAENETUNREACH:
		return ENETUNREACH;
	case WSAENETRESET:
		return ENETRESET;
	case WSAECONNABORTED:
		return ECONNABORTED;
	case WSAECONNRESET:
		return ECONNRESET;
	case WSAENOBUFS:
		return ENOBUFS;
	case WSAEISCONN:
		return EISCONN;
	case WSAENOTCONN:
		return ENOTCONN;
	case WSAESHUTDOWN:
		return EPIPE;
	case WSAETIMEDOUT:
		return ETIMEDOUT;
	case WSAECONNREFUSED:
		return ECONNREFUSED;
	case WSAEHOSTUNREACH:
		return EHOSTUNREACH;
	case WSAEDESTADDRREQ:
		return EDESTADDRREQ;
	case WSA_NOT_ENOUGH_MEMORY:
		return ENOMEM;
	default:
		return EIO;
	}
}

int hw_w32_fail(void) {
	errno = hw_w32_error(WSAGetLastError());
	return -1;
}

// ---------------------------------------------------------------------------------- descriptors

enum {
	SLOT_FREE = 0,
	SLOT_SOCKET,
	SLOT_OBJECT
};

typedef struct slot {
	uintptr_t handle; // the SOCKET, the object, or (free) the next free index
	uint32_t sndbuf;  // SO_SNDBUF of a stream socket once it has been asked for; 0 before
	uint8_t kind;
	uint8_t nonblock;
	uint8_t stream; // SOCK_STREAM
} slot;

#define CHUNK_BITS 10
#define CHUNK_SIZE (1 << CHUNK_BITS)
#define CHUNK_MAX  1024 // about a million descriptors

static _Atomic(slot *) g_chunks[CHUNK_MAX];
static SRWLOCK g_lock = SRWLOCK_INIT;
static int g_free = -1;   // newest freed index
static _Atomic int g_end; // indexes below this have been handed out at least once

static slot *slot_at(int index) {
	return &atomic_load(&g_chunks[index >> CHUNK_BITS])[index & (CHUNK_SIZE - 1)];
}

static int fd_new(uintptr_t handle, uint8_t kind, int nonblock) {
	AcquireSRWLockExclusive(&g_lock);
	int index = g_free;
	if (index >= 0) {
		g_free = (int)slot_at(index)->handle;
	} else {
		index = atomic_load(&g_end);
		if (index >= CHUNK_MAX * CHUNK_SIZE) {
			ReleaseSRWLockExclusive(&g_lock);
			errno = EMFILE;
			return -1;
		}
		if ((index & (CHUNK_SIZE - 1)) == 0) {
			slot *chunk = calloc(CHUNK_SIZE, sizeof(*chunk));
			if (!chunk) {
				ReleaseSRWLockExclusive(&g_lock);
				errno = ENOMEM;
				return -1;
			}
			atomic_store(&g_chunks[index >> CHUNK_BITS], chunk);
		}
		atomic_store(&g_end, index + 1);
	}
	slot *s = slot_at(index);
	s->handle = handle;
	s->sndbuf = 0;
	s->nonblock = nonblock ? 1 : 0;
	s->stream = 0;
	s->kind = kind;
	ReleaseSRWLockExclusive(&g_lock);
	return index + HW_W32_FD_BASE;
}

// The slot of a descriptor of the given kind (0: any that is in use), or NULL with errno EBADF.
static slot *fd_slot(int fd, uint8_t kind) {
	int index = fd - HW_W32_FD_BASE;
	if (index >= 0 && index < atomic_load(&g_end)) {
		slot *s = slot_at(index);
		if (s->kind != SLOT_FREE && (kind == 0 || s->kind == kind)) return s;
	}
	errno = EBADF;
	return NULL;
}

static void fd_release(int fd) {
	int index = fd - HW_W32_FD_BASE;
	AcquireSRWLockExclusive(&g_lock);
	slot *s = slot_at(index);
	s->kind = SLOT_FREE;
	s->handle = (uintptr_t)g_free;
	g_free = index;
	ReleaseSRWLockExclusive(&g_lock);
}

int hw_w32_adopt(SOCKET s, int nonblock) {
	int fd = fd_new((uintptr_t)s, SLOT_SOCKET, nonblock);
	if (fd < 0) {
		int saved = errno;
		closesocket(s);
		errno = saved;
		return -1;
	}
	int type = 0, len = sizeof(type);
	if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&type, &len) == 0 && type == SOCK_STREAM) {
		slot_at(fd - HW_W32_FD_BASE)->stream = 1;
	}
	return fd;
}

SOCKET hw_w32_sock(int fd) {
	slot *s = fd_slot(fd, SLOT_SOCKET);
	return s ? (SOCKET)s->handle : INVALID_SOCKET;
}

int hw_w32_object(hw_w32_obj *obj) {
	return fd_new((uintptr_t)obj, SLOT_OBJECT, 0);
}

hw_w32_obj *hw_w32_object_of(int fd) {
	slot *s = fd_slot(fd, SLOT_OBJECT);
	return s ? (hw_w32_obj *)s->handle : NULL;
}

// ---------------------------------------------------------------------------------- sockets

static int clamp_len(size_t n) {
	return n > INT_MAX ? INT_MAX : (int)n;
}

// What every socket here starts with. Urgent data is read in line, so that select's "exceptional"
// set only ever means a failed connect. And a datagram socket does not turn an ICMP "port
// unreachable" for something it sent into an error on its next receive, which is what Windows
// does unless told otherwise.
static void socket_defaults(SOCKET s, int type) {
	if (type == SOCK_STREAM) {
		BOOL on = TRUE;
		setsockopt(s, SOL_SOCKET, SO_OOBINLINE, (const char *)&on, sizeof(on));
	} else if (type == SOCK_DGRAM) {
		BOOL off = FALSE;
		DWORD ignored = 0;
		WSAIoctl(s, _WSAIOW(IOC_VENDOR, 12) /* SIO_UDP_CONNRESET */, &off, sizeof(off), NULL, 0, &ignored, NULL, NULL);
	}
}

int hw_w32_socket(int domain, int type, int protocol) {
	SOCKET s = WSASocketW(domain, type, protocol, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
	if (s == INVALID_SOCKET) return hw_w32_fail();
	socket_defaults(s, type);
	return hw_w32_adopt(s, 0);
}

int hw_w32_accept(int fd, struct sockaddr *addr, socklen_t *len) {
	slot *ls = fd_slot(fd, SLOT_SOCKET);
	if (!ls) return -1;
	SOCKET s = accept((SOCKET)ls->handle, addr, len);
	if (s == INVALID_SOCKET) return hw_w32_fail();
	SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
	socket_defaults(s, SOCK_STREAM);
	// An accepted socket has its listener's blocking mode.
	return hw_w32_adopt(s, ls->nonblock);
}

int hw_w32_bind(int fd, const struct sockaddr *addr, socklen_t len) {
	SOCKET s = hw_w32_sock(fd);
	if (s == INVALID_SOCKET) return -1;
	return bind(s, addr, len) == 0 ? 0 : hw_w32_fail();
}

int hw_w32_connect(int fd, const struct sockaddr *addr, socklen_t len) {
	SOCKET s = hw_w32_sock(fd);
	if (s == INVALID_SOCKET) return -1;
	if (connect(s, addr, len) == 0) return 0;
	int err = WSAGetLastError();
	// What POSIX calls a connect that has been started on a non-blocking socket.
	errno = err == WSAEWOULDBLOCK ? EINPROGRESS : hw_w32_error(err);
	return -1;
}

int hw_w32_listen(int fd, int backlog) {
	SOCKET s = hw_w32_sock(fd);
	if (s == INVALID_SOCKET) return -1;
	return listen(s, backlog) == 0 ? 0 : hw_w32_fail();
}

int hw_w32_shutdown(int fd, int how) {
	SOCKET s = hw_w32_sock(fd);
	if (s == INVALID_SOCKET) return -1;
	return shutdown(s, how) == 0 ? 0 : hw_w32_fail();
}

int hw_w32_getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
	SOCKET s = hw_w32_sock(fd);
	if (s == INVALID_SOCKET) return -1;
	return getsockname(s, addr, len) == 0 ? 0 : hw_w32_fail();
}

int hw_w32_getpeername(int fd, struct sockaddr *addr, socklen_t *len) {
	SOCKET s = hw_w32_sock(fd);
	if (s == INVALID_SOCKET) return -1;
	return getpeername(s, addr, len) == 0 ? 0 : hw_w32_fail();
}

int hw_w32_getsockopt(int fd, int level, int name, void *value, socklen_t *len) {
	SOCKET s = hw_w32_sock(fd);
	if (s == INVALID_SOCKET) return -1;
	if (getsockopt(s, level, name, value, len) != 0) return hw_w32_fail();
	// The pending error of a socket is read as an errno value.
	if (level == SOL_SOCKET && name == SO_ERROR && *len >= (socklen_t)sizeof(int)) {
		int *err = value;
		*err = hw_w32_error(*err);
	}
	return 0;
}

int hw_w32_setsockopt(int fd, int level, int name, const void *value, socklen_t len) {
	SOCKET s = hw_w32_sock(fd);
	if (s == INVALID_SOCKET) return -1;
	if (level == SOL_SOCKET && name == SO_REUSEADDR) return 0; // see <sys/socket.h>
	if (level == SOL_SOCKET && name == SO_REUSEPORT) {
		errno = ENOPROTOOPT;
		return -1;
	}
	if (setsockopt(s, level, name, value, len) != 0) return hw_w32_fail();
	if (level == SOL_SOCKET && name == SO_SNDBUF) fd_slot(fd, SLOT_SOCKET)->sndbuf = 0; // ask again
	return 0;
}

// MSG_DONTWAIT on a blocking socket: make it non-blocking for the one call. A socket belongs to
// one thread, so nobody else sees it change.
static int dontwait_begin(const slot *s, int flags) {
	if (!(flags & MSG_DONTWAIT) || s->nonblock) return 0;
	u_long on = 1;
	ioctlsocket((SOCKET)s->handle, FIONBIO, &on);
	return 1;
}

static void dontwait_end(const slot *s) {
	u_long off = 0;
	ioctlsocket((SOCKET)s->handle, FIONBIO, &off);
}

// The most one send call may hand the kernel: see the top of this file.
static int send_limit(slot *s) {
	if (!s->stream) return INT_MAX;
	if (s->sndbuf == 0) {
		int size = 0, len = sizeof(size);
		if (getsockopt((SOCKET)s->handle, SOL_SOCKET, SO_SNDBUF, (char *)&size, &len) != 0 || size <= 0) size = INT_MAX;
		s->sndbuf = (uint32_t)size;
	}
	return (int)s->sndbuf;
}

static int send_blocks(const slot *s, int flags) {
	return s->stream && !s->nonblock && !(flags & MSG_DONTWAIT);
}

// A blocking send of all of `n`, a send buffer at a time. Returns what went out, or -1 when that is
// nothing.
static ssize_t send_all(slot *s, const char *buf, size_t n, int flags) {
	size_t piece = (size_t)send_limit(s);
	size_t done = 0;
	while (done < n) {
		int r = send((SOCKET)s->handle, buf + done, (int)(n - done > piece ? piece : n - done), flags);
		if (r == SOCKET_ERROR) {
			if (done > 0) break;
			errno = hw_w32_error(WSAGetLastError());
			return -1;
		}
		done += (size_t)r;
	}
	return (ssize_t)done;
}

ssize_t hw_w32_send(int fd, const void *buf, size_t n, int flags) {
	slot *s = fd_slot(fd, SLOT_SOCKET);
	if (!s) return -1;
	if (send_blocks(s, flags)) return send_all(s, buf, n, flags);
	int limit = send_limit(s);
	int restore = dontwait_begin(s, flags);
	int r = send((SOCKET)s->handle, buf, n > (size_t)limit ? limit : (int)n, flags & ~MSG_DONTWAIT);
	int err = r == SOCKET_ERROR ? WSAGetLastError() : 0;
	if (restore) dontwait_end(s);
	if (r == SOCKET_ERROR) {
		errno = hw_w32_error(err);
		return -1;
	}
	return r;
}

ssize_t hw_w32_recv(int fd, void *buf, size_t n, int flags) {
	slot *s = fd_slot(fd, SLOT_SOCKET);
	if (!s) return -1;
	int restore = dontwait_begin(s, flags);
	int r = recv((SOCKET)s->handle, buf, clamp_len(n), flags & ~MSG_DONTWAIT);
	int err = r == SOCKET_ERROR ? WSAGetLastError() : 0;
	if (restore) dontwait_end(s);
	if (r == SOCKET_ERROR) {
		errno = hw_w32_error(err);
		return -1;
	}
	return r;
}

ssize_t hw_w32_sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *to, socklen_t to_len) {
	slot *s = fd_slot(fd, SLOT_SOCKET);
	if (!s) return -1;
	int restore = dontwait_begin(s, flags);
	int r = sendto((SOCKET)s->handle, buf, clamp_len(n), flags & ~MSG_DONTWAIT, to, to_len);
	int err = r == SOCKET_ERROR ? WSAGetLastError() : 0;
	if (restore) dontwait_end(s);
	if (r == SOCKET_ERROR) {
		errno = hw_w32_error(err);
		return -1;
	}
	return r;
}

ssize_t hw_w32_recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *from, socklen_t *from_len) {
	slot *s = fd_slot(fd, SLOT_SOCKET);
	if (!s) return -1;
	int restore = dontwait_begin(s, flags);
	int r = recvfrom((SOCKET)s->handle, buf, clamp_len(n), flags & ~MSG_DONTWAIT, from, from_len);
	int err = r == SOCKET_ERROR ? WSAGetLastError() : 0;
	if (restore) dontwait_end(s);
	if (r == SOCKET_ERROR) {
		errno = hw_w32_error(err);
		return -1;
	}
	return r;
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
	slot *s = fd_slot(fd, SLOT_SOCKET);
	if (!s) return -1;
	if (send_blocks(s, flags)) {
		ssize_t total = 0;
		for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++) {
			ssize_t r = send_all(s, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len, flags);
			if (r < 0) return total > 0 ? total : -1;
			total += r;
			if ((size_t)r < msg->msg_iov[i].iov_len) break;
		}
		return total;
	}
	// More buffers than this go out as a short write, which every caller has to handle anyway.
	WSABUF bufs[64];
	DWORD count = 0;
	size_t room = (size_t)send_limit(s);
	for (size_t i = 0; i < msg->msg_iovlen && count < 64 && room > 0; i++) {
		size_t len = msg->msg_iov[i].iov_len;
		if (len > room) len = room;
		bufs[count].buf = msg->msg_iov[i].iov_base;
		bufs[count].len = (ULONG)len;
		room -= len;
		count++;
	}
	int restore = dontwait_begin(s, flags);
	DWORD sent = 0;
	int r = WSASend((SOCKET)s->handle, bufs, count, &sent, (DWORD)(flags & ~MSG_DONTWAIT), NULL, NULL);
	int err = r == SOCKET_ERROR ? WSAGetLastError() : 0;
	if (restore) dontwait_end(s);
	if (r == SOCKET_ERROR) {
		errno = hw_w32_error(err);
		return -1;
	}
	return (ssize_t)sent;
}

int poll(struct hw_w32_pollfd *fds, nfds_t n, int timeout_ms) {
	if (n > FD_SETSIZE) {
		errno = EINVAL;
		return -1;
	}
	// select, not WSAPoll: before Windows 10 2004 WSAPoll never reports a connect that failed.
	fd_set rd, wr, ex;
	FD_ZERO(&rd);
	FD_ZERO(&wr);
	FD_ZERO(&ex);
	int watched = 0, ready = 0;
	for (nfds_t i = 0; i < n; i++) {
		fds[i].revents = 0;
		if (fds[i].fd < 0) continue;
		SOCKET s = hw_w32_sock(fds[i].fd);
		if (s == INVALID_SOCKET) {
			fds[i].revents = POLLNVAL;
			ready++;
			continue;
		}
		if (fds[i].events & POLLIN) FD_SET(s, &rd);
		if (fds[i].events & POLLOUT) FD_SET(s, &wr);
		FD_SET(s, &ex);
		watched++;
	}
	if (ready > 0) timeout_ms = 0;
	if (watched == 0) {
		if (timeout_ms != 0) Sleep(timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms);
		return ready;
	}
	struct timeval tv = {.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
	if (select(0, &rd, &wr, &ex, timeout_ms < 0 ? NULL : &tv) == SOCKET_ERROR) return hw_w32_fail();
	for (nfds_t i = 0; i < n; i++) {
		if (fds[i].fd < 0 || fds[i].revents) continue;
		SOCKET s = hw_w32_sock(fds[i].fd);
		short got = 0;
		if (FD_ISSET(s, &rd)) got |= (short)(fds[i].events & POLLIN);
		if (FD_ISSET(s, &wr)) got |= POLLOUT;
		if (FD_ISSET(s, &ex)) got |= POLLERR;
		fds[i].revents = got;
		if (got) ready++;
	}
	return ready;
}

int fcntl(int fd, int cmd, ...) {
	slot *s = fd_slot(fd, SLOT_SOCKET);
	if (!s) return -1;
	int arg = 0;
	if (cmd == F_SETFL || cmd == F_SETFD) {
		va_list ap;
		va_start(ap, cmd);
		arg = va_arg(ap, int);
		va_end(ap);
	}
	SOCKET sock = (SOCKET)s->handle;
	switch (cmd) {
	case F_GETFL:
		return s->nonblock ? O_NONBLOCK : 0;
	case F_SETFL: {
		u_long on = (arg & O_NONBLOCK) ? 1 : 0;
		if (ioctlsocket(sock, FIONBIO, &on) != 0) return hw_w32_fail();
		s->nonblock = (uint8_t)on;
		return 0;
	}
	case F_GETFD: {
		DWORD flags = 0;
		if (!GetHandleInformation((HANDLE)sock, &flags)) {
			errno = EBADF;
			return -1;
		}
		return (flags & HANDLE_FLAG_INHERIT) ? 0 : FD_CLOEXEC;
	}
	case F_SETFD:
		if (!SetHandleInformation((HANDLE)sock, HANDLE_FLAG_INHERIT, (arg & FD_CLOEXEC) ? 0 : HANDLE_FLAG_INHERIT)) {
			errno = EBADF;
			return -1;
		}
		return 0;
	default:
		errno = EINVAL;
		return -1;
	}
}

// ---------------------------------------------------------------------------------- both kinds

ssize_t hw_w32_read(int fd, void *buf, size_t n) {
	if (fd < HW_W32_FD_BASE) return _read(fd, buf, (unsigned)clamp_len(n));
	return hw_w32_recv(fd, buf, n, 0);
}

ssize_t hw_w32_write(int fd, const void *buf, size_t n) {
	if (fd < HW_W32_FD_BASE) return _write(fd, buf, (unsigned)clamp_len(n));
	return hw_w32_send(fd, buf, n, 0);
}

int hw_w32_close(int fd) {
	if (fd < HW_W32_FD_BASE) return _close(fd);
	slot *s = fd_slot(fd, 0);
	if (!s) return -1;
	uint8_t kind = s->kind;
	uintptr_t handle = s->handle;
	fd_release(fd);
	if (kind == SLOT_OBJECT) {
		hw_w32_obj *obj = (hw_w32_obj *)handle;
		obj->drop(obj);
		return 0;
	}
	return closesocket((SOCKET)handle) == 0 ? 0 : hw_w32_fail();
}

int hw_w32_pair(int fds[2]) {
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	int len = sizeof(addr);
	SOCKET listener = WSASocketW(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
	SOCKET a = INVALID_SOCKET, b = INVALID_SOCKET;
	if (listener == INVALID_SOCKET) return hw_w32_fail();
	if (bind(listener, (struct sockaddr *)&addr, len) != 0 ||
	    getsockname(listener, (struct sockaddr *)&addr, &len) != 0 || listen(listener, 1) != 0) {
		goto fail;
	}
	a = WSASocketW(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
	if (a == INVALID_SOCKET || connect(a, (struct sockaddr *)&addr, len) != 0) goto fail;
	// Anything on this machine can connect to a loopback port: take only our own connection.
	struct sockaddr_in mine, theirs;
	int mine_len = sizeof(mine), theirs_len = sizeof(theirs);
	if (getsockname(a, (struct sockaddr *)&mine, &mine_len) != 0) goto fail;
	for (;;) {
		b = accept(listener, (struct sockaddr *)&theirs, &theirs_len);
		if (b == INVALID_SOCKET) goto fail;
		if (theirs.sin_port == mine.sin_port && theirs.sin_addr.s_addr == mine.sin_addr.s_addr) break;
		closesocket(b);
		theirs_len = sizeof(theirs);
	}
	closesocket(listener);
	listener = INVALID_SOCKET;
	SetHandleInformation((HANDLE)b, HANDLE_FLAG_INHERIT, 0);
	// Eight bytes written are eight bytes readable now, as with a pipe.
	BOOL on = TRUE;
	setsockopt(a, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(on));
	setsockopt(b, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(on));
	fds[0] = hw_w32_adopt(a, 0);
	if (fds[0] < 0) {
		a = INVALID_SOCKET;
		goto fail_errno;
	}
	fds[1] = hw_w32_adopt(b, 0);
	if (fds[1] < 0) {
		int saved = errno;
		hw_w32_close(fds[0]);
		errno = saved;
		return -1;
	}
	return 0;
fail:
	errno = hw_w32_error(WSAGetLastError());
fail_errno:;
	int saved = errno;
	if (listener != INVALID_SOCKET) closesocket(listener);
	if (a != INVALID_SOCKET) closesocket(a);
	if (b != INVALID_SOCKET) closesocket(b);
	errno = saved;
	return -1;
}

int pipe(int fds[2]) {
	return hw_w32_pair(fds);
}

// ---------------------------------------------------------------------------------- the rest

long sysconf(int name) {
	if (name != _SC_NPROCESSORS_ONLN) {
		errno = EINVAL;
		return -1;
	}
	DWORD n = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
	return n > 0 ? (long)n : 1;
}

void *memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len) {
	const unsigned char *h = haystack;
	if (needle_len == 0) return (void *)(uintptr_t)h;
	if (needle_len > haystack_len) return NULL;
	const unsigned char first = *(const unsigned char *)needle;
	const unsigned char *last = h + (haystack_len - needle_len);
	for (const unsigned char *p = h; p <= last; p++) {
		p = memchr(p, first, (size_t)(last - p) + 1);
		if (!p) return NULL;
		if (memcmp(p, needle, needle_len) == 0) return (void *)(uintptr_t)p;
	}
	return NULL;
}

int hw_w32_rename(const char *from, const char *to) {
	if (MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return 0;
	DWORD err = GetLastError();
	errno = (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) ? ENOENT : EACCES;
	return -1;
}

int hw_w32_mkdir(const char *path, int mode) {
	(void)mode;
	return _mkdir(path);
}

// ---------------------------------------------------------------------------------- signals

static _Atomic(hw_w32_sighandler) g_on_int, g_on_term;

static BOOL WINAPI console_event(DWORD event) {
	int signo = event == CTRL_C_EVENT ? SIGINT : SIGTERM;
	hw_w32_sighandler handler = atomic_load(signo == SIGINT ? &g_on_int : &g_on_term);
	if (!handler) return FALSE;
	handler(signo);
	// For a console that is closing, a logoff and a shutdown, the process is ended as soon as
	// this returns: give main the time to finish what the handler asked for.
	if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT) Sleep(4000);
	return TRUE;
}

int sigemptyset(sigset_t *set) {
	*set = 0;
	return 0;
}

int sigaction(int signo, const struct sigaction *act, struct sigaction *old) {
	if (signo != SIGINT && signo != SIGTERM) {
		errno = EINVAL;
		return -1;
	}
	_Atomic(hw_w32_sighandler) *held = signo == SIGINT ? &g_on_int : &g_on_term;
	if (old) {
		memset(old, 0, sizeof(*old));
		old->sa_handler = atomic_load(held);
	}
	if (!act) return 0;
	static _Atomic int hooked;
	if (!atomic_exchange(&hooked, 1)) SetConsoleCtrlHandler(console_event, TRUE);
	atomic_store(held, act->sa_handler);
	// For raise(). The runtime resets a handler when it has run; console_event does not go
	// through the runtime, so what the console sends keeps arriving.
	signal(signo, act->sa_handler);
	return 0;
}

hw_w32_sighandler hw_w32_signal(int signo, hw_w32_sighandler handler) {
	if (signo == SIGPIPE) return SIG_DFL;
	return signal(signo, handler);
}
