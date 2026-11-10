// <poll.h> for Windows: poll(2) over the descriptors of posix.c. See src/compat/win32/hw_w32.h.
#ifndef HOLYWISP_COMPAT_POLL_H
#define HOLYWISP_COMPAT_POLL_H

#include <sys/socket.h>

// Winsock has a struct pollfd of its own, whose fd is a SOCKET.
struct hw_w32_pollfd {
	int fd;
	short events;
	short revents;
};
#define pollfd hw_w32_pollfd

typedef unsigned long nfds_t;

// Sockets only, at most 64 of them. POLLIN, POLLOUT and POLLERR are reported; a peer that hung
// up is POLLIN, and the read says so.
int poll(struct pollfd *fds, nfds_t n, int timeout_ms);

#endif
