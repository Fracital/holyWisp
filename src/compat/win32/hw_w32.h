/*
 * What the three Windows files share: posix.c here, and src/common/loop_select.c and sys_win32.c.
 *
 * Windows has no descriptors for sockets, only SOCKET handles that close(2), read(2) and poll(2)
 * know nothing about, and Winsock reports errors through WSAGetLastError(), not errno. posix.c
 * gives every socket a descriptor of the POSIX kind: a small int that the calls named in the
 * headers under include/ accept, with errno set the POSIX way. The rest of the tree is written
 * against those names and never sees a SOCKET.
 */
#ifndef HOLYWISP_COMPAT_WIN32_H
#define HOLYWISP_COMPAT_WIN32_H

#include <winsock2.h>

// Descriptors posix.c hands out start here. The C runtime's own (files, the standard streams) are
// always below it (8192 is the most _setmaxstdio allows), so close(), read() and write() can tell
// which kind they were given from the number alone.
#define HW_W32_FD_BASE 8192

// Something that is not a socket but lives in the descriptor table, so that close() frees it:
// embed this first in the object.
typedef struct hw_w32_obj {
	void (*drop)(struct hw_w32_obj *self);
} hw_w32_obj;

// A descriptor for a socket, which is closed if none can be had. -1 with errno.
int hw_w32_adopt(SOCKET s, int nonblock);
// The socket behind a descriptor; INVALID_SOCKET with errno EBADF if it is not one.
SOCKET hw_w32_sock(int fd);
// A descriptor for an object, and the object behind one (NULL with errno EBADF).
int hw_w32_object(hw_w32_obj *obj);
hw_w32_obj *hw_w32_object_of(int fd);

// The errno value for a Winsock error code.
int hw_w32_error(int wsa_error);
// errno = the last Winsock error; returns -1.
int hw_w32_fail(void);

// Two connected stream sockets on loopback, blocking: Windows' stand-in for a pipe a loop can
// watch. What is written to either is read from the other. 0, or -1 with errno.
int hw_w32_pair(int fds[2]);

#endif
