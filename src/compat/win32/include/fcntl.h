// <fcntl.h> for Windows: fcntl(2) for the sockets of posix.c. See src/compat/win32/hw_w32.h.
#ifndef HOLYWISP_COMPAT_FCNTL_H
#define HOLYWISP_COMPAT_FCNTL_H

// This file stands in front of the toolchain's header of the same name and passes on to it.
#pragma GCC system_header
#include_next <fcntl.h>

#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4

#define FD_CLOEXEC 1
// Only ever a status flag of a socket; it shares no call with the runtime's O_ flags.
#define O_NONBLOCK 0x40000000

// The four commands above, on sockets. Close-on-exec is the handle not being inheritable, which
// is how every socket here starts out.
int fcntl(int fd, int cmd, ...);

#endif
