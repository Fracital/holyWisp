/*
 * <unistd.h> for Windows: read, write and close that take both kinds of descriptor, the C
 * runtime's and the sockets of posix.c. See src/compat/win32/hw_w32.h.
 */
#ifndef HOLYWISP_COMPAT_UNISTD_H
#define HOLYWISP_COMPAT_UNISTD_H

// This file stands in front of the toolchain's header of the same name and passes on to it.
#pragma GCC system_header
#include <stddef.h>
#include_next <unistd.h>

#include <sys/types.h>

ssize_t hw_w32_read(int fd, void *buf, size_t n);
ssize_t hw_w32_write(int fd, const void *buf, size_t n);
int hw_w32_close(int fd);

// Not a pipe: a connected pair of loopback sockets, because that is what a loop here can watch.
// Both ends are blocking; fds[0] is the one to read.
int pipe(int fds[2]);

#define _SC_NPROCESSORS_ONLN 84
// _SC_NPROCESSORS_ONLN only.
long sysconf(int name);

#ifndef HW_W32_NO_MACROS
#define read(fd, buf, n)  hw_w32_read((fd), (buf), (n))
#define write(fd, buf, n) hw_w32_write((fd), (buf), (n))
#define close(fd)         hw_w32_close(fd)
#endif

#endif
