// <sys/uio.h> for Windows: only the type. See src/compat/win32/hw_w32.h.
#ifndef HOLYWISP_COMPAT_SYS_UIO_H
#define HOLYWISP_COMPAT_SYS_UIO_H

#include <stddef.h>

struct iovec {
	void *iov_base;
	size_t iov_len;
};

#endif
