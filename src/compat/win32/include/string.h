// <string.h> for Windows: plus memmem(3). See src/compat/win32/hw_w32.h.
#ifndef HOLYWISP_COMPAT_STRING_H
#define HOLYWISP_COMPAT_STRING_H

// This file stands in front of the toolchain's header of the same name and passes on to it.
#pragma GCC system_header
#include_next <string.h>

void *memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len);

#endif
