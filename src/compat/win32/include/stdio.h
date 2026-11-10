// <stdio.h> for Windows: rename(2) that replaces its target. See src/compat/win32/hw_w32.h.
#ifndef HOLYWISP_COMPAT_STDIO_H
#define HOLYWISP_COMPAT_STDIO_H

// This file stands in front of the toolchain's header of the same name and passes on to it.
#pragma GCC system_header
#include_next <stdio.h>

// The runtime's rename fails when the new name exists; POSIX's replaces it in one step.
int hw_w32_rename(const char *from, const char *to);

#ifndef HW_W32_NO_MACROS
#define rename(from, to) hw_w32_rename((from), (to))
#endif

#endif
